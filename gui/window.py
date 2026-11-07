"""The window: header, tabs, the activity strip, start and stop.

Страницы — это вид: они показывают состояние и просят сделать что-то
у ``EngineSession``.  Правила (кого пропускать, когда подтверждать) живут в
движке; диалоги подтверждения — здесь, как в консоли.

Окно рассчитано на 980×760 и остаётся читаемым, когда его тянут к
минимальному размеру: все подписи переносятся по словам, а боковые
отступы и внешний вид задаются в одном месте (``widgets.common``).
"""

from __future__ import annotations

import contextlib
import time
from typing import List, Optional

import bridge
from PySide6.QtCore import QObject, QSize, QTimer, Qt, Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMainWindow, QPushButton,
                               QScrollArea, QSizePolicy, QTabWidget,
                               QVBoxLayout, QWidget)

from .core import events as ev
from .core.search import Finder
from .core.session import BridgeSession, EngineConfig
from .pages.activity import LogPage
from .pages.base import Page
from .pages.connections import ConnectionsPage
from .pages.devices import DevicesPage
from .pages.forward import ForwardPage
from .pages.overview import OverviewPage
from .pages.sync import SyncPage
from .pages.session_bridge import EngineSession
from .widgets.common import (ACCENT, ERROR, IDLE_GREY, LiveDot, MUTED, OK,
                             WARN, style_sheet)

# A stall means the engine loop has not ticked for this long.
STALL_SECONDS = 5.0
# "Something was forwarded" stays lit on the strip this long.
FLASH_SECONDS = 1.5


class EventRelay(QObject):
    """Receives the session's signals on the GUI thread.

    Qt queues a signal that crosses threads to the receiver's thread, so the
    relay is the one place where an engine event becomes a GUI call.
    """

    forwarded = Signal(object)
    heartbeat = Signal(float)


def _default_finder(parent: QObject) -> Finder:
    """The real searcher; ``gui.main`` passes its own so tests can fake it."""
    from .core.search import DeviceSearch
    return DeviceSearch(parent)


class MainWindow(QMainWindow):
    def __init__(self, cfg: EngineConfig, autostart: bool = True,
                 parent: Optional[QWidget] = None,
                 finder: Optional[Finder] = None):
        super().__init__(parent)
        self.setWindowTitle("Мост Meshtastic ↔ Bitchat")
        self.setMinimumSize(520, 480)
        self.resize(980, 760)
        self.setStyleSheet(style_sheet())

        self.finder = finder if finder is not None else _default_finder(self)
        self.session = self._make_session(cfg)
        self._last_beat = 0.0
        self._last_forward = 0.0
        self._forward_until = 0.0
        self._core_state = "stopped"

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)
        root.addWidget(self._build_header())

        self.pages: List[Page] = []
        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(True)
        self.tabs.setElideMode(Qt.TextElideMode.ElideRight)
        self.tabs.setDocumentMode(True)
        self.tabs.setIconSize(QSize(16, 16))
        # Pictures instead of words in the strip (the Russian titles need
        # more width than a laptop window usually has); the full name is the
        # tab's tooltip and the page's own heading.
        for page, title, icon in (
                (DevicesPage(self.session), "Устройства: радио, чат, телефон",
                 "⌂"),
                (OverviewPage(self.session), "Обзор", "◉"),
                (ForwardPage(self.session),
                 "Пересылка Bitchat → LoRa", "➜"),
                (SyncPage(self.session), "Синхронизация", "⇄"),
                (ConnectionsPage(self.session), "Подключения", "⚯"),
                (LogPage(self.session), "Журнал", "☰")):
            page.setProperty("tabTitle", title)
            self.pages.append(page)
            index = self.tabs.addTab(self._scrollable(page), icon)
            self.tabs.setTabToolTip(index, title)
        self.tabs.tabBar().setExpanding(False)
        root.addWidget(self.tabs, 1)
        root.addWidget(self._build_footer())
        self.setCentralWidget(central)
        self._wire_devices()

        self._idle_timer = QTimer(self)
        self._idle_timer.setInterval(300)
        self._idle_timer.timeout.connect(self._check_liveness)
        self._idle_timer.start()

        self._set_core_state("stopped")
        if autostart:
            QTimer.singleShot(0, self.start_bridge)

    # --------------------------------------------------------- engine glue
    def _wire_devices(self) -> None:
        """Connect the device page to the searcher and to the engine.

        The page only asks; the window owns the searcher (threads) and the
        engine session, so a restart keeps working without touching pages.
        """
        self.devices = next((page for page in self.pages
                            if isinstance(page, DevicesPage)), None)
        if self.devices is None:
            return
        self.devices.attach(self.finder)
        self.devices.config_path = (self._bridge.cfg.config_path
                                    or "config.json")
        cfg = self._bridge.cfg
        # What the page shows before anything is searched: the radio and chat
        # the config file gives, exactly what the old window used silently.
        if cfg.transport:
            self.devices.set_transport(cfg.transport)
        if cfg.chat_target:
            self.devices.set_chat(cfg.chat_target)
        self.devices.start_requested.connect(self._start_from_devices)
        self.devices.chat_picked.connect(self._devices_chat)
        self.devices.stop_requested.connect(self.stop_bridge)
        self.finder.radios.connect(self.devices.on_radios)
        self.finder.radios_failed.connect(self.devices.on_radios_failed)
        self.finder.phones.connect(self.devices.on_phones)
        self.finder.chats.connect(self.devices.on_chats)
        self.finder.failed.connect(self.devices.on_failed)
        self._dev_watch = QTimer(self)
        self._dev_watch.setInterval(200)
        self._dev_watch.timeout.connect(self._sync_devices)
        self._dev_watch.start()

    def _start_from_devices(self) -> None:
        """Start the bridge on what the device page has chosen."""
        if self.devices is None:
            return
        transport = self.devices.transport
        if not transport:
            return
        self.start_bridge(transport=transport, chat=self.devices.chat,
                          phone=self.devices.phone)

    def _sync_devices(self) -> None:
        """Mirror the engine's state on the device page (prompt and button).

        The page cannot read the engine itself: the session is replaced on
        every start, so the window tells it what to show.
        """
        if self.devices is None:
            return
        running = bool(self._bridge.alive)
        if running:
            self.devices.show_prompt(self.devices.prompt_for_engine(
                self._bridge))
            self.devices.set_busy(True)
            return
        if not (self.devices.shows_engine or self.devices.is_busy):
            # Nothing has been started for this page yet: its own lines stay.
            return
        self.devices.show_prompt(self.devices.prompt_when_stopped())
        self.devices.set_engine_state("stopped")
        self.devices.set_busy(False)

    # ------------------------------------------------------------- checks
    def _devices_chat(self, chat) -> None:
        """The owner moved the chat selector: check the chat with this radio.

        A direct chat needs a node that exists on that radio; a channel must
        be enabled there.  Until now this was checked by the radio itself;
        the page asks the same question and puts the answer in the status
        line, while the engine keeps making its own final decision.
        """
        if not chat or not self.devices.transport or self.session is None:
            return
        session = self.session
        # The engine is asked only when it is running; while it is stopped
        # the page says so and the check happens at start.
        if not getattr(session, "ble", None) or \
                not getattr(session, "mesh", None):
            self.devices.show_check("Радио ещё не на связи: проверка будет "
                                    "при запуске моста.")
            return
        try:
            decided = session.check_chat(chat)
        except Exception as exc:  # noqa: BLE001
            self.devices.show_check(f"Беседа не проверена: {exc}")
            return
        self.devices.show_check(decided)

    # Note: the page's chat signal is wired to the window only, never to
    # the page's own set_chat — the page has no engine to ask.

    def _make_session(self, cfg: EngineConfig) -> EngineSession:
        """One engine thread + one action layer for every page."""
        relay = EventRelay(self)
        bridge_session = BridgeSession(cfg, self)
        bridge_session.event.connect(relay.forwarded)
        bridge_session.heartbeat.connect(relay.heartbeat)
        bridge_session.started.connect(self._on_started)
        bridge_session.stopped.connect(self._on_stopped)
        self.relay = relay
        self._bridge = bridge_session
        self.relay.forwarded.connect(self.receive)
        self.relay.heartbeat.connect(self._heartbeat)
        self.engine = EngineSession(bridge_session, self)
        return self.engine

    # -------------------------------------------------------------- layout
    def _build_header(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        self.core_dot = LiveDot(size=16)
        layout.addWidget(self.core_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        titles = QWidget()
        titles_layout = QVBoxLayout(titles)
        titles_layout.setContentsMargins(0, 0, 0, 0)
        titles_layout.setSpacing(0)
        self.core_label = QLabel("Мост остановлен")
        self.core_label.setStyleSheet("font-size: 15px; font-weight: 600;")
        self.core_label.setWordWrap(True)
        self.core_detail = QLabel("")
        self.core_detail.setObjectName("Muted")
        self.core_detail.setWordWrap(True)
        self.core_detail.setSizePolicy(QSizePolicy.Policy.Ignored,
                                       QSizePolicy.Policy.Preferred)
        titles_layout.addWidget(self.core_label)
        titles_layout.addWidget(self.core_detail)
        layout.addWidget(titles, 1)
        self.btn_start = QPushButton("Запустить")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_bridge)
        self.btn_stop = QPushButton("Остановить")
        self.btn_stop.clicked.connect(self.stop_bridge)
        layout.addWidget(self.btn_start)
        layout.addWidget(self.btn_stop)
        return bar

    def _build_footer(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        # The activity strip: a small dot that flashes on every forwarding
        # and one line about the last one.
        self.traffic_dot = LiveDot(size=12)
        layout.addWidget(self.traffic_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        self.traffic = QLabel("Пересылок ещё не было")
        self.traffic.setObjectName("Muted")
        self.traffic.setWordWrap(True)
        self.traffic.setSizePolicy(QSizePolicy.Policy.Ignored,
                                   QSizePolicy.Policy.Preferred)
        layout.addWidget(self.traffic, 1)
        self.heartbeat_label = QLabel("—")
        self.heartbeat_label.setObjectName("Muted")
        self.heartbeat_label.setAlignment(Qt.AlignmentFlag.AlignRight |
                                          Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.heartbeat_label)
        return bar

    def _scrollable(self, page: QWidget) -> QScrollArea:
        """Pages scroll instead of clipping when the window is small.

        The page is pinned to the visible width (no horizontal scrolling)
        and to the height it needs at that width, so a long page scrolls
        vertically and a page with no free space (the journal) still fills
        the tab.
        """
        class _Fit(QWidget):
            """The page, kept as wide as the scroll area and as tall as it
            needs at that width."""

            def __init__(self, inner: QWidget) -> None:
                super().__init__()
                self._inner = inner
                layout = QVBoxLayout(self)
                layout.setContentsMargins(0, 2, 0, 2)
                layout.addWidget(inner)

            def sizeHint(self) -> QSize:  # noqa: N802
                width = self.width() or self._inner.minimumSizeHint().width()
                return QSize(width, self._inner.heightForWidth(width) + 4)

            def minimumSizeHint(self) -> QSize:  # noqa: N802
                return QSize(self._inner.minimumSizeHint().width(), 100)

            def resizeEvent(self, event) -> None:  # noqa: N802
                self._fit(event.size().width())
                super().resizeEvent(event)

            def showEvent(self, event) -> None:  # noqa: N802
                self._fit(self.width())
                super().showEvent(event)

            def _fit(self, width: int) -> None:
                width = max(1, width)
                self._inner.setFixedWidth(width)
                needed = self._inner.heightForWidth(width)
                if needed > 0 and self._inner.minimumHeight() != needed:
                    self._inner.setMinimumHeight(needed)
                    self.updateGeometry()

        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QScrollArea.Shape.NoFrame)
        area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        area.setWidget(_Fit(page))
        return area

    # ------------------------------------------------------------ controls
    def start_bridge(self, transport: Optional[dict] = None,
                     chat: Optional[dict] = None,
                     phone: Optional[dict] = None) -> None:
        """Start the engine.

        With no arguments it uses the config file, as old builds did.  The
        device page passes the radio, the chat and the confirmed phone it
        collected, which is what the console menu does before ``bridge.run``.
        """
        if self._bridge.alive:
            return
        cfg = self._bridge.cfg
        self._own_device_choice = False
        if transport or chat or phone:
            # The choice is made here, by the owner: the engine may bind the
            # phone and start without asking again.
            self._own_device_choice = True
            cfg.ready = True
            if chat:
                cfg.chat_target = dict(chat)
                cfg.channel = int(chat.get("index", 0)) \
                    if chat.get("kind") == "channel" else cfg.channel
            if phone and phone.get("peer"):
                cfg.bitchat_peer = str(phone["peer"]).lower()
                cfg.bitchat_key = phone.get("signing_pub")
                cfg.bitchat_nickname = phone.get("nickname") or ""
                cfg.bitchat_fingerprint = phone.get("fingerprint") or ""
            if transport:
                bridge.save_transport(cfg.config_path, transport)
                cfg.transport = dict(transport)
        self.session = self._make_session(cfg)
        for page in self.pages:
            page.set_session(self.session)
        self._last_beat = 0.0
        self._set_core_state("starting")
        self._bridge.start()

    def stop_bridge(self) -> None:
        self._bridge.request_stop()
        self.core_label.setText("Останавливается…")
        self.core_dot.set_state(WARN, alive=True)
        self.btn_stop.setEnabled(False)

    def closeEvent(self, event) -> None:  # noqa: N802
        # A readable buffer must not outlive the window: the engine wipes it
        # in its own stop path, so wait for that path to finish.
        if self._bridge.alive:
            self._bridge.shutdown(timeout=12.0)
        # Searches run on their own threads; they must end before Qt takes
        # the widgets away, or a late result would be delivered to nothing.
        with contextlib.suppress(Exception):
            self.finder.shutdown()
        event.accept()

    # --------------------------------------------------------------- state
    @property
    def core_state(self) -> str:
        return self._core_state

    def _set_core_state(self, name: str) -> None:
        self._core_state = name
        if name == "running":
            self.core_label.setText("Мост работает")
            self.core_dot.set_state(OK, alive=True)
            self.core_detail.setText("")
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
        elif name == "starting":
            self.core_label.setText("Запускается…")
            self.core_dot.set_state(WARN, alive=True)
            self.core_detail.setText("Поиск радио и телефона.")
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
        else:
            self.core_label.setText("Мост остановлен")
            self.core_dot.set_state(IDLE_GREY, alive=False)
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
        for page in self.pages:
            page.on_core_state(name)

    def _on_started(self) -> None:
        self._set_core_state("running")
        self._refresh_pages()

    def _on_stopped(self, reason: str) -> None:
        self._set_core_state("stopped")
        if reason:
            self.traffic.setText(f"Мост остановлен с ошибкой: {reason}")
            self.receive(ev.LogEvent(f"Мост остановлен: {reason}",
                                     ev.Level.ERROR))
        else:
            self.traffic.setText("Мост остановлен")

    def _refresh_pages(self) -> None:
        snapshot = self.session.snapshot()
        if snapshot is not None:
            for page in self.pages:
                page.on_state(snapshot)

    # ------------------------------------------------------------- events
    def _heartbeat(self, gap: float) -> None:
        self._last_beat = time.monotonic()
        self.heartbeat_label.setText(f"живой · {time.strftime('%H:%M:%S')}")
        self._refresh_pages()
        for page in self.pages:
            if isinstance(page, OverviewPage):
                page.on_heartbeat(max(0.0, float(gap)))

    def _check_liveness(self) -> None:
        if self._core_state != "running":
            return
        if self._last_beat and \
                time.monotonic() - self._last_beat > STALL_SECONDS:
            self.core_dot.set_state(ERROR, alive=True)
            self.core_label.setText("Мост не отвечает")
            self.core_detail.setText("Движок молчит дольше пяти секунд — "
                                     "смотрите «Журнал».")
        if self._forward_until and time.monotonic() > self._forward_until:
            self._forward_until = 0.0
            self.traffic_dot.set_state(IDLE_GREY, alive=False)

    def receive(self, event: ev.Event) -> None:
        """One engine event: fan it out to the pages and the strip."""
        for page in self.pages:
            page.on_event(event)
        if isinstance(event, ev.ForwardedEvent):
            self._last_forward = time.time()
            self._forward_until = time.monotonic() + FLASH_SECONDS
            self.traffic_dot.set_state(ACCENT, alive=True)
            self.traffic_dot.flash()
            where = "в LoRa" if event.direction == "to_lora" else "на телефон"
            who = f" от «{event.author}»" if event.author else ""
            self.traffic.setText(f"передано {where}{who}: {event.count}")
