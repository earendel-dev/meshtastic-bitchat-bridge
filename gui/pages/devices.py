"""Устройства: то же меню, что у консоли, но в окне.

Консоль при запуске спрашивает две вещи: какое радио (Wi-Fi, Bluetooth,
USB или адрес вручную) и какой телефон Bitchat.  Окно раньше брало радио
из ``config.json`` и не спрашивало ничего — здесь появляется тот же выбор.

Порядок намеренно повторяет консольный:

1. выбрать радио (поиск или адрес руками);
2. выбрать беседу в радио (канал или личный чат с узлом);
3. найти телефон и подтвердить его **два раза**;
4. запустить мост.

Выбор радио запоминается в ``config.json``, как в консоли.  Телефон не
запоминается никогда: его подтверждают на каждом запуске.
"""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QListWidgetItem, QPushButton,
                               QSizePolicy, QWidget)

import bridge
from ..core import events as ev
from ..widgets import MUTED, OK, WARN
from ..widgets.dialogs import confirm_twice
from .base import Page
from .session_bridge import EngineSession

NODE_PAGE = 30        # node lists are long; the console pages them by 20


def _wrap(label: QLabel) -> QLabel:
    label.setWordWrap(True)
    label.setSizePolicy(QSizePolicy.Policy.Ignored,
                        QSizePolicy.Policy.Preferred)
    return label


def _compact(button: QPushButton) -> QPushButton:
    button.setMinimumWidth(0)
    button.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    return button


def phone_summary(phone: dict) -> str:
    """One line about a found phone; the text never includes a message."""
    name = phone.get("nickname") or phone.get("name") or "Bitchat"
    parts = [name]
    peer = phone.get("peer") or ""
    if peer:
        parts.append(f"@{peer[:4]}")
    fingerprint = phone.get("fingerprint") or ""
    if fingerprint:
        parts.append(fingerprint.split("-")[0])
    rssi = phone.get("rssi")
    if rssi:
        parts.append(f"{rssi} dBm")
    return " — ".join(parts)


def phone_details(phone: dict) -> str:
    """Everything the console shows before binding, as a dialog text."""
    return bridge.describe_phone(phone).strip()


class DevicesPage(Page):
    title = "Устройства"
    subtitle = ("То же, что меню консоли: радио, беседа в нём и телефон. "
                "Телефон подтверждается дважды на каждый запуск.")

    # The page only asks; the window decides when the engine starts.
    start_requested = Signal()
    stop_requested = Signal()
    # Emitted when the owner moves the chat selector to another row; the
    # window then makes sure the question made sense for this radio.
    chat_picked = Signal(object)

    def __init__(self, session: Optional[EngineSession],
                 parent: Optional[QWidget] = None):
        super().__init__(session, parent)
        self.transport: Optional[dict] = None
        self.chat: Optional[dict] = None
        self.phone: Optional[dict] = None
        self.finder = None           # gui.core.search.DeviceSearch
        self.config_path = "config.json"
        self._phones: List[dict] = []
        self._radio_items: List[dict] = []
        self._chat_items: List[dict] = []
        self._node_items: List[dict] = []
        self._node_page = 0
        self._running = False
        self._busy_now = False
        self._status_when_running = ""
        # True while the page itself moves the combo: the signal it causes
        # must not be taken for a choice, or set_chat would call itself.
        self._picking = False

        # ---------------------------------------------------------- radio
        self.body.addWidget(self._heading("1. Радио Meshtastic"))
        self.radio_value = _wrap(QLabel("не выбрано"))
        self.radio_value.setObjectName("Muted")
        self.body.addWidget(self.radio_value)

        buttons = QHBoxLayout()
        buttons.setSpacing(6)
        self.btn_wifi = _compact(QPushButton("Wi-Fi"))
        self.btn_wifi.setToolTip("Найти Meshtastic в локальной сети")
        self.btn_wifi.clicked.connect(lambda: self._search_radio("wifi"))
        self.btn_ble = _compact(QPushButton("Bluetooth"))
        self.btn_ble.setToolTip("Найти Meshtastic по Bluetooth")
        self.btn_ble.clicked.connect(lambda: self._search_radio("ble"))
        self.btn_usb = _compact(QPushButton("USB"))
        self.btn_usb.setToolTip("Список COM-портов")
        self.btn_usb.clicked.connect(lambda: self._search_radio("serial"))
        buttons.addWidget(self.btn_wifi)
        buttons.addWidget(self.btn_ble)
        buttons.addWidget(self.btn_usb)
        self.body.addLayout(buttons)

        manual = QHBoxLayout()
        manual.setSpacing(6)
        self.manual = QLineEdit()
        self.manual.setPlaceholderText("IP / COM / BLE-адрес")
        self.manual.setMinimumWidth(0)
        self.manual.returnPressed.connect(self._manual_radio)
        self.btn_manual = _compact(QPushButton("Вручную"))
        self.btn_manual.setToolTip("Подключиться к адресу, введённому слева")
        self.btn_manual.clicked.connect(self._manual_radio)
        manual.addWidget(self.manual, 2)
        manual.addWidget(self.btn_manual, 1)
        self.body.addLayout(manual)

        self.radio_list = QListWidget()
        self.radio_list.setMinimumHeight(64)
        self.radio_list.itemDoubleClicked.connect(
            lambda _item: self._use_selected_radio())
        self.body.addWidget(self.radio_list)
        radio_row = QHBoxLayout()
        self.btn_use_radio = _compact(QPushButton("Подключить выбранное"))
        self.btn_use_radio.clicked.connect(self._use_selected_radio)
        radio_row.addWidget(self.btn_use_radio)
        self.body.addLayout(radio_row)

        # ----------------------------------------------------------- chat
        self.body.addWidget(self._heading("2. Беседа в радио"))
        self.chat_value = _wrap(QLabel("как в config.json"))
        self.chat_value.setObjectName("Muted")
        self.body.addWidget(self.chat_value)
        self.check_value = _wrap(QLabel(""))
        self.check_value.setObjectName("Muted")
        self.body.addWidget(self.check_value)
        self.chat_combo = QComboBox()
        self.chat_combo.setMinimumWidth(0)
        self.chat_combo.addItem("Список ещё не получен", None)
        self.chat_combo.currentIndexChanged.connect(self._combo_changed)
        self.body.addWidget(self.chat_combo)
        self.btn_chats = _compact(QPushButton("Прочитать каналы и узлы"))
        self.btn_chats.clicked.connect(self._load_chats)
        self.body.addWidget(self.btn_chats)
        self.node_list = QListWidget()
        self.node_list.setMinimumHeight(64)
        self.node_list.itemClicked.connect(self._node_chosen)
        self.node_list.hide()
        self.page_row = QWidget()
        row = QHBoxLayout(self.page_row)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        self.btn_prev = _compact(QPushButton("←"))
        self.btn_prev.clicked.connect(lambda: self._turn_page(-1))
        self.btn_next = _compact(QPushButton("→"))
        self.btn_next.clicked.connect(lambda: self._turn_page(1))
        self.page_label = _wrap(QLabel(""))
        self.page_label.setObjectName("Muted")
        row.addWidget(self.btn_prev)
        row.addWidget(self.btn_next)
        row.addWidget(self.page_label, 1)
        self.page_row.hide()
        self.body.addWidget(self.node_list)
        self.body.addWidget(self.page_row)

        # ---------------------------------------------------------- phone
        self.body.addWidget(self._heading("3. Телефон Bitchat"))
        self.phone_value = _wrap(QLabel("не выбран"))
        self.phone_value.setObjectName("Muted")
        self.phone_value.setStyleSheet(f"color: {MUTED};")
        self.body.addWidget(self.phone_value)
        self.phone_list = QListWidget()
        self.phone_list.setMinimumHeight(64)
        self.phone_list.itemDoubleClicked.connect(
            lambda _item: self._confirm_phone())
        self.body.addWidget(self.phone_list)
        phones = QHBoxLayout()
        phones.setSpacing(6)
        self.btn_scan_phone = _compact(QPushButton("Найти телефон"))
        self.btn_scan_phone.clicked.connect(self._scan_phones)
        self.btn_confirm_phone = _compact(QPushButton("Подтвердить"))
        self.btn_confirm_phone.clicked.connect(self._confirm_phone)
        phones.addWidget(self.btn_scan_phone)
        phones.addWidget(self.btn_confirm_phone)
        self.body.addLayout(phones)

        # -------------------------------------------------------- start
        self.body.addWidget(self._heading("4. Запуск"))
        self.ready_value = _wrap(QLabel(""))
        self.ready_value.setObjectName("Muted")
        self.body.addWidget(self.ready_value)
        self.btn_start = QPushButton("Запустить мост")
        self.btn_start.setObjectName("Primary")
        self.btn_start.setMinimumWidth(0)
        self.btn_start.setSizePolicy(QSizePolicy.Policy.Ignored,
                                     QSizePolicy.Policy.Fixed)
        self.btn_start.clicked.connect(self._start)
        self.btn_stop = QPushButton("Остановить мост")
        self.btn_stop.setMinimumWidth(0)
        self.btn_stop.setSizePolicy(QSizePolicy.Policy.Ignored,
                                    QSizePolicy.Policy.Fixed)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        buttons = QHBoxLayout()
        buttons.setSpacing(6)
        buttons.addWidget(self.btn_start, 1)
        buttons.addWidget(self.btn_stop, 1)
        self.body.addLayout(buttons)
        self.status = _wrap(QLabel(""))
        self.body.addWidget(self.status)

        self._refresh_ready()
        self._idle()

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _heading(text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet("font-weight: 600;")
        label.setWordWrap(True)
        return label

    def attach(self, finder) -> None:
        """Point the page at the searcher that runs the searches."""
        self.finder = finder

    def set_transport(self, transport: Optional[dict]) -> None:
        self.transport = dict(transport) if transport else None
        self._show_radio()
        self._refresh_ready()
        self._idle()

    def set_chat(self, chat: Optional[dict]) -> None:
        self.chat = dict(chat) if chat else None
        self.chat_value.setText(self._chat_text())
        # Keep the list in step with the choice (the index is -1 when the
        # list is empty, and a -1 combo shows nothing at all).  The change
        # this move causes is ours, not the owner's, so it is ignored by
        # ``_combo_changed``.
        index = self._combo_index(self.chat)
        if index is not None:
            self._picking = True
            try:
                self.chat_combo.setCurrentIndex(index)
            finally:
                self._picking = False
        self._idle()
    def set_phone(self, phone: Optional[dict]) -> None:
        self.phone = dict(phone) if phone else None
        if self.phone:
            self.phone_value.setText(phone_summary(self.phone))
            self.phone_value.setStyleSheet(f"color: {OK};")
        else:
            self.phone_value.setText("не выбран")
            self.phone_value.setStyleSheet(f"color: {MUTED};")
        self._refresh_ready()
        self._idle()

    def show_check(self, text: str) -> None:
        """Show the radio's answer about the chosen chat."""
        self.check_value.setText(text or "")
        self.check_value.setStyleSheet(f"color: {MUTED};")

    def _combo_index(self, chat: Optional[dict]) -> Optional[int]:
        """Which combo row shows *chat*, or ``None`` when it is not listed."""
        if not chat or not self._chat_items:
            return None
        wanted = (chat.get("kind"),
                  int(chat.get("index", 0))
                  if chat.get("kind") == "channel" else 0)
        for i, item in enumerate(self._chat_items):
            target = item.get("target") or {}
            have = (target.get("kind"),
                    int(target.get("index", 0))
                    if target.get("kind") == "channel" else 0)
            if have == wanted:
                return i
        return None

    def _chat_text(self) -> str:
        if not self.chat:
            return "как в config.json"
        kind = self.chat.get("kind")
        if kind == "channel":
            return f"канал {self.chat.get('index', 0)}"
        if kind == "dm":
            return f"личный чат: {self.chat.get('node')}"
        return "всё: каналы и личные сообщения"

    def _show_radio(self) -> None:
        if not self.transport:
            self.radio_value.setText("не выбрано")
            self.radio_value.setStyleSheet(f"color: {MUTED};")
            return
        self.radio_value.setText(self.transport.get("label")
                                 or f"{self.transport.get('kind')} "
                                    f"{self.transport.get('target')}")
        self.radio_value.setStyleSheet(f"color: {OK};")

    def _refresh_ready(self) -> None:
        if self._running:
            return
        if not self.transport:
            self.ready_value.setText(
                "Выберите радио. Телефон можно подтвердить и после запуска: "
                "мост запустится и будет ждать его появления.")
        elif self.phone:
            self.ready_value.setText(
                "Радио и телефон выбраны. Можно запускать.")
        else:
            self.ready_value.setText(
                "Радио выбрано, телефон ещё нет. Мост запустится и будет "
                "ждать телефон с Bitchat.")

    # ------------------------------------------------- engine state (window)
    def set_busy(self, busy: bool) -> None:
        """The window says whether the bridge is running.

        The page never looks at the engine itself: the session object is
        replaced on every start, so the window is the one who knows.
        """
        busy = bool(busy)
        if busy == self._running:
            # The window delivers this on every tick; it must not wipe the
            # line the page has just written about a stop.
            if not busy and self._busy_now:
                # The start never took: the engine is not running (it may
                # have failed straight away), so the buttons come back.
                self._busy_now = False
                if self.status.text().startswith("Запускаю"):
                    self.status.setText("Мост не запустился — попробуйте ещё "
                                        "раз или посмотрите журнал.")
                self._apply_enabled()
            return
        self._running = busy
        self.btn_stop.setEnabled(busy)
        if busy:
            self._busy_now = False
            self._status_when_running = self.status.text()
            self.status.setText("Мост работает. Телефон можно подтвердить и "
                                "после запуска — движок будет ждать его.")
            self.status.setStyleSheet(f"color: {MUTED};")
            self._apply_enabled()
            return
        self._busy_now = False
        if (self._status_when_running and
                self.status.text().startswith("Мост работает")):
            # Nobody said anything newer while it ran: the page's own line
            # about the phone or a search stays; the prompt says "stopped".
            self.status.setText(self._status_when_running)
        self.ready_value.setText("Мост остановлен. Можно запустить снова.")
        self._apply_enabled()

    @property
    def is_busy(self) -> bool:
        """True while a search runs or a start is being requested."""
        return self._busy_now

    @property
    def shows_engine(self) -> bool:
        """True once this page was told that an engine is running for it."""
        return self._running

    def set_engine_state(self, name: str) -> None:
        """What the window's start/stop buttons show, mirrored here."""
        if name == "stopped":
            self.btn_stop.setEnabled(False)

    def prompt_for_engine(self, bridge_session) -> str:
        """What the phone is waiting for, read from the live engine."""
        cfg = getattr(bridge_session, "cfg", None)
        peer = (getattr(cfg, "bitchat_peer", "") or "").lower()
        if not peer:
            return ("Мост работает. Телефон не подтверждён: движок ждёт "
                    "телефон с Bitchat, пока не найдёт его.")
        label = getattr(cfg, "bitchat_nickname", "") or "@" + peer[:4]
        connected = False
        try:
            connected = bool(bridge_session.ble and bridge_session.ble.connected)
        except Exception:  # noqa: BLE001
            connected = False
        if connected:
            return (f"Мост работает и связан с телефоном {label}. Этот же "
                    "телефон можно сменить ниже — будет отключён старый.")
        return (f"Мост работает, ждёт телефон {label}. Другой телефон "
                "подключиться не сможет.")

    @staticmethod
    def prompt_when_stopped() -> str:
        return "Мост остановлен."

    def show_prompt(self, text: str) -> None:
        if text and self.ready_value.text() != text:
            self.ready_value.setText(text)

    def _stop(self) -> None:
        self.status.setText("Останавливаю мост…")
        self.status.setStyleSheet(f"color: {WARN};")
        self.stop_requested.emit()

    def _busy(self, text: str) -> None:
        self._busy_now = True
        self._apply_enabled()
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {WARN};")

    def _idle(self, text: str = "", level: str = MUTED) -> None:
        if self._busy_now:
            return
        self._apply_enabled()
        if text:
            self.status.setText(text)
            self.status.setStyleSheet(f"color: {level};")

    def _apply_enabled(self) -> None:
        """What may be pressed now: nothing while busy or while running."""
        free = not (self._busy_now or self._running)
        self.btn_wifi.setEnabled(free)
        self.btn_ble.setEnabled(free)
        self.btn_usb.setEnabled(free)
        self.btn_manual.setEnabled(free)
        self.manual.setEnabled(free)
        self.btn_use_radio.setEnabled(free and bool(self.radio_list.count()))
        self.btn_chats.setEnabled(free and bool(self.transport))
        self.btn_scan_phone.setEnabled(free)
        self.btn_confirm_phone.setEnabled(free and bool(self.phone_list.count()))
        self.btn_start.setEnabled(free and bool(self.transport))
        self.btn_stop.setEnabled(self._running)

    def _done(self, text: str = "", level: str = MUTED) -> None:
        """A search (or a choice) ended: buttons come back, line is shown."""
        self._busy_now = False
        if text:
            self.status.setText(text)
            self.status.setStyleSheet(f"color: {level};")
        self._apply_enabled()

    # -------------------------------------------------------------- radio
    def _search_radio(self, kind: str) -> None:
        if self.finder is None:
            self._done("Поиск устройств недоступен.", WARN)
            return
        self.radio_list.clear()
        self._radio_items = []
        names = {"wifi": "Ищу радио по Wi-Fi… (может занять до полуминуты)",
                 "ble": "Ищу радио по Bluetooth…",
                 "serial": "Читаю список COM-портов…"}
        self._busy(names.get(kind, "Ищу радио…"))
        self.finder.find_radios(kind)

    def on_radios(self, devices: list) -> None:
        self._radio_items = list(devices)
        self.radio_list.clear()
        for device in self._radio_items:
            self.radio_list.addItem(device.get("label") or str(device))
        if self._radio_items:
            self.radio_list.setCurrentRow(0)
        self._done(f"Найдено устройств: {len(self._radio_items)}. Выберите и "
                   "нажмите «Подключить выбранное».",
                   OK if self._radio_items else MUTED)

    def on_radios_failed(self, text: str) -> None:
        self._done(text, WARN)

    def _use_selected_radio(self) -> None:
        row = self.radio_list.currentRow()
        if not (0 <= row < len(self._radio_items)):
            self._done("Сначала найдите радио или введите адрес.", WARN)
            return
        self._adopt_radio(self._radio_items[row])

    def _manual_radio(self) -> None:
        parsed = bridge.parse_transport_text(self.manual.text())
        if parsed is None:
            self._done("Введите адрес: IP, COM-порт или BLE-адрес.", WARN)
            return
        self._adopt_radio(parsed)

    def _adopt_radio(self, transport: dict) -> None:
        self.set_transport(transport)
        # The console remembers the radio in config.json; the phone never.
        bridge.save_transport(self.config_path, transport)
        self._done(f"Радио выбрано: {transport.get('label')}", OK)

    # --------------------------------------------------------------- chat
    def _load_chats(self) -> None:
        if self.finder is None or not self.transport:
            self._done("Сначала выберите радио.", WARN)
            return
        self._busy("Читаю каналы и список узлов…")
        self.finder.find_chats(self.transport)

    def on_chats(self, entries: list, nodes: list) -> None:
        self._chat_items = list(entries)
        self._node_items = list(nodes)
        self.chat_combo.clear()
        for item in self._chat_items:
            self.chat_combo.addItem(item["label"], item["target"])
        self.chat_combo.addItem("Личный чат с узлом…", {"kind": "__nodes"})
        # A fresh list must not lose the choice: point at the new index of
        # what is chosen now (the config file's chat before anything else).
        index = self._combo_index(self.chat)
        if index is not None:
            self.chat_combo.setCurrentIndex(index)
        self._show_nodes()
        channels = max(0, len(self._chat_items) - 1)
        self._done(f"Каналов: {channels}, узлов: {len(self._node_items)}.",
                   OK)

    def on_chats_failed(self, text: str) -> None:
        self._done(text, WARN)

    def _show_nodes(self) -> None:
        self._node_page = 0
        self._render_nodes()

    def _turn_page(self, delta: int) -> None:
        pages = max(1, (len(self._node_items) + NODE_PAGE - 1) // NODE_PAGE)
        self._node_page = max(0, min(pages - 1, self._node_page + delta))
        self._render_nodes()

    def _render_nodes(self) -> None:
        pages = max(1, (len(self._node_items) + NODE_PAGE - 1) // NODE_PAGE)
        start = self._node_page * NODE_PAGE
        self.node_list.clear()
        for item in self._node_items[start:start + NODE_PAGE]:
            entry = QListWidgetItem(item["label"])
            entry.setData(Qt.ItemDataRole.UserRole, item["target"])
            self.node_list.addItem(entry)
        self.page_label.setText(f"страница {self._node_page + 1}/{pages}, "
                                f"всего узлов: {len(self._node_items)}")
        self.btn_prev.setEnabled(self._node_page > 0)
        self.btn_next.setEnabled(self._node_page + 1 < pages)

    def _combo_changed(self, index: int) -> None:
        if self._picking:
            return
        target = self.chat_combo.itemData(index)
        if not target:
            return
        if target.get("kind") == "__nodes":
            self.node_list.show()
            self.page_row.show()
            self._render_nodes()
            return
        self.node_list.hide()
        self.page_row.hide()
        self.set_chat(target)
        self.chat_picked.emit(dict(target))
        self._done(f"Беседа: {self._chat_text()}", OK)

    def _node_chosen(self, item: QListWidgetItem) -> None:
        target = item.data(Qt.ItemDataRole.UserRole)
        if target:
            self.set_chat(target)
            self.chat_picked.emit(dict(target))
            self._done(f"Беседа: {self._chat_text()}", OK)

    # -------------------------------------------------------------- phone
    def _scan_phones(self) -> None:
        if self.finder is None:
            self._done("Поиск телефонов недоступен.", WARN)
            return
        self.phone_list.clear()
        self._busy("Ищу телефоны Bitchat… Телефон должен быть рядом, Bitchat "
                   "открыт.")
        self.finder.find_phones(8.0)

    def on_phones(self, phones: list) -> None:
        self._phones = list(phones)
        self.phone_list.clear()
        for phone in self._phones:
            entry = QListWidgetItem(phone_summary(phone))
            entry.setToolTip(phone_details(phone))
            self.phone_list.addItem(entry)
        if not self._phones:
            self._done("Телефон не ответил. Откройте Bitchat и держите его "
                       "рядом.", WARN)
            return
        self.phone_list.setCurrentRow(0)
        self._done(f"Телефонов найдено: {len(self._phones)}. Выберите один и "
                   "нажмите «Подтвердить».", OK)

    def on_failed(self, text: str) -> None:
        """A search ended with an error (no radio answered, and so on)."""
        self._done(text, WARN)

    def _confirm_phone(self) -> None:
        row = self.phone_list.currentRow()
        if not (0 <= row < len(self._phones)):
            self._done("Сначала найдите телефон.", WARN)
            return
        phone = self._phones[row]
        if not phone.get("peer"):
            self._done("У этого телефона нет подтверждённого peer id.", WARN)
            return
        title = f"Привязать телефон «{phone_summary(phone)}»?"
        if not confirm_twice(
                self, "Подтверждение телефона",
                title + "\n\n" + phone_details(phone) + "\n\n"
                "Адрес Bluetooth на iOS случайный: мост сверяет peer id и "
                "подпись ключа, а не адрес. Другие телефоны подключиться не "
                "смогут."):
            self._done("Телефон не подтверждён.", MUTED)
            return
        self.set_phone(phone)
        self._done(f"Телефон подтверждён: {phone_summary(phone)}. Можно "
                   "запускать мост.", OK)

    # -------------------------------------------------------------- start
    def _start(self) -> None:
        if not self.transport:
            self._done("Сначала выберите радио.", WARN)
            return
        # The engine exists from this moment: if the window cannot start it,
        # the page must not stay "busy" forever (see set_busy).
        # The engine starts now: the page is busy until the window says it
        # runs (or says it failed), so nothing can be re-pressed meanwhile.
        self._busy_now = True
        self._apply_enabled()
        self.status.setText("Запускаю мост…")
        self.status.setStyleSheet(f"color: {WARN};")
        self.start_requested.emit()

    def on_event(self, event: ev.Event) -> None:
        if isinstance(event, ev.LogEvent) and event.level == ev.Level.ERROR \
                and "адио" in event.text:
            self.status.setText(event.text)
            self.status.setStyleSheet(f"color: {WARN};")
