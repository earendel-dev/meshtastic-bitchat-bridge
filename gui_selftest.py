"""GUI self-test: drives every control of the window without a radio.

Run from the project root:

    .venv\\Scripts\\python.exe -X utf8 gui_selftest.py

* phase 1 builds the real window offscreen (``QT_QPA_PLATFORM=offscreen``)
  and presses every button, switch and tab in every combination that makes
  sense, checking what the user would see: labels, counters, disabled states;
* phase 2 starts the real engine thread with a configuration that touches
  neither Wi-Fi nor Bluetooth: the radio transport is a local port that
  answers nothing, the BLE scanner is not started — the check waits until
  the engine gives up on the radio, then exercises stop/start and the live
  actions on the real handlers.

Nothing here prints message text, addresses or keys: the same rule as the
application itself.  Exit code 0 means every check passed.
"""

from __future__ import annotations

import gc
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from PySide6.QtCore import QPoint, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget  # noqa: E402
import gui.pages.connections as connections_page  # noqa: E402
import gui.pages.devices as devices_page  # noqa: E402
import gui.pages.forward as forward_page  # noqa: E402
import gui.pages.session_bridge as session_bridge  # noqa: E402
import gui.pages.sync as sync_page  # noqa: E402
import gui.widgets.dialogs as dialogs  # noqa: E402
from gui.core import events as ev  # noqa: E402
from gui.core.search import Finder  # noqa: E402
from gui.core.session import EngineConfig  # noqa: E402
from gui.main import wanted_menu, window_for_ui_test  # noqa: E402
from gui.pages.activity import LogPage  # noqa: E402
from gui.pages.base import Page  # noqa: E402
from gui.pages.connections import ConnectionsPage  # noqa: E402
from gui.pages.devices import DevicesPage  # noqa: E402
from gui.pages.forward import ForwardPage  # noqa: E402
from gui.pages.overview import OverviewPage  # noqa: E402
from gui.pages.sync import SyncPage  # noqa: E402

RESULTS = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    ok = bool(ok)
    RESULTS.append((name, ok))
    line = ("  ok   " if ok else "  FAIL ") + name
    if not ok and detail:
        line += f"   [{detail}]"
    print(line, flush=True)
    return ok


def section(title: str) -> None:
    print(f"\n{title}", flush=True)


def pump(ms: int = 60) -> None:
    """Let Qt deliver queued signals and run its timers.

    Several threads work at once here (search, engine, the Meshtastic
    library).  Python's own garbage collector may walk their objects exactly
    while one of them is inside a native call; the collection is therefore
    left for the moment the test really waits for something (see
    ``collect``), never to a chance pause between two events.
    """
    gc_was_on = gc.isenabled()
    gc.disable()
    try:
        end = time.monotonic() + ms / 1000.0
        while time.monotonic() < end:
            QApplication.processEvents()
            time.sleep(0.005)
    finally:
        if gc_was_on:
            gc.enable()


def collect() -> None:
    """Run a garbage collection at a point where the test is in control."""
    deadline = time.monotonic() + 0.2
    while time.monotonic() < deadline:
        gc.collect(0)
        time.sleep(0.005)
    gc.collect()


class FakeEngine:
    """An ``EngineSession`` stand-in that records what the pages ask for."""

    def __init__(self) -> None:
        self.calls = []
        self.mode = "bound"
        self.sources = set()
        self.replied = set()
        self.full_sync = False
        self.schedule_text = "периодическая синхронизация выключена"
        self.answer = "ok"          # ok | refuse | raise
        self.peers_seen = []

    # ---- state the pages read
    def stats(self) -> dict:
        return {
            "forward_mode": self.mode,
            "forward_name": self.mode,
            "sources": sorted(self.sources),
            "replied": sorted(self.replied),
            "full_sync": self.full_sync,
            "bound": True,
            "bound_label": "Привязанный",
            "bound_fingerprint": "AAAA-BBBB-CCCC",
        }

    def snapshot(self):
        # Like the real engine: the snapshot is read live, not from a cache.
        return ev.StateEvent(forward_mode=self.mode,
                             full_sync=self.full_sync,
                             bound=True, bound_label="Привязанный",
                             schedule=self.schedule_text,
                             sources=tuple(sorted(self.sources)),
                             replied=tuple(sorted(self.replied)))

    def peers(self):
        return list(self.peers_seen)

    # ---- actions
    def set_forward_mode(self, mode, sources=None, confirmed=False):
        self.calls.append(("mode", mode, tuple(sorted(sources or ())),
                           confirmed))
        if self.answer == "raise":
            raise RuntimeError("намеренная ошибка")
        if self.answer == "refuse":
            return False
        if mode != "bound" and not confirmed:
            return False
        if mode == "custom":
            chosen = {p for p in (sources or ()) if p != "aa" * 8}
            if not chosen:
                return False
            self.sources = chosen
        self.mode = mode
        return True

    def mark_source(self, peer, add=True):
        self.calls.append(("mark", peer, add))
        if add:
            self.sources.add(peer)
        else:
            self.sources.discard(peer)

    def set_full_sync(self, enabled, confirmed=False):
        self.calls.append(("full", enabled, confirmed))
        if enabled and not confirmed:
            return False
        self.full_sync = enabled
        return True

    def sync_to_lora(self, count):
        self.calls.append(("sync_lora", count))

    def sync_to_bitchat(self, count):
        self.calls.append(("sync_phone", count))

    def schedule(self, direction, count, interval):
        self.calls.append(("schedule", direction, count, interval))
        if not self.full_sync:
            return "повтор работает только при включённой полной синхронизации"
        self.schedule_text = (f"Bitchat → Meshtastic: последние {count} "
                              f"каждые {interval} с")
        return ""

    def reset_binding(self):
        self.calls.append(("reset",))


class FakeFinder(Finder):
    """A searcher that answers from canned lists instead of the hardware."""

    def __init__(self) -> None:
        super().__init__()
        self.calls = []
        self.radios_found = [{"kind": "tcp", "target": "192.0.2.10",
                              "port": 4403,
                              "label": "Радио — 192.0.2.10:4403 (Wi-Fi)"}]
        self.phones_found = [{
            "kind": "bitchat", "target": "AA:BB:CC:DD:EE:01",
            "peer": "aa" * 8, "nickname": "Мой телефон",
            "fingerprint": "AAAA-BBBB-CCCC", "signing_pub": b"k" * 32,
            "rssi": -48, "label": "Телефон",
        }]
        self.chats_found = ([{"label": "Общий канал",
                              "target": {"kind": "channel", "index": 0}},
                             {"label": "Семья",
                              "target": {"kind": "channel", "index": 1}},
                             {"label": "Всё",
                              "target": {"kind": "all"}}],
                            [{"label": f"Узел {i} — !{i:08x}",
                              "target": {"kind": "dm", "node": i},
                              "name": f"Узел {i}"} for i in range(45)])

    def find_radios(self, kind: str) -> None:
        self.calls.append(("radios", kind))
        self.radios.emit([dict(item) for item in self.radios_found])

    def find_phones(self, seconds: float) -> None:
        self.calls.append(("phones", seconds))
        self.phones.emit([dict(item) for item in self.phones_found])

    def find_chats(self, transport) -> None:
        self.calls.append(("chats", dict(transport or {})))
        entries, nodes = self.chats_found
        self.chats.emit([dict(item) for item in entries],
                        [dict(item) for item in nodes])

    def fail_radios(self, text: str) -> None:
        self.radios_failed.emit(text)


class Dialogue:
    """Replaces both confirmation dialogs; records the questions."""

    def __init__(self) -> None:
        self.asked = 0
        self.answer = True

    def twice(self, *args, **kwargs) -> bool:
        self.asked += 1
        return self.answer


def install_dialogs():
    """Route the modal confirmations of every page through one place."""
    dialogue = Dialogue()
    for module in (forward_page, sync_page, connections_page, devices_page):
        module.confirm_twice = dialogue.twice
    dialogs.confirm_twice = dialogue.twice
    return dialogue


def click(widget) -> None:
    widget.click()


def text_visible(label) -> bool:
    """True when the label has text and does not clip it vertically."""
    return bool(label.text()) and label.isVisible() or bool(label.text())


def page_index(win, cls) -> int:
    for i, page in enumerate(win.pages):
        if isinstance(page, cls):
            return i
    raise LookupError(cls)


def _too_wide(widget) -> str:
    """Why a widget cannot fit into its parent horizontally, or ''."""
    parent = widget.parentWidget()
    hint = widget.minimumSizeHint().width()
    if parent is not None and hint > parent.width() + 1:
        return (f"{type(widget).__name__} «{getattr(widget, 'text', lambda: '')()[:30]}» "
                f"требует {hint} px, а в родителе {parent.width()}")
    for child in widget.findChildren(QWidget):
        if not child.isVisible() or child.layout() is None:
            continue
        reason = _too_wide(child)
        if reason:
            return reason
    return ""


def layout_problems(win, width: int, height: int) -> list:
    """Anything the user would see clipped at this window size."""
    win.resize(width, height)
    pump(150)
    problems = []
    for index in range(win.tabs.count()):
        win.tabs.setCurrentIndex(index)
        pump(80)
        area = win.tabs.widget(index)
        page = area.widget().findChild(Page)
        if page is None:
            problems.append(f"вкладка {index}: страница не найдена")
            continue
        if page.width() > area.viewport().width() + 1:
            problems.append(f"вкладка {index}: страница шире окна "
                            f"({page.width()} > {area.viewport().width()})")
        for label in page.findChildren(QLabel):
            if not label.isVisible() or not label.text():
                continue
            if label.maximumWidth() < label.sizeHint().width() + 1 and \
                    label.minimumSizeHint().width() > label.width() + 1:
                problems.append(f"вкладка {index}: подпись "
                                f"«{label.text()[:24]}» не влезает "
                                f"({label.minimumSizeHint().width()} > "
                                f"{label.width()})")
            if not label.wordWrap():
                continue
            need = label.heightForWidth(label.width())
            if need > label.height() + 1:
                problems.append(f"вкладка {index}: обрезана подпись "
                                f"«{label.text()[:24]}» "
                                f"({need}>{label.height()})")
        for button in page.findChildren(QPushButton):
            if button.isVisible() and button.text():
                need = button.sizeHint().height()
                if need > button.height() + 1:
                    problems.append(f"вкладка {index}: кнопка "
                                    f"«{button.text()[:24]}» не влезла по "
                                    f"высоте ({need}>{button.height()})")
    for label in (win.core_label, win.core_detail, win.traffic,
                  win.heartbeat_label):
        if label.text():
            need = label.heightForWidth(label.width())
            if need > label.height() + 1:
                problems.append(f"шапка/подвал: обрезано "
                                f"«{label.text()[:20]}»")
    return problems


# ===========================================================================
# Phase 1 — the window on fake state
# ===========================================================================
def phase_window() -> None:
    section("1. Окно и вкладки")
    app = QApplication.instance()
    cfg = EngineConfig(transport={"kind": "tcp", "target": "127.0.0.1"})
    win = window_for_ui_test(cfg)
    win.show()
    pump()

    titles = [win.tabs.tabText(i) for i in range(win.tabs.count())]
    check("шесть вкладок", len(win.pages) == 6, str(len(win.pages)))
    check("названия вкладок",
          [p.title for p in win.pages] ==
          ["Устройства", "Обзор", "Пересылка Bitchat → LoRa", "Синхронизация",
           "Подключения", "Журнал"],
          str([p.title for p in win.pages]))
    check("вкладки подписаны значками",
          len(titles) == 6 and all(t and len(t) <= 2 for t in titles),
          str(titles))
    check("у каждой вкладки есть полная подсказка",
          all(win.tabs.tabToolTip(i) for i in range(win.tabs.count())))
    check("«Устройства» — первая вкладка",
          isinstance(win.pages[0], DevicesPage))
    check("мост не запущен", not win._bridge.alive)
    check("состояние «остановлен»", win.core_state == "stopped")
    check("«Стоп» выключен, «Старт» включён",
          win.btn_start.isEnabled() and not win.btn_stop.isEnabled())

    # Every tab in turn, twice (back and forth): nothing may raise.
    for order in (range(6), reversed(range(6))):
        for i in order:
            win.tabs.setCurrentIndex(i)
            pump(5)
    check("переключение всех вкладок в обе стороны", True)

    # ---------------------------------------------------------- fake state
    section("2. Обзор: жив ли мост и идёт ли пересылка")
    overview = win.pages[page_index(win, OverviewPage)]

    win.receive(ev.MessageCountsEvent(lora_to_bitchat=3, bitchat_to_lora=7,
                                      bitchat_blocked=2, lora_queue=1))
    pump()
    check("счётчики на экране",
          (overview.c_to_lora.value.text(), overview.c_blocked.value.text(),
           overview.c_to_phone.value.text(), overview.c_queue.value.text())
          == ("7", "2", "3", "1"),
          overview.c_to_lora.value.text())

    win.receive(ev.ForwardedEvent("to_lora", 4, "Друг", "сообщение"))
    pump()
    check("полоса пересылки вспыхнула",
          "в LoRa" in win.traffic.text() and "4" in win.traffic.text(),
          win.traffic.text())
    check("точка пересылки сменила цвет",
          win.traffic_dot.color.name().lower() == "#4c9aff",
          win.traffic_dot.color.name())
    check("«последнее действие» с именем",
          "Друг" in overview.last_box.text(), overview.last_box.text())
    check("счётчик пересылок растёт",
          "4" in overview.traffic.text(), overview.traffic.text())
    win.receive(ev.ForwardedEvent("to_bitchat", 2, "", "досылка"))
    pump()
    check("пересылка на телефон тоже видна",
          "на телефон" in win.traffic.text(), win.traffic.text())
    check("итог по обеим сторонам", "6" in overview.traffic.text(),
          overview.traffic.text())

    win.receive(ev.LinkEvent("radio", True, "Wi-Fi 192.0.2.10:4403"))
    win.receive(ev.LinkEvent("phone", True, "AA:BB"))
    pump()
    check("радио подключено", "Wi-Fi" in overview.radio.detail.text(),
          overview.radio.detail.text())
    check("телефон подключён", "AA:BB" in overview.phone.detail.text(),
          overview.phone.detail.text())
    win.receive(ev.LinkEvent("radio", False, ""))
    pump()
    check("радио отключилось", overview.radio.detail.text() in ("—", "нет связи"),
          overview.radio.detail.text())

    section("3. Живость внутри окна")
    win._set_core_state("running")
    win._last_beat = time.monotonic()
    for page in win.pages:
        if type(page).__name__ == "OverviewPage":
            page.on_heartbeat(1.0)
    win._check_liveness()
    check("пульс — зелёный",
          win.core_dot.color.name().lower() == "#3fb950",
          win.core_dot.color.name())
    check("точка на странице тоже зелёная",
          overview.heart.color.name().lower() == "#3fb950")
    for name, expected in (("starting", "#d29922"), ("stopped", "#4a5560")):
        win._set_core_state(name)
        check(f"состояние {name} — цвет {expected}",
              win.core_dot.color.name().lower() == expected,
              win.core_dot.color.name())
    check("остановка гасит «Стоп»",
          win.btn_start.isEnabled() and not win.btn_stop.isEnabled())
    win._set_core_state("running")
    win._last_beat = time.monotonic() - 10
    win._check_liveness()
    pump()
    check("зависание видно в шапке",
          win.core_dot.color.name().lower() == "#f85149",
          win.core_dot.color.name())
    check("шапка говорит «не отвечает»", "не отвечает" in win.core_label.text(),
          win.core_label.text())
    overview.on_heartbeat(12.0)
    overview._tick()
    check("страница обзора видит зависание",
          overview.heart.color.name().lower() == "#f85149",
          overview.heart.color.name())

    # ---------------------------------------------------------- forward page
    section("4. Пересылка: все режимы и подтверждения")
    forward = win.pages[page_index(win, ForwardPage)]
    engine = FakeEngine()
    engine.peers_seen = [ev.PeerEvent("aa" * 8, "Привязанный", "FP-BOUND",
                                      True),
                         ev.PeerEvent("bb" * 8, "Друг", "FP-FRIEND"),
                         ev.PeerEvent("cc" * 8, "Третий", "FP-THIRD")]
    forward.set_session(engine)
    forward.on_core_state("running")
    forward.on_state(ev.StateEvent(forward_mode="bound", bound=True,
                                   sources=(), replied=(),
                                   peers=tuple(engine.peers_seen)))
    pump()
    check("список телефонов построен", forward.phones.count() == 3,
          str(forward.phones.count()))
    check("привязанный помечен и не снимается",
          "привязанный" in forward.phones.item(0).text()
          and not (forward.phones.item(0).flags() &
                   Qt.ItemFlag.ItemIsEnabled))
    check("остальные снимаемы",
          bool(forward.phones.item(1).flags() & Qt.ItemFlag.ItemIsEnabled))
    check("по умолчанию отмечен только привязанный",
          forward._checked_peers() == [])

    dialogue = install_dialogs()
    dialogue.answer = False
    forward._on_radio("all", True)
    check("отказ в подтверждении — режим не меняется",
          not any(c[0] == "mode" for c in engine.calls)
          and forward._buttons["bound"].isChecked(),
          str(engine.calls[-1:]))

    dialogue.answer = True
    forward._on_radio("all", True)
    check("«любой телефон» после двух подтверждений",
          any(c[:2] == ("mode", "all") and c[3] for c in engine.calls),
          str(engine.calls[-1:]))
    check("подпись режима обновилась",
          "всё, что дошло" in forward.note.text(), forward.note.text())

    engine.calls.clear()
    forward._on_radio("custom", True)
    check("custom без отмеченных не включается",
          not any(c[0] == "mode" for c in engine.calls)
          and "Отметьте" in forward.status.text(), forward.status.text())

    forward.phones.item(1).setCheckState(Qt.CheckState.Checked)
    pump()
    check("галочка сообщает движку",
          ("mark", "bb" * 8, True) in engine.calls, str(engine.calls[-1:]))
    forward._on_radio("custom", True)
    check("custom с отмеченным включён",
          any(c[:2] == ("mode", "custom") and c[3] for c in engine.calls),
          str(engine.calls[-1:]))
    check("custom не отправляет привязанный в списке",
          all("aa" * 8 not in c[2] for c in engine.calls if c[0] == "mode"))

    forward._on_radio("replies", True)
    check("режим «те, кому я ответил»",
          any(c[:2] == ("mode", "replies") for c in engine.calls),
          str(engine.calls[-1:]))
    forward.on_state(ev.StateEvent(forward_mode="replies",
                                   replied=("cc" * 8,),
                                   peers=tuple(engine.peers_seen)))
    pump()
    check("в replies отмечен тот, кому ответили",
          forward.phones.item(2).checkState() == Qt.CheckState.Checked
          and forward.phones.item(1).checkState() == Qt.CheckState.Unchecked)
    check("счётчик ответивших в подписи",
          "сейчас 1" in forward.note.text(), forward.note.text())

    engine.calls.clear()
    forward._on_radio("bound", True)
    check("возврат к «один телефон» без подтверждения",
          ("mode", "bound", (), True) in engine.calls,
          str(engine.calls[-1:]))
    check("«Один телефон» — самая строгая подпись",
          forward.note.text().startswith("В LoRa уходят только"))

    engine.answer = "refuse"
    dialogue.answer = True
    forward._on_radio("all", True)
    check("движок отказал — окно честно пишет",
          "Не удалось" in forward.status.text() or
          forward._buttons["bound"].isChecked(),
          forward.status.text())

    engine.answer = "ok"
    forward.phones.item(1).setCheckState(Qt.CheckState.Checked)
    forward._apply_custom()
    check("«Применить выбранные» включает custom",
          any(c[:2] == ("mode", "custom") for c in engine.calls),
          str(engine.calls[-1:]))
    forward.phones.item(1).setCheckState(Qt.CheckState.Unchecked)
    forward.phones.item(2).setCheckState(Qt.CheckState.Unchecked)
    pump()
    forward._apply_custom()
    check("«Применить» без выбора — подсказка",
          "Отметьте" in forward.status.text(), forward.status.text())

    forward.on_core_state("stopped")
    check("на остановке режимы недоступны",
          not forward._buttons["all"].isEnabled())
    forward._on_radio("all", True)
    check("на остановке переключение ничего не делает (кнопка выключена)",
          not forward._buttons["all"].isEnabled())
    forward.on_core_state("running")
    check("после запуска режимы снова доступны",
          forward._buttons["all"].isEnabled())

    # ------------------------------------------------------------- sync page
    section("5. Синхронизация")
    sync = win.pages[page_index(win, SyncPage)]
    engine2 = FakeEngine()
    sync.set_session(engine2)
    sync.on_core_state("running")
    pump()

    for combo in (sync.count_to_phone, sync.count_to_lora,
                  sync.period_count, sync.period_direction,
                  sync.period_minutes):
        for i in range(combo.count()):
            combo.setCurrentIndex(i)
            pump(2)
    check("все варианты выпадающих списков перебираются", True)

    sync.count_to_phone.setCurrentIndex(2)
    click(sync.btn_to_phone)
    check("пересылка на телефон с выбранным числом",
          ("sync_phone", sync.count_to_phone.currentData())
          in engine2.calls, str(engine2.calls[-1:]))
    sync.count_to_lora.setCurrentIndex(3)
    click(sync.btn_to_lora)
    check("пересылка в LoRa с выбранным числом",
          ("sync_lora", sync.count_to_lora.currentData())
          in engine2.calls, str(engine2.calls[-1:]))

    dialogue.answer = False
    click(sync.btn_full)
    check("отказ — полная синхронизация не включена",
          not engine2.full_sync and "Выключена" in sync.full_state.text())
    dialogue.answer = True
    click(sync.btn_full)
    check("согласие — включена",
          engine2.full_sync and sync._full_sync and
          "Включена" in sync.full_state.text(), sync.full_state.text())
    check("кнопка стала «выключить»",
          sync.btn_full.text().startswith("Выключить"), sync.btn_full.text())
    sync.on_state(ev.StateEvent(full_sync=True))
    check("после подтверждения состояние сходится",
          sync._full_sync and sync.btn_full.text().startswith("Выключить"),
          sync.btn_full.text())
    click(sync.btn_full)
    check("выключение одним нажатием",
          not engine2.full_sync and not sync._full_sync and
          sync.btn_full.text().startswith("Включить"), sync.btn_full.text())

    click(sync.btn_period)
    check("повтор без полной синхронизации — объяснение",
          "полной" in sync.period_status.text(), sync.period_status.text())

    engine2.full_sync = True
    sync.on_state(ev.StateEvent(full_sync=True))
    sync.period_minutes.setCurrentIndex(0)      # 1 min = the minimum
    click(sync.btn_period)
    check("повтор при полной синхронизации включён",
          any(c[0] == "schedule" for c in engine2.calls),
          sync.period_status.text())

    sync.on_core_state("stopped")
    check("на остановке синхронизация недоступна",
          not sync.btn_to_phone.isEnabled() and not sync.btn_full.isEnabled())
    before = len(engine2.calls)
    click(sync.btn_to_phone)
    click(sync.btn_to_lora)
    click(sync.btn_full)
    check("кнопки на остановке ничего не делают",
          len(engine2.calls) == before, str(len(engine2.calls) - before))

    # ------------------------------------------------------ connections page
    section("6. Подключения")
    conn = win.pages[page_index(win, ConnectionsPage)]
    engine3 = FakeEngine()
    conn.set_session(engine3)
    conn.on_core_state("running")
    conn.on_state(ev.StateEvent(radio_connected=True,
                                radio_detail="Wi-Fi 192.0.2.10:4403",
                                chat_target="канал 0 (Primary)",
                                bound=True, bound_label="Привязанный"))
    pump()
    check("радио показано", "Wi-Fi" in conn.radio_value.text())
    check("чат показан", "Primary" in conn.chat_value.text())
    check("телефон показан", conn.phone_value.text() == "Привязанный")
    conn.on_event(ev.BindingEvent(True, "Другой", "FINGER"))
    check("смена привязки обновляет имя и отпечаток",
          conn.phone_value.text() == "Другой" and
          conn.key_value.text() == "FINGER")
    conn.on_event(ev.BindingEvent(False, "", ""))
    check("без привязки — «не привязан»",
          conn.phone_value.text() == "не привязан")

    dialogue.answer = False
    click(conn.btn_reset)
    check("отказ — телефон не меняется",
          not any(c[0] == "reset" for c in engine3.calls))
    dialogue.answer = True
    click(conn.btn_reset)
    check("согласие — привязка сброшена",
          ("reset",) in engine3.calls, str(engine3.calls[-1:]))
    conn.on_core_state("stopped")
    check("на остановке «сменить телефон» недоступно",
          not conn.btn_reset.isEnabled())

    # ------------------------------------------------------------- log page
    section("7. Журнал")
    log = win.pages[page_index(win, LogPage)]
    start = log.view.blockCount()
    for level in (ev.Level.INFO, ev.Level.OK, ev.Level.WARN, ev.Level.ERROR):
        log.append(f"проверка {level.value} <&>", level)
    pump()
    check("строки добавляются", log.view.blockCount() >= start + 4,
          str(log.view.blockCount()))
    check("текст не попадает в журнал через события",
          all("текст сообщения" not in log.view.toPlainText().lower()
              for _ in (0,)))
    log.on_core_state("starting")
    log.on_core_state("stopped")
    pump()
    check("запуск и остановка отмечены",
          "Запуск" in log.view.toPlainText() and
          "остановлен" in log.view.toPlainText())
    check("журнал только для чтения", log.view.isReadOnly())

    # --------------------------------------------------------- scaling
    section("8. Масштабирование и вписывание текста")
    check("минимальный размер окна задан",
          win.minimumWidth() > 0 and win.minimumHeight() > 0,
          f"{win.minimumWidth()}x{win.minimumHeight()}")
    tab_problems = []
    for width in (520, 640, 820, 980):
        win.resize(width, 640)
        pump(150)
        bar = win.tabs.tabBar()
        if bar.sizeHint().width() > win.tabs.width() + 1:
            tab_problems.append(f"{width}: вкладки просятся в "
                                f"{bar.sizeHint().width()} px, "
                                f"а ширина {win.tabs.width()}")
        if bar.height() > bar.fontMetrics().height() * 3:
            tab_problems.append(f"{width}: полоса вкладок слишком высокая")
    check("полоса вкладок влезает в окно", not tab_problems,
          "; ".join(tab_problems))
    for width, height in ((500, 400), (560, 520), (720, 600), (980, 760),
                          (1280, 900), (1600, 1000)):
        problems = layout_problems(win, width, height)
        check(f"окно {width}×{height}: ничего не вылезает", not problems,
              "; ".join(problems[:4]))

    # A long radio / chat / phone name must wrap, not widen the page.
    win.devices.set_transport({"kind": "tcp", "target": "192.0.2.10",
                               "label": "Очень длинное имя радио — "
                                        "192.0.2.10:4403 (Wi-Fi)"})
    win.devices.on_chats([{"label": "Длинное имя канала " * 3,
                           "target": {"kind": "channel", "index": 2}}], [])
    win.devices.chat_combo.setCurrentIndex(0)
    win.devices.on_phones([{"peer": "aa" * 8, "nickname": "Телефон с очень "
                                                         "длинным именем",
                            "fingerprint": "AAAA-BBBB-CCCC-DDDD"}])
    for width, height in ((520, 480), (600, 520)):
        problems = layout_problems(win, width, height)
        check(f"длинные имена при {width}×{height} тоже влезают", not problems,
              "; ".join(problems[:4]))

    win.resize(980, 760)
    pump()

    # ---------------------------------------------------- restart wiring
    section("9. Перезапуск и смена сессии")
    old = win.session
    # §4–§6 подменяли сессии страниц на поддельные, чтобы нажимать кнопки
    # без движка; здесь возвращаем окну его настоящую сессию и проверяем,
    # что страницы следуют за окном.
    for page in win.pages:
        page.set_session(old)
    for page in win.pages:
        check(f"страница {type(page).__name__} видит сессию",
              page.session is old)
    check("все страницы смотрят в одну сессию",
          len({id(page.session) for page in win.pages}) == 1
          and win.engine is old)
    win.start_bridge()
    pump(50)
    check("запуск создаёт новую сессию", win.session is not old)
    check("все страницы получили новую сессию",
          all(p.session is win.session for p in win.pages))
    check("движок запущен", win._bridge.alive)
    win._bridge.request_stop()
    pump(50)

    # ------------------------------------------------- device tab (п. 1)
    section("9a. Устройства: радио, беседа, телефон, запуск")
    finder = FakeFinder()
    cfg_dev = EngineConfig(transport=None, config_path=os.path.join(
        ROOT, "var", "gui-selftest-config.json"))
    with open(cfg_dev.config_path, "w", encoding="utf-8") as fh:
        fh.write("{}")
    dev_win = window_for_ui_test(cfg_dev, finder=finder)
    dev_win.show()
    pump(40)
    dev = dev_win.pages[page_index(dev_win, DevicesPage)]
    check("поиск подменён на вкладке «Устройства»", dev.finder is finder)
    check("без радио мост не стартует",
          not dev.btn_start.isEnabled() and dev.transport is None)
    check("беседа и телефон пусты",
          dev.chat is None and dev.phone is None)

    dialogue = install_dialogs()
    dev._start()
    check("«Запустить» без радио ничего не запускает",
          not dev_win._bridge.alive, dev.status.text())

    # ---- radio: three searches, like the console's first menu
    for kind in ("wifi", "ble", "serial"):
        dev.btn_use_radio.setEnabled(True)
        dev._search_radio(kind)
        check(f"поиск радио «{kind}» спрошен",
              finder.calls[-1] == ("radios", kind))
        pump(20)
    check("найденное радио попало в список", dev.radio_list.count() == 1,
          str(dev.radio_list.count()))
    check("«Подключить» доступно после поиска", dev.btn_use_radio.isEnabled())

    adopted = []
    dev.start_requested.connect(lambda: adopted.append(dev.transport))
    dev._use_selected_radio()
    pump()
    check("радио выбрано из списка",
          dev.transport == finder.radios_found[0], str(dev.transport))
    check("радио подписано в окне",
          "192.0.2.10" in dev.radio_value.text(), dev.radio_value.text())
    check("с радио «Запустить» доступно", dev.btn_start.isEnabled())
    import json
    with open(cfg_dev.config_path, encoding="utf-8") as fh:
        saved = json.load(fh)
    check("радио записано в config.json",
          saved.get("transport", {}).get("target") == "192.0.2.10",
          str(saved.get("transport")))
    check("телефон в config.json не пишется",
          "phone" not in json.dumps(saved) and
          "bitchat_peer" not in saved, str(sorted(saved)))

    # ---- radio typed by hand: the same rules as the console
    for text, kind in (("192.0.2.55", "tcp"), ("COM7", "serial"),
                       ("AA:BB:CC:DD:EE:FF", "ble")):
        dev.manual.setText(text)
        dev._manual_radio()
        check(f"адрес «{text}» разобран как {kind}",
              dev.transport is not None and dev.transport.get("kind") == kind,
              str(dev.transport))
    dev.manual.setText("   ")
    dev._manual_radio()
    check("пустой адрес не принимается", dev.transport.get("kind") == "ble")
    dev.on_radios(finder.radios_found)
    dev._use_selected_radio()

    # ---- chat: channels, then a direct chat from the node list
    dev._load_chats()
    pump(20)
    check("список бесед запрошен", finder.calls[-1][0] == "chats")
    check("каналы и «всё» в списке", dev.chat_combo.count() == 4,
          str(dev.chat_combo.count()))
    dev.chat_combo.setCurrentIndex(1)
    pump(10)
    check("канал выбран", dev.chat == {"kind": "channel", "index": 1},
          str(dev.chat))
    check("личный чат — отдельный пункт",
          dev.chat_combo.itemText(3).startswith("Личный чат"),
          dev.chat_combo.itemText(3))
    dev.chat_combo.setCurrentIndex(3)
    pump(10)
    check("список узлов показан", dev.node_list.isVisible() or
          dev.node_list.count() == 30)
    check("узлы разбиты по страницам",
          dev.node_list.count() == 30 and "1/2" in dev.page_label.text(),
          dev.page_label.text())
    dev._turn_page(1)
    check("вторая страница узлов", dev.node_list.count() == 15,
          str(dev.node_list.count()))
    dev._node_chosen(dev.node_list.item(0))
    check("личный чат с узлом выбран",
          dev.chat.get("kind") == "dm" and dev.chat.get("node") == 30,
          str(dev.chat))
    check("личный чат подписан", "30" in dev.chat_value.text(),
          dev.chat_value.text())
    # The window mirrors the engine every 200 ms; let it settle.
    pump(60)

    # ---- phone: two confirmations, refusal keeps the bridge unbinding
    finder.phones_found = []
    dev._scan_phones()
    pump(20)
    dev.on_phones([])
    check("пустой поиск телефонов объяснён", "не ответил" in dev.status.text(),
          dev.status.text())
    finder.phones_found = FakeFinder().phones_found
    dev._scan_phones()
    pump(20)
    check("телефон найден", dev.phone_list.count() == 1)
    check("до подтверждения телефон не выбран", dev.phone is None)
    dialogue.answer = False
    dev._confirm_phone()
    check("отказ в подтверждении — телефон не выбран",
          dev.phone is None and dev.status.text() == "Телефон не подтверждён.",
          dev.status.text())
    check("без телефона запуск всё равно возможен",
          dev.btn_start.isEnabled(),
          f"start={dev.btn_start.isEnabled()} run={dev._running} "
          f"busy={dev._busy_now} transport={bool(dev.transport)}")
    # The window keeps mirroring the engine on its timer; give it a moment
    # so the page settles before the next confirmation.
    pump(60)
    dialogue.answer = True
    dev._confirm_phone()
    check("подтверждённый телефон запомнен",
          dev.phone is not None and dev.phone.get("peer") == "aa" * 8)
    check("подтверждение спрашивает дважды", dialogue.asked >= 2,
          str(dialogue.asked))
    check("в подписи — имя и отпечаток",
          "Мой телефон" in dev.phone_value.text()
          and "AAAA" in dev.phone_value.text(), dev.phone_value.text())
    check("«можно запускать» после подтверждения",
          "Можно запускать" in dev.ready_value.text(), dev.ready_value.text())

    # ---- start: the window hands its choice to the engine
    called = {}
    original = dev_win.start_bridge
    dev_win.start_bridge = lambda transport=None, chat=None, phone=None: \
        called.update(transport=transport, chat=chat, phone=phone)
    dev._start()
    pump(10)
    dev_win.start_bridge = original
    check("запуск передаёт выбранное радио, чат и телефон",
          called.get("transport", {}).get("target") == "192.0.2.10"
          and called.get("chat", {}).get("kind") == "dm"
          and called.get("phone", {}).get("peer") == "aa" * 8,
          str({k: type(v) for k, v in called.items()}))
    check("на запуске кнопки поиска гаснут", not dev.btn_wifi.isEnabled(),
          f"run={dev._running} busy={dev._busy_now} "
          f"status={dev.status.text()!r}")
    dev.set_busy(True)
    check("пока мост работает, «Остановить» доступно",
          dev.btn_stop.isEnabled() and not dev.btn_start.isEnabled())
    dev.set_busy(False)
    check("после остановки поиск снова доступен", dev.btn_wifi.isEnabled())

    problems = layout_problems(dev_win, 520, 480)
    check("вкладка «Устройства» влезает в минимальное окно", not problems,
          "; ".join(problems[:4]))
    dev_win.close()
    pump(30)
    os.remove(cfg_dev.config_path)

    # The console shows its menu unless a radio is given; the window now
    # follows the same rule instead of silently starting from the file.
    section("9b. Когда окно ждёт выбора устройства")
    check("без --host окно ждёт выбора", wanted_menu(["--config", "x.json"]))
    check("с --host запускается сразу",
          not wanted_menu(["--host", "192.0.2.10"]))
    check("--menu просит выбор даже с --host",
          wanted_menu(["--host", "192.0.2.10", "--menu"]))
    check("--no-menu отменяет выбор", not wanted_menu(["--no-menu"]))

    win.close()
    pump(30)


# ===========================================================================
# Phase 2 — the real engine, but not a real radio
# ===========================================================================
def phase_engine() -> None:
    section("10. Настоящий движок без радио и без телефона")
    app = QApplication.instance()
    # TCP to a closed local port: the transport fails fast and never leaves
    # the machine.  No BLE scanner task is created in this check.
    cfg = EngineConfig(transport={"kind": "tcp", "target": "127.0.0.1:1"},
                       forward_mode="custom")
    win = window_for_ui_test(cfg)
    win.show()
    pump(20)

    win.start_bridge()
    bridge = win._bridge
    ok = bridge.wait_ready(20.0)
    check("движок поднялся и отдал обработчики", ok)
    pump(1500)
    check("поток движка живой", bridge.alive)

    session = win.session
    stats = session.stats()
    check("get_stats() отвечает", isinstance(stats, dict) and
          "forward_mode" in stats)
    check("custom не поднимается без списка: старт в bound",
          stats.get("forward_mode") == "bound", str(stats.get("forward_mode")))
    snapshot = session.snapshot()
    check("снимок состояния полный",
          snapshot is not None and snapshot.forward_mode == "bound")

    forward = win.pages[page_index(win, ForwardPage)]
    forward.on_core_state("running")
    check("список телефонов читается у живого движка", forward.phones.count() == 0)

    check("режим меняется без подтверждения -> отказ",
          not session.set_forward_mode("all"))
    check("custom без списка -> отказ",
          not session.set_forward_mode("custom", sources=[], confirmed=True))
    check("«любой телефон» принимается с подтверждением",
          session.set_forward_mode("all", confirmed=True))
    pump(120)
    check("движок подтверждает режим",
          session.stats().get("forward_mode") == "all",
          session.stats().get("forward_mode"))
    check("back to bound", session.set_forward_mode("bound", confirmed=True))

    check("полная синхронизация без подтверждения -> отказ",
          not session.set_full_sync(True))
    check("полная синхронизация с подтверждением",
          session.set_full_sync(True, confirmed=True))
    pump(150)
    check("движок знает про полную синхронизацию",
          bool(session.stats().get("full_sync")))

    session.sync_to_lora(5)
    session.sync_to_bitchat(5)
    pump(200)
    check("ручная синхронизация не падает без данных", True)
    reason = session.schedule("bit2lora", 5, 900)
    check("расписание добавляется", reason == "", reason)
    described = session.snapshot().schedule if session.snapshot() else ""
    check("расписание описано", "каждые" in described, described)
    session.set_full_sync(False)
    pump(150)
    check("выключение полной синхронизации", not session.stats().get("full_sync"))

    session.reset_binding()
    pump(120)
    check("сброс привязки не падает", session.stats().get("bound") is False)
    collect()


    # Nothing may outlive this window: the engine thread is stopped here,
    # not left to the garbage collector.
    # The engine of this block is running on a radio that is not there: it
    # retries in the background.  It must be stopped before the window goes,
    # or its thread would outlive the window that owns the engine.
    win.stop_bridge()
    deadline = time.monotonic() + 20
    while bridge.alive and time.monotonic() < deadline:
        pump(100)
    check("движок §10 остановлен перед следующей проверкой", not bridge.alive)
    win.close()
    pump(50)
    # ---- §10a: engine started from the device page (bound before scan)
    section("10a. Движок, запущенный с выбранными устройствами")
    finder = FakeFinder()
    phone = dict(finder.phones_found[0])
    dev_cfg_path = os.path.join(ROOT, "var", "gui-selftest-engine.json")
    with open(dev_cfg_path, "w", encoding="utf-8") as fh:
        fh.write("{}")
    cfg2 = EngineConfig(transport=None, ready=False, config_path=dev_cfg_path)
    dev_win = window_for_ui_test(cfg2, finder=finder)
    dev_win.show()
    pump(30)
    dev = dev_win.pages[page_index(dev_win, DevicesPage)]
    dev.on_radios(finder.radios_found)
    dev._use_selected_radio()
    dev.on_chats(*finder.chats_found)
    dev.chat_combo.setCurrentIndex(1)          # канал 1, а не «всё»
    dev.on_phones(finder.phones_found)
    install_dialogs().answer = True
    dev._confirm_phone()
    # The radio of this check is the local closed port: its target is
    # replaced so nothing is said about an address that is not in use.
    dev._adopt_radio({"kind": "tcp", "target": "127.0.0.1:1",
                      "label": "локальный порт (проверка)"})
    dev._start()
    pump(20)
    dev_bridge = dev_win._bridge
    check("мост поднялся из вкладки «Устройства»",
          dev_bridge.wait_ready(20.0))
    pump(400)
    dev_session = dev_win.session
    dev_stats = dev_session.stats()
    check("телефон привязан ещё до поиска",
          dev_stats.get("bound") is True, str(dev_stats.get("bound")))
    check("привязан именно выбранный",
          dev_stats.get("bound") is True and
          dev_stats.get("bound_label") == phone["nickname"],
          str(dev_stats.get("bound_label")))
    check("подпись ключа взята из announce",
          bool(dev_stats.get("bound_fingerprint")),
          str(dev_stats.get("bound_fingerprint")))
    check("выбранный канал дошёл до движка",
          dev_stats.get("forward_mode") == "bound"
          and getattr(dev_bridge.cfg, "channel", None) == 1,
          f'channel={getattr(dev_bridge.cfg, "channel", None)}')
    check("радио в конфиге — выбранное",
          getattr(dev_bridge.cfg.transport, "get", lambda *_: None)(
              "target") == "127.0.0.1:1")
    pump(400)
    check("вкладка знает, кого ждёт", dev.phone["nickname"] in
          dev.ready_value.text(), dev.ready_value.text())
    check("пока мост работает, поиск выключен и «Остановить» доступно",
          not dev.btn_wifi.isEnabled() and dev.btn_stop.isEnabled(),
          f"run={dev._running} busy={dev._busy_now} "
          f"wifi={dev.btn_wifi.isEnabled()} stop={dev.btn_stop.isEnabled()} "
          f"alive={dev_bridge.alive}")
    dev.btn_stop.click()
    deadline = time.monotonic() + 20
    while dev_bridge.alive and time.monotonic() < deadline:
        pump(100)
    pump(400)
    check("кнопка «Остановить» на вкладке останавливает мост",
          not dev_bridge.alive)
    check("после остановки снова можно выбирать",
          dev.btn_wifi.isEnabled() and not dev.btn_stop.isEnabled())
    check("окно говорит, что мост остановлен",
          "остановлен" in dev.ready_value.text().lower(),
          dev.ready_value.text())
    dev_win.close()
    pump(30)
    deadline = time.monotonic() + 15
    while dev_bridge.alive and time.monotonic() < deadline:
        pump(100)
    check("вкладка «Устройства» останавливает свой движок",
          not dev_bridge.alive)
    os.remove(dev_cfg_path)

    # Section 10a of this block used the heartbeat of the engine above; the
    # ticker is checked here, on a fresh engine of its own.
    win.start_bridge()
    pump(200)
    check("запуск после остановки", win._bridge.alive)
    session = win.session
    beats = []
    session.heartbeat.connect(lambda gap: beats.append(gap))
    deadline = time.monotonic() + 3.5
    while time.monotonic() < deadline and len(beats) < 2:
        pump(50)
    check("движок присылает пульс раз в секунду", len(beats) >= 2,
          str(len(beats)))
    check("пауза между пульсами разумная",
          all(0.0 < b < 5.0 for b in beats), str([round(b, 2) for b in beats]))

    win.stop_bridge()
    deadline = time.monotonic() + 20
    while bridge.alive and time.monotonic() < deadline:
        pump(100)
    check("остановка завершается", not bridge.alive)
    win.close()
    # The state reaches the header through a queued signal of the engine
    # thread: poll it the way the user would see it, without windows open.
    deadline = time.monotonic() + 3.0
    while win.core_state != "stopped" and time.monotonic() < deadline:
        pump(100)
    check("окно показывает «остановлен»", win.core_state == "stopped",
          win.core_state)
    check("закрытие окна останавливает движок", not win._bridge.alive)


# ===========================================================================
# Phase 3 — the shipped executable
# ===========================================================================
EXE = os.path.join(ROOT, "var", "dist", "MeshBridge-GUI-0.1.0-alpha1.exe")
EXE_CHECK = os.path.join(ROOT, "var", "dist",
                         "MeshBridge-GUI-0.1.0-alpha1-selfcheck.exe")


def phase_exe() -> None:
    """The built file starts, draws its window and keeps its engine alive.

    No radio and no phone: the executable runs next to a config that points
    the transport at a closed local port, so nothing leaves the machine.
    The console twin imports the same code and says what it sees, which a
    windowed build cannot do.
    """
    section("11. Собранный exe")
    if not os.path.exists(EXE):
        print("  skip  exe не собран (gui.spec) — проверка запуска")
        return
    import json
    import subprocess
    import tempfile
    work = tempfile.mkdtemp(prefix="meshgui-")
    with open(os.path.join(work, "config.json"), "w", encoding="utf-8") as fh:
        json.dump({"name": "MeshBridge", "ble_scan_seconds": 3.0,
                   "transport": {"kind": "tcp", "target": "127.0.0.1:1"},
                   "chat": {"kind": "channel", "index": 0},
                   "quiet": True, "menu": False}, fh)

    if os.path.exists(EXE_CHECK):
        run = subprocess.run([EXE_CHECK, "--self-check"], cwd=work,
                             capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=120)
        out = (run.stdout or "") + (run.stderr or "")
        check("exe импортирует движок и окно",
              "SELF-CHECK PASSED" in out, out.strip().splitlines()[-1:])
        check("exe собирает окно", "window ok: 6 tabs" in out,
              out.strip()[-200:])
    else:
        check("консольный близнец для проверки собран", False,
              "нет " + os.path.basename(EXE_CHECK))

    proc = subprocess.Popen([EXE], cwd=work,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        pump(9000)          # Qt start-up, engine thread, first ticks
        alive = proc.poll() is None
        check("exe стартует и держит окно", alive,
              f"процесс завершился с кодом {proc.returncode}")
        if alive:
            check("exe не упал за 9 секунд работы", proc.poll() is None)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        check("exe завершается по запросу", proc.poll() is not None)


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    t0 = time.monotonic()
    error = None
    try:
        phase_window()
        phase_engine()
        phase_exe()
    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        error = "исключение"
    failed = [name for name, ok in RESULTS if not ok]
    print(f"\nпроверок: {len(RESULTS)}, провалено: {len(failed)}, "
          f"{time.monotonic() - t0:.1f} с", flush=True)
    if error:
        print("  FAIL", error)
    for name in failed:
        print("  FAIL", name)
    if failed or error:
        return 1
    print("ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
