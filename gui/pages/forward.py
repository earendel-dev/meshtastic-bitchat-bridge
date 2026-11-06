"""Что пересылать из Bitchat в LoRa: режимы и список телефонов.

Смена режима повторяет консоль: предупреждение, затем двойное
подтверждение.  Список «рядом» строится по announce, прошедшим проверку
подписи; привязанный телефон в списке отмечен и не снимается.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QButtonGroup, QHBoxLayout, QLabel,
                               QListWidget, QListWidgetItem, QPushButton,
                               QRadioButton, QSizePolicy, QVBoxLayout, QWidget)

from ..core import events as ev
from ..widgets.dialogs import confirm_twice
from .base import Page
from .session_bridge import EngineSession, mode_warning

MODES = [
    ("bound", "Один телефон",
     "Только привязанный телефон. Самый строгий режим."),
    ("custom", "Выбранные телефоны",
     "Привязанный телефон плюс отмеченные ниже."),
    ("replies", "Те, кому я ответил",
     "Привязанный телефон плюс те, кому вы ответили в общем чате."),
    ("all", "Любой телефон",
     "Всё, что дошло до моста. Самый широкий режим."),
]


def _wrap(label: QLabel) -> QLabel:
    """A label that wraps by word and may become narrower than its text."""
    label.setWordWrap(True)
    label.setSizePolicy(QSizePolicy.Policy.Ignored,
                        QSizePolicy.Policy.Preferred)
    return label


class ForwardPage(Page):
    title = "Пересылка Bitchat → LoRa"
    subtitle = ("Кто имеет право попасть из Bitchat в LoRa. Решение действует "
                "на всю пересылку: ручную, полную и по расписанию.")

    def __init__(self, session: Optional[EngineSession],
                 parent: Optional[QWidget] = None):
        super().__init__(session, parent)
        self._mode = "bound"
        self._sources: List[str] = []
        self._replied: List[str] = []
        self._peers: List[ev.PeerEvent] = []

        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self._buttons: Dict[str, QRadioButton] = {}
        for mode, label, hint in MODES:
            row = QWidget()
            row.setSizePolicy(QSizePolicy.Policy.Preferred,
                              QSizePolicy.Policy.Preferred)
            layout = QVBoxLayout(row)
            layout.setContentsMargins(0, 2, 0, 2)
            layout.setSpacing(0)
            button = QRadioButton(label)
            button.setStyleSheet("font-weight: 600;")
            button.setMinimumWidth(0)
            button.setSizePolicy(QSizePolicy.Policy.Ignored,
                                 QSizePolicy.Policy.Fixed)
            text = QLabel(hint)
            text.setObjectName("Muted")
            text.setContentsMargins(22, 0, 0, 0)
            _wrap(text)
            layout.addWidget(button)
            layout.addWidget(text)
            button.toggled.connect(
                lambda checked, m=mode: self._on_radio(m, checked))
            self.group.addButton(button)
            self._buttons[mode] = button
            self.body.addWidget(row)
        self._buttons["bound"].setChecked(True)

        self.note = _wrap(QLabel(""))
        self.note.setObjectName("Muted")
        self.body.addWidget(self.note)

        header = QHBoxLayout()
        title = QLabel("Телефоны рядом")
        title.setStyleSheet("font-weight: 600;")
        header.addWidget(title)
        header.addStretch(1)
        self.apply_button = QPushButton("Применить выбранные")
        self.apply_button.setMinimumWidth(0)
        self.apply_button.setSizePolicy(QSizePolicy.Policy.Ignored,
                                        QSizePolicy.Policy.Fixed)
        self.apply_button.clicked.connect(self._apply_custom)
        header.addWidget(self.apply_button, 1)
        self.body.addLayout(header)

        self.phones = QListWidget()
        self.phones.setMinimumHeight(110)
        self.phones.setWordWrap(False)
        self.phones.itemChanged.connect(self._on_item_changed)
        self.body.addWidget(self.phones)

        self.status = _wrap(QLabel(""))
        self.status.setObjectName("Muted")
        self.body.addWidget(self.status)

        self._running = False

    # ------------------------------------------------------------- hooks
    def on_event(self, event: ev.Event) -> None:
        if isinstance(event, ev.ForwardModeEvent):
            self._apply_mode(event.mode, event.sources, event.replied)
        elif isinstance(event, ev.BindingEvent):
            self.refresh_phones()

    def on_state(self, state: ev.StateEvent) -> None:
        self._apply_mode(state.forward_mode, state.sources, state.replied)
        self.refresh_phones()

    def on_core_state(self, name: str) -> None:
        self._running = name == "running"
        for button in self._buttons.values():
            button.setEnabled(self._running)
        self.apply_button.setEnabled(self._running and self._mode == "custom")
        self._render_phones()

    # --------------------------------------------------------------- ui
    def _apply_mode(self, mode: str, sources, replied) -> None:
        self._mode = mode if mode in self._buttons else "bound"
        self._sources = list(sources or ()) if self._mode == "custom" else []
        self._replied = list(replied or ()) if self._mode == "replies" else []
        self._sync_radios()
        self._describe()
        self._render_phones()

    def _sync_radios(self) -> None:
        button = self._buttons.get(self._mode)
        if button is not None and not button.isChecked():
            button.blockSignals(True)
            button.setChecked(True)
            button.blockSignals(False)
        self.apply_button.setEnabled(self._running and self._mode == "custom")

    def _describe(self) -> None:
        if self._mode == "bound":
            self.note.setText("В LoRa уходят только сообщения этого телефона.")
        elif self._mode == "custom":
            self.note.setText(f"В LoRa идут сообщения привязанного телефона "
                              f"и {len(self._sources)} отмеченных.")
        elif self._mode == "replies":
            self.note.setText(
                f"В LoRa идут сообщения привязанного телефона и тех, кому вы "
                f"ответили (сейчас {len(self._replied)}). Список собирается "
                f"сам и живёт до перезапуска.")
        else:
            self.note.setText("В LoRa идёт всё, что дошло до моста. "
                              "Подпись проверяется у всех, чей ключ известен.")

    def refresh_phones(self) -> None:
        if self.session is None:
            return
        self._peers = list(self.session.peers())
        self._render_phones()

    def _render_phones(self) -> None:
        if self.session is None:
            return
        if self._mode == "custom":
            self._sources = list(self.session.stats().get("sources") or [])
        self.phones.blockSignals(True)
        self.phones.clear()
        for peer in self._peers:
            label = peer.label
            if peer.is_bound:
                label = f"{label}  (привязанный, всегда пересылается)"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, peer.peer_id)
            flags = item.flags() | Qt.ItemFlag.ItemIsUserCheckable
            if peer.is_bound:
                flags &= ~Qt.ItemFlag.ItemIsEnabled
                item.setCheckState(Qt.CheckState.Checked)
            else:
                checked = (peer.peer_id in self._sources or
                           (self._mode == "replies" and
                            peer.peer_id in self._replied))
                item.setCheckState(Qt.CheckState.Checked if checked
                                   else Qt.CheckState.Unchecked)
            item.setFlags(flags)
            item.setToolTip(f"отпечаток ключа: {peer.fingerprint}"
                            if peer.fingerprint else "ключ ещё не получен")
            self.phones.addItem(item)
        self.phones.blockSignals(False)
        self.phones.setToolTip("\n".join(
            self.phones.item(i).text() for i in range(self.phones.count())))
        if not self._peers:
            self.status.setText("Пока никого не видно: телефон появится "
                                "здесь после своего announce.")

    def _on_item_changed(self, item: QListWidgetItem) -> None:
        if self.session is None:
            return
        peer = item.data(Qt.ItemDataRole.UserRole)
        self.session.mark_source(peer,
                                 item.checkState() == Qt.CheckState.Checked)

    def _checked_peers(self) -> List[str]:
        """Picked phones, without the bound one: it is always a source and
        is shown disabled, so its tick must not count as a choice."""
        out = []
        for row in range(self.phones.count()):
            item = self.phones.item(row)
            if item.checkState() != Qt.CheckState.Checked:
                continue
            if not bool(item.flags() & Qt.ItemFlag.ItemIsEnabled):
                continue
            out.append(item.data(Qt.ItemDataRole.UserRole))
        return out

    # ------------------------------------------------------------ actions
    def _on_radio(self, mode: str, checked: bool) -> None:
        if not checked or mode == self._mode:
            return
        if self.session is None or not self._running:
            self._sync_radios()
            return
        if mode == "bound":
            self.session.set_forward_mode("bound", confirmed=True)
            self._apply_mode("bound", (), ())
            return
        if mode == "custom" and not self._checked_peers():
            self.phones.setFocus()
            self.status.setText("Отметьте хотя бы один телефон в списке, "
                                "затем повторите.")
            self._sync_radios()
            return
        if not confirm_twice(self, "Смена режима пересылки",
                             mode_warning(mode)):
            self._sync_radios()
            self._describe()
            return
        chosen = self._checked_peers()
        if self.session.set_forward_mode(mode, sources=chosen,
                                         confirmed=True):
            self._apply_mode(mode, chosen if mode == "custom" else (),
                             self._replied)
            self.status.setText("")
        else:
            self._sync_radios()
            self.status.setText("Не удалось сменить режим.")

    def _apply_custom(self) -> None:
        chosen = self._checked_peers()
        if not chosen:
            self.status.setText("Отметьте хотя бы один телефон.")
            return
        if self.session is None or not self._running:
            return
        if self._mode == "custom":
            self.session.set_forward_mode("custom", sources=chosen,
                                          confirmed=True)
            self._apply_mode("custom", chosen, self._replied)
            self.status.setText("")
            return
        if not confirm_twice(self, "Смена режима пересылки",
                             mode_warning("custom")):
            return
        if self.session.set_forward_mode("custom", sources=chosen,
                                         confirmed=True):
            self._apply_mode("custom", chosen, self._replied)
            self.status.setText("")
