"""Физические связи: что привязано, где радио, какой телефон, какой чат."""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QPushButton,
                               QSizePolicy, QWidget)

from ..core import events as ev
from ..widgets import MUTED, OK
from ..widgets.dialogs import confirm_twice
from .base import Page
from .session_bridge import EngineSession


def _wrap(label: QLabel) -> QLabel:
    """A label that wraps by word and may become narrower than its text."""
    label.setWordWrap(True)
    label.setSizePolicy(QSizePolicy.Policy.Ignored,
                        QSizePolicy.Policy.Preferred)
    return label


class ConnectionsPage(Page):
    title = "Подключения"
    subtitle = ("Обе стороны выбираются при запуске. Сменить телефон можно "
                "без перезапуска моста.")

    def __init__(self, session: Optional[EngineSession],
                 parent: Optional[QWidget] = None):
        super().__init__(session, parent)
        self._running = False
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)
        self.radio_value = self._pair(grid, 0, "Радио Meshtastic")
        self.chat_value = self._pair(grid, 1, "Чат в радио")
        self.phone_value = self._pair(grid, 2, "Привязанный телефон")
        self.key_value = self._pair(grid, 3, "Отпечаток ключа")
        self.body.addLayout(grid)

        row = QHBoxLayout()
        self.btn_reset = QPushButton("Сменить телефон…")
        self.btn_reset.setMinimumWidth(0)
        self.btn_reset.setSizePolicy(QSizePolicy.Policy.Ignored,
                                     QSizePolicy.Policy.Fixed)
        self.btn_reset.clicked.connect(self._reset)
        row.addWidget(self.btn_reset)
        row.addStretch(1)
        self.body.addLayout(row)

        self.hint = QLabel(
            "После смены телефона мост остаётся запущенным: он ждёт, пока "
            "рядом появится телефон с Bitchat, и привязывается заново. "
            "Режим пересылки возвращается к «Один телефон».")
        self.hint.setObjectName("Muted")
        self.hint.setWordWrap(True)
        self.hint.setSizePolicy(QSizePolicy.Policy.Ignored,
                                QSizePolicy.Policy.Preferred)
        self.body.addWidget(self.hint)

    @staticmethod
    def _pair(grid: QGridLayout, row: int, title: str) -> QLabel:
        label = _wrap(QLabel(title))
        label.setObjectName("Muted")
        value = _wrap(QLabel("—"))
        grid.addWidget(label, row, 0)
        grid.addWidget(value, row, 1)
        return value

    # ------------------------------------------------------------- hooks
    def on_event(self, event: ev.Event) -> None:
        if isinstance(event, ev.ChatTargetEvent):
            self.chat_value.setText(event.description or "—")
        elif isinstance(event, ev.LinkEvent) and event.name == "radio":
            self.radio_value.setText(event.detail or "нет связи")
            self.radio_value.setStyleSheet(
                f"color: {OK};" if event.connected else f"color: {MUTED};")
        elif isinstance(event, ev.BindingEvent):
            self._set_binding(event)

    def on_state(self, state: ev.StateEvent) -> None:
        self.radio_value.setText(state.radio_detail or "нет связи")
        self.radio_value.setStyleSheet(
            f"color: {OK};" if state.radio_connected else f"color: {MUTED};")
        self.chat_value.setText(state.chat_target or "—")
        self._set_binding(ev.BindingEvent(
            state.bound, state.bound_label,
            self.session.stats().get("bound_fingerprint", "")
            if self.session else ""))

    def on_core_state(self, name: str) -> None:
        self._running = name == "running"
        self.btn_reset.setEnabled(self._running)

    def _set_binding(self, event: ev.BindingEvent) -> None:
        if event.bound:
            self.phone_value.setText(event.label)
            self.phone_value.setStyleSheet(f"color: {OK};")
            self.key_value.setText(event.fingerprint or "ключ ещё не получен")
        else:
            self.phone_value.setText("не привязан")
            self.phone_value.setStyleSheet(f"color: {MUTED};")
            self.key_value.setText("—")

    # ------------------------------------------------------------ actions
    def _reset(self) -> None:
        if self.session is None or not self._running:
            return
        if not confirm_twice(
                self, "Смена телефона",
                "Текущий телефон будет отключён, привязка и списки "
                "пересылки сброшены, режим вернётся к «Один телефон»."):
            return
        self.session.reset_binding()
