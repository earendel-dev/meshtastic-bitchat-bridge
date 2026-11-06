"""Синхронизация: что, куда и когда уходит между двумя сетями."""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QPushButton,
                               QSizePolicy, QVBoxLayout, QWidget)

import bridge
from ..core import events as ev
from ..widgets import MUTED, OK
from ..widgets.dialogs import confirm_twice
from .base import Page
from .session_bridge import EngineSession


def _wrap(label: QLabel) -> QLabel:
    label.setWordWrap(True)
    label.setSizePolicy(QSizePolicy.Policy.Ignored,
                        QSizePolicy.Policy.Preferred)
    return label


class SyncPage(Page):
    title = "Синхронизация"
    subtitle = ("С радио в LoRa — по команде, потому что эфир узкий: каждая "
                "отправка ждёт своей очереди.")

    def __init__(self, session: Optional[EngineSession],
                 parent: Optional[QWidget] = None):
        super().__init__(session, parent)
        self._full_sync = False
        self._running = False

        self.body.addWidget(self._section(
            "LoRa → Bitchat (на телефон)",
            "Новое приходит автоматически. Эта кнопка досылает то, что уже "
            "накопилось."))
        self.count_to_phone = self._count_box()
        self.btn_to_phone = self._button("Отправить на телефон", primary=True)
        self.btn_to_phone.clicked.connect(self._sync_to_phone)
        self.body.addLayout(self._row(self.count_to_phone, self.btn_to_phone))

        self.body.addWidget(self._section(
            "Bitchat → LoRa (в эфир)",
            "Сообщения копятся в буфере и уходят по одному с паузой. Кого "
            "пропускает выбранный режим — решается в разделе «Пересылка»."))
        self.count_to_lora = self._count_box()
        self.btn_to_lora = self._button("Отправить в LoRa", primary=True)
        self.btn_to_lora.clicked.connect(self._sync_to_lora)
        self.body.addLayout(self._row(self.count_to_lora, self.btn_to_lora))

        self.body.addWidget(self._section(
            "Полная синхронизация в обе стороны",
            "Каждое новое сообщение сразу уходит на другую сторону, без "
            "ручных кнопок."))
        self.btn_full = self._button("Включить полную синхронизацию")
        self.btn_full.clicked.connect(self._toggle_full)
        self.full_state = _wrap(QLabel("Выключена"))
        self.full_state.setObjectName("Muted")
        self.body.addWidget(self.btn_full)
        self.body.addWidget(self.full_state)

        self.body.addWidget(self._section(
            "Повтор по расписанию",
            "Досылать только новое с заданным периодом. Работает, пока "
            "включена полная синхронизация."))
        self.period_direction = QComboBox()
        self.period_direction.addItem("Bitchat → LoRa", "bit2lora")
        self.period_direction.addItem("LoRa → Bitchat", "lora2bit")
        self.period_count = self._count_box()
        self.period_minutes = QComboBox()
        for minutes in (1, 5, 15, 30, 60, 180, 1440):
            self.period_minutes.addItem(f"{minutes} мин", minutes * 60)
        self.period_minutes.setCurrentIndex(2)
        self.btn_period = self._button("Включить повтор")
        self.btn_period.clicked.connect(self._add_period)
        self.body.addLayout(self._row(self.period_direction,
                                      self.period_count,
                                      self.period_minutes))
        self.body.addLayout(self._row(self.btn_period))
        self.period_status = _wrap(QLabel("Повторов нет."))
        self.period_status.setObjectName("Muted")
        self.body.addWidget(self.period_status)

    # ------------------------------------------------------------ layout
    @staticmethod
    def _count_box() -> QComboBox:
        box = QComboBox()
        for number in bridge.SYNC_COUNTS:
            box.addItem(f"последние {number}", number)
        box.setCurrentIndex(1)
        return box

    @staticmethod
    def _button(text: str, primary: bool = False) -> QPushButton:
        """A button that wraps its text instead of widening the page."""
        button = QPushButton(text)
        button.setSizePolicy(QSizePolicy.Policy.Preferred,
                             QSizePolicy.Policy.Minimum)
        button.setMinimumWidth(0)
        if primary:
            button.setObjectName("Primary")
        return button

    @staticmethod
    def _row(*widgets: QWidget) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)
        for widget in widgets:
            row.addWidget(widget)
        row.addStretch(1)
        return row

    def _section(self, title: str, hint: str) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(2)
        head = QLabel(title)
        head.setStyleSheet("font-weight: 600;")
        _wrap(head)
        text = QLabel(hint)
        text.setObjectName("Muted")
        _wrap(text)
        layout.addWidget(head)
        layout.addWidget(text)
        return box

    # ------------------------------------------------------------- hooks
    def on_event(self, event: ev.Event) -> None:
        if isinstance(event, ev.FullSyncEvent):
            self._set_full(event.enabled)
        elif isinstance(event, ev.ScheduleEvent):
            self.period_status.setText(event.description or "Повторов нет.")

    def on_state(self, state: ev.StateEvent) -> None:
        self._set_full(state.full_sync)
        self.period_status.setText(state.schedule or "Повторов нет.")

    def on_core_state(self, name: str) -> None:
        self._running = name == "running"
        for widget in (self.btn_to_phone, self.btn_to_lora, self.btn_full,
                       self.btn_period):
            widget.setEnabled(self._running)

    def _set_full(self, enabled: bool) -> None:
        self._full_sync = bool(enabled)
        self.btn_full.setText("Выключить полную синхронизацию"
                              if self._full_sync
                              else "Включить полную синхронизацию")
        self.btn_full.setAccessibleName(self.btn_full.text())
        self.full_state.setText("Включена" if self._full_sync else "Выключена")
        self.full_state.setStyleSheet(
            f"color: {OK};" if self._full_sync else f"color: {MUTED};")

    # ------------------------------------------------------------ actions
    def _sync_to_phone(self) -> None:
        if self.session is None or not self._running:
            return
        self.session.sync_to_bitchat(self.count_to_phone.currentData())

    def _sync_to_lora(self) -> None:
        if self.session is None or not self._running:
            return
        self.session.sync_to_lora(self.count_to_lora.currentData())

    def _toggle_full(self) -> None:
        if self.session is None or not self._running:
            return
        if self._full_sync:
            if not self.session.set_full_sync(False):
                self.period_status.setText("Не удалось выключить полную "
                                           "синхронизацию.")
                return
            self._set_full(False)
            self.period_status.setText("Полная синхронизация выключена.")
            return
        if not confirm_twice(
                self, "Полная синхронизация",
                bridge.PRIVATE_WARNING_1 + "\n\n" + bridge.PRIVATE_WARNING_2):
            return
        if not self.session.set_full_sync(True, confirmed=True):
            # The engine refused (it is going down, or the channel was not
            # confirmed): the switch must show the truth, not the wish.
            self._set_full(False)
            self.period_status.setText("Не удалось включить полную "
                                       "синхронизацию.")
            return
        self._set_full(True)
        self.period_status.setText(
            "Полная синхронизация включена: всё новое уходит сразу.")

    def _add_period(self) -> None:
        if self.session is None or not self._running:
            return
        reason = self.session.schedule(self.period_direction.currentData(),
                                       self.period_count.currentData(),
                                       self.period_minutes.currentData())
        if reason:
            self.period_status.setText(reason.capitalize() + ".")
            return
        snapshot = self.session.snapshot()
        self.period_status.setText(
            snapshot.schedule if snapshot and snapshot.schedule
            else "Повтор включён.")
