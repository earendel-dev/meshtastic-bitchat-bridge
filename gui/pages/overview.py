"""Обзор: жив ли мост и что через него прошло.

Два независимых индикатора, ровно о том, что просили:

* ``heart`` пульсирует, пока движок присылает секундные отметки; нет
  отметки пять секунд — точка краснеет и подписывается «завис».  Это не
  про сеть, это про сам процесс.
* полоса «пересылка» внизу окна вспыхивает на каждом реально ушедшем
  сообщении; здесь же — счётчики и время последней пересылки.
"""

from __future__ import annotations

import time
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QSizePolicy,
                               QVBoxLayout, QWidget)

from ..core import events as ev
from ..widgets import Counter, LinkRow, LiveDot, MUTED, OK, WARN
from .base import Page
from .session_bridge import EngineSession


class OverviewPage(Page):
    title = "Обзор"
    subtitle = ("Слева — жив ли мост и обе связи. Справа — сколько ждёт и что "
                "ушло. Текст сообщений не показывается никогда.")

    def __init__(self, session: Optional[EngineSession],
                 parent: Optional[QWidget] = None):
        super().__init__(session, parent)
        top = QVBoxLayout()
        top.setSpacing(6)

        card = QWidget()
        card_layout = QHBoxLayout(card)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(12)
        self.heart = LiveDot(size=26)
        card_layout.addWidget(self.heart, 0, Qt.AlignmentFlag.AlignTop)
        text = QWidget()
        text_layout = QVBoxLayout(text)
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(2)
        self.alive_label = QLabel("Мост не запущен")
        self.alive_label.setStyleSheet("font-size: 18px; font-weight: 600;")
        self.alive_label.setWordWrap(True)
        self.alive_detail = QLabel("—")
        self.alive_detail.setObjectName("Muted")
        self.alive_detail.setWordWrap(True)
        self.alive_detail.setSizePolicy(QSizePolicy.Policy.Ignored,
                                        QSizePolicy.Policy.Preferred)
        text_layout.addWidget(self.alive_label)
        text_layout.addWidget(self.alive_detail)
        card_layout.addWidget(text, 1)
        top.addWidget(card)

        self.traffic = QLabel("")
        self.traffic.setObjectName("Muted")
        self.traffic.setWordWrap(True)
        top.addWidget(self.traffic)
        self.body.addLayout(top)

        self.radio = LinkRow("Радио LoRa")
        self.phone = LinkRow("Телефон Bitchat")
        self.body.addWidget(self.radio)
        self.body.addWidget(self.phone)

        grid = QGridLayout()
        grid.setSpacing(10)
        self.c_to_phone = Counter("ждут отправки\nна телефон")
        self.c_to_lora = Counter("в буфере\nдля LoRa")
        self.c_blocked = Counter("в буфере,\nне проходят режим")
        self.c_queue = Counter("в очереди\nэфира LoRa")
        for column, counter in enumerate((self.c_to_phone, self.c_to_lora,
                                          self.c_blocked, self.c_queue)):
            grid.addWidget(counter, 0, column)
        self.body.addLayout(grid)

        self.last_box = QLabel("Последнее действие появится здесь "
                               "(без текста сообщения).")
        self.last_box.setObjectName("Muted")
        self.last_box.setWordWrap(True)
        self.last_box.setSizePolicy(QSizePolicy.Policy.Ignored,
                                    QSizePolicy.Policy.Preferred)
        self.body.addWidget(self.last_box)

        self._last_forward_at = 0.0
        self._sent_total = 0
        self._radio_on = False
        self._phone_on = False
        self._core = "stopped"
        self._beat_age = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    # ------------------------------------------------------------- hooks
    def on_event(self, event: ev.Event) -> None:
        if isinstance(event, ev.MessageCountsEvent):
            self._set_counts(event)
        elif isinstance(event, ev.LinkEvent):
            self._set_link(event)
        elif isinstance(event, ev.ForwardedEvent):
            self._forwarded(event)
        elif isinstance(event, ev.LogEvent) and event.level == ev.Level.ERROR:
            self.heart.flash()

    def on_state(self, state: ev.StateEvent) -> None:
        self._set_counts(state.counts)
        self._radio_on = state.radio_connected
        self._phone_on = state.phone_connected
        self.radio.set_state(state.radio_connected, state.radio_detail)
        self.phone.set_state(state.phone_connected, state.phone_detail)

    def on_core_state(self, name: str) -> None:
        self._core = name
        if name == "running":
            self.alive_label.setText("Мост работает")
            self.alive_label.setStyleSheet(
                f"font-size: 18px; font-weight: 600; color: {OK};")
            self.heart.set_state(OK, alive=True)
            self.alive_detail.setText("Пульс — раз в секунду. Если он "
                                      "остановился, мост завис.")
        elif name == "starting":
            self.alive_label.setText("Запускается…")
            self.alive_label.setStyleSheet(
                f"font-size: 18px; font-weight: 600; color: {WARN};")
            self.heart.set_state(WARN, alive=True)
            self.alive_detail.setText("Поиск радио и телефона.")
        else:
            self.alive_label.setText("Мост остановлен")
            self.alive_label.setStyleSheet(
                f"font-size: 18px; font-weight: 600; color: {MUTED};")
            self.heart.set_state(MUTED, alive=False)
            self.alive_detail.setText("Нажмите «Запустить», чтобы начать.")

    def on_heartbeat(self, gap: float) -> None:
        """Called by the window with the gap between two engine ticks."""
        self._beat_age = gap

    # ---------------------------------------------------------- internals
    def _set_counts(self, counts: ev.MessageCountsEvent) -> None:
        self.c_to_phone.set_value(counts.lora_to_bitchat,
                                  "Из LoRa, ещё не передано на телефон")
        self.c_to_lora.set_value(counts.bitchat_to_lora,
                                 "Из Bitchat, ждёт синхронизации в LoRa")
        self.c_blocked.set_value(counts.bitchat_blocked,
                                 "Пришло, но выбранный режим не пропускает")
        self.c_queue.set_value(counts.lora_queue,
                               "Уходит в эфир по одному, с интервалом")

    def _set_link(self, event: ev.LinkEvent) -> None:
        if event.name == "radio":
            self._radio_on = event.connected
            self.radio.set_state(event.connected, event.detail)
        elif event.name == "phone":
            self._phone_on = event.connected
            self.phone.set_state(event.connected, event.detail)

    def _forwarded(self, event: ev.ForwardedEvent) -> None:
        self._last_forward_at = time.time()
        self._sent_total += max(0, event.count)
        where = "в LoRa" if event.direction == "to_lora" else "на телефон"
        kind = event.kind or "сообщение"
        who = f" от «{event.author}»" if event.author else ""
        self.last_box.setText(f"{kind}{who}: ушло {where} — {event.count}")
        (self.radio if event.direction == "to_lora" else self.phone).flash()
        self.heart.flash()
        self._tick()

    def _tick(self) -> None:
        if self._last_forward_at:
            age = int(time.time() - self._last_forward_at)
            when = f"{age} с назад" if age < 60 else f"{age // 60} мин назад"
            base = self.last_box.text().split("  ·  ")[0]
            self.last_box.setText(f"{base}  ·  {when}")
            self.traffic.setText(f"всего пересылок: {self._sent_total}")
        if self._core == "running" and self._beat_age > 5.0:
            self.heart.set_state("#f85149", alive=True)
            self.alive_label.setText("Мост не отвечает")
            self.alive_label.setStyleSheet(
                "font-size: 18px; font-weight: 600; color: #f85149;")
            self.alive_detail.setText("Движок молчит дольше пяти секунд. "
                                      "Смотрите «Журнал».")
        elif self._core == "running" and self._beat_age <= 5.0:
            self.heart.set_state(OK, alive=True)
