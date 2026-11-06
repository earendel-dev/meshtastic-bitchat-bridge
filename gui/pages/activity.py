"""Журнал: что сделал мост. Без текста сообщений — только факты."""

from __future__ import annotations

import time
from typing import Optional

from PySide6.QtWidgets import QPlainTextEdit, QWidget

from ..core import events as ev
from ..widgets import ERROR, MUTED, OK, WARN
from .base import Page
from .session_bridge import EngineSession

_COLOURS = {
    ev.Level.INFO: "",
    ev.Level.OK: OK,
    ev.Level.WARN: WARN,
    ev.Level.ERROR: ERROR,
}


class LogPage(Page):
    title = "Журнал"
    subtitle = ("События моста: связи, буферы, отправки, отказы. Текст "
                "сообщений сюда не попадает — только счётчики и имена.")

    MAX_LINES = 500

    def __init__(self, session: Optional[EngineSession],
                 parent: Optional[QWidget] = None):
        super().__init__(session, parent)
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(self.MAX_LINES)
        self.view.setPlaceholderText("Пока пусто.")
        self.view.setMinimumHeight(200)
        self.body.addWidget(self.view, 1)

    def on_event(self, event: ev.Event) -> None:
        if isinstance(event, ev.LogEvent):
            self.append(event.text, event.level)
        elif isinstance(event, ev.LinkEvent):
            what = "Радио" if event.name == "radio" else "Телефон"
            if event.connected:
                self.append(f"{what}: связь есть. {event.detail}".strip(),
                            ev.Level.OK)
            else:
                self.append(f"{what}: связи нет.", ev.Level.WARN)
        elif isinstance(event, ev.ForwardedEvent):
            where = "LoRa" if event.direction == "to_lora" else "телефон"
            who = f" от «{event.author}»" if event.author else ""
            self.append(f"Передано в {where}{who}: {event.count} "
                        f"({event.kind or 'сообщение'}).", ev.Level.OK)
        elif isinstance(event, ev.BindingEvent):
            if event.bound:
                self.append(f"Привязан телефон «{event.label}».", ev.Level.OK)
            else:
                self.append("Телефон не привязан.", ev.Level.WARN)

    def append(self, text: str, level: ev.Level = ev.Level.INFO) -> None:
        stamp = time.strftime("%H:%M:%S")
        colour = _COLOURS.get(level, "")
        safe = text.replace("&", "&amp;").replace("<", "&lt;")
        line = f'<span style="color:{MUTED}">{stamp}</span> '
        if colour:
            line += f'<span style="color:{colour}">{safe}</span>'
        else:
            line += safe
        self.view.appendHtml(line)

    def on_core_state(self, name: str) -> None:
        if name == "starting":
            self.append("Запуск моста…")
        elif name == "stopped":
            self.append("Мост остановлен.", ev.Level.WARN)
