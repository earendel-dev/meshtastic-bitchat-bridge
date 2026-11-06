"""Base class for a page: a card around one group of functions."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFrame, QLabel, QSizePolicy, QVBoxLayout,
                               QWidget)

from ..core import events as ev


class Page(QFrame):
    """One group of functions.

    A page gets the live session and the event stream.  It only *shows* and
    *asks*; all rules live in the engine.
    """

    title = "Раздел"
    subtitle = ""

    def __init__(self, session, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.session = session
        self.setObjectName("Panel")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(8)
        self.head = QLabel(self.title)
        self.head.setObjectName("Title")
        self.head.setWordWrap(True)
        outer.addWidget(self.head)
        self.sub = None
        if self.subtitle:
            self.sub = QLabel(self.subtitle)
            self.sub.setObjectName("Muted")
            self.sub.setWordWrap(True)
            self.sub.setSizePolicy(QSizePolicy.Policy.Ignored,
                                   QSizePolicy.Policy.Preferred)
            outer.addWidget(self.sub)
        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        outer.addLayout(self.body)
        outer.addStretch(1)

    def set_session(self, session) -> None:
        """Point the page at the current live session (it is replaced when
        the bridge is restarted)."""
        self.session = session

    # Hooks a page may override; the window calls them.
    def on_event(self, event: ev.Event) -> None:
        pass

    def on_state(self, state: ev.StateEvent) -> None:
        pass

    def on_core_state(self, name: str) -> None:
        """'running', 'starting' or 'stopped'."""
        pass
