"""Small reusable widgets: the live dot, counters, links, colours.

Every metric that the window uses lives here, so the look is changed in one
file.  Sizes are expressed in font units (``em``) rather than pixels, so the
window keeps its proportions when Windows uses a different text scale.
"""

from __future__ import annotations

import math
import time
from typing import Optional

from PySide6.QtCore import (QEasingCurve, QPropertyAnimation, QSize, Qt,
                            QTimer)
from PySide6.QtGui import QColor, QPainter, QPaintEvent
from PySide6.QtWidgets import (QCheckBox, QFrame, QHBoxLayout, QLabel,
                               QSizePolicy, QVBoxLayout, QWidget)

BG = "#12161c"
PANEL = "#1a2028"
PANEL_ALT = "#212934"
BORDER = "#242c38"
TEXT = "#e6edf3"
MUTED = "#8b98a5"
ACCENT = "#4c9aff"
OK = "#3fb950"
WARN = "#d29922"
ERROR = "#f85149"
IDLE_GREY = "#4a5560"


def style_sheet() -> str:
    return f"""
    QWidget {{ background: {BG}; color: {TEXT};
               font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 13px; }}
    QMainWindow, QScrollArea, QScrollArea > QWidget > QWidget {{ background: {BG}; }}
    QFrame#Panel {{ background: {PANEL}; border: 1px solid {BORDER};
                    border-radius: 10px; }}
    QFrame#Counter {{ background: {PANEL_ALT}; border: 1px solid {BORDER};
                      border-radius: 8px; }}
    QLabel#Title {{ font-size: 15px; font-weight: 600; }}
    QLabel#Muted {{ color: {MUTED}; }}
    QLabel#Value {{ font-size: 20px; font-weight: 600; }}
    QPushButton {{ background: {PANEL_ALT}; border: 1px solid #2b3542;
                   border-radius: 7px; padding: 6px 12px;
                   min-height: 1.6em; }}
    QPushButton:hover {{ border-color: {ACCENT}; }}
    QPushButton:pressed {{ background: #1a2028; }}
    QPushButton:disabled {{ color: {MUTED}; border-color: {BORDER}; }}
    QPushButton#Primary {{ background: {ACCENT}; color: #0b1220;
                           font-weight: 600; border: none; }}
    QPushButton#Primary:hover {{ background: #63a8ff; }}
    QPushButton#Primary:disabled {{ background: #2b3542; color: {MUTED}; }}
    QCheckBox, QRadioButton {{ spacing: 8px; }}
    QComboBox, QSpinBox {{ background: {PANEL_ALT}; border: 1px solid #2b3542;
                           border-radius: 7px; padding: 4px 8px;
                           min-width: 6em; }}
    QComboBox QAbstractItemView {{ background: {PANEL_ALT}; color: {TEXT};
                                   selection-background-color: {ACCENT}; }}
    QTabWidget::pane {{ border: none; }}
    QTabBar::tab {{ background: transparent; color: {MUTED};
                    padding: 7px 12px; margin-right: 2px;
                    border-bottom: 2px solid transparent; }}
    QTabBar::tab:selected {{ color: {TEXT}; border-bottom-color: {ACCENT}; }}
    QTabBar::tab:hover {{ color: {TEXT}; }}
    QPlainTextEdit {{ background: #0e1218; border: 1px solid {BORDER};
                      border-radius: 8px; color: {TEXT}; }}
    QListWidget {{ background: {PANEL_ALT}; border: 1px solid {BORDER};
                   border-radius: 8px; padding: 2px; }}
    QListWidget::item {{ padding: 3px 2px; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: #2b3542; border-radius: 5px;
                                   min-height: 24px; }}
    QToolTip {{ background: {PANEL_ALT}; color: {TEXT};
               border: 1px solid {BORDER}; }}
    """


class LiveDot(QWidget):
    """A dot that says three things at once:

    * colour — what is connected (green) or not (grey);
    * a slow breathing pulse — the bridge is alive and this link is up;
    * a short flash — a message just went through this link.
    """

    def __init__(self, parent: Optional[QWidget] = None, size: int = 12):
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        self._color = QColor(IDLE_GREY)
        self._phase = 0.0
        self._pulse = 0.0
        self._alive = True
        self._anim = QPropertyAnimation(self, b"pulse", self)
        self._anim.setDuration(700)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self._timer = QTimer(self)
        self._timer.setInterval(60)
        self._timer.timeout.connect(self._step)
        self._timer.start()

    # QPropertyAnimation needs a real property to drive.
    def _get_pulse(self) -> float:
        return self._pulse

    def _set_pulse(self, value: float) -> None:
        self._pulse = float(value)
        self.update()

    pulse = property(_get_pulse, _set_pulse)

    @property
    def color(self) -> QColor:
        return QColor(self._color)

    def set_state(self, color: str, alive: bool = True) -> None:
        self._color = QColor(color)
        self._alive = alive
        self.update()

    def flash(self) -> None:
        self._anim.stop()
        self._anim.start()

    def _step(self) -> None:
        self._phase = (self._phase + 0.06) % 1.0
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        size = self._size
        painter.setPen(Qt.PenStyle.NoPen)
        if self._alive:
            breath = 0.5 + 0.5 * math.sin(self._phase * 2 * math.pi)
            halo = QColor(self._color)
            halo.setAlphaF(0.10 + 0.22 * breath)
            painter.setBrush(halo)
            painter.drawEllipse(0, 0, size, size)
        if self._pulse > 0:
            ring = QColor(self._color)
            ring.setAlphaF(0.55 * self._pulse)
            painter.setBrush(ring)
            grow = int(size * 0.45 * self._pulse)
            painter.drawEllipse(-grow, -grow, size + 2 * grow, size + 2 * grow)
        core = int(size * 0.55)
        off = (size - core) / 2
        painter.setBrush(self._color)
        painter.drawEllipse(int(off), int(off), core, core)


class Counter(QFrame):
    """One number with a caption; flashes when the number grows."""

    def __init__(self, caption: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("Counter")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)
        self.value = QLabel("0")
        self.value.setObjectName("Value")
        self.caption = QLabel(caption)
        self.caption.setObjectName("Muted")
        self.caption.setWordWrap(True)
        self.caption.setSizePolicy(QSizePolicy.Policy.Ignored,
                                   QSizePolicy.Policy.Preferred)
        layout.addWidget(self.value)
        layout.addWidget(self.caption)
        self._flash_until = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(120)
        self._timer.timeout.connect(self._restore)
        self._timer.start()

    def set_value(self, number: int, tooltip: str = "") -> None:
        text = str(number)
        if self.value.text() != text:
            self.value.setText(text)
            if number:
                self.flash()
        if tooltip:
            self.setToolTip(tooltip)

    def flash(self) -> None:
        self._flash_until = time.monotonic() + 1.2
        self.value.setStyleSheet(f"color: {ACCENT};")

    def _restore(self) -> None:
        if self._flash_until and time.monotonic() > self._flash_until:
            self._flash_until = 0.0
            self.value.setStyleSheet(f"color: {TEXT};")


class Switch(QCheckBox):
    """A checkbox used as the on/off switch of one function."""

    def __init__(self, text: str, parent: Optional[QWidget] = None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class LinkRow(QWidget):
    """Name of a link, a live dot and one line of detail."""

    def __init__(self, title: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        self.dot = LiveDot()
        self.title = QLabel(title)
        self.title.setMinimumWidth(0)
        self.detail = QLabel("—")
        self.detail.setObjectName("Muted")
        self.detail.setWordWrap(True)
        self.detail.setSizePolicy(QSizePolicy.Policy.Ignored,
                                  QSizePolicy.Policy.Preferred)
        layout.addWidget(self.dot)
        layout.addWidget(self.title)
        layout.addWidget(self.detail, 1)

    def set_state(self, connected: bool, detail: str) -> None:
        self.dot.set_state(OK if connected else IDLE_GREY, alive=connected)
        self.detail.setText(detail or "—")

    def flash(self) -> None:
        self.dot.flash()
