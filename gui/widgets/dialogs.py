"""Подтверждения: те же два шага, что и в консоли.

Консоль просит два раза ввести ``yes``; окно просит два осознанных нажатия.
Смысл один: решение, которое расширяет то, что может уйти в эфир, не
должно случаться от одного случайного клика.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import QMessageBox, QWidget


def confirm_twice(parent: Optional[QWidget], title: str, warning: str,
                  first: str = "Продолжить",
                  second: str = "Подтвердить") -> bool:
    """Show ``warning`` and ask twice; ``True`` only if both are accepted."""
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setText(warning)
    box.setStandardButtons(QMessageBox.StandardButton.Cancel |
                           QMessageBox.StandardButton.Ok)
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    box.button(QMessageBox.StandardButton.Ok).setText(first)
    box.button(QMessageBox.StandardButton.Cancel).setText("Отмена")
    if box.exec() != QMessageBox.StandardButton.Ok:
        return False
    check = QMessageBox(parent)
    check.setWindowTitle(title)
    check.setIcon(QMessageBox.Icon.Question)
    check.setText("Это окончательное решение?")
    check.setInformativeText(warning)
    check.setStandardButtons(QMessageBox.StandardButton.Cancel |
                             QMessageBox.StandardButton.Ok)
    check.setDefaultButton(QMessageBox.StandardButton.Cancel)
    check.button(QMessageBox.StandardButton.Ok).setText(second)
    check.button(QMessageBox.StandardButton.Cancel).setText("Отмена")
    return check.exec() == QMessageBox.StandardButton.Ok


def inform(parent: Optional[QWidget], title: str, text: str) -> None:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setIcon(QMessageBox.Icon.Information)
    box.setText(text)
    box.exec()
