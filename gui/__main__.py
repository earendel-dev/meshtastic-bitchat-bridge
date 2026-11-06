"""Запуск окна: ``python -m gui`` из корня проекта.

Отдельный модуль, потому что ``python -m gui`` ищет ``gui/__main__.py``.
"""

from __future__ import annotations

from .main import main

if __name__ == "__main__":
    raise SystemExit(main())
