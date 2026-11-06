"""Smoke check of the frozen build: ``gui_boot.exe --self-check``.

The windowed build has no console, so a failure to import leaves nothing
but a stack trace in a dialog.  This mode imports the real bridge, builds
the window offscreen and reports what it found on stdout and in the exit
code; the self-test runs it with a log file to read.
"""

from __future__ import annotations

import os
import sys


def self_check() -> int:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    lines = []
    try:
        import bridge
        lines.append("bridge ok")
        from gui.core.session import EngineConfig
        from gui.main import window_for_ui_test
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(sys.argv[:1])
        cfg = EngineConfig(transport={"kind": "tcp", "target": "127.0.0.1:1"})
        window = window_for_ui_test(cfg)
        window.show()
        app.processEvents()
        lines.append(f"window ok: {window.tabs.count()} tabs")
        window.close()
        lines.append("SELF-CHECK PASSED")
        code = 0
    except BaseException as exc:  # noqa: BLE001
        import traceback
        lines.append(traceback.format_exc())
        lines.append(f"SELF-CHECK FAILED: {type(exc).__name__}: {exc}")
        code = 1
    print("\n".join(lines), flush=True)
    return code


if __name__ == "__main__":
    if "--self-check" in sys.argv[1:]:
        raise SystemExit(self_check())
    from gui.main import main

    raise SystemExit(main(sys.argv[1:]))
