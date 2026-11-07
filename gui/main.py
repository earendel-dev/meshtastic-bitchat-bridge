"""Entry points of the Qt 6 front end.

    python -m gui            запуск, как у консоли, но с настройками из config
    python -m gui --connect  сразу подключиться по конфигу без лишних меню

The window and the console share one engine (``bridge.py``): the GUI only
starts it, steers it through the documented hooks and shows what it does.
"""

from __future__ import annotations

import sys
from typing import List, Optional

from PySide6.QtWidgets import QApplication

import bridge
from .core.session import EngineConfig
from .window import MainWindow

APP_TITLE = "Мост Meshtastic ↔ Bitchat"


def _config_from_file(path: str) -> dict:
    try:
        return bridge.load_config(path)
    except Exception:  # noqa: BLE001
        return dict(getattr(bridge, "DEFAULT_CONFIG", {}))


def build_config(argv: Optional[List[str]] = None) -> EngineConfig:
    """Read ``config.json`` and the usual command line flags.

    The device menu now lives in the window: when the config names no radio
    and no flag was given, the config is still returned but nothing starts
    until the owner picks a radio on the «Устройства» page — the same rule
    as the console, which shows its menu unless ``--no-menu`` is passed.
    """
    args = bridge.parse_args(list(argv if argv is not None else sys.argv[1:]))
    cfg_file = _config_from_file(getattr(args, "config",
                                         "config.json") or "config.json")
    transport = bridge.transport_from_config(cfg_file)
    host = getattr(args, "host", None)
    port = getattr(args, "port", None)
    ble_address = getattr(args, "ble_address", None)
    if host:
        transport = {"kind": "tcp", "target": host}
    elif port:
        transport = {"kind": "serial", "target": port}
    elif ble_address:
        transport = {"kind": "ble", "target": ble_address}

    chat = getattr(args, "chat", None)
    chat_target = bridge.parse_chat(chat) if chat else \
        bridge.chat_from_config(cfg_file)
    channel = int(chat_target.get("index", 0)) \
        if chat_target.get("kind") == "channel" else \
        int(cfg_file.get("meshtastic_channel", 0) or 0)

    forward = str(getattr(args, "bitchat_forward", None) or
                  cfg_file.get("bitchat_forward") or "bound").lower()
    if forward not in ("bound", "custom", "all", "replies"):
        forward = "bound"

    return EngineConfig(
        transport=transport,
        name=getattr(args, "name", None) or
        str(cfg_file.get("name") or "Bridge"),
        scan_seconds=float(cfg_file.get("ble_scan_seconds", 8.0) or 8.0),
        channel=channel,
        chat_target=chat_target,
        history_limit=int(cfg_file.get("history_limit", 100) or 100),
        lora_send_interval=float(cfg_file.get("lora_send_interval", 10.0)),
        lora_stale_seconds=float(cfg_file.get("lora_stale_seconds", 1800.0)),
        bitchat_target=cfg_file.get("bitchat_target") or None,
        full_sync=bool(cfg_file.get("full_sync", False)),
        forward_mode=forward,
        config_path=getattr(args, "config", None),
    )


def window_for_ui_test(cfg: EngineConfig, finder=None) -> MainWindow:
    """The real window that never touches a radio or a phone.

    Used by the UI checks: real widgets, real event plumbing, no engine and
    no real search (``finder`` replaces the searcher when one is given).
    """
    return MainWindow(cfg, autostart=False, finder=finder)


def wanted_menu(argv: Optional[List[str]] = None) -> bool:
    """True when the console would open its device menu.

    ``--menu`` asks for it, ``--no-menu`` refuses it; otherwise the menu is
    shown when no radio was given on the command line (the same condition
    ``bridge.main`` uses, minus the console-only ``isatty`` check).
    """
    args = bridge.parse_args(list(argv if argv is not None else sys.argv[1:]))
    if getattr(args, "menu", False):
        return True
    if getattr(args, "no_menu", False):
        return False
    return not (args.host or args.port or args.ble_address)


def main(argv: Optional[List[str]] = None) -> int:
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_TITLE)
    cfg = build_config(argv)
    if wanted_menu(argv):
        # Like the console: nothing starts until a radio is chosen.  The
        # phone may be confirmed before or after the start.
        window = MainWindow(cfg, autostart=False)
        window.tabs.setCurrentIndex(0)
    else:
        window = MainWindow(cfg, autostart=True)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
