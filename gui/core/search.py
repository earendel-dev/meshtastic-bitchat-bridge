"""Search for a radio and a phone without blocking the window.

Scanning takes seconds (a Wi-Fi sweep, a Bluetooth pass, a probe of every
advertiser that looks like Bitchat), so it runs in its own thread and reports
back through a Qt signal.  The searches themselves are the engine's own
functions, so the window accepts exactly what the console accepts.

What is searched:

* radio — the same four ways as the console menu: Wi-Fi, Bluetooth, USB and
  an address typed by hand;
* chat — after the radio answers: its channels, or a direct chat with one
  node from its node database;
* phone — ``scan_bitchat_peers``, which keeps only devices that answer a
  Bitchat announce.  The confirmation of the chosen phone is a separate
  step (two dialogs), never part of the search.
"""

from __future__ import annotations

import contextlib
from typing import Callable, List, Optional

from PySide6.QtCore import QObject, QThread, Signal

import bridge


class Finder(QObject):
    """Runs one search function on a thread and keeps its result.

    The real finder is :class:`DeviceSearch`; the self-test uses a helper
    that returns canned lists, so the window's flow is checked without a
    radio or a phone.

    The signals live here, not in the real class, so that the window can
    wire a fake searcher exactly the way it wires the real one.
    """

    radios = Signal(list)                # found radios
    radios_failed = Signal(str)          # nothing there / no Bluetooth
    phones = Signal(list)                # identified Bitchat phones
    chats = Signal(list, list)           # channels, nodes of a radio
    failed = Signal(str)                 # any search ended with an error

    # ------------------------------------------------------------- calling
    def find_radios(self, kind: str) -> None:
        raise NotImplementedError

    def find_phones(self, seconds: float) -> None:
        raise NotImplementedError

    def find_chats(self, transport: Optional[dict]) -> None:
        raise NotImplementedError

    def wait_idle(self, timeout_ms: int = 0) -> bool:
        """Block until every search ended; a fake one is always idle."""
        return True

    def shutdown(self) -> None:
        """Stop whatever is running (a fake one has nothing to stop)."""


class _Job(QObject):
    """One search on one thread; the thread cleans itself up."""

    done = Signal(object)

    def __init__(self, fn: Callable[[], object], parent: Optional[QObject] = None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001
            result = ("error", str(exc))
        self.done.emit(result)


class DeviceSearch(Finder):
    """The real searches, each on its own thread."""

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._threads: List[QThread] = []
        self._jobs: List[_Job] = []

    # ------------------------------------------------------------- plumbing
    def _run(self, fn: Callable[[], object], on_done: Callable[[object], None],
             on_error: Optional[Callable[[str], None]] = None) -> None:
        # One search at a time: Windows BLE is not reliable from two threads,
        # and two results arriving at once would fight over the same list.
        self.wait_idle(60000)
        thread = QThread(self)
        job = _Job(fn)
        job.moveToThread(thread)
        self._threads.append(thread)

        def finished(result: object) -> None:
            if on_error is not None and isinstance(result, tuple) and \
                    len(result) == 2 and result[0] == "error":
                on_error(str(result[1]))
            else:
                on_done(result)

        def cleanup() -> None:
            thread.quit()
            thread.wait(2000)
            if thread in self._threads:
                self._threads.remove(thread)
            if job in self._jobs:
                self._jobs.remove(job)

        job.done.connect(finished)
        job.done.connect(lambda _r: cleanup())
        thread.started.connect(job.run)
        thread.start()
        # Python must keep the job alive: the thread itself holds no
        # reference to it, only the signal connection does.
        self._jobs.append(job)

    def wait_idle(self, timeout_ms: int = 30000) -> bool:
        """Block until every search thread ended (used by the self-test)."""
        for thread in list(self._threads):
            if not thread.wait(timeout_ms):
                return False
        return True

    def shutdown(self) -> None:
        """Ask every running search to finish before the window goes away."""
        for thread in list(self._threads):
            thread.quit()
        for thread in list(self._threads):
            thread.wait(2000)
        self._threads.clear()

    @property
    def busy(self) -> bool:
        return any(thread.isRunning() for thread in self._threads)

    # -------------------------------------------------------------- radios
    def find_radios(self, kind: str) -> None:
        """``wifi``, ``ble``, ``serial`` — the console's first three items."""
        if kind == "wifi":
            fn = bridge.scan_wifi_devices_quiet
            empty = "Meshtastic в этой сети не найден."
        elif kind == "ble":
            fn = lambda: bridge.scan_ble_devices(8.0, quiet=True)  # noqa: E731
            empty = "Meshtastic по Bluetooth не найден."
        elif kind == "serial":
            fn = lambda: bridge.scan_serial_devices(quiet=True)  # noqa: E731
            empty = "COM-портов не найдено."
        else:
            self.radios_failed.emit(f"неизвестный способ поиска: {kind}")
            return

        def done(found: object) -> None:
            items = list(found or [])
            if items:
                self.radios.emit(items)
            else:
                self.radios_failed.emit(empty)

        self._run(fn, done,
                  lambda text: self.radios_failed.emit(
                      f"Поиск не удался: {text}"))

    def probe(self, transport: dict) -> None:
        """Check a typed address before the window offers it."""
        def fn() -> object:
            kind = transport.get("kind")
            if kind == "tcp":
                from meshtastic.tcp_interface import TCPInterface
                iface = TCPInterface(transport["target"], connectNow=True,
                                     timeout=8)
                iface.close()
            elif kind == "serial":
                from meshtastic.serial_interface import SerialInterface
                iface = SerialInterface(transport["target"], connectNow=True,
                                        timeout=8)
                iface.close()
            else:
                from meshtastic.ble_interface import BLEInterface
                iface = BLEInterface(transport["target"], timeout=15)
                iface.close()
            return [dict(transport)]

        self._run(fn, lambda found: self.radios.emit(list(found)),
                  lambda text: self.radios_failed.emit(
                      f"Устройство не ответило: {text}"))

    # -------------------------------------------------------------- phones
    def find_phones(self, seconds: float) -> None:
        self._run(lambda: bridge.scan_bitchat_peers(seconds),
                  lambda found: self.phones.emit(list(found or [])),
                  lambda text: self.failed.emit(f"Поиск телефонов: {text}"))

    # -------------------------------------------------------------- chains
    def find_chats(self, transport: Optional[dict]) -> None:
        """Connect once to the radio and read its channels and node list.

        Same question as the console asks after a radio is chosen.  The
        connection is opened directly here, so it fails fast when the radio
        is unreachable instead of retrying in the background the way the
        bridge itself does.
        """
        def fn() -> object:
            import asyncio
            handler = bridge.MeshtasticHandler(asyncio.new_event_loop(),
                                               transport)
            try:
                if not handler._try_connect():
                    raise RuntimeError("радио не ответило")
                return bridge.list_chat_entries(handler), \
                    bridge.list_nodes(handler)
            finally:
                with contextlib.suppress(Exception):
                    handler.stop()

        self._run(fn, lambda result: self.chats.emit(*result),
                  lambda text: self.failed.emit(f"Список чатов: {text}"))
