"""Engine lifecycle: build the bridge in a worker thread and keep it alive.

Qt owns the main thread, so the bridge runs its own asyncio loop in a
``threading.Thread``.  Everything the GUI asks the engine is posted to that
loop; everything the engine reports comes back as an event, which the
session re-publishes through a Qt signal (safe across threads).

The GUI never contains forwarding rules: the very same handlers the console
builds are created here, with the same constructor arguments as
``bridge.run``.  If the console and the GUI ever disagree, that is a bug in
one place, not two.

How the GUI touches the engine (and nothing else):

* calls — ``BitchatBLEHandler.set_forward_mode_gui`` /
  ``reset_binding_gui`` (both posted onto the engine loop), the resend
  coroutines, ``full_sync``, ``bitchat_sources``, ``bitchat_replied``;
* reads — ``BitchatBLEHandler.get_stats()``, which is written to be called
  from another thread, and two queues owned by the handler.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass
from typing import Optional

from PySide6.QtCore import QObject, Signal

import bridge
from . import events as ev

log = logging.getLogger("gui.session")

# How often the engine thread reports that it is still alive.  The window
# turns "no tick for 5 s" into a visible stall, so this must stay well below.
TICK_SECONDS = 1.0


@dataclass
class EngineConfig:
    """Everything the engine needs to start; mirrors ``bridge.run``."""

    transport: Optional[dict] = None
    name: str = "Bridge"
    scan_seconds: float = 8.0
    channel: int = 0
    chat_target: Optional[dict] = None
    history_limit: int = 100
    lora_send_interval: float = 10.0
    lora_stale_seconds: float = 1800.0
    bitchat_target: Optional[str] = None
    full_sync: bool = False
    bitchat_peer: Optional[str] = None
    forward_mode: str = "bound"
    config_path: Optional[str] = None
    # The window chooses the devices before any engine exists: the radio and
    # the confirmed phone are handed in here and the engine starts bound to
    # them, exactly as the console menu does before calling ``bridge.run``.
    ready: bool = False
    label: str = ""
    # The signature the phone published in its announce, so the binding check
    # starts with the key instead of learning it on the first packet.
    bitchat_key: Optional[bytes] = None
    bitchat_nickname: str = ""
    bitchat_fingerprint: str = ""


class BridgeSession(QObject):
    """Own the engine thread and expose its state to the window."""

    event = Signal(object)          # one of gui.core.events.Event
    started = Signal()
    stopped = Signal(str)           # reason, empty when it was a clean stop
    heartbeat = Signal(float)       # seconds between two engine ticks

    def __init__(self, cfg: EngineConfig, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.cfg = cfg
        self.ble: Optional["bridge.BitchatBLEHandler"] = None
        self.mesh: Optional["bridge.MeshtasticHandler"] = None
        self.scheduler: Optional["bridge.SyncScheduler"] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._stop: Optional[asyncio.Event] = None
        self._ready = threading.Event()
        self._error = ""
        self._last_tick = time.monotonic()
        self._last_forward_count = 0
        self._last_last_tx = 0.0

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._ready.clear()
        self._error = ""
        self._last_tick = time.monotonic()
        self._thread = threading.Thread(target=self._run_engine,
                                        name="bridge-engine", daemon=True)
        self._thread.start()

    @property
    def alive(self) -> bool:
        """True while the engine thread runs."""
        return bool(self._thread and self._thread.is_alive())

    def _run_engine(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop
        try:
            loop.run_until_complete(self._main())
        except Exception as exc:  # noqa: BLE001
            log.exception("engine stopped with an error")
            self._error = str(exc)
            self.event.emit(ev.LogEvent(
                f"Мост остановлен из-за ошибки: {exc}", ev.Level.ERROR))
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                loop.close()
                self._ready.set()
                self.stopped.emit(self._error)

    async def _main(self) -> None:
        cfg = self.cfg
        # The same hardening the console path applies before any message can
        # arrive (best effort, never stops the bridge).
        await asyncio.to_thread(bridge._keep_dumps_off_memory)
        await asyncio.to_thread(bridge._deny_debug)
        await asyncio.to_thread(bridge._lock_process_memory)

        ble = bridge.BitchatBLEHandler(
            asyncio.get_running_loop(), cfg.name, cfg.scan_seconds,
            cfg.history_limit, target_address=cfg.bitchat_target,
            full_sync=cfg.full_sync, target_peer=cfg.bitchat_peer)
        mesh = bridge.MeshtasticHandler(
            asyncio.get_running_loop(), cfg.transport,
            default_channel=cfg.channel,
            lora_send_interval=cfg.lora_send_interval,
            history_limit=cfg.history_limit,
            lora_stale_seconds=cfg.lora_stale_seconds)
        mesh.set_chat_target(cfg.chat_target or {"kind": "all"})
        ble.set_meshtastic_handler(mesh)
        mesh.set_ble_handler(ble)
        mode = cfg.forward_mode
        if mode not in ("bound", "all"):
            # custom/replies hold a list that is never stored: start strict.
            mode = "bound"
        ble.set_forward_mode(mode)
        self.ble, self.mesh = ble, mesh
        self.scheduler = bridge.SyncScheduler()
        self._stop = asyncio.Event()
        self._last_tick = time.monotonic()
        if cfg.ready:
            # The window already found the radio and confirmed the phone, so
            # binding happens here: the scanner only accepts that peer and
            # never asks anything (no console to ask).
            if cfg.bitchat_peer:
                ble.bind_peer(cfg.bitchat_peer, cfg.bitchat_nickname,
                              cfg.bitchat_fingerprint, cfg.bitchat_key)
        self._ready.set()
        self.started.emit()

        await asyncio.to_thread(mesh.start)
        self.event.emit(ev.LinkEvent(
            "radio", mesh.interface is not None, mesh.describe_target()))
        self.event.emit(ev.ChatTargetEvent(mesh.describe_target()))
        if cfg.ready and mesh.interface is not None:            self.event.emit(ev.LogEvent(
                f"Радио на связи: {mesh.describe_target()}", ev.Level.OK))
        elif cfg.ready:
            self.event.emit(ev.LogEvent(
                "Радио не ответило: мост пробует снова в фоне.",
                ev.Level.WARN))

        tasks = [
            asyncio.create_task(ble.scanner()),
            asyncio.create_task(ble.announce_loop()),
            asyncio.create_task(ble.maintenance_loop()),
            asyncio.create_task(mesh.text_flush_loop()),
            asyncio.create_task(bridge.log_truncate_loop()),
            asyncio.create_task(self._ticker()),
            asyncio.create_task(self._periodic_sync()),
        ]
        try:
            await self._stop.wait()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await _quiet(asyncio.to_thread(mesh.stop), "radio stop")
            await _quiet(ble.stop(), "phone stop")

    async def _ticker(self) -> None:
        """One tick a second: liveness, both links, counters, the phone."""
        while True:
            await asyncio.sleep(TICK_SECONDS)
            ble, mesh = self.ble, self.mesh
            if ble is None or mesh is None:
                continue
            now = time.monotonic()
            gap = now - self._last_tick
            self._last_tick = now
            self.heartbeat.emit(gap)
            self.event.emit(self.counts_event())
            self.event.emit(_binding_event(ble))
            self.event.emit(ev.LinkEvent(
                "radio", mesh.interface is not None, mesh.describe_target()))
            self.event.emit(ev.LinkEvent(
                "phone", bool(ble.connected), ", ".join(sorted(ble.connected))))
            self._emit_new_forwardings(ble)

    def _emit_new_forwardings(self, ble) -> None:
        """Turn the handler's forwarding counter into one activity event.

        The handler bumps its counter every time a message really goes out
        from Bitchat to LoRa; comparing with the last value read tells the
        window "something moved" without asking the engine for history.
        """
        stats = ble.get_stats()
        sent = int(stats.get("_sent") or 0)
        if sent > self._last_forward_count:
            delta = sent - self._last_forward_count
            latest = stats.get("_latest") or {}
            author = latest.get("author", "") if isinstance(latest, dict) else ""
            self.event.emit(ev.ForwardedEvent("to_lora", delta, author or "",
                                              "сообщение"))
        self._last_forward_count = sent

    def counts_event(self) -> ev.MessageCountsEvent:
        ble, mesh = self.ble, self.mesh
        if ble is None or mesh is None:
            return ev.MessageCountsEvent()
        stats = ble.get_stats()
        undelivered = sum(1 for entry in list(mesh.history_lora)
                          if not entry.get("delivered"))
        return ev.MessageCountsEvent(
            lora_to_bitchat=undelivered,
            bitchat_to_lora=stats["queued_to_lora"],
            bitchat_blocked=stats["blocked"],
            lora_queue=len(mesh.pending_texts),
        )

    async def _periodic_sync(self) -> None:
        """Guard the schedule: the repeat only lives while full sync is on."""
        while True:
            await asyncio.sleep(5.0)
            ble = self.ble
            if ble is None or ble.full_sync or self.scheduler is None:
                continue
            if self.scheduler.jobs:
                self.scheduler.clear()
                self.event.emit(ev.ScheduleEvent(self.scheduler.describe()))
                self.event.emit(ev.LogEvent(
                    "Полная синхронизация выключена: повтор по расписанию "
                    "остановлен.", ev.Level.WARN))

    # ------------------------------------------------------------- controls
    def call(self, fn, *args, **kwargs):
        """Run ``fn`` on the engine loop and return a concurrent future."""
        if not self.loop or not self.loop.is_running():
            raise RuntimeError("мост ещё не запущен")
        return asyncio.run_coroutine_threadsafe(
            _maybe_await(fn, *args, **kwargs), self.loop)

    def request_stop(self) -> None:
        if self.loop and self._stop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self._stop.set)

    def shutdown(self, timeout: float = 12.0) -> bool:
        """Stop the engine and wait for its thread (buffers die with it)."""
        self.request_stop()
        if self._thread:
            self._thread.join(timeout)
        return not (self._thread and self._thread.is_alive())

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def wait_ready(self, timeout: float = 15.0) -> bool:
        """Block until the handlers exist (used by the self-test)."""
        return self._ready.wait(timeout) and self.ble is not None

    def last_tick_age(self) -> float:
        return time.monotonic() - self._last_tick


async def _maybe_await(fn, *args, **kwargs):
    result = fn(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return await result
    return result


async def _quiet(awaitable, what: str) -> None:
    """Shutdown steps must not keep the thread alive on an error.

    A cancelled step is expected here: the engine is going down.
    """
    try:
        await awaitable
    except BaseException as exc:  # noqa: BLE001
        log.debug("stops: %s — %r", what, exc)


def _binding_event(ble) -> ev.BindingEvent:
    peer = ble.bound_peer
    if not peer:
        return ev.BindingEvent(False, "", "")
    label = ble.peer_nicknames.get(peer, "") or "@" + peer[:4]
    return ev.BindingEvent(True, label, ble.peer_fingerprints.get(peer, ""))
