"""What a page may ask the engine to do, and the live view it gets back.

The window owns one ``EngineSession``; a page holds it as ``self.session``
and only calls the methods below.  When the bridge is restarted the window
builds a new ``EngineSession`` and hands it to every page — a page never
touches the thread, the loop or the BLE stack itself.

Privacy: nothing here returns message text.  Buffers appear as counts, the
phone as its chosen name, the key as a fingerprint.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from PySide6.QtCore import QObject, Signal

import bridge
from ..core import events as ev
from ..core.session import BridgeSession

MODES = ("bound", "custom", "all", "replies")


class EngineSession(QObject):
    """Actions + live state for the pages."""

    changed = Signal(object)        # one of gui.core.events.Event
    heartbeat = Signal(float)       # seconds since the previous engine tick

    def __init__(self, session: BridgeSession, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.session = session
        self._private_confirmed = False
        session.event.connect(self.changed)
        session.heartbeat.connect(self.heartbeat)

    # ------------------------------------------------------------ helpers
    def _emit(self, event: ev.Event) -> None:
        self.changed.emit(event)

    def log(self, text: str, level: ev.Level = ev.Level.INFO) -> None:
        self._emit(ev.LogEvent(text, level))

    @property
    def ready(self) -> bool:
        return self.session.ble is not None and self.session.mesh is not None

    def _guard(self, action):
        """Run one engine call; a handler that dies must not take the
        window's slot down with it (the error is logged, not raised)."""
        if not self.ready:
            return None
        try:
            return action()
        except Exception as exc:  # noqa: BLE001
            self.log(f"Действие не выполнено: {exc}", ev.Level.ERROR)
            return None

    def _calm_emit(self, event: ev.Event) -> None:
        """Emit an event that handler threads also trigger.

        The engine thread may publish an event while the window is closing;
        a raise here would end that thread, so the emit is guarded too.
        """
        try:
            self._emit(event)
        except RuntimeError:
            pass

    @property
    def alive(self) -> bool:
        return self.session.alive

    def _submit(self, fn, *args):
        return self.session.call(fn, *args)

    # ------------------------------------------------------------- state
    def snapshot(self) -> Optional[ev.StateEvent]:
        """The current state, or ``None`` while the engine is not up."""
        if not self.ready:
            return None
        ble, mesh = self.session.ble, self.session.mesh
        stats = ble.get_stats()
        return ev.StateEvent(
            forward_mode=stats["forward_mode"],
            forward_name=stats["forward_name"],
            full_sync=stats["full_sync"],
            bound=stats["bound"],
            bound_label=stats["bound_label"],
            radio_connected=mesh.interface is not None,
            radio_detail=mesh.describe_target() if mesh.interface else "",
            phone_connected=bool(stats["connected"]),
            phone_detail=", ".join(stats["connected"]),
            chat_target=mesh.describe_target(),
            schedule=(self.session.scheduler.describe()
                      if self.session.scheduler else ""),
            counts=self.counts(stats),
            sources=tuple(stats["sources"]),
            replied=tuple(stats["replied"]),
        )

    def counts(self, stats: Optional[dict] = None) -> ev.MessageCountsEvent:
        if not self.ready:
            return ev.MessageCountsEvent()
        stats = stats if stats is not None else self.session.ble.get_stats()
        mesh = self.session.mesh
        undelivered = sum(1 for entry in list(mesh.history_lora)
                          if not entry.get("delivered"))
        return ev.MessageCountsEvent(
            lora_to_bitchat=undelivered,
            bitchat_to_lora=stats["queued_to_lora"],
            bitchat_blocked=stats["blocked"],
            lora_queue=len(mesh.pending_texts),
        )

    def stats(self) -> dict:
        if not self.ready:
            return {}
        return self.session.ble.get_stats()

    def peers(self) -> List[ev.PeerEvent]:
        if not self.ready:
            return []
        return [ev.PeerEvent(peer_id=item["id"], label=item["label"],
                             fingerprint=item["fingerprint"],
                             is_bound=item["bound"])
                for item in self.session.ble.get_stats()["peers"]]

    # --------------------------------------------------------- forward mode
    def set_forward_mode(self, mode: str, sources=None,
                         confirmed: bool = False) -> bool:
        """Switch what may leave for LoRa.

        ``custom``/``all``/``replies`` widen the rule and need
        ``confirmed=True``; the window shows the warning and asks twice, so
        this flag means "the owner really said so".
        """
        if not self.ready:
            return False
        if mode not in MODES:
            return False
        if mode != "bound" and not confirmed:
            return False
        chosen = set(sources or ())
        if mode == "custom":
            chosen.discard(self.session.ble.bound_peer or "")
            if not chosen:
                return False
        try:
            accepted = self.session.ble.set_forward_mode_gui(
                mode, chosen if mode == "custom" else None)
        except Exception as exc:  # noqa: BLE001
            self.log(f"Режим не изменён: {exc}", ev.Level.ERROR)
            return False
        if not accepted:
            return False
        self._emit_mode()
        return True

    def mark_source(self, peer: str, add: bool = True) -> None:
        """Tick or untick one phone in the ``custom`` list."""
        if not self.ready or not peer or peer == self.session.ble.bound_peer:
            return
        if add:
            self.session.ble.bitchat_sources.add(peer)
        else:
            self.session.ble.bitchat_sources.discard(peer)
        self._emit_mode()

    def _emit_mode(self) -> None:
        stats = self.stats()
        self._emit(ev.ForwardModeEvent(
            mode=stats["forward_mode"], name=stats["forward_name"],
            sources=tuple(stats["sources"]), replied=tuple(stats["replied"])))

    # ----------------------------------------------------------- full sync
    def set_full_sync(self, enabled: bool, confirmed: bool = False) -> bool:
        """Two-way sync.  Enabling needs the private-channel confirmation."""
        if not self.ready:
            return False
        ble = self.session.ble
        if not enabled:
            ble.full_sync = False
            self._calm_emit(ev.FullSyncEvent(False))
            self.log("Полная синхронизация выключена: новые сообщения снова "
                     "ждут ручной отправки.")
            return True
        if not (confirmed or self._private_confirmed):
            return False
        self._private_confirmed = True
        try:
            asyncio.run_coroutine_threadsafe(self._enable_full_sync(),
                                             self.session.loop)
        except RuntimeError as exc:
            self.log(f"Мост ещё не запущен: {exc}", ev.Level.ERROR)
            return False
        return True

    async def _enable_full_sync(self) -> None:
        ble, mesh = self.session.ble, self.session.mesh
        ble.full_sync = True
        self._calm_emit(ev.FullSyncEvent(True))
        if ble.connected:
            asyncio.ensure_future(ble.flush_undelivered())
        queued = 0
        skipped = 0
        for entry in list(ble.history_bitchat):
            if entry.get("sent_lora") or entry.get("queued_lora"):
                continue
            if not ble.may_forward(entry.get("peer")):
                skipped += 1
                continue
            if mesh.send_history_entry(entry):
                queued += 1
        msg = ("Полная синхронизация включена: новое сообщение сразу уходит "
               "на другую сторону.")
        if queued:
            msg += f" В очередь LoRa поставлено: {queued}."
        if skipped:
            msg += f" Пропущено по режиму: {skipped}."
        self.log(msg, ev.Level.OK)

    # ---------------------------------------------------------------- sync
    def sync_to_lora(self, count: int) -> None:
        self._run(self.session.ble.resend_bitchat, (count, False),
                  "В очередь LoRa", "to_lora")

    def sync_to_bitchat(self, count: int) -> None:
        self._run(self.session.ble.resend_lora, (count, False),
                  "На телефон", "to_bitchat")

    def _run(self, coro_fn, args: tuple, what: str, direction: str) -> None:
        if not self.ready:
            self.log("Мост ещё не запущен.", ev.Level.WARN)
            return
        try:
            future = self._submit(coro_fn, *args)
        except RuntimeError as exc:
            self.log(str(exc), ev.Level.ERROR)
            return

        def done(fut) -> None:
            try:
                sent = fut.result()
            except Exception as exc:  # noqa: BLE001
                self.log(f"{what}: ошибка — {exc}", ev.Level.ERROR)
                return
            if sent:
                self.log(f"{what}: {sent}", ev.Level.OK)
                self._calm_emit(ev.ForwardedEvent(direction, int(sent), "",
                                                  "досылка"))
            else:
                self.log(f"{what}: нечего отправлять.")

        future.add_done_callback(done)

    def schedule(self, direction: str, count: int,
                 interval_seconds: float) -> str:
        """Add a repeating job.  Returns a reason to show, or ``""``."""
        if not self.ready or self.session.scheduler is None:
            return "мост ещё не запущен"
        if direction not in ("lora2bit", "bit2lora"):
            return "неизвестное направление"
        if interval_seconds < 60:
            return "период меньше минуты забьёт эфир"
        if not self.session.ble.full_sync:
            return ("повтор работает только при включённой полной "
                    "синхронизации")
        try:
            self.session.scheduler.add(direction, count, interval_seconds)
        except Exception as exc:  # noqa: BLE001
            return f"расписание не принято: {exc}"
        self._calm_emit(ev.ScheduleEvent(self.session.scheduler.describe()))
        return ""

    # ------------------------------------------------------------ binding
    def reset_binding(self) -> None:
        """Let the bound phone go; the scanner binds the next one."""
        if not self.ready:
            return
        try:
            self.session.loop.call_soon_threadsafe(
                self.session.ble.reset_binding_gui)
        except RuntimeError as exc:
            self.log(str(exc), ev.Level.ERROR)
            return
        self._calm_emit(ev.BindingEvent(False, "", ""))
        self.log("Привязка сброшена: мост ждёт следующий телефон с Bitchat. "
                 "Подтверждение потребуется заново.", ev.Level.WARN)

    # ---------------------------------------------------------------- exit
    def request_stop(self) -> None:
        self.session.request_stop()


def mode_warning(mode: str) -> str:
    """The same text the console prints before it widens the rule."""
    return {
        "custom": bridge.FORWARD_WARNING_CUSTOM,
        "replies": bridge.FORWARD_WARNING_REPLIES,
        "all": bridge.FORWARD_WARNING_ALL,
    }.get(mode, "")
