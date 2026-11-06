"""Events the bridge reports to a user interface.

The engine never calls into Qt directly.  Everything observable is delivered
as one of these events, so the core keeps working with no GUI installed and a
test can drive the user interface with plain objects.

Rules kept from the engine itself (see DEVELOPMENT.md):

* no message text is ever carried in an event — only counts, names and kinds;
* no peer key or address is part of an event unless the owner opened the
  panel that needs it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple


class Level(str, Enum):
    INFO = "info"
    OK = "ok"
    WARN = "warn"
    ERROR = "error"


@dataclass(frozen=True)
class LogEvent:
    """One line for the activity panel."""

    text: str
    level: Level = Level.INFO


@dataclass(frozen=True)
class MessageCountsEvent:
    """How many messages are waiting / delivered on each side.

    Only numbers: the text of a message never leaves the sealed buffer.
    """

    lora_to_bitchat: int = 0      # not yet delivered to the phone
    bitchat_to_lora: int = 0      # buffered, may still go to LoRa
    bitchat_blocked: int = 0      # buffered but the mode refuses the author
    lora_queue: int = 0           # waiting in the rate-limited LoRa queue


@dataclass(frozen=True)
class ForwardedEvent:
    """Something was actually handed over to the other side.

    ``direction`` is ``"to_lora"`` or ``"to_bitchat"``.  ``author`` is the
    display name the engine already shows, never the text.
    """

    direction: str
    count: int = 1
    author: str = ""
    kind: str = ""                # e.g. "сообщение", "синхронизация"


@dataclass(frozen=True)
class LinkEvent:
    """State of one link.  ``name`` is ``"radio"`` or ``"phone"``."""

    name: str
    connected: bool
    detail: str = ""


@dataclass(frozen=True)
class PeerEvent:
    """A Bitchat peer was seen (list for the source picker)."""

    peer_id: str
    label: str
    fingerprint: str = ""
    is_bound: bool = False


@dataclass(frozen=True)
class BindingEvent:
    """The phone binding changed."""

    bound: bool
    label: str = ""
    fingerprint: str = ""


@dataclass(frozen=True)
class ForwardModeEvent:
    """The Bitchat -> LoRa mode changed."""

    mode: str                     # bound | custom | all | replies
    name: str                     # one human line
    sources: Tuple[str, ...] = ()
    replied: Tuple[str, ...] = ()


@dataclass(frozen=True)
class FullSyncEvent:
    """Two-way sync was switched on or off."""

    enabled: bool


@dataclass(frozen=True)
class ScheduleEvent:
    """The periodic sync description changed."""

    description: str


@dataclass(frozen=True)
class ChatTargetEvent:
    """Which Meshtastic chat the bridge is bound to."""

    description: str


@dataclass(frozen=True)
class StateEvent:
    """A full snapshot, so the UI can redraw after a restart."""

    forward_mode: str = "bound"
    forward_name: str = ""
    full_sync: bool = False
    bound: bool = False
    bound_label: str = ""
    radio_connected: bool = False
    radio_detail: str = ""
    phone_connected: bool = False
    phone_detail: str = ""
    chat_target: str = ""
    schedule: str = ""
    counts: MessageCountsEvent = field(default_factory=MessageCountsEvent)
    sources: Tuple[str, ...] = ()
    replied: Tuple[str, ...] = ()
    peers: Tuple[PeerEvent, ...] = ()


Event = (LogEvent | MessageCountsEvent | ForwardedEvent | LinkEvent
         | PeerEvent | BindingEvent | ForwardModeEvent | FullSyncEvent
         | ScheduleEvent | ChatTargetEvent | StateEvent)
