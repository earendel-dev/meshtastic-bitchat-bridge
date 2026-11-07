#!/usr/bin/env python3
"""
Meshtastic <-> Bitchat bridge (Windows-friendly) with an interactive menu.

Features
--------
* Interactive console menu: scan only the connected physical networks (TCP),
  Bluetooth LE or COM ports and pick one by number; a VPN does not slow the
  Wi-Fi scan because virtual adapters are skipped.
* Bitchat phones are discovered automatically over BLE and one phone is bound
  for the session after an explicit confirmation; packets are accepted only
  from that phone and only with a verified Ed25519 signature.
* Smart one-way automatic sync: new LoRa messages are delivered to the phone
  once, immediately.  Already delivered messages are never replayed on
  reconnect; the last N are kept for an explicit manual resend.
* Bitchat -> Meshtastic is intentionally manual: Bitchat messages are buffered
  and sent only from the runtime menu ("s"), choosing direction, count
  (5/10/20/50) and an optional repeat period.  LoRa sends are rate-limited so
  the air is not flooded with old messages.
* Quiet by default: no verbose logs; the log file is wiped every five minutes,
  after a link ends and on shutdown.

Based on https://github.com/GigaProjects/meshtastic-bitchat-bridge
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ctypes
import gc
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import zlib
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import nacl.bindings
import nacl.encoding
import nacl.signing

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

from pubsub import pub

try:  # optional, only for very old Bitchat clients
    import lz4.block  # type: ignore
except Exception:  # pragma: no cover
    lz4 = None  # type: ignore

APP_NAME = "mesh-bitchat-bridge"
# Pre-release numbering: 0.1.0-alpha.1 is the first downloadable build; the
# engineering number after '+' is bumped on every published file.
APP_VERSION = "0.1.0-alpha.1+2026.11.07"
VERSION = "0.1.0-alpha.1"

# --- Bitchat protocol (BitFoundation / MessageType.swift) ---
BITCHAT_SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"  # mainnet
BITCHAT_CHAR_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

# --- Bitchat link upkeep ---
# Bitchat and the Windows BLE stack drop idle links, so the bridge keeps the
# link warm and rebuilds it when the phone goes quiet.
KEEPALIVE_SECONDS = 15.0     # send a short announce this often
LINK_TIMEOUT = 90.0          # rebuild the link after this much silence

# --- Meshtastic BLE service ---
MESHTASTIC_BLE_SERVICE = "6ba1b218-15a8-461f-9fa8-5dcae273eafd"
MESHTASTIC_TCP_PORT = 4403
BROADCAST_NUM = 0xFFFFFFFF

PACKET_VERSION = 0x01
TYPE_ANNOUNCE = 0x01
TYPE_MESSAGE = 0x02
TYPE_FRAGMENT = 0x20

# Every other type the client defines.  They are dropped before their payload
# is decoded - several of them (group, noise, voice, file) carry ciphertext or
# binary data that would never become a LoRa message, so decoding them was
# pure waste.  Types not listed here are unknown and refused as well.
OTHER_PACKET_TYPES = frozenset({
    0x03,  # leave
    0x04,  # courier envelope
    0x05,  # request sync
    0x10,  # noise handshake
    0x11,  # noise encrypted (private chat)
    0x12,  # v2 link handshake
    0x1F,  # reserved, sits right below the fragment type
    0x21,  # request sync (extended)
    0x22,  # file transfer
    0x23,  # board post
    0x25,  # group message (ChaCha20-Poly1305)
    0x28,  # Nostr carrier
    0x29,  # voice
    0x2A,  # prekey bundle
    0x2C,  # prekey request
})
FORWARDABLE_PACKET_TYPES = frozenset({TYPE_ANNOUNCE, TYPE_MESSAGE,
                                      TYPE_FRAGMENT})

TTL = 0x07
FLAG_HAS_RECIPIENT = 0x01
FLAG_HAS_SIGNATURE = 0x02
FLAG_IS_COMPRESSED = 0x04

HEADER_SIZE_V1 = 14
SENDER_ID_SIZE = 8
RECIPIENT_ID_SIZE = 8
SIGNATURE_SIZE = 64
BROADCAST_ID = b"\xff" * 8

PAD_BLOCK_SIZES = (256, 512, 1024, 2048)
MAX_QUEUE = 500

# Address prefixes understood in Bitchat public messages:
#   "#2 привет"        -> Meshtastic channel index 2
#   "/c2 привет"       -> same
#   "/dm <node> привет" -> direct message to a node
RE_CHANNEL_TARGET = re.compile(
    r"^(?:#|/(?:ch|c|channel|канал))\s*(\d{1,2})\s+(.+)$", re.IGNORECASE | re.DOTALL
)
RE_DM_TARGET = re.compile(
    r"^/(?:dm|p|priv|лс)\s+(\S+)\s+(.+)$", re.IGNORECASE | re.DOTALL
)

# --- Bitchat identity helpers ---------------------------------------------
# A phone's Bitchat identity is sha256(noise_public)[:8].  Because the id is
# only a hash prefix, it can be copied into a packet by anyone, so it is never
# used alone as proof: every packet is checked against the sender's Ed25519
# signing key, which is published inside a self-signed announce.


def _packet_signed_blobs(data: bytes):
    """Return (signature, candidate signed blobs) for a Bitchat packet.

    The header is rebuilt the way the protocol signs it (TTL zero, signature
    flag cleared).  A few header variants are tried as well, because clients
    on different builds disagree about those two fields; accepting any of
    them still requires a valid Ed25519 signature over the exact bytes.
    """
    if len(data) < HEADER_SIZE_V1 + SENDER_ID_SIZE + SIGNATURE_SIZE:
        return None
    flags = data[11]
    if not (flags & FLAG_HAS_SIGNATURE):
        return None
    payload_len = struct.unpack(">H", data[12:14])[0]
    offset = HEADER_SIZE_V1 + SENDER_ID_SIZE
    if flags & FLAG_HAS_RECIPIENT:
        offset += RECIPIENT_ID_SIZE
    sig_start = offset + payload_len
    if sig_start + SIGNATURE_SIZE > len(data):
        return None
    signature = bytes(data[sig_start:sig_start + SIGNATURE_SIZE])

    blobs = []
    for ttl in (0x00, data[2]):
        for flag_value in (flags & ~FLAG_HAS_SIGNATURE, flags):
            header = bytearray(data[:sig_start])
            header[2] = ttl
            header[11] = flag_value
            unsigned = bytes(header)
            blobs.append(unsigned)
            for block in PAD_BLOCK_SIZES:
                need = block - len(unsigned)
                if 0 < need <= 255:
                    blobs.append(unsigned + bytes([need]) * need)
    return signature, blobs


def verify_packet_signature(data: bytes, signing_pub: bytes) -> bool:
    """True when this packet carries a valid signature from *signing_pub*."""
    if not signing_pub:
        return False
    parsed = _packet_signed_blobs(data)
    if not parsed or not signing_pub:
        return False
    signature, blobs = parsed
    try:
        key = nacl.signing.VerifyKey(signing_pub)
    except Exception:  # noqa: BLE001
        return False
    for blob in blobs:
        try:
            key.verify(blob, signature)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def parse_announce_fields(payload: bytes) -> dict:
    """Tag/value fields of an announce: 1 nickname, 2 noise key, 3 signing key."""
    fields: dict = {}
    offset = 0
    while offset + 2 <= len(payload):
        tag = payload[offset]
        length = payload[offset + 1]
        offset += 2
        if offset + length > len(payload):
            break
        fields[tag] = payload[offset:offset + length]
        offset += length
    return fields


def peer_fingerprint(signing_pub: bytes) -> str:
    """Short human-checkable fingerprint of a phone's signing key."""
    digest = hashlib.sha256(signing_pub).hexdigest()
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))


def _loop(name: str = "loop"):
    """A private event loop for a one-off connection.

    ``find_chats`` runs on its own thread and builds a handler the way
    ``bridge.run`` does.  Such a loop is created, used for one connection and
    closed; it is never closed again later (``asyncio.run`` on the same
    thread would otherwise shut down a loop that was closed here).
    """
    return asyncio.new_event_loop()

# --- Volatile message buffer ----------------------------------------------
# Messages that wait for delivery or a free radio slot are held in RAM only,
# encrypted with an ephemeral key generated at start-up.  Nothing reaches the
# disk: a memory dump or a swapped-out page does not reveal the text, and the
# key disappears with the process.
_BUFFER_KEY: Optional[bytes] = None


def _lock_process_memory() -> bool:
    """Ask Windows to keep this process out of the pagefile.

    The buffer is encrypted anyway, but a swapped-out page would still hand a
    copy of the process memory to anyone who can read pagefile.sys.  With the
    working set locked, the buffer never leaves RAM.  Failure is not fatal:
    the buffer stays encrypted either way.
    """
    if os.name != "nt":
        return False
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.SetProcessWorkingSetSize.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]
        k32.SetProcessWorkingSetSize.restype = ctypes.c_int
        k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        k32.VirtualLock.restype = ctypes.c_int
        ok = bool(k32.SetProcessWorkingSetSize(
            ctypes.c_void_p(-1), ctypes.c_size_t(-1), ctypes.c_size_t(-1)))
        if ok:
            # A small pin proves the privilege works; the real protection is
            # the working-set lock above.
            page = ctypes.create_string_buffer(4096)
            k32.VirtualLock(ctypes.cast(page, ctypes.c_void_p), 4096)
            del page
        return ok
    except Exception:  # noqa: BLE001
        return False


# --- Protection of the running process ------------------------------------
# Message text lives in this process only (encrypted) for the few seconds
# before it is delivered.  What is left to protect is that short window from
# a tool that copies memory out: a memory dump, a debugger, or a crash dump
# written by Windows itself.
#
#   * the crash-dump path (Windows Error Reporting) is switched off for the
#     interpreter, so a crash leaves no readable copy on disk;
#   * the access list of the process is narrowed so that only the user who
#     runs the bridge and administrators can read its memory.
#
# All of it is best effort and only touches this process on Windows: on any
# other system the functions return at once, and a failure (no rights, old
# version) leaves the process exactly as it was.  Nothing here touches the
# radio or the console.
#
# PROCESS_ALL_ACCESS without the two rights a memory dump needs.
_PROCESS_RIGHTS = 0x1F0F6F


def _keep_dumps_off_memory() -> bool:
    """Switch off local crash dumps for the Python executable.

    Windows Error Reporting can write a full copy of a crashing process to
    disk on its own.  This turns that behaviour off for the interpreter that
    runs the bridge, so even an unexpected crash leaves no file holding
    message text.

    The setting lives in HKLM and needs administrator rights; the bridge is
    normally started as a plain user, so the call fails and that is expected:
    the process-level protection next to it does not depend on it.
    """
    if os.name != "nt":
        return False
    try:
        import winreg  # noqa: PLC0415  (Windows only, imported on demand)

        # WER matches the image name, e.g. "python.exe".
        path = ("SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\"
                f"LocalDumps\\{os.path.basename(sys.executable)}")
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                winreg.KEY_SET_VALUE) as key:
            # DumpType 0 means "write no dump at all".
            winreg.SetValueEx(key, "DumpType", 0, winreg.REG_DWORD, 0)
        return True
    except Exception:  # noqa: BLE001
        return False


def _deny_debug() -> bool:
    """Make the running bridge refuse dumps and debuggers.

    One change, limited to this process: its access list keeps full control
    for the user who started the bridge and for administrators only.  Every
    other account loses the rights a dump needs (read memory, duplicate
    handles), and a limited account cannot open the process for memory
    access even when it runs a dump tool.  No deny entries are involved, so
    the bridge itself and its owner keep every right they had (stop, read
    status, close), and nothing changes outside this process.

    Best effort: the call is attempted once at start-up, a failure (old or
    unusual system) is ignored, and the bridge keeps running with its
    encrypted buffer as the main protection.
    """
    if os.name != "nt":
        return False
    try:
        return _restrict_process_readers()
    except Exception:  # noqa: BLE001
        return False


def _current_user_sid() -> Optional[str]:
    """The text form of the SID of the user running the bridge."""
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.LocalFree.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        advapi.OpenProcessToken.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        advapi.OpenProcessToken.restype = ctypes.c_int
        advapi.GetTokenInformation.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32)]
        advapi.GetTokenInformation.restype = ctypes.c_int
        advapi.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        advapi.ConvertSidToStringSidW.restype = ctypes.c_int

        token = ctypes.c_void_p()
        # TOKEN_QUERY is enough to read the user SID.
        if not advapi.OpenProcessToken(k32.GetCurrentProcess(), 0x0008,
                                       ctypes.byref(token)):
            return None
        try:
            need = ctypes.c_uint32()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(need))
            if not need.value:
                return None
            # TokenUser returns a TOKEN_USER whose first field is the SID.
            buf = ctypes.create_string_buffer(need.value)
            if not advapi.GetTokenInformation(token, 1, buf, need.value,
                                              ctypes.byref(need)):
                return None
            sid_ptr = ctypes.c_void_p.from_buffer(buf).value
            text = ctypes.c_wchar_p()
            if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(sid_ptr),
                                                 ctypes.byref(text)):
                return None
            value = text.value
            k32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
            return value
        finally:
            k32.CloseHandle(token)
    except Exception:  # noqa: BLE001
        return None


def _set_process_dacl(sddl: str) -> bool:
    """Apply *sddl* as the access list of the current process."""
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32)]
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = \
            ctypes.c_int
        ntdll.NtSetSecurityObject.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        ntdll.NtSetSecurityObject.restype = ctypes.c_uint32
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.LocalFree.argtypes = [ctypes.c_void_p]

        sd = ctypes.c_void_p()
        size = ctypes.c_uint32()
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(sd), ctypes.byref(size)):
            return False
        try:
            # Pseudo-handle -1 means "this process"; 0x4 asks for the DACL
            # only.  0 (STATUS_SUCCESS) means the list was applied.
            rc = ntdll.NtSetSecurityObject(ctypes.c_void_p(-1), 0x4, sd)
            return rc == 0
        finally:
            k32.LocalFree(sd)
    except Exception:  # noqa: BLE001
        return False


def _restrict_process_readers() -> bool:
    """Narrow the access list of the bridge process.

    Full control stays with the user who started the bridge (Windows gives
    it that anyway).  No deny entries are involved: they would make the
    process unreadable even for the user who has to stop it.
    """
    try:
        sid = _current_user_sid()
        if not sid:
            return False
        return _set_process_dacl(
            f"O:{sid}G:{sid}D:(A;;0x{_PROCESS_RIGHTS:X};;;{sid})")
    except Exception:  # noqa: BLE001
        return False


def _buffer_key() -> bytes:
    global _BUFFER_KEY
    if _BUFFER_KEY is None:
        _BUFFER_KEY = os.urandom(32)
    return _BUFFER_KEY


def seal_text(text: str) -> bytes:
    """Encrypt one message for the in-memory buffer (XChaCha20-Poly1305).

    A random nonce per message means two deliveries of the same text never
    look alike in memory.
    """
    nonce = os.urandom(24)
    box = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        text.encode("utf-8"), None, nonce, _buffer_key())
    return nonce + box


def open_text(blob: Optional[bytes]) -> str:
    """Decrypt a buffered message; an unreadable buffer yields ''."""
    if not blob:
        return ""
    try:
        nonce, box = blob[:24], blob[24:]
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            box, None, nonce, _buffer_key()).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def wipe_sensitive_memory() -> None:
    """Erase the buffer key and drop everything that holds message text.

    Called after every delivery and when the process stops, so a waiting
    message lives in the encrypted buffer only for the time it is needed.
    The next message gets a fresh key.  The key is zeroed where it lies
    before its reference is dropped, so a copy of the process memory taken
    afterwards finds no usable key next to the sealed bodies.
    """
    global _BUFFER_KEY
    if _BUFFER_KEY is not None:
        key = bytearray(_BUFFER_KEY)
        for index in range(len(key)):
            key[index] = 0
        del key
        _BUFFER_KEY = None
    gc.collect()


def collapse_duplicate_entries(history) -> int:
    """Drop text of sent entries that a newer entry repeats.

    After a message has been delivered it does not need to stay readable: if
    the same body is also waiting in the buffer (a resend, a repeated sync),
    the older copy is emptied so the text is held in one place only.
    """
    seen = set()
    removed = 0
    for entry in reversed(list(history)):
        blob = entry.get("sealed")
        if blob and blob in seen:
            entry["sealed"] = b""
            removed += 1
        elif blob:
            seen.add(blob)
    return removed


def pad_body(text: str, block: int = 128) -> bytes:
    """Pad a message so its length does not reveal its size.

    Every payload becomes exactly one block, whatever its real length (up to
    the block size), so a short "да" and a paragraph look identical on air.
    Longer messages are split into whole blocks.
    """
    raw = text.encode("utf-8")
    blocks = max(1, -(-len(raw) // block))
    return raw + b"\x00" * (blocks * block - len(raw))


log = logging.getLogger("bridge")


# --------------------------------------------------------------------------
# Config / logging
# --------------------------------------------------------------------------
DEFAULT_CONFIG = {
    # No hard-coded radio address: the address is only remembered after the
    # user picks one (see save_config) or passes --host/--port/--ble.
    "name": "MeshBridge",
    "chat": {"kind": "channel", "index": 0},
    "ble_scan_seconds": 3.0,
    "bitchat_target": "",
    # The bound phone is never written here: the binding is confirmed in the
    # console for one session only (see confirm_binding).
    "full_sync": False,
    # Which Bitchat senders may reach LoRa:
    #   "bound"  — only the bound phone (default, the strict mode);
    #   "custom" — the bound phone plus the peers picked in the console ("b");
    #   "all"    — anything that arrives on the phone link.
    # Only this MODE is remembered.  The peer ids for "custom" are never
    # stored: after a restart the bridge starts in "bound" and the list is
    # picked again, so an edited file cannot widen what leaves the radio.
    "bitchat_forward": "bound",
    "history_limit": 100,
    "lora_send_interval": 10.0,
    "lora_stale_seconds": 1800,
    "log_file": "bridge.log",
    "log_truncate_seconds": 300,
    "quiet": True,
    "menu": True,
}


def load_config(path: str) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cfg.update(json.load(fh))
        except Exception as exc:  # noqa: BLE001
            print(f"Не удалось прочитать {path}: {exc}")
    return cfg


def save_config(path: str, cfg: dict) -> None:
    """Remember the user's choices, including the radio they picked.

    The program itself ships with no address at all; the address appears in
    the config only after the user selects a device or passes one on the CLI.
    """
    if not path:
        return
    data = dict(DEFAULT_CONFIG)
    data.update({k: v for k, v in cfg.items() if k in DEFAULT_CONFIG})
    data["transport"] = cfg.get("transport", {})
    data["bitchat_target"] = cfg.get("bitchat_target", "")
    data["full_sync"] = bool(cfg.get("full_sync", False))
    mode = str(cfg.get("bitchat_forward") or "bound")
    data["bitchat_forward"] = mode if mode in ("bound", "custom", "all") \
        else "bound"
    data["chat"] = cfg.get("chat", DEFAULT_CONFIG["chat"])
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    except OSError as exc:
        print(f"Не удалось сохранить {path}: {exc}")


class TruncatingFileHandler(logging.FileHandler):
    """A file handler that forcibly empties the log every N seconds.

    The user asked for no log noise by default and for logs to be wiped after
    a link ends and roughly every five minutes.  Truncating on ``emit`` keeps
    the file tiny even if a warning is written right after a wipe.
    """

    def __init__(self, filename, truncate_interval: float = 300.0,
                 encoding: str = "utf-8") -> None:
        super().__init__(filename, mode="a", encoding=encoding)
        self.truncate_interval = max(30.0, float(truncate_interval))
        self._last_truncate = time.time()

    def truncate_now(self) -> None:
        self.acquire()
        try:
            if self.stream:
                self.stream.seek(0)
                self.stream.truncate(0)
                self.stream.flush()
        except Exception:  # noqa: BLE001
            pass
        finally:
            self.release()
        self._last_truncate = time.time()

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D401
        if time.time() - self._last_truncate >= self.truncate_interval:
            self.truncate_now()
        super().emit(record)


_LOG_HANDLERS: List[logging.Handler] = []
_LOG_TRUNCATE_INTERVAL = 300.0


def setup_logging(debug: bool, log_file: str, quiet: bool = True,
                  truncate_seconds: float = 300.0) -> None:
    """Set up console/file logging.

    By default the bridge is quiet: only warnings and errors are written.
    ``--debug`` turns on full diagnostics.  The log file is truncated on
    start-up and periodically by :class:`TruncatingFileHandler`.
    """
    global _LOG_TRUNCATE_INTERVAL
    _LOG_TRUNCATE_INTERVAL = max(30.0, float(truncate_seconds))
    _LOG_HANDLERS.clear()
    level = logging.DEBUG if debug else (logging.WARNING if quiet else logging.INFO)
    log.setLevel(level)
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    console.setLevel(level)
    root.addHandler(console)

    if log_file:
        try:
            fh = TruncatingFileHandler(log_file, truncate_seconds, encoding="utf-8")
            fh.setFormatter(fmt)
            fh.setLevel(level)
            root.addHandler(fh)
            fh.truncate_now()
            _LOG_HANDLERS.append(fh)
        except OSError as exc:
            log.warning("Log file disabled: %s", exc)

    for noisy in ("bleak", "meshtastic", "pubsub"):
        logging.getLogger(noisy).setLevel(logging.DEBUG if debug else logging.WARNING)


def truncate_logs() -> None:
    """Forcibly empty all bridge log files (called on link loss/stop)."""
    for handler in list(_LOG_HANDLERS):
        if isinstance(handler, TruncatingFileHandler):
            handler.truncate_now()


async def log_truncate_loop() -> None:
    """Wipe the log every N seconds even if nothing new was written."""
    while True:
        await asyncio.sleep(_LOG_TRUNCATE_INTERVAL)
        truncate_logs()


def say(text: str) -> None:
    """User-facing console output that stays visible in quiet mode."""
    try:
        print(text, flush=True)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------
# Discovery helpers (used by the menu)
# --------------------------------------------------------------------------
def local_ipv4() -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:  # noqa: BLE001
        return None
    finally:
        sock.close()


def local_ipv4_addresses() -> List[str]:
    """Return IPv4 addresses of networks that are actually connected."""
    return [net["ip"] for net in connected_networks()]


# Virtual/tunnel adapters that must not slow down the Wi-Fi search.  Their
# addresses can stay visible in psutil even when they are down, and a
# Meshtastic radio never lives on a VMware/VPN subnet.
_VIRTUAL_IFACE_HINTS = (
    "vmware", "vmnet", "virtualbox", "vbox", "hyper-v", "vethernet",
    "virtual", "docker", "wsl", "loopback", "openvpn", "tap-",
    "tap windows", "tap-windows", "wireguard", "tailscale", "zerotier",
    "hamachi", "radmin", "npcap", "bluetooth", "teredo", "isatap",
    "vpn", "tunnel",
)


def _is_virtual_iface(name: str, description: str = "") -> bool:
    """True for adapters that can never host a Meshtastic radio.

    The check looks at the adapter *name* and at the driver description
    Windows reports, because a VPN tunnel is often named by a bare code
    (the VPN's Wintun adapter is just "wwan99") while its description still
    says "Wintun Tunnel".  Without the description such an adapter stayed in
    the sweep and added a whole /24 of dead addresses to every search.
    """
    low = f"{name} {description}".lower()
    return any(hint in low for hint in _VIRTUAL_IFACE_HINTS)


def _iface_descriptions() -> dict:
    """Adapter name -> driver description (Windows only, best effort).

    psutil knows adapter names but not what driver backs them, so a tunnel
    with a code-like name is indistinguishable from a real NIC.  Windows
    itself reports the description ("Wintun Tunnel", "Intel(R) Wi-Fi", …),
    which is what lets the search recognise it.  A missing or unreadable
    answer is not an error: the caller simply keeps the name-only check.
    """
    if os.name != "nt":
        return {}
    # WMI is used instead of Get-NetAdapter: the console PowerShell starts
    # with is in the OEM code page, so adapter names written in Russian come
    # back as broken bytes and would never match psutil's names.  WMI hands
    # the strings to Python as real Unicode.
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
             "Get-CimInstance Win32_NetworkAdapter | ForEach-Object { "
             "$_.NetConnectionID + '|' + $_.Name }"],
            capture_output=True, timeout=15)
        text = completed.stdout.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return {}
    described = {}
    for line in text.splitlines():
        name, _, description = line.partition("|")
        if name.strip():
            described[name.strip()] = description.strip()
    return described


def connected_networks() -> List[dict]:
    """Enumerate only the networks this computer is connected to.

    The old scan took every IPv4 address psutil could see, including down
    VMware/TAP adapters, and probed a /24 around each one.  That is both slow
    and pointless.  Here we keep adapters that are up and have a usable IPv4
    address, prefer physical adapters and fall back to virtual ones only when
    nothing else is available.  The returned CIDR is what gets scanned next.
    """
    try:
        import psutil  # type: ignore
    except Exception:  # noqa: BLE001
        return []

    try:
        stats = psutil.net_if_stats()
        if_addrs = psutil.net_if_addrs()
    except Exception:  # noqa: BLE001
        return []

    # Read the driver descriptions once: they are what marks a tunnel whose
    # adapter name is only a code ("wwan99") as virtual.
    descriptions = _iface_descriptions()

    physical: List[dict] = []
    virtual: List[dict] = []

    for name, addrs in if_addrs.items():
        st = stats.get(name)
        if st is not None and not st.isup:
            continue  # adapter is down: never scan its stale address

        for snic in addrs:
            if getattr(snic, "family", None) != socket.AF_INET:
                continue
            try:
                ip = ipaddress.IPv4Address(snic.address)
            except ValueError:
                continue
            if (ip.is_loopback or ip.is_link_local or ip.is_unspecified
                    or ip.is_multicast):
                continue
            # 198.18.0.0/15 is reserved for benchmarking and is the default
            # address range of tunnel/VPN adapters (Wintun, WireGuard).  No
            # router or radio ever lives there.
            if ip in ipaddress.IPv4Network("198.18.0.0/15"):
                continue

            mask = getattr(snic, "netmask", None)
            try:
                iface = ipaddress.IPv4Interface(f"{ip}/{mask}")
            except ValueError:
                continue

            net = iface.network
            if net.prefixlen < 24:
                # A /16 would mean probing tens of thousands of hosts.
                # Stay inside the /24 that contains this interface.
                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)

            entry = {"iface": name, "ip": str(ip), "cidr": str(net),
                     "network": net}
            bucket = virtual if _is_virtual_iface(
                name, descriptions.get(name, "")) else physical
            if all(other["cidr"] != entry["cidr"] for other in bucket):
                bucket.append(entry)

    return physical or virtual


def lan_prefixes() -> List[str]:
    """Connected network addresses (kept for diagnostics/compatibility)."""
    return [str(net["network"].network_address) for net in connected_networks()]


async def _port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


async def _scan_lan(port: int = MESHTASTIC_TCP_PORT,
                    networks: Optional[List[dict]] = None,
                    skip: Optional[set] = None) -> List[str]:
    """Fast sweep: hosts in the connected networks that accept *port*.

    ``skip`` holds hosts that were already asked in an earlier wave: probing
    them a second time would only repeat the same negative answer and is what
    made a second wave take as long as the first.
    """
    hosts: List[str] = []
    for entry in (connected_networks() if networks is None else networks):
        net = entry["network"]
        hosts.extend(str(host) for host in net.hosts())

    hosts = list(dict.fromkeys(hosts))
    if skip:
        hosts = [h for h in hosts if h not in skip]
    if not hosts:
        return []

    sem = asyncio.Semaphore(128)

    async def probe(host: str) -> Optional[str]:
        async with sem:
            return host if await _port_open(host, port) else None

    found = await asyncio.gather(*(probe(h) for h in hosts))
    return [h for h in found if h]


async def _scan_lan_long(port: int = MESHTASTIC_TCP_PORT,
                         networks: Optional[List[dict]] = None,
                         skip: Optional[set] = None) -> List[str]:
    """Slow pass for radios that answer late.

    Some ESP32 builds answer the very first connection several seconds after
    the request, so the fast sweep misses them.  This pass asks every host
    with a longer timeout, using a few connections at a time, so a busy
    network does not slow it down.

    Hosts in ``skip`` already got their answer from the fast sweep and are not
    asked again: a closed port that stayed closed for 0.3 s is the ordinary
    case (every phone, printer and idle host on the network), and re-probing
    all of them with a 2 s timeout is what turned a miss into a three-minute
    wait.
    """
    hosts: List[str] = []
    for entry in (connected_networks() if networks is None else networks):
        hosts.extend(str(host) for host in entry["network"].hosts())
    hosts = list(dict.fromkeys(hosts))
    if skip:
        hosts = [h for h in hosts if h not in skip]
    if not hosts:
        return []

    sem = asyncio.Semaphore(48)

    async def probe(host: str) -> Optional[str]:
        async with sem:
            return host if await _port_open(host, port, timeout=2.0) else None

    found = await asyncio.gather(*(probe(h) for h in hosts))
    return [h for h in found if h]


def _verify_hosts(hosts: List[str], port: int, attempts: int = 3) -> List[tuple]:
    """Identify candidate hosts in parallel; keep only real Meshtastic radios.

    A radio wakes slowly from time to time and stays silent for the first
    request.  It is asked again a few times before the scan gives up on it,
    so one unlucky moment does not hide a working module.
    """
    if not hosts:
        return []
    found: List[tuple] = []
    done: set = set()
    with ThreadPoolExecutor(max_workers=min(8, len(hosts))) as pool:
        for attempt in range(attempts):
            pending = [h for h in hosts if h not in done]
            if not pending:
                break
            if attempt:
                time.sleep(0.5)
            futures = {pool.submit(_probe_tcp_name, host, 2.0, port): host
                       for host in pending}
            for future, host in futures.items():
                try:
                    name = future.result()
                except Exception:  # noqa: BLE001
                    name = None
                if name is not None:
                    found.append((host, name))
                    done.add(host)
    return found


def _meshtastic_name(iface) -> str:
    try:
        info = iface.getMyNodeInfo() or {}
        user = info.get("user", {})
        return user.get("longName") or user.get("shortName") or "?"
    except Exception:  # noqa: BLE001
        return "?"


def _try_meshtastic_tcp(host: str, timeout: int = 12, no_nodes: bool = False,
                        port: int = MESHTASTIC_TCP_PORT):
    import meshtastic.tcp_interface as tcp

    return tcp.TCPInterface(host, connectNow=True, noNodes=no_nodes,
                            timeout=timeout, portNumber=port)


def _try_meshtastic_ble(address: str, timeout: int = 20):
    from meshtastic.ble_interface import BLEInterface

    return BLEInterface(address, timeout=timeout)


def _try_meshtastic_serial(port: str, timeout: int = 12):
    import meshtastic.serial_interface as serial_iface

    return serial_iface.SerialInterface(port, connectNow=True, timeout=timeout)


@contextlib.contextmanager
def _quiet_meshtastic():
    """Silence meshtastic's shutdown noise while probing a radio.

    Closing a TCPInterface while its reader thread still has buffered data
    makes the library log a broken-pipe traceback to stderr.  That is harmless
    for a probe but looks scary in the menu, so hide it for a moment.
    """
    mt_logger = logging.getLogger("meshtastic")
    old_level = mt_logger.level
    mt_logger.setLevel(logging.CRITICAL)
    try:
        with open(os.devnull, "w", encoding="utf-8") as devnull, \
                contextlib.redirect_stderr(devnull):
            yield
            time.sleep(0.3)  # let the reader thread finish printing
    finally:
        mt_logger.setLevel(old_level)


_MESH_START1 = 0x94
_MESH_START2 = 0xC3
_MESH_NODELESS_CONFIG_ID = 69420


def _fast_probe_tcp(host: str, port: int = MESHTASTIC_TCP_PORT,
                    timeout: float = 2.0) -> Optional[str]:
    """Ask a radio for a nodeless config dump and return its node name.

    The meshtastic library spends several seconds tearing its reader thread
    down after a probe, which made a LAN scan feel extremely slow.  This
    speaks the same Stream API handshake directly over a plain socket, so a
    radio is identified in roughly 0.5 s (see ``want_config_id``).
    """
    try:
        from meshtastic.protobuf import mesh_pb2
    except Exception:  # noqa: BLE001
        return None

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(bytes([_MESH_START2] * 32))  # wake-up bytes

        request = mesh_pb2.ToRadio()
        request.want_config_id = _MESH_NODELESS_CONFIG_ID
        body = request.SerializeToString()
        sock.sendall(bytes([_MESH_START1, _MESH_START2,
                            (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + body)

        deadline = time.time() + timeout
        buf = b""
        my_num = None
        names: Dict[int, str] = {}
        while time.time() < deadline:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 4:
                if buf[0] != _MESH_START1 or buf[1] != _MESH_START2:
                    buf = buf[1:]
                    continue
                length = (buf[2] << 8) | buf[3]
                if len(buf) < 4 + length:
                    break
                frame, buf = buf[4:4 + length], buf[4 + length:]
                message = mesh_pb2.FromRadio()
                try:
                    message.ParseFromString(frame)
                except Exception:  # noqa: BLE001
                    continue
                kind = message.WhichOneof("payload_variant")
                if kind == "my_info":
                    my_num = message.my_info.my_node_num
                elif kind == "node_info":
                    user = message.node_info.user
                    names[message.node_info.num] = (user.long_name
                                                    or user.short_name or "")
                if my_num is not None and my_num in names:
                    return names[my_num] or "?"
        if my_num is not None and my_num in names:
            return names[my_num] or "?"
        return None
    except Exception:  # noqa: BLE001
        return None
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


def _probe_tcp_name(host: str, timeout: float = 2.0,
                    port: int = MESHTASTIC_TCP_PORT) -> Optional[str]:
    """Identify a Meshtastic radio over TCP.

    A radio that speaks the protocol answers in well under a second.  The
    retry only happens when the first attempt failed *quickly* (a dropped
    packet); a slow failure means nothing is there, and retrying would just
    double the wait on non-radio hosts.
    """
    started = time.time()
    name = _fast_probe_tcp(host, port, timeout)
    if name is not None:
        return name
    if time.time() - started < timeout * 0.5:
        time.sleep(0.1)
        return _fast_probe_tcp(host, port, timeout)
    return None


def _mdns_host(port: int, timeout: float = 1.2) -> Optional[str]:
    """Resolve meshtastic.local in the background with a hard timeout.

    Windows' resolver can stall for ~3 s when nothing answers, so it runs in a
    thread and is simply abandoned if it is too slow.
    """
    result: dict = {}

    def _resolve() -> None:
        try:
            for info in socket.getaddrinfo("meshtastic.local", port,
                                            proto=socket.IPPROTO_TCP):
                result["addr"] = info[4][0]
                break
        except Exception:  # noqa: BLE001
            pass

    worker = threading.Thread(target=_resolve, daemon=True)
    worker.start()
    worker.join(timeout)
    return result.get("addr")


async def _discover_tcp_devices(port: int = MESHTASTIC_TCP_PORT,
                                networks: Optional[List[dict]] = None,
                                quiet: bool = False) -> List[dict]:
    """All Meshtastic radios reachable over TCP in the connected networks.

    One fast sweep finds radios that answer immediately.  When fewer than two
    radios are found, a second sweep with a longer timeout follows: a radio
    that was busy at that moment (or answers its first request slowly) is
    asked again instead of silently missing from the list.

    The second sweep only asks hosts the first one never reached (see
    ``_scan_lan_long``), so a missing radio costs seconds, not minutes.
    """
    def say(*args) -> None:
        if not quiet:
            print(*args)

    say(f"Ищу Meshtastic с открытым портом {port} в этих сетях...")
    hosts = await _scan_lan(port, networks)
    verified = _verify_hosts(hosts, port) if hosts else []
    if len(verified) < 2:
        say("  перепроверяю с большим терпением...")
        slow = await _scan_lan_long(port, networks, skip=set(hosts))
        extra = [h for h in slow if h not in {v[0] for v in verified}]
        if extra:
            verified.extend(_verify_hosts(extra, port))

    devices: List[dict] = []
    for host, name in verified:
        devices.append({"kind": "tcp", "target": host, "port": port,
                        "label": f"{name} — {host}:{port} (Wi-Fi)"})
        say(f"  ок: {name} — {host}:{port}")
    return devices


def scan_wifi_devices(port: int = MESHTASTIC_TCP_PORT) -> List[dict]:
    networks = connected_networks()
    if not networks:
        print("Не удалось определить подключённые сети.")
        print("Проверьте, что компьютер подключён к Wi-Fi или Ethernet.")
        return []

    print(f"Подключённые сети ({len(networks)}):")
    for net in networks:
        print(f"  • {net['iface']} — {net['ip']} ({net['cidr']})")

    # Ask the mDNS name in parallel with the port sweep — it is free when it
    # answers fast and costs nothing when it does not.
    mdns_result: dict = {}

    def _mdns() -> None:
        addr = _mdns_host(port)
        if addr:
            mdns_result["addr"] = addr

    mdns_thread = threading.Thread(target=_mdns, daemon=True)
    mdns_thread.start()

    devices = asyncio.run(_discover_tcp_devices(port, networks))
    if not devices and mdns_result.get("addr"):
        devices = asyncio.run(_discover_tcp_devices(
            port, [{"network": ipaddress.IPv4Network(
                f"{mdns_result['addr']}/32", strict=False)}]))

    if not devices:
        print(f"Meshtastic с портом {port} не найден.")
    return devices


def scan_ble_devices(seconds: float = 8.0, quiet: bool = False) -> List[dict]:
    def say(*args) -> None:
        if not quiet:
            print(*args)

    say(f"Сканирую Bluetooth {seconds:.0f} c...")

    async def _scan():
        devs = await BleakScanner.discover(timeout=seconds, return_adv=True)
        out = []
        for device, adv in devs.values():
            uuids = {str(u).lower() for u in (adv.service_uuids or [])}
            name = (adv.local_name or getattr(device, "name", "") or "")
            if MESHTASTIC_BLE_SERVICE in uuids or name.lower().startswith("meshtastic"):
                out.append({"kind": "ble", "target": device.address,
                            "label": f"{name or 'Meshtastic'} — {device.address} (BLE)"})
        return out

    try:
        found = asyncio.run(_scan())
    except Exception as exc:  # noqa: BLE001
        say(f"Bluetooth недоступен: {exc}")
        return []

    if not found:
        say("Meshtastic по Bluetooth не найден "
            "(на ESP32 BLE выключается, когда включён Wi-Fi).")
    return found


def _probe_announce_packet() -> bytes:
    """A signed announce used only while identifying nearby phones."""
    probe = BitchatBLEHandler(None, "MeshBridge")  # type: ignore[arg-type]
    return probe.build_announce()


def _bitchat_characteristics(client) -> list:
    """Return the Bitchat characteristic objects exposed by a phone.

    Bitchat on iOS publishes the same service twice. Looking the
    characteristic up by UUID then fails with "Multiple Characteristics with
    this UUID", so callers must pass one of these objects to bleak instead.
    """
    out = []
    for service in client.services:
        if str(getattr(service, "uuid", "")).lower() != BITCHAT_SERVICE_UUID:
            continue
        for char in getattr(service, "characteristics", []) or []:
            if str(getattr(char, "uuid", "")).lower() == BITCHAT_CHAR_UUID:
                out.append(char)
    return out


def _identify_one(address: str, announce: bytes, seconds: float = 3.5) -> dict:
    """Connect briefly and read this phone's announce (peer id + nickname).

    Returns ``{"peer": hex, "nickname": str, "char": characteristic}`` where
    *peer* is the 8-byte Bitchat sender id, and the app's fallback display
    name for a stranger is ``anon<first 4 hex>``.

    Bitchat sends its announce 0.4 s after a central subscribes, so the wait
    can stay short; stale addresses fail on connect instead of on the wait.
    """
    result = {"peer": None, "nickname": None, "char": None,
              "variants": 0, "error": None, "signing_pub": None,
              "noise_pub": None, "signature_ok": False}

    async def _probe():
        notes: list = []
        # Windows BLE connect to a real phone takes 3-11 s, so the connect
        # timeout has to stay generous; the post-connect wait is short
        # because Bitchat announces ~0.4 s after we subscribe.
        client = BleakClient(address, timeout=12.0)
        try:
            await client.connect()
            chars = _bitchat_characteristics(client)
            result["variants"] = len(chars)
            # The second instance is the one that actually accepts
            # notifications on current Bitchat builds; try it first.
            for char in sorted(chars, key=lambda c: -getattr(c, "handle", 0)):
                notes.clear()
                try:
                    await client.start_notify(
                        char, lambda _c, data: notes.append(bytes(data)))
                except Exception as exc:  # noqa: BLE001
                    result["error"] = f"{getattr(char, 'handle', '?')}: {exc}"
                    continue

                result["char"] = char
                try:
                    await client.write_gatt_char(char, announce,
                                                 response=False)
                except Exception:  # noqa: BLE001
                    with contextlib.suppress(Exception):
                        await client.write_gatt_char(char, announce,
                                                     response=True)

                deadline = time.time() + seconds
                while time.time() < deadline and not notes:
                    if not client.is_connected:
                        break
                    await asyncio.sleep(0.1)
                if notes:
                    break

            for raw in notes:
                parsed = BitchatBLEHandler._parse_packet(raw)
                if not parsed:
                    continue
                sender, packet_type, _ts, _flags, payload = parsed
                if packet_type != TYPE_ANNOUNCE:
                    continue
                fields = parse_announce_fields(payload)
                signing_pub = fields.get(0x03)
                noise_pub = fields.get(0x02)
                result["peer"] = sender.hex()
                result["nickname"] = (fields.get(0x01) or b"").decode(
                    "utf-8", "ignore") or None
                result["signing_pub"] = signing_pub
                result["noise_pub"] = noise_pub
                # The announce must prove itself: a valid signature from the
                # key it carries, and a peer id derived from its noise key.
                if signing_pub:
                    result["signature_ok"] = verify_packet_signature(
                        bytes(raw), signing_pub)
                if signing_pub and noise_pub:
                    derived = hashlib.sha256(noise_pub).digest()[:SENDER_ID_SIZE]
                    result["signature_ok"] = (
                        result["signature_ok"] and derived == sender)
                break
        finally:
            with contextlib.suppress(Exception):
                await client.disconnect()
        return result

    try:
        return asyncio.run(_probe())
    except Exception as exc:  # noqa: BLE001
        result["error"] = repr(exc)
        return result


def _identify_peers(devices: List[dict], seconds: float = 3.5) -> List[dict]:
    """Turn raw advertisers into identified phones, one live peer each.

    iOS rotates its Bluetooth address, so Windows keeps stale entries that
    still point at the same phone. Those never answer, so a device counts as
    a Bitchat phone only when it returns an announce. Probes run in parallel
    (each stale address fails on its own) and results are merged by the
    announced peer id, which is stable across address rotation.
    """
    if not devices:
        return []

    announce = b""
    with contextlib.suppress(Exception):
        announce = _probe_announce_packet()

    # Windows BLE is only reliable from one thread.  Probes used to run in a
    # thread pool, and then a full connection opened from the event loop (or
    # the other way round) could time out even though the phone was nearby.
    # Every probe now runs on this one worker thread, in order.
    infos = [_identify_one(dev["target"], announce, seconds)
             for dev in devices]

    # Bitchat rate-limits announces per subscribed central, so a live phone
    # occasionally stays silent on the first try. Retry the silent ones once
    # before dropping them.
    for i, info in enumerate(infos):
        if info.get("peer"):
            continue
        log.debug("Повторная проверка %d адрес(ов)", 1)
        retry = _identify_one(devices[i]["target"], announce, seconds)
        if retry.get("peer"):
            infos[i] = retry

    # -- merge answers by peer id, drop everything that did not answer -----
    phones: List[dict] = []
    by_peer: dict = {}
    unverified = 0
    for dev, info in zip(devices, infos):
        peer = info.get("peer")
        if not peer:
            log.debug("Адрес %s не ответил как Bitchat", dev["target"])
            continue
        if not info.get("signature_ok"):
            # A phone whose announce does not prove its own identity is not
            # offered for binding: otherwise the id could simply be copied.
            unverified += 1
            log.warning("Пир %s не подтвердил подпись — пропущен", peer[:4])
            continue
        known = by_peer.get(peer)
        if known is not None:
            # Same phone reached through another (older) address.
            if dev["target"] not in known["addresses"]:
                known["addresses"].append(dev["target"])
            known["rssi"] = max(known.get("rssi") or -999,
                                dev.get("rssi") or -999)
            continue
        phone = {
            "kind": "bitchat",
            "target": dev["target"],
            "addresses": [dev["target"]],
            "name": dev.get("name") or "Bitchat",
            "rssi": dev.get("rssi"),
            "peer": peer,
            "peer_id": peer,
            "user_id": "@" + peer[:4],
            "nickname": info.get("nickname"),
            "char": info.get("char"),
            "signing_pub": info.get("signing_pub"),
            "noise_pub": info.get("noise_pub"),
            "fingerprint": peer_fingerprint(info["signing_pub"]),
            "service_data": dev.get("service_data"),
            "service_uuids": dev.get("service_uuids") or [],
            "label": dev.get("label") or "Bitchat",
        }
        by_peer[peer] = phone
        phones.append(phone)

    if unverified:
        print(f"  отброшено устройств без подтверждённой подписи: {unverified}")
    phones.sort(key=lambda d: -(d.get("rssi") or -999))
    return phones


def _best_characteristic(client):
    """Pick the Bitchat characteristic to notify/write on.

    Current Bitchat builds publish the same service twice, so ``bleak``
    refuses to resolve the characteristic by UUID ("Multiple
    Characteristics with this UUID"). The higher handle is the instance
    that actually delivers notifications, so prefer it.
    """
    chars = _bitchat_characteristics(client)
    if not chars:
        return None
    return max(chars, key=lambda c: getattr(c, "handle", 0))


def scan_bitchat_peers(seconds: float = 8.0,
                       identify: bool = True) -> List[dict]:
    """Find phones that really run Bitchat.

    Two stages:

    1. BLE scan — keep advertisers that expose the Bitchat service.
    2. Identify — connect to each candidate and wait for its announce, which
       is the only proof that the device is a Bitchat phone. Windows keeps
       stale entries for addresses iOS has already rotated away, and those
       never answer; showing them would let the user pick a dead address.

    *identify* is only disabled by tests, where BLE is not available.
    """
    print(f"Ищу телефоны Bitchat по Bluetooth ({seconds:.0f} c)...")

    # -- stage 1: BLE scan of raw advertisers -----------------------------
    async def _scan():
        devs = await BleakScanner.discover(timeout=seconds, return_adv=True)
        out = []
        for device, adv in devs.values():
            uuids = {str(u).lower() for u in (adv.service_uuids or [])}
            name = (adv.local_name or getattr(device, "name", "") or "")
            service_data = (adv.service_data or {}).get(BITCHAT_SERVICE_UUID)
            # Bitchat hides its name and only advertises the service, so the
            # UUID (or service data) is the reliable marker.
            if BITCHAT_SERVICE_UUID in uuids or service_data:
                out.append({"kind": "bitchat", "target": device.address,
                            "name": name or "Bitchat",
                            "rssi": getattr(adv, "rssi", None),
                            "service_uuids": sorted(uuids),
                            "service_data": service_data.hex()
                                            if service_data else None,
                            "user_id": None, "nickname": None,
                            "label": name or "Bitchat"})
        out.sort(key=lambda d: -(d.get("rssi") or -999))
        return out

    try:
        candidates = asyncio.run(_scan())
    except Exception as exc:  # noqa: BLE001
        print(f"Bluetooth недоступен: {exc}")
        return []

    if not candidates:
        print("Телефоны Bitchat рядом не найдены.")
        return []

    # -- stage 2: keep only devices that prove they are Bitchat -------------
    if identify:
        print(f"  найдено {len(candidates)} адрес(ов), проверяю Bitchat у каждого...")
        found = _identify_peers(candidates)
        lost = len(candidates) - len(found)
        if lost:
            log.debug("Отброшено %d адрес(ов) без ответа Bitchat", lost)
    else:
        found = candidates

    # -- stage 3: human-readable label --------------------------------------
    for dev in found:
        parts = []
        user_id = dev.get("user_id")
        nickname = dev.get("nickname")
        alias = dev.get("name")
        if user_id:
            parts.append(user_id)
        known = {(user_id or "").lstrip("@").lower()}
        if nickname and nickname.lower() not in known:
            parts.append(f"«{nickname}»")
            known.add(nickname.lower())
        if alias and alias != "Bitchat" and alias.lower() not in known:
            parts.append(alias)
        parts.append(dev["target"])
        if dev.get("rssi"):
            parts.append(f"{dev['rssi']} dBm")
        dev["label"] = " — ".join(parts)

    if not found:
        print("Bitchat-телефоны не ответили "
              "(приложение должно быть открыто и на экране).")
    return found


def describe_phone(phone: dict) -> str:
    """Everything observable about a phone, shown before binding."""
    lines = [
        "  Bitchat nickname : " + (phone.get("nickname") or "(нет)"),
        "  Bitchat peer ID  : " + (phone.get("peer") or "?"),
        "  Ключ (отпечаток): " + (phone.get("fingerprint") or "?"),
        "  BLE-адрес        : " + (phone.get("target") or "?"),
        "  BLE-имя          : " + (phone.get("name") or "?"),
        "  RSSI             : " + str(phone.get("rssi") or "?"),
        "  Сервисы          : " + ", ".join(
            phone.get("service_uuids") or ["(нет в рекламе)"]),
        "  Service data     : " + (phone.get("service_data") or "(нет)"),
    ]
    return "\n".join(lines)


def confirm_binding(phone: dict) -> bool:
    """Ask the user to confirm the only phone this bridge may talk to."""
    print("\nБудет привязан один телефон. Проверьте данные:")
    print(describe_phone(phone))
    print("\nАдрес Bluetooth на iOS случайный и может смениться: мост сверяет\n"
          "не адрес, а Bitchat peer ID и подпись ключа. Другие телефоны\n"
          "подключиться не смогут. При смене устройства нужна команда сброса.")
    try:
        raw = input("Введите yes, чтобы привязать это устройство: ")
    except (EOFError, KeyboardInterrupt):
        return False
    raw = raw.strip().lower()
    if raw not in ("yes", "да"):
        return False
    # Second, short confirmation: binding decides the whole session and cannot
    # be undone except with the explicit console command.
    try:
        again = input("Подтвердите ещё раз (yes): ")
    except (EOFError, KeyboardInterrupt):
        return False
    return again.strip().lower() in ("yes", "да")


def unbound_phone() -> dict:
    """Stand-in phone used when scanning is unavailable."""
    return {"kind": "bitchat", "target": None, "peer": None,
            "nickname": None, "fingerprint": None, "label": "Bitchat"}


def choose_bitchat_peer(seconds: float = 8.0) -> Optional[dict]:
    """Let the user pick which Bitchat phone this bridge talks to.

    Returns the chosen phone dict (see ``_identify_peers``) or ``None`` when
    no phone was found or nothing was chosen; the bridge then stays without
    a phone instead of attaching to a random device nearby.
    """
    devices = scan_bitchat_peers(seconds)
    if not devices:
        print("Телефоны Bitchat не найдены.")
        return None

    if len(devices) == 1:
        return devices[0]

    print("\nНайденные устройства Bitchat:")
    for i, dev in enumerate(devices, 1):
        print(f"  {i}) {dev['label']}")
    print("  0) не выбирать")

    while True:
        try:
            raw = input("Номер устройства: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if raw in ("0", ""):
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(devices):
            return devices[int(raw) - 1]
        print("Нет такого номера.")


def scan_serial_devices(quiet: bool = False) -> List[dict]:
    def say(*args) -> None:
        if not quiet:
            print(*args)

    try:
        import serial.tools.list_ports as list_ports
    except Exception as exc:  # noqa: BLE001
        say(f"pyserial недоступен: {exc}")
        return []

    ports = list(list_ports.comports())
    if not ports:
        say("COM-портов не найдено.")
        return []

    devices = []
    for port in ports:
        devices.append({"kind": "serial", "target": port.device,
                        "label": f"{port.device} — {port.description} (USB)"})
    return devices


# --------------------------------------------------------------------------
# Meshtastic side
# --------------------------------------------------------------------------
class MeshtasticHandler:
    def __init__(self, loop: asyncio.AbstractEventLoop, transport: Optional[dict],
                 connect_timeout: int = 25, default_channel: int = 0,
                 lora_send_interval: float = 10.0,
                 history_limit: int = 100,
                 lora_stale_seconds: float = 1800.0) -> None:
        self.loop = loop
        self.transport = transport or {}
        self.connect_timeout = connect_timeout
        self.default_channel = max(0, min(7, int(default_channel or 0)))
        # Which Meshtastic chat the bridge is bound to:
        #   {"kind": "all"}                      — everything (default)
        #   {"kind": "channel", "index": N}      — one channel
        #   {"kind": "dm", "node": <num or id>}  — direct chat with one node
        self.target_kind = "all"
        self.target_channel = self.default_channel
        self.target_node = None
        self.interface = None
        self.ble_handler: Optional["BitchatBLEHandler"] = None
        self._subscribed = False
        self._stopping = False
        self._reconnect_delay = 5
        self._max_reconnect_delay = 30
        self._reconnecting = False
        # The reconnect retry as a real task of this loop, so stop() can end
        # it instead of leaving a pending task behind.
        self._reconnect_task: Optional[asyncio.Task] = None
        # Outgoing Bitchat -> LoRa queue.  Entries are dicts with a timestamp
        # so old automatic messages can be dropped instead of flooding LoRa.
        self.pending_texts: deque = deque(maxlen=MAX_QUEUE)
        self._recent_sent: deque = deque(maxlen=50)
        self._seen_ids: deque = deque(maxlen=200)
        # History of LoRa -> Bitchat messages.  Each entry is a dict and is
        # marked delivered once the phone has actually received it, so a
        # reconnect does not replay old messages.
        self.history_limit = max(1, int(history_limit))
        self.history_lora: deque = deque(maxlen=self.history_limit)
        # Air-time protection: never send Bitchat messages to LoRa faster
        # than this many seconds apart.
        self.lora_send_interval = max(0.0, float(lora_send_interval))
        self.lora_stale_seconds = max(0.0, float(lora_stale_seconds))
        self._last_send_at = 0.0
        self._flush_lock = asyncio.Lock()

    def set_ble_handler(self, handler: "BitchatBLEHandler") -> None:
        self.ble_handler = handler

    # -- chat target ------------------------------------------------------
    def set_chat_target(self, target: Optional[dict]) -> None:
        kind = (target or {}).get("kind", "all")
        if kind not in ("all", "channel", "dm"):
            kind = "all"
        self.target_kind = kind
        self.target_node = None
        if kind == "channel":
            self.target_channel = max(0, min(7, int(target.get("index", 0))))
            self.default_channel = self.target_channel
        elif kind == "dm":
            node = target.get("node")
            if isinstance(node, str):
                resolved = self.resolve_destination(node)
                node = resolved if resolved is not None else node
            self.target_node = node
            self.target_channel = self.default_channel
        else:
            self.target_channel = self.default_channel

    def describe_target(self) -> str:
        if self.target_kind == "channel":
            return f"канал {self.target_channel} ({self.channel_label(self.target_channel)})"
        if self.target_kind == "dm":
            return f"личный чат с {self._node_label(self.target_node)}"
        return "все каналы и личные сообщения"

    def current_target(self) -> Tuple[int, Optional[object]]:
        """Return (channel, destination) for a plain Bitchat message."""
        if self.target_kind == "dm":
            num = self._target_node_num()
            return self.default_channel, (num if num is not None
                                          else f"@{self.target_node}")
        if self.target_kind == "channel":
            return self.target_channel, None
        return self.default_channel, None

    def _node_label(self, node) -> str:
        if node is None:
            return "?"
        try:
            nodes = (self.interface.nodes or {}) if self.interface else {}
        except Exception:  # noqa: BLE001
            nodes = {}
        for item in nodes.values():
            if item.get("num") == node:
                user = item.get("user") or {}
                return (user.get("longName") or user.get("shortName")
                        or str(node))
        return str(node)

    def _target_node_num(self):
        """Resolve the DM target once the radio is available."""
        node = self.target_node
        if isinstance(node, str) and not node.isdigit():
            resolved = self.resolve_destination(node)
            if resolved is not None:
                self.target_node = resolved
                return resolved
            return None
        if isinstance(node, str) and node.isdigit():
            self.target_node = int(node)
            return self.target_node
        return node

    def _same_node(self, from_id, node) -> bool:
        if node is None:
            return False
        if isinstance(node, str) and node.startswith("!"):
            return from_id.lower() == node.lower()
        if isinstance(from_id, str) and from_id.startswith("!"):
            try:
                return int(from_id[1:], 16) == int(node)
            except ValueError:
                return False
        return str(from_id) == str(node)

    def _accepts_incoming(self, is_dm: bool, channel_index: int,
                          from_id) -> bool:
        if self.target_kind == "all":
            return True
        if self.target_kind == "channel":
            return (not is_dm) and channel_index == self.target_channel
        if self.target_kind == "dm":
            num = self._target_node_num()
            return is_dm and self._same_node(from_id, num if num is not None
                                             else self.target_node)
        return True

    # -- connection -------------------------------------------------------
    def _subscribe(self) -> None:
        if not self._subscribed:
            pub.subscribe(self.on_receive, "meshtastic.receive")
            pub.subscribe(self.on_connection_lost, "meshtastic.connection.lost")
            self._subscribed = True

    def _open_interface(self):
        kind = (self.transport or {}).get("kind")
        target = (self.transport or {}).get("target")
        port = int((self.transport or {}).get("port") or MESHTASTIC_TCP_PORT)
        if kind == "tcp" and target:
            return _try_meshtastic_tcp(target, self.connect_timeout, port=port)
        if kind == "ble" and target:
            return _try_meshtastic_ble(target, self.connect_timeout + 10)
        if kind == "serial" and target:
            return _try_meshtastic_serial(target, self.connect_timeout)
        return self._auto_connect()

    def _auto_connect(self):
        errors = []
        if local_ipv4_addresses():
            for host in asyncio.run(_scan_lan()):
                try:
                    return _try_meshtastic_tcp(host, self.connect_timeout)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{host}: {exc}")
        try:
            import serial.tools.list_ports as list_ports
            hints = ("cp210", "ch340", "ch910", "ch343", "usb serial", "silicon labs")
            for port in list_ports.comports():
                if any(h in (port.description or "").lower() for h in hints):
                    try:
                        return _try_meshtastic_serial(port.device, self.connect_timeout)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"{port.device}: {exc}")
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError("; ".join(errors) or "Meshtastic не найден")

    def _try_connect(self) -> bool:
        try:
            iface = self._open_interface()
        except Exception as exc:  # noqa: BLE001
            log.warning("Meshtastic недоступен: %s", exc)
            return False
        self.interface = iface
        self._subscribe()
        self._reconnect_delay = 5
        log.info("Meshtastic подключён (%s) — узел: %s",
                 self._describe_transport(), _meshtastic_name(iface))
        say(f"[LoRa] подключено: {self._describe_transport()} — узел "
            f"{_meshtastic_name(iface)}")
        summary = self.channel_summary()
        if summary:
            log.info("Каналы LoRa: %s (по умолчанию %d)",
                     summary, self.default_channel)
        if self.pending_texts:
            log.info("В очереди на отправку в LoRa: %d", len(self.pending_texts))
            asyncio.run_coroutine_threadsafe(self.flush_texts(), self.loop)
        return True

    def _describe_transport(self) -> str:
        kind = (self.transport or {}).get("kind")
        target = (self.transport or {}).get("target")
        if kind == "tcp":
            port = int((self.transport or {}).get("port") or MESHTASTIC_TCP_PORT)
            return f"Wi-Fi {target}:{port}"
        if kind == "ble":
            return f"Bluetooth {target}"
        if kind == "serial":
            return f"USB {target}"
        return "auto"

    def start(self) -> None:
        if not self._try_connect():
            log.warning("Радио офлайн, продолжаю попытки в фоне...")
            self._schedule_reconnect()

    def _schedule_reconnect(self) -> None:
        if self._stopping or self._reconnecting or not self.loop.is_running():
            return
        self._reconnecting = True
        self._reconnect_task = self.loop.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        delay = self._reconnect_delay
        try:
            while not self._stopping and self.interface is None:
                await asyncio.sleep(delay)
                if self._stopping:
                    return
                if await asyncio.to_thread(self._try_connect):
                    log.info("Meshtastic снова на связи")
                    return
                delay = min(delay * 2, self._max_reconnect_delay)
        except asyncio.CancelledError:
            # stop() closes the interface; there is nothing to retry.
            pass
        finally:
            self._reconnecting = False

    # -- pubsub callbacks -------------------------------------------------
    def _cleanup_interface(self) -> None:
        if self.interface is not None:
            try:
                self.interface.close()
            except Exception:  # noqa: BLE001
                pass
            self.interface = None

    def on_connection_lost(self, interface=None) -> None:
        if self._stopping:
            return
        log.warning("Связь с Meshtastic потеряна, переподключаюсь...")
        say("[LoRa] связь потеряна, переподключаюсь...")
        truncate_logs()
        self._cleanup_interface()
        self._schedule_reconnect()

    def _sender_name(self, from_id: str) -> str:
        try:
            if self.interface and self.interface.nodes:
                node = self.interface.nodes.get(from_id)
                if node and node.get("user"):
                    return node["user"].get("longName") or from_id
        except Exception:  # noqa: BLE001
            pass
        return from_id

    # -- channels / addressing -------------------------------------------
    def _channels(self):
        try:
            return list(self.interface.localNode.channels) if self.interface else []
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _is_enabled(ch) -> bool:
        try:
            return int(ch.role) != 0  # 0 = DISABLED
        except Exception:  # noqa: BLE001
            return True

    def channel_label(self, index: int) -> str:
        """Human name for a channel index, e.g. 'Primary' or 'Семья'."""
        channels = self._channels()
        if 0 <= index < len(channels) and self._is_enabled(channels[index]):
            try:
                name = channels[index].settings.name
            except Exception:  # noqa: BLE001
                name = ""
            if name:
                return name
        return "Primary" if index == 0 else f"канал {index}"

    def channel_exists(self, index: int) -> bool:
        channels = self._channels()
        if not (0 <= index < len(channels)):
            return False
        return self._is_enabled(channels[index])

    def channel_summary(self) -> str:
        channels = self._channels()
        parts = []
        for i, ch in enumerate(channels):
            if not self._is_enabled(ch):
                continue
            try:
                name = ch.settings.name
            except Exception:  # noqa: BLE001
                name = ""
            parts.append(f"{i}={name or ('Primary' if i == 0 else 'без имени')}")
        return ", ".join(parts)

    def describe_channels(self) -> str:
        channels = self._channels()
        if not channels:
            return "[Bridge] радио недоступно, список каналов не получен."
        summary = self.channel_summary()
        if not summary:
            return "[Bridge] включённых каналов нет."
        return ("[Bridge] каналы Meshtastic: " + summary
                + f". По умолчанию: {self.default_channel}. "
                "Пишите «#N текст» для канала N или «/dm узел текст» лично.")

    def resolve_destination(self, token: str):
        """Turn a node id / short name / long name into a Meshtastic node number."""
        token = token.strip()
        if not token:
            return None
        low = token.lower()
        try:
            nodes = (self.interface.nodes or {}) if self.interface else {}
        except Exception:  # noqa: BLE001
            nodes = {}
        for node in nodes.values():
            user = node.get("user") or {}
            num = node.get("num")
            if low in (str(user.get("id", "")).lower(),
                       str(user.get("longName", "")).lower(),
                       str(user.get("shortName", "")).lower()) or token == str(num):
                return num
        # Raw node id like !a1b2c3d4
        if token.startswith("!") and len(token) > 1:
            try:
                return int(token[1:], 16)
            except ValueError:
                return None
        if token.isdigit():
            return int(token)
        return None

    def on_receive(self, packet, interface=None) -> None:
        try:
            decoded = packet.get("decoded") or {}
            text = decoded.get("text")
            if not text:
                return
            if text.startswith("[Bit:") or text.startswith("[Bit]"):
                return

            packet_id = packet.get("id")
            if packet_id is not None:
                if packet_id in self._seen_ids:
                    return
                self._seen_ids.append(packet_id)

            now = time.time()
            sent_digest = hashlib.sha256(text.encode("utf-8")).digest()
            for sent_text, sent_at in list(self._recent_sent):
                if sent_text == sent_digest and now - sent_at < 120:
                    return

            sender = self._sender_name(packet.get("fromId", "unknown"))
            try:
                channel_index = int(packet.get("channel", 0) or 0)
            except Exception:  # noqa: BLE001
                channel_index = 0
            to_num = packet.get("to")
            is_dm = to_num is not None and int(to_num) != BROADCAST_NUM

            from_id = packet.get("fromId", "unknown")
            if not self._accepts_incoming(is_dm, channel_index, from_id):
                log.debug("Пропускаю сообщение вне выбранного чата: %s, канал %d",
                          sender, channel_index)
                return

            if is_dm:
                prefix = f"[Mesh DM: {sender}]"
            elif channel_index:
                prefix = f"[Mesh: {sender} / {self.channel_label(channel_index)}]"
            else:
                prefix = f"[Mesh: {sender}]"

            where = "личное" if is_dm else f"канал {channel_index}"
            log.info("(LoRa -> BLE) от %s, %s: %d символов",
                     sender, where, len(text))
            # The text itself never reaches the console: only the fact that
            # something arrived.
            say(f"[LoRa] {sender}: сообщение ({len(text)} симв.)")
            body = f"{prefix} {text}"
            entry = {
                "ts": time.time(),
                "sealed": seal_text(body),
                "delivered": False,
            }
            self.history_lora.append(entry)
            collapse_duplicate_entries(self.history_lora)
            self._gui_last_rx = time.time()
            self._gui_latest = {"direction": "rx", "author": sender,
                                "kind": "из LoRa", "chars": len(text),
                                "at": self._gui_last_rx}
            if self.ble_handler and self.loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.ble_handler.deliver_history(entry), self.loop
                )
        except Exception as exc:  # noqa: BLE001
            log.error("Ошибка обработки LoRa-пакета: %s", exc)

    # -- sending ----------------------------------------------------------
    def _notify_bitchat(self, text: str) -> None:
        """Best-effort notice back to Bitchat peers from a worker thread."""
        if not self.ble_handler:
            return
        try:
            if self.loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.ble_handler.broadcast(text), self.loop)
        except Exception:  # noqa: BLE001
            pass

    def _resolve_target(self, channel: Optional[int], destination):
        """Return (channel, destination, unresolved_token)."""
        ch = self.default_channel if channel is None else int(channel)
        if isinstance(destination, str) and destination.startswith("@"):
            token = destination[1:]
            resolved = self.resolve_destination(token)
            if resolved is None:
                return ch, f"@{token}", token
            return ch, resolved, None
        return ch, destination, None

    def enqueue_text(self, text: str, channel: Optional[int] = None,
                     destination=None, manual: bool = False,
                     history_entry: Optional[dict] = None) -> bool:
        """Put a message into the rate-limited LoRa send queue."""
        ch, dest, _unresolved = self._resolve_target(channel, destination)
        entry = {
            "ts": time.time(),
            "queued_at": time.time(),
            "sealed": seal_text(text),
            "channel": ch,
            "destination": dest,
            "manual": bool(manual),
            "history": history_entry,
        }
        self.pending_texts.append(entry)
        target = (f"личное {dest}" if dest is not None else f"канал {ch}")
        log.info("(BLE -> LoRa очередь) [%s] %d символов", target, len(text))
        if self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.flush_texts(), self.loop)
        return True

    def send_text(self, text: str, channel: Optional[int] = None,
                  destination=None) -> bool:
        """Send immediately (used by --test-send)."""
        if (channel is None and destination is None
                and self.target_kind == "dm" and self.target_node is not None):
            num = self._target_node_num()
            destination = num if num is not None else f"@{self.target_node}"
        ch, dest, unresolved = self._resolve_target(channel, destination)
        if unresolved is not None:
            log.error("Узел «%s» не найден — сообщение пропущено", unresolved)
            self._notify_bitchat(
                f"[Bridge] узел «{unresolved}» не найден, сообщение не отправлено")
            return True
        if self.interface is None:
            self.enqueue_text(text, ch, dest, manual=True)
            return False
        entry = {"ts": time.time(), "queued_at": time.time(),
                 "sealed": seal_text(text),
                 "channel": ch, "destination": dest, "manual": True,
                 "history": None}
        ok = self._send_entry(entry)
        if not ok and not self._stopping:
            self.pending_texts.append(entry)
        return ok

    def _send_entry(self, entry: dict) -> bool:
        text = open_text(entry.get("sealed"))
        if not text:
            # Unreadable buffer entry: nothing to send, never retry it.
            return True
        ch = int(entry.get("channel") or 0)
        destination = entry.get("destination")
        if isinstance(destination, str) and destination.startswith("@"):
            token = destination[1:]
            resolved = self.resolve_destination(token)
            if resolved is None:
                log.error("Узел «%s» не найден — сообщение из очереди пропущено",
                          token)
                self._notify_bitchat(
                    f"[Bridge] узел «{token}» не найден, сообщение не отправлено")
                return True  # drop it instead of retrying forever
            destination = resolved
            entry["destination"] = resolved
        try:
            if destination is not None:
                log.info("(BLE -> LoRa) [личное %s] %d символов",
                         destination, len(text))
            elif ch:
                log.info("(BLE -> LoRa) [канал %d %s] %d символов", ch,
                         self.channel_label(ch), len(text))
            else:
                log.info("(BLE -> LoRa) %d символов", len(text))
            kwargs = {"channelIndex": ch}
            if destination is not None:
                kwargs["destinationId"] = destination
            self.interface.sendText(text, **kwargs)
        except Exception as exc:  # noqa: BLE001
            log.error("Отправка в LoRa не удалась: %s", exc)
            self.on_connection_lost()
            return False
        # Only a successful send goes into the echo filter: a failed attempt
        # must not suppress the same text when it is really received later.
        self._recent_sent.append(
            (hashlib.sha256(text.encode()).digest(), time.time()))
        return True

    async def flush_texts(self) -> None:
        """Send queued messages one-by-one with air-time spacing."""
        if self._flush_lock.locked():
            return
        async with self._flush_lock:
            sent = 0
            while self.pending_texts and not self._stopping:
                entry = self.pending_texts[0]
                if self.interface is None:
                    break
                age = time.time() - float(entry.get("queued_at")
                                          or entry.get("ts") or 0)
                if self.lora_stale_seconds and age > self.lora_stale_seconds:
                    self.pending_texts.popleft()
                    say("[LoRa] устаревшее сообщение пропущено "
                        "(содержимое не выводится)")
                    self._gui_dropped += 1
                    self._gui_latest = {"direction": "drop", "author": "",
                                        "kind": "устарело", "chars": 0,
                                        "at": time.time()}
                    hist = entry.get("history")
                    if isinstance(hist, dict):
                        hist["queued_lora"] = False
                        hist["dropped"] = True
                    continue
                wait = self.lora_send_interval - (time.time() - self._last_send_at)
                if wait > 0:
                    await asyncio.sleep(wait)
                if self.interface is None or self._stopping:
                    break
                ok = await asyncio.to_thread(self._send_entry, entry)
                if not ok:
                    break
                self._last_send_at = time.time()
                self.pending_texts.popleft()
                sent += 1
                hist = entry.get("history")
                if isinstance(hist, dict):
                    hist["sent_lora"] = True
                self._gui_sent += 1
                self._gui_last_tx = self._last_send_at
                self._gui_latest = {
                    "direction": "tx",
                    "author": (hist or {}).get("name", "") if isinstance(hist, dict) else "",
                    "kind": "в LoRa",
                    "chars": len(open_text(entry.get("sealed"))),
                    "at": self._gui_last_tx,
                }
            if sent:
                say(f"[LoRa] отправлено из очереди: {sent} "
                    f"(осталось {len(self.pending_texts)})")

    async def text_flush_loop(self) -> None:
        """Keep trying to drain the outgoing queue while the radio is up."""
        while not self._stopping:
            await asyncio.sleep(5)
            if self.pending_texts and self.interface is not None:
                await self.flush_texts()

    def send_history_entry(self, entry: dict) -> bool:
        """Queue one Bitchat history item for LoRa."""
        text = open_text(entry.get("sealed"))
        if not text:
            return False
        name = entry.get("name") or "?"
        body = f"[Bit:{name}] {text}"
        ok = self.enqueue_text(body, channel=entry.get("channel"),
                               destination=entry.get("destination"),
                               manual=True, history_entry=entry)
        if ok:
            entry["queued_lora"] = True
        return ok

    def stop(self) -> None:
        self._stopping = True
        task = self._reconnect_task
        if task is not None and not task.done():
            loop = self.loop
            if loop.is_running() and not loop.is_closed():
                try:
                    loop.call_soon_threadsafe(task.cancel)
                except RuntimeError:
                    pass
        self._reconnect_task = None
        self._cleanup_interface()


# --------------------------------------------------------------------------
# Bitchat side
# --------------------------------------------------------------------------
class BitchatBLEHandler:
    def __init__(self, loop: asyncio.AbstractEventLoop, nickname: str,
                 scan_seconds: float = 3.0, history_limit: int = 100,
                 target_address: Optional[str] = None,
                 full_sync: bool = False,
                 target_peer: Optional[str] = None) -> None:
        self.loop = loop
        self.nickname = nickname
        self.scan_seconds = scan_seconds
        self.history_limit = max(1, int(history_limit))
        # When set, only this BLE address may be bridged (other people's
        # phones nearby must never receive our traffic). iOS rotates its
        # Bluetooth address, so a list of known addresses is accepted.
        self.target_address = (target_address or "").strip() or None
        self.target_addresses = {
            a.strip().lower()
            for a in (self.target_address or "").split(",")
            if a.strip()
        }
        # Bitchat characteristic object per connected address (see _write_raw).
        self._chars: Dict[str, object] = {}
        # Peer id last seen from each connected address, so the bridge can
        # recognise its own phone even after the address rotated.
        self.peer_ids: Dict[str, str] = {}
        # Timestamp of the last packet received from each address, and of the
        # last keepalive sent. Used by the watchdog to detect a dead link.
        self._last_seen: Dict[str, float] = {}
        # When each link was opened; the watchdog gives a new link a grace
        # period of LINK_TIMEOUT before it expects packets from the phone.
        self._opened_at: Dict[str, float] = {}
        # Last keepalive sent to each address, and the last "who are you"
        # reminder sent to a link that has not answered yet.
        self._last_keepalive: Dict[str, float] = {}
        self.last_nudge: Dict[str, float] = {}
        # Stable Bitchat identity of the chosen phone (8 bytes as hex). This is
        # confirmed in the console for the current session only; it is never
        # written to the config file.
        self.target_peer = (target_peer or "").strip().lower() or None
        # Ed25519 signing key of every peer whose announce proved itself.
        # Messages from a sender without a verified key are dropped.
        self.peer_keys: Dict[str, bytes] = {}
        self.peer_fingerprints: Dict[str, str] = {}
        self._rejected_packets = 0
        # One phone, one link, for the whole session. The binding can only be
        # changed with the explicit console command.
        self.bound_peer: Optional[str] = self.target_peer
        # Two confirmations for private channels are asked once per session.
        self.private_confirmed = False
        # Full two-way sync: forward every incoming message to the other side
        # immediately, in addition to the normal one-way behaviour.
        self.full_sync = bool(full_sync)
        # Which Bitchat senders may reach LoRa (see DEFAULT_CONFIG):
        #   "bound"  — only the bound phone (strict, default);
        #   "custom" — the bound phone plus peer ids listed in
        #              ``bitchat_sources`` (every key proven by an announce);
        #   "replies" — the bound phone plus phones it answered in the public
        #              chat (learned live, see ``_note_public_traffic``);
        #   "all"    — any sender that arrives on the phone link, including
        #              fragments with no verifiable signature (a fragment
        #              carries only a sender id, so authorship cannot be
        #              proven there — the user accepts this explicitly).
        # "custom" never becomes active without its list, so a plain restart
        # cannot silently widen what leaves the radio.
        self.forward_mode: str = "bound"
        self.bitchat_sources: set = set()
        # Phones the owner has *answered* in the public chat ("replies" mode).
        # In that mode a message from someone reaches LoRa only after the bound
        # phone has posted after them in the same public chat, which is what an
        # owner answering a stranger looks like on the wire.  Keyed exactly
        # like ``bitchat_sources``.  Never stored in the config file.
        self.bitchat_replied: set = set()
        # Peer id whose message was the last one seen in the public chat, and
        # the number of that message.  When the bound phone posts after it,
        # that peer is marked as answered.  Only ids and a counter are kept,
        # never the text.
        self._last_public_sender: Optional[str] = None
        self._public_counter: int = 0
        self._last_public_seq: int = 0
        # Address of the link the current chain of fragments arrived on; it
        # picks the right per-link fragment table in _handle_fragment.
        self._fragment_addr: Optional[str] = None
        # Forward mode remembered in the config file.  "custom" is kept
        # strict until its (never stored) phone list is picked in the console.
        self.saved_forward_mode: str = "bound"
        self.connected: Dict[str, BleakClient] = {}
        self.connecting: set = set()
        # Addresses that carried the bound phone during this session; they are
        # tried first after a drop instead of a full scan.
        self._known_addresses: set = set()
        # Addresses whose probe has just received a signed announce from the
        # bound phone; the next link is opened there without another scan.
        self._live_from_scan: set = set()
        # Peer id carried in the advertisement of each address (Bitchat puts
        # it into the service data).  This is only a routing hint: the
        # identity is still proven by a signed announce before any message is
        # accepted.
        self.advertised_peers: Dict[str, str] = {}
        self.meshtastic: Optional[MeshtasticHandler] = None
        self.peer_nicknames: Dict[str, str] = {}
        # Announce nickname of a peer that is not the bound phone, keyed by
        # "peer:<id>" — kept apart so the bound phone's name can never be
        # overwritten.  BLE name per address is only a last resort for peers
        # which never announced.
        self.peer_aliases: Dict[str, str] = {}
        self.peer_hostnames: Dict[str, str] = {}
        self._seen_packets: deque = deque(maxlen=200)
        # Reassembled frames, keyed by (BLE address, fragment id): a fragment
        # table per link, so a fragment from a second phone can never be glued
        # into a frame that the first phone started.
        self._fragments: Dict[Tuple[str, bytes], dict] = {}
        self._stopping = False
        self._bluetooth_warned = False
        # Last N Bitchat messages, kept for the manual "send last 5/10/20/50"
        # sync.  They are never sent to LoRa automatically.  The text itself
        # is only held sealed inside the entry; nothing readable is kept
        # beside it, not even a preview.
        self.history_bitchat: deque = deque(maxlen=self.history_limit)
        # Recently delivered LoRa -> Bitchat bodies, used to filter echoes
        # (digests only, never the text).
        self._recent_outgoing: deque = deque(maxlen=200)
        self._delivery_lock = asyncio.Lock()
        # Indicators for a user interface (gui/).  Only counters, a kind and
        # a name: never the text of a message.
        self._gui_latest: Optional[dict] = None
        self._gui_sent = 0
        self._gui_dropped = 0
        self._gui_last_rx = 0.0
        self._gui_last_tx = 0.0
        self._announced = False

        # PeerID in Bitchat = sha256(Noise public key)[:8] (see PeerID.swift)
        self.signing_key = nacl.signing.SigningKey.generate()
        self.signing_pub = bytes(self.signing_key.verify_key)
        self.noise_private = nacl.bindings.crypto_box_keypair()[1]
        self.noise_public = nacl.bindings.crypto_scalarmult_base(self.noise_private)
        self.my_id = hashlib.sha256(self.noise_public).digest()[:SENDER_ID_SIZE]
        log.info("Bitchat identity: %s (ник: %s)", self.my_id.hex(), nickname)

    def set_meshtastic_handler(self, handler: MeshtasticHandler) -> None:
        self.meshtastic = handler

    # -- encoding ---------------------------------------------------------
    @staticmethod
    def _pad(data: bytes) -> bytes:
        for block in PAD_BLOCK_SIZES:
            if len(data) + 16 <= block:
                need = block - len(data)
                if 0 < need <= 255:
                    return data + bytes([need]) * need
                return data
        return data

    def build_packet(self, packet_type: int, payload: bytes,
                     recipient: Optional[bytes] = None, pad: bool = False) -> bytes:
        header = bytearray([PACKET_VERSION, packet_type, TTL])
        header += struct.pack(">Q", int(time.time() * 1000))
        flags = FLAG_HAS_SIGNATURE | (FLAG_HAS_RECIPIENT if recipient else 0)
        header.append(flags)
        header += struct.pack(">H", len(payload))

        # Signature covers the padded unsigned packet with TTL=0 and without
        # the HAS_SIGNATURE flag (BitchatPacket.toBinaryDataForSigning()).
        signing_header = bytearray(header)
        signing_header[2] = 0x00
        signing_header[11] = flags & ~FLAG_HAS_SIGNATURE
        unsigned = bytearray(signing_header) + self.my_id
        if recipient:
            unsigned += recipient[:RECIPIENT_ID_SIZE]
        unsigned += payload
        signature = self.signing_key.sign(self._pad(bytes(unsigned))).signature

        packet = bytearray(header) + self.my_id
        if recipient:
            packet += recipient[:RECIPIENT_ID_SIZE]
        packet += payload
        packet += signature
        return self._pad(bytes(packet)) if pad else bytes(packet)

    def build_announce(self) -> bytes:
        payload = bytearray()
        name = self.nickname.encode("utf-8")[:255]
        payload += bytes([0x01, len(name)]) + name
        payload += bytes([0x02, len(self.noise_public)]) + self.noise_public
        payload += bytes([0x03, len(self.signing_pub)]) + self.signing_pub
        return self.build_packet(TYPE_ANNOUNCE, bytes(payload), recipient=BROADCAST_ID)

    # -- decoding ---------------------------------------------------------
    def _decompress(self, payload: bytes) -> Optional[str]:
        if len(payload) < 3:
            return None
        compressed = payload[2:]  # 2-byte original size (v1)
        tries = [lambda d: zlib.decompress(d), lambda d: zlib.decompress(d, -15)]
        if lz4 is not None:
            tries.append(lambda d: lz4.block.decompress(d, uncompressed_size=65536))
        for fn in tries:
            try:
                return fn(compressed).decode("utf-8", errors="ignore")
            except Exception:  # noqa: BLE001
                continue
        log.error("Не удалось распаковать payload (%d байт)", len(payload))
        return None

    def _handle_packet(self, sender: bytes, packet_type: int, timestamp: int,
                       flags: int, payload: bytes, raw: Optional[bytes] = None,
                       client=None, source_addr: Optional[str] = None) -> None:
        if sender == self.my_id:
            return
        key = (sender, timestamp, packet_type)
        if key in self._seen_packets:
            return
        self._seen_packets.append(key)

        short_id = sender.hex()[-4:]
        if packet_type == TYPE_ANNOUNCE:
            # An announce carries the key that has to verify it, so it is
            # checked only after its fields are read (and only once).  It is
            # read even while the mode refuses it: the key is what a later
            # message from this peer will be checked against.
            self._handle_announce(sender, payload, short_id, raw, client,
                                  source_addr=source_addr)
            return

        if packet_type not in (TYPE_MESSAGE, TYPE_FRAGMENT):
            # Service traffic (group, noise, voice, files, relayed Nostr, …).
            # Its body is ciphertext or binary, so it can never become a LoRa
            # message; it is dropped before any decoding or signature work.
            log.debug("Пропущен служебный пакет %s типа 0x%02x", short_id,
                      packet_type)
            return

        # Everything else is checked against the key learned from a verified
        # announce, before anything is decoded, so unverified data never
        # reaches the text pipeline.
        if not self._packet_allowed(sender, raw, source_addr):
            self._rejected_packets += 1
            log.debug("Отклонён пакет %s: не подтверждён или не наш пир",
                      short_id)
            return
        if flags & FLAG_IS_COMPRESSED:
            text = self._decompress(payload)
            if text is None:
                return
        else:
            text = payload.decode("utf-8", errors="ignore")

        if packet_type == TYPE_MESSAGE:
            name = self._display_name(sender, source_addr)
            self._note_public_traffic(sender.hex(), source_addr)
            self._on_bitchat_text(text, name, sender.hex())

    def _note_public_traffic(self, peer: str, source_addr: Optional[str]) -> None:
        """Track who spoke last in the public chat, to learn who was answered.

        The bridge never reads the text to decide this.  It only remembers the
        id of the last public sender; when the bound phone posts afterwards,
        that sender counts as answered and is added to ``bitchat_replied``.
        An owner replying to a stranger in #mesh is exactly this pattern, and
        it is the only signal the wire offers, because a public message has no
        addressee.
        """
        if not self.bound_peer:
            return
        self._public_counter += 1
        from_bound = peer == self.bound_peer or (
            bool(source_addr) and self.peer_ids.get(source_addr) == self.bound_peer)
        if from_bound:
            # The bound phone spoke: whoever it was answering is now a source.
            if self._last_public_sender and \
                    self._last_public_sender != self.bound_peer:
                if self._last_public_sender not in self.bitchat_replied:
                    self.bitchat_replied.add(self._last_public_sender)
                    log.info("Пир %s отмечен как ответивший (режим «ответившие» "
                             "теперь %d)", self._last_public_sender[-4:],
                             len(self.bitchat_replied))
            self._last_public_sender = None
            return
        self._last_public_sender = peer
        self._last_public_seq = self._public_counter

    def _packet_allowed(self, sender: bytes, raw: Optional[bytes],
                        source_addr: Optional[str] = None) -> bool:
        """True for a sender that may reach LoRa, with a verified signature.

        The rule depends on ``forward_mode`` (see __init__):

        * ``bound`` — exactly the bound phone, signature verified;
        * ``custom`` — the bound phone or one of ``bitchat_sources``, each
          proven by its own self-signed announce;
        * ``replies`` — the bound phone and the phones it has answered in the
          public chat (``bitchat_replied``).  A stranger's message starts
          reaching LoRa only after the owner posts after it in #mesh; nothing
          is forwarded from people the owner never answered;
        * ``all`` — the bound phone, any chosen phone, and any sender whose key
          is not known yet.  Once a peer's key is known (from its verified
          announce) this mode *requires* a valid signature from it: a frame
          that claims that peer id but carries no signature, or a bad one, is
          refused.  Only a peer never heard of before is accepted by id alone,
          because that is all the client delivered.  A fragment never carries
          a signature, so its authorship is never provable.

        The bound phone is still the only phone that may *receive* traffic;
        these modes only decide what may be *forwarded to LoRa*.
        """
        peer = sender.hex()
        is_bound = bool(self.bound_peer) and peer == self.bound_peer
        # Fallback: the link that delivered the packet is proven to belong
        # to the bound phone (its announce was checked at connect time), so
        # its own packets do not need a second check.
        from_bound_link = bool(source_addr) and \
            self.peer_ids.get(source_addr) == self.bound_peer

        if self.forward_mode == "all":
            key = self.peer_keys.get(peer)
            if key is not None:
                # We know this peer's key, so we can check it: a missing or a
                # bad signature is a refusal, not a pass.  Without this, anyone
                # who copied the peer id of a known phone could slip an
                # unsigned frame in under its name.
                if raw is None:
                    return False
                return verify_packet_signature(bytes(raw), key)
            # Key unknown: the id is all the client gave us.  Accepted by the
            # owner's explicit choice for this mode; a later announce with a
            # real key makes the check above active for this peer.
            return True

        allowed = is_bound or from_bound_link
        if not allowed and self.forward_mode == "custom":
            allowed = peer in self.bitchat_sources
        if not allowed and self.forward_mode == "replies":
            allowed = peer in self.bitchat_replied
        if not allowed:
            return False

        if self.forward_mode == "custom" and peer in self.bitchat_sources:
            # A chosen phone is trusted by the key it proved with its own
            # announce; the packet is still checked when its frame carries a
            # signature (a reassembled fragment carries none).
            key = self.peer_keys.get(peer)
            if key is not None and raw is not None:
                return verify_packet_signature(bytes(raw), key)
            return True

        if self.forward_mode == "replies" and peer in self.bitchat_replied:
            # Same trust as a listed phone: the id was learned from verified
            # traffic; the frame is checked whenever it carries a signature.
            key = self.peer_keys.get(peer)
            if key is not None and raw is not None:
                return verify_packet_signature(bytes(raw), key)
            return True

        key = self.peer_keys.get(peer)
        if not key:
            # No verified key for this sender: accept only the bound phone's
            # own packets that arrived over its proven link.
            return is_bound or from_bound_link
        if raw is None:
            return False
        return verify_packet_signature(bytes(raw), key)

    def _pick_only_peer(self) -> None:
        """After the first bound phone, refuse every other Bitchat device."""
        if self.bound_peer:
            self.target_peer = self.bound_peer

    def _reply_to_bitchat(self, text: str) -> None:
        log.info("(Bridge -> Bitchat) %d символов", len(text))
        try:
            asyncio.get_running_loop().create_task(self.broadcast(text))
        except RuntimeError:  # called from a non-async thread
            asyncio.run_coroutine_threadsafe(self.broadcast(text), self.loop)

    # Bridge commands; only the bound phone may use them.
    COMMANDS = ("/help", "/?", "/помощь", "/ch", "/channels", "/каналы",
                "/sync", "/синхро", "/синхронизация")

    def _answer_command(self, low: str) -> None:
        if low in ("/help", "/?", "/помощь"):
            self._reply_to_bitchat(
                "[Bridge] Сообщения в LoRa автоматически не уходят. "
                "Они копятся здесь; в консоли нажмите «s» и выберите "
                "«Bitchat → Meshtastic», количество и период. "
                "«/ch» — каналы, «#N текст» и «/dm узел текст» — адресация."
            )
        elif low in ("/ch", "/channels", "/каналы"):
            if self.meshtastic:
                self._reply_to_bitchat(self.meshtastic.describe_channels())
            else:
                self._reply_to_bitchat("[Bridge] радио Meshtastic недоступно.")
        elif low in ("/sync", "/синхро", "/синхронизация"):
            self._reply_to_bitchat(
                "[Bridge] Синхронизация запускается из консоли моста: "
                "нажмите «s» и выберите направление, количество (5/10/20/50) "
                "и при желании период повтора."
            )

    def _is_echo(self, text: str) -> bool:
        """Ignore messages that the bridge itself injected into Bitchat."""
        if text.startswith(("[Mesh:", "[Mesh DM:", "[Bridge]")):
            return True
        now = time.time()
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        for body, ts in list(self._recent_outgoing):
            if body == digest and now - ts < 180:
                return True
        return False

    def _display_name(self, sender: bytes, source_addr: Optional[str] = None) -> str:
        """A sender name safe for a prefix on the LoRa side.

        Preference: the announce nickname, then an alias learned from that
        peer's announce, then the BLE name of the link, then the peer id.
        Control characters are dropped and the name is limited to 32
        characters, so a hostile peer cannot forge protocol lines or fill the
        LoRa packet with its own name.
        """
        peer = sender.hex()
        candidates = [self.peer_nicknames.get(peer),
                      self.peer_aliases.get(f"peer:{peer}")]
        if source_addr:
            candidates.append(self.peer_hostnames.get(source_addr, ""))
        for raw_name in candidates:
            name = self._clean_name(raw_name)
            if name:
                return name
        return f"@{peer[:4]}"

    @staticmethod
    def _clean_name(raw_name) -> str:
        """One printable line, at most 32 characters ("" when unusable)."""
        if not raw_name:
            return ""
        name = "".join(ch for ch in str(raw_name)
                       if ch.isprintable() and ch not in "[]\r\n")
        return " ".join(name.split())[:32]

    def _on_bitchat_text(self, text: str, name: str,
                         peer: Optional[str] = None) -> None:
        """Buffer a Bitchat message; never forward it to LoRa automatically.

        ``peer`` is the peer id of the author (hex).  It is stored with the
        entry so that a later "Bitchat → LoRa" sync can tell whose message it
        is, and so the console can show a foreign author only when the chosen
        forwarding mode actually allows it to leave the bridge.
        """
        stripped = text.strip()
        if not stripped or self._is_echo(stripped):
            return
        peer_key = (peer or "").lower()
        is_bound = bool(self.bound_peer) and peer_key == self.bound_peer
        clean = self._clean_name(name) or (
            f"@{peer_key[:4]}" if peer_key else "Bitchat")
        low = stripped.lower()
        if low in self.COMMANDS:
            if is_bound:
                self._answer_command(low)
            return
        self._buffer_text(stripped, clean, peer_key, is_bound)

    def _buffer_text(self, stripped: str, clean: str, peer_key: str,
                     is_bound: bool) -> None:
        """Queue the message (with the author's name) for a later LoRa sync."""
        foreign = not is_bound

        channel, destination = (0, None)
        if self.meshtastic:
            channel, destination = self.meshtastic.current_target()

        match = RE_DM_TARGET.match(stripped)
        if match:
            token, body = match.group(1), match.group(2).strip()
            destination = f"@{token}"
            body_text = body
        else:
            match = RE_CHANNEL_TARGET.match(stripped)
            if match:
                channel = int(match.group(1))
                destination = None
                body_text = match.group(2).strip()
            else:
                body_text = stripped
        # Ready-to-send line: the author's name goes with the text, so the
        # LoRa chat can see who wrote it in Bitchat.  An explicit "/dm"
        # target stays a destination; the name still goes into the body.
        body_text = f"[Бит: {clean}] {body_text}"

        # No text is kept outside the sealed body: not even a short preview
        # for the console or the buffer list.
        entry = {
            "ts": time.time(),
            "name": clean,
            "peer": peer_key,
            "foreign": foreign,
            "sealed": seal_text(body_text),
            "preview": "",
            "channel": max(0, min(7, int(channel))),
            "destination": destination,
            "sent_lora": False,
        }
        self.history_bitchat.append(entry)
        collapse_duplicate_entries(self.history_bitchat)
        log.info("(BLE -> LoRa буфер) %s: %d символов", clean, len(body_text))
        self._gui_last_rx = time.time()
        self._gui_latest = {"direction": "rx", "author": clean,
                            "kind": "сообщение", "chars": len(body_text),
                            "at": self._gui_last_rx}
        if self.full_sync and self.meshtastic and self.may_forward(peer_key):
            # Full two-way mode: forward at once, still via the rate-limited
            # LoRa queue so the air is not flooded.
            self.meshtastic.send_history_entry(entry)
            say(f"[Bitchat] {clean}: сообщение ({len(body_text)} симв.) "
                "в очереди на LoRa")
            return
        if foreign:
            say(f"[Bitchat] {clean}: сообщение ({len(body_text)} симв.) "
                f"(чужой пир, в буфере {len(self.history_bitchat)}, "
                "в LoRa не уйдёт в текущем режиме)")
            return
        say(f"[Bitchat] {clean}: сообщение ({len(body_text)} симв.) "
            f"(в буфере {len(self.history_bitchat)}, "
            "ждёт ручной синхронизации)")

    def may_forward(self, peer: Optional[str]) -> bool:
        """True when a message from this peer may leave for LoRa.

        Same rule as _packet_allowed, without the signature (the signature
        was checked when the packet arrived).  Used before queueing a synced
        entry, so a buffer item can never bypass the chosen mode.
        """
        peer = (peer or "").lower()
        if not peer:
            return False
        if self.bound_peer and peer == self.bound_peer:
            return True
        if self.forward_mode == "all":
            return True
        if self.forward_mode == "custom":
            return peer in self.bitchat_sources
        if self.forward_mode == "replies":
            return peer in self.bitchat_replied
        return False

    def set_forward_mode(self, mode: str) -> None:
        """Switch the Bitchat → LoRa forwarding mode (console action)."""
        if mode not in ("bound", "custom", "all", "replies"):
            mode = "bound"
        self.forward_mode = mode
        if mode != "custom":
            self.bitchat_sources.clear()
        if mode != "replies":
            self.bitchat_replied.clear()
        log.info("Bitchat -> LoRa: режим %s", mode)

    @staticmethod
    def _parse_announce_nickname(payload: bytes) -> Optional[str]:
        """Extract the nickname tag (0x01) from an announce payload."""
        try:
            offset = 0
            while offset + 2 <= len(payload):
                tag = payload[offset]
                length = payload[offset + 1]
                offset += 2
                if offset + length > len(payload):
                    return None
                value = payload[offset:offset + length]
                offset += length
                if tag == 0x01:
                    return value.decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return None
        return None

    def _handle_announce(self, sender: bytes, payload: bytes, short_id: str,
                         raw: Optional[bytes] = None, client=None,
                         source_addr: Optional[str] = None) -> None:
        fields = parse_announce_fields(payload)
        nickname = (fields.get(0x01) or b"").decode("utf-8", "ignore") or None
        signing_pub = fields.get(0x03)
        noise_pub = fields.get(0x02)
        if not signing_pub or raw is None:
            return
        # An announce is self-signed: the signature is checked against the key
        # it carries, and the peer id must be derived from the noise key. A
        # copied peer id without the matching private key fails here.
        if not verify_packet_signature(bytes(raw), signing_pub):
            log.debug("Announce %s с неверной подписью отклонён", short_id)
            return
        if noise_pub:
            derived = hashlib.sha256(noise_pub).digest()[:SENDER_ID_SIZE]
            if derived != sender:
                log.debug("Announce %s: id не выводится из ключа", short_id)
                return
        key = sender.hex()
        self.peer_keys[key] = signing_pub
        self.peer_fingerprints[key] = peer_fingerprint(signing_pub)
        # The bound phone keeps its own names table; every other peer gets an
        # alias, so a stranger can never rename (or spoof) the bound phone.
        bound = self.bound_peer is not None and key == self.bound_peer
        table = self.peer_nicknames if bound else self.peer_aliases
        table_key = key if bound else f"peer:{key}"
        if nickname and table.get(table_key) != nickname:
            table[table_key] = nickname
            log.info("Пир %s теперь известен как «%s»", short_id, nickname)

    def _handle_fragment(self, sender: bytes, payload: bytes, flags: int,
                         source_addr: Optional[str] = None) -> None:
        """Collect one fragment; hand the reassembled frame to _handle_packet.

        A fragment itself has no signature — only the 8-byte sender id in its
        header — so the reassembled frame is re-checked by _handle_packet
        exactly like a direct packet.  The table is keyed by link address and
        fragment id, so fragments from different phones can never be glued
        together (which would otherwise let anyone splice words into another
        sender's message).
        """
        if len(payload) < 13:
            return
        frag_id = payload[:8]
        index = int.from_bytes(payload[8:10], "big")
        total = int.from_bytes(payload[10:12], "big")
        inner_type = payload[12]
        chunk = payload[13:]
        if total <= 0 or total > 10000 or index >= total:
            return
        if inner_type not in (TYPE_MESSAGE, TYPE_ANNOUNCE):
            # A fragment chain of group/noise/voice traffic can never become a
            # LoRa message: refuse it here so a filler cannot occupy memory
            # until the whole chain arrives.
            return
        table_key = (source_addr or "", frag_id)
        entry = self._fragments.setdefault(
            table_key, {"sender": sender, "total": total,
                        "type": inner_type, "parts": {}, "ts": time.time()}
        )
        if entry["sender"] != sender:
            # A different sender under the same fragment id on the same link:
            # an inconsistent chain, dropped rather than trusted.
            del self._fragments[table_key]
            return
        entry["parts"][index] = chunk
        entry["ts"] = time.time()

        if len(entry["parts"]) == entry["total"]:
            data = b"".join(entry["parts"][i] for i in range(entry["total"]))
            del self._fragments[table_key]
            parsed = self._parse_packet(data)
            if parsed:
                self._handle_packet(*parsed, source_addr=source_addr)

        now = time.time()
        for k in [k for k, v in list(self._fragments.items())
                  if now - v["ts"] > 60]:
            del self._fragments[k]

    @staticmethod
    def _parse_packet(data: bytes) -> Optional[Tuple[bytes, int, int, int, bytes]]:
        if len(data) < HEADER_SIZE_V1 + SENDER_ID_SIZE:
            return None
        if data[0] != PACKET_VERSION:
            log.debug("Пропускаю пакет протокола v%d", data[0])
            return None
        packet_type = data[1]
        timestamp = struct.unpack(">Q", data[3:11])[0]
        flags = data[11]
        payload_len = struct.unpack(">H", data[12:14])[0]
        offset = HEADER_SIZE_V1
        sender = data[offset:offset + SENDER_ID_SIZE]
        offset += SENDER_ID_SIZE
        if flags & FLAG_HAS_RECIPIENT:
            offset += RECIPIENT_ID_SIZE
        payload = data[offset:offset + payload_len]
        return sender, packet_type, timestamp, flags, payload

    def _notification(self, client: BleakClient, char, data: bytearray) -> None:
        try:
            parsed = self._parse_packet(bytes(data))
            if not parsed:
                return
            sender, packet_type, timestamp, flags, payload = parsed
            # Any packet proves the link is alive (watchdog input).
            addr = getattr(client, "address", "")
            self._last_seen[addr] = time.time()
            # Remember which Bitchat identity sits behind this address: the
            # address rotates, the identity does not.
            if packet_type == TYPE_ANNOUNCE:
                self.peer_ids[addr] = sender.hex()
            if packet_type == TYPE_FRAGMENT:
                self._handle_fragment(sender, payload, flags, source_addr=addr)
            else:
                self._handle_packet(sender, packet_type, timestamp, flags,
                                    payload, raw=bytes(data), client=client,
                                    source_addr=addr)
        except Exception as exc:  # noqa: BLE001
            log.error("Ошибка BLE-пакета (%s): %s", client.address, exc)

    # -- delivery / queues -----------------------------------------------
    async def _mtu(self, client: BleakClient) -> int:
        try:
            return int(client.mtu_size or 23)
        except Exception:  # noqa: BLE001
            return 23

    async def _write(self, client: BleakClient, packet: bytes) -> None:
        mtu = await self._mtu(client)
        max_chunk = mtu - 3 - (HEADER_SIZE_V1 + SENDER_ID_SIZE +
                               RECIPIENT_ID_SIZE + 13 + SIGNATURE_SIZE)
        if len(packet) <= mtu - 3 or max_chunk < 16:
            await self._write_raw(client, packet)
            return

        parsed = self._parse_packet(packet)
        if not parsed:
            await self._write_raw(client, packet)
            return
        _sender, packet_type, _ts, _flags, payload = parsed
        frag_id = os.urandom(8)
        chunks = [payload[i:i + max_chunk] for i in range(0, len(payload), max_chunk)]
        for index, chunk in enumerate(chunks):
            frag = (frag_id + struct.pack(">H", index) +
                    struct.pack(">H", len(chunks)) + bytes([packet_type]) + chunk)
            await self._write_raw(
                client, self.build_packet(TYPE_FRAGMENT, frag, recipient=BROADCAST_ID)
            )

    async def _wait_for_peer(self, client: BleakClient,
                             seconds: float = 4.0,
                             announce_first: bool = True) -> Optional[str]:
        """Wait until this phone sends its announce; return its peer id.

        The announce is the only proof of identity, so it is also what keeps
        the bridge from latching onto a stranger's phone after the real one
        rotated its Bluetooth address.  Bitchat usually answers straight away;
        if it stays silent, our own announce is written once as a prompt.
        """
        if announce_first:
            await self._write_raw(client, self.build_announce())
        deadline = time.time() + seconds
        prompted = announce_first
        while time.time() < deadline:
            peer = self.peer_ids.get(getattr(client, "address", ""))
            if peer:
                return peer
            if not client.is_connected:
                return None
            if not prompted and time.time() > deadline - seconds / 2:
                prompted = True
                with contextlib.suppress(Exception):
                    await self._write_raw(client, self.build_announce())
            await asyncio.sleep(0.1)
        return None

    async def _wait_for_announce(self, client: BleakClient,
                                 seconds: float = 4.0) -> bool:
        """Wait until this link produces a verified announce. True on success."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            peer = self.peer_ids.get(getattr(client, "address", ""))
            if peer and self.peer_keys.get(peer):
                return True
            if not client.is_connected:
                return False
            await asyncio.sleep(0.1)
        return False

    async def _write_raw(self, client: BleakClient, packet: bytes) -> None:
        """Write one packet to the phone.

        The characteristic object is stored per client, because Bitchat
        publishes its service twice and resolving by UUID raises
        "Multiple Characteristics with this UUID".
        """
        char = self._chars.get(getattr(client, "address", ""))
        if char is None:
            char = _best_characteristic(client)
            if char is None:
                raise BleakError("у телефона нет Bitchat-характеристики")
            self._chars[getattr(client, "address", "")] = char
        try:
            await client.write_gatt_char(char, packet, response=True)
        except Exception:
            await client.write_gatt_char(char, packet, response=False)

    def _disconnected(self, client: BleakClient) -> None:
        """Note a phone that went away.

        The phone may reconnect with a new (rotated) address, so the old
        address is never remembered as dead and is not blacklisted.  The
        scanner decides whether the phone is reachable again.
        """
        addr = getattr(client, "address", "?")
        log.info("Пир Bitchat отключился: %s", addr)
        say("[Bitchat] телефон отключился")
        self._chars.pop(addr, None)
        self.connected.pop(addr, None)
        self._last_seen.pop(addr, None)
        self._opened_at.pop(addr, None)
        self._last_keepalive.pop(addr, None)
        self.last_nudge.pop(addr, None)
        self.connecting.discard(addr)
        truncate_logs()

    async def connect(self, device) -> None:
        """Connect to one Bitchat phone and start bridging."""
        addr = device.address
        # Exactly one phone for the whole session. Once a peer is bound, any
        # other Bitchat device is ignored before a connection is even opened.
        if self.bound_peer and len(self.connected) >= 1 and \
                self.bound_peer not in {
                    pid for a, pid in self.peer_ids.items()
                    if a in self.connected}:
            log.debug("Уже связан с пиром %s — %s не подключаю",
                      self.bound_peer[:4], addr)
            return
        if self.target_address and addr.lower() not in self.target_addresses \
                and not self.target_peer:
            return
        if self.bound_peer and not self.peer_ids.get(addr) and \
                addr in self._known_addresses:
            # Fast path: this address worked a moment ago.  One quick trial;
            # the handshake still requires a signed announce, so a wrong
            # guess costs a few seconds and nothing else.
            self.peer_ids[addr] = self.bound_peer
        if addr in self.connected or addr in self.connecting:
            return
        self.connecting.add(addr)
        client = BleakClient(addr, timeout=15.0, disconnected_callback=self._disconnected)
        try:
            await client.connect()
            # Bitchat exposes two identical services; pick the object once.
            char = _best_characteristic(client)
            if char is None:
                raise BleakError("устройство не предоставляет Bitchat-сервис")
            await client.start_notify(
                char, lambda c, d: self._notification(client, c, d))
            self._chars[addr] = char
            # The phone proves itself with a signed announce before it is
            # accepted.  The probe of the scanner has just obtained one, so
            # the handshake may use it; otherwise the phone is asked directly.
            peer = self.peer_ids.get(addr)
            fresh = self._last_seen.get(addr, 0.0)
            waited = False
            if not peer or not self.peer_keys.get(peer) or \
                    time.time() - fresh > 2.0:
                # Do not spend an announce write here: the phone answers the
                # link's own announce a moment later, and every avoidable
                # write makes iOS slower to respond.
                peer = await self._wait_for_peer(client, seconds=8.0,
                                                 announce_first=False)
                waited = await self._wait_for_announce(client, 4.0)
            if not peer and not waited:
                peer = await self._wait_for_peer(client, seconds=8.0,
                                                 announce_first=True)
            if waited:
                # The phone answered our own announce: refresh the idle timer.
                self._last_keepalive[addr] = time.time()
            if not peer:
                raise BleakError("телефон не прислал announce")
            if not self.peer_keys.get(peer):
                raise BleakError("announce не подтвердил подпись")
            if self.bound_peer and peer != self.bound_peer:
                raise BleakError(f"другой телефон (@{peer[:4]}) не разрешён")
            if not self.bound_peer:
                self.bound_peer = peer
                self.target_peer = peer
            if self.connected:
                raise BleakError("к мосту уже подключён телефон")
            self.connected[addr] = client
            # A fresh link counts as alive right away, otherwise the watchdog
            # would treat a quiet phone as dead and rebuild a healthy link.
            self._last_seen[addr] = time.time()
            self._opened_at[addr] = time.time()
            self._known_addresses.add(addr)
            # Bitchat answers an announce, and the answer refreshes its idle
            # timer.  A short announce goes out right away: the link must be
            # proven live before the keepalive interval starts.
            await self._write_raw(client, self.build_announce())
            self._last_keepalive[addr] = time.time()
            log.info("Пир Bitchat подключён: %s", getattr(device, "name", None) or addr)
            say("[Bitchat] телефон подключён")
            await self.flush_undelivered(client)
        except Exception as exc:  # noqa: BLE001
            log.debug("BLE-подключение к %s не удалось: %s", addr, exc)
            self._chars.pop(addr, None)
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                pass
        finally:
            self.connecting.discard(addr)

    @staticmethod
    def _is_bitchat(device, adv) -> bool:
        """True when this advertisement belongs to a Bitchat phone.

        Bitchat hides its name, so the service UUID (or its service data,
        which carries the 8-byte peer id) is the marker.
        """
        uuids = {str(u).lower() for u in (adv.service_uuids or [])}
        if BITCHAT_SERVICE_UUID in uuids:
            return True
        data = {str(k).lower(): v
                for k, v in (adv.service_data or {}).items()}
        if data.get(BITCHAT_SERVICE_UUID):
            return True
        name = (adv.local_name or getattr(device, "name", "") or "").lower()
        return "bitchat" in name

    @staticmethod
    def _advertised_peer(adv) -> Optional[str]:
        """Peer id that a Bitchat phone puts into its advertisement.

        The service data carries the same 8-byte id that the announce uses.
        It is not proof of identity (anyone can copy it), only a way to pick
        the right address out of a scan instead of probing every device.
        """
        data = {str(k).lower(): v
                for k, v in (adv.service_data or {}).items()}
        blob = data.get(BITCHAT_SERVICE_UUID)
        if blob and len(blob) >= SENDER_ID_SIZE:
            return blob[:SENDER_ID_SIZE].hex()
        return None

    async def _resolve_bound_address(self):
        """Check, which currently advertised address answers as the bound peer.

        The identity is proven by opening a short link and waiting for a
        signed announce, exactly like the start-up scan does.  Returns the
        scanned device object of the bound phone, or ``None`` when it is out
        of reach.
        """
        devices = await BleakScanner.discover(timeout=self.scan_seconds,
                                              return_adv=True)
        candidates = {}
        hinted = {}
        for device, adv in devices.values():
            if not self._is_bitchat(device, adv):
                continue
            candidates[device.address] = device
            self.advertised_peers[device.address] = self._advertised_peer(adv)
            if self.advertised_peers[device.address] == self.bound_peer:
                hinted[device.address] = device
        # A phone that advertises the bound peer id is almost certainly the
        # bound phone; if the announce later disagrees, the link is refused.
        pool = hinted or candidates
        if not pool:
            return None
        checked = await asyncio.to_thread(
            _identify_peers, [{"target": a} for a in pool])
        for phone in checked:
            if phone.get("peer") == self.bound_peer and \
                    phone.get("signature_ok", True):
                self.peer_keys[phone["peer"]] = phone.get("signing_pub")
                self.peer_fingerprints[phone["peer"]] = phone.get(
                    "fingerprint")
                self.peer_ids[phone["target"]] = phone["peer"]
                self._live_from_scan.add(phone["target"])
                # The probe has just received a signed announce, so the
                # handshake does not need to ask for it again.
                self._last_seen[phone["target"]] = time.time()
                return candidates[phone["target"]]
        return None

    async def scanner(self) -> None:
        """Keep scanning for the chosen Bitchat phone and connect when seen."""
        log.info("Ищу Bitchat-пиры по Bluetooth...")
        # The bound phone is proven by a short probe only when the link is
        # down; while it is up the radio is not scanned at all, because a
        # scan spends the time Bitchat needs to answer the keepalive.
        while not self._stopping:
            try:
                # Nothing else may touch the radio while a link is up or being
                # opened: a scan or a probe spends the time Bitchat needs to
                # answer, and that is what makes iOS drop the bridge.
                if self.connected or self.connecting:
                    await asyncio.sleep(2.0)
                    continue

                # 1. A probe that answered a second ago is the best address:
                #    open the real link there without another scan.
                if self._live_from_scan:
                    address = self._live_from_scan.pop()
                    self._known_addresses.add(address)
                    await self._try_address(address)
                    if self.connected:
                        continue

                # 2. Addresses that carried the phone earlier this session.
                for address in sorted(self._known_addresses):
                    if await self._try_address(address):
                        break
                    self._known_addresses.discard(address)
                    self.peer_ids.pop(address, None)
                if self.connected:
                    continue

                # 3. The full connection is refused right after the phone
                #    leaves the screen; a short probe finds out whether the
                #    bound phone answers before a real link is opened.
                target = None
                if self.bound_peer:
                    live = await self._resolve_bound_address()
                    if live is None:
                        await asyncio.sleep(3.0)
                        continue
                    target = type("Probed", (), {"address": live.address,
                                                 "name": None})()
                else:
                    devices = await BleakScanner.discover(
                        timeout=self.scan_seconds, return_adv=True)
                    candidates = [device for device, adv in devices.values()
                                  if self._is_bitchat(device, adv)]
                    # One phone at a time: with several Bitchat devices in
                    # range the user picks one in the console before launch.
                    if len(candidates) == 1:
                        target = candidates[0]
                self._bluetooth_warned = False
                if target is not None:
                    if (target.address in self.connected
                            or target.address in self.connecting):
                        continue
                    if self.bound_peer and target.address not in self.peer_ids:
                        continue
                    asyncio.create_task(self.connect(target))
                    await asyncio.sleep(12.0)
            except BleakError as exc:
                if not self._bluetooth_warned:
                    log.error("Проблема с Bluetooth: %s", exc)
                    self._bluetooth_warned = True
                await asyncio.sleep(10)
            except Exception as exc:  # noqa: BLE001
                log.debug("Ошибка BLE-сканирования: %s", exc)
                await asyncio.sleep(2)
            await asyncio.sleep(1.0)

    async def _try_address(self, address: str) -> bool:
        """Open the link at a known address and report whether it worked."""
        if address in self.connected or address in self.connecting:
            return False
        asyncio.create_task(self.connect(
            type("Known", (), {"address": address, "name": None})()))
        for _ in range(24):
            await asyncio.sleep(0.5)
            if address in self.connected:
                return True
            if address not in self.connecting:
                return False
        return address in self.connected

    async def deliver_history(self, entry: dict) -> None:
        """Deliver one LoRa history item to the phone if it is connected."""
        if self._stopping:
            return
        async with self._delivery_lock:
            body = open_text(entry.get("sealed"))
            if not body:
                return
            if self.connected:
                packet = self.build_packet(TYPE_MESSAGE, pad_body(body),
                                           recipient=BROADCAST_ID)
                if await self._broadcast_packet(packet):
                    entry["delivered"] = True
                    self._recent_outgoing.append(
                        (hashlib.sha256(body.encode("utf-8")).digest(),
                         time.time()))
                    return
            log.info("Нет Bitchat-пира — сообщение остаётся в истории")

    async def _broadcast_packet(self, packet: bytes) -> bool:
        ok = False
        for addr, client in list(self.connected.items()):
            try:
                await self._write(client, packet)
                ok = True
            except Exception as exc:  # noqa: BLE001
                log.warning("Отправка %s не удалась: %s", addr, exc)
        return ok

    async def flush_undelivered(self, client: Optional[BleakClient] = None) -> int:
        """Send only messages the phone has not received yet."""
        if not self.meshtastic:
            return 0
        async with self._delivery_lock:
            entries = [e for e in list(self.meshtastic.history_lora)
                       if not e.get("delivered")]
            if not entries:
                return 0
            if client is None and not self.connected:
                return 0
            sent = 0
            for entry in entries:
                body = open_text(entry.get("sealed"))
                if not body:
                    entry["delivered"] = True
                    continue
                packet = self.build_packet(TYPE_MESSAGE, pad_body(body),
                                           recipient=BROADCAST_ID)
                try:
                    if client is not None:
                        await self._write(client, packet)
                    elif not await self._broadcast_packet(packet):
                        break
                except Exception as exc:  # noqa: BLE001
                    log.warning("Досылка истории не удалась: %s", exc)
                    break
                entry["delivered"] = True
                self._recent_outgoing.append(
                    (hashlib.sha256(body.encode("utf-8")).digest(),
                     time.time()))
                sent += 1
                await asyncio.sleep(0.05)
            if sent:
                say(f"[Bitchat] досылаю пропущенное: {sent}")
            return sent

    async def resend_lora(self, count: int, only_new: bool = False) -> int:
        """Manually replay the last N LoRa messages to the phone."""
        if not self.meshtastic:
            return 0
        async with self._delivery_lock:
            entries = list(self.meshtastic.history_lora)
            if only_new:
                entries = [e for e in entries if not e.get("delivered")]
            entries = entries[-max(1, int(count)):]
            if not entries:
                return 0
            if not self.connected:
                say("[Bitchat] телефон не подключён — синхронизация невозможна")
                return 0
            sent = 0
            for entry in entries:
                body = open_text(entry.get("sealed"))
                if not body:
                    continue
                packet = self.build_packet(TYPE_MESSAGE, pad_body(body),
                                           recipient=BROADCAST_ID)
                if await self._broadcast_packet(packet):
                    entry["delivered"] = True
                    self._recent_outgoing.append(
                        (hashlib.sha256(body.encode("utf-8")).digest(),
                         time.time()))
                    sent += 1
                await asyncio.sleep(0.05)
            return sent

    async def resend_bitchat(self, count: int, only_new: bool = False) -> int:
        """Queue the last N Bitchat messages for rate-limited LoRa sending.

        Entries whose author is not allowed by the current forwarding mode
        are skipped (not marked as dropped), so switching the mode later can
        still send them on an explicit request.
        """
        if not self.meshtastic:
            return 0
        entries = list(self.history_bitchat)
        if only_new:
            entries = [e for e in entries
                       if not e.get("sent_lora") and not e.get("queued_lora")
                       and not e.get("dropped")]
        entries = entries[-max(1, int(count)):]
        queued = 0
        for entry in entries:
            if entry.get("queued_lora") and not entry.get("sent_lora"):
                continue
            if not self.may_forward(entry.get("peer")):
                continue
            self.meshtastic.send_history_entry(entry)
            queued += 1
        return queued

    async def broadcast(self, message: str) -> None:
        """Send a bridge notice to connected phones (never stored)."""
        if not self.connected:
            log.debug("Некому отправлять ответ Bitchat (%d символов)",
                      len(message))
            return
        packet = self.build_packet(TYPE_MESSAGE, pad_body(message),
                                   recipient=BROADCAST_ID)
        await self._broadcast_packet(packet)

    async def announce_loop(self) -> None:
        while not self._stopping:
            await asyncio.sleep(60)
            if not self.connected:
                continue
            packet = self.build_announce()
            for addr, client in list(self.connected.items()):
                try:
                    await self._write(client, packet)
                except Exception as exc:  # noqa: BLE001
                    log.debug("Повторный announce для %s не удался: %s", addr, exc)

    async def maintenance_loop(self) -> None:
        """Keep the phone link alive and retry pending deliveries.

        Two jobs:

        * watchdog — Bitchat (and the Windows BLE stack) drop an idle link
          after a while; a phone that changed address shows up under a new
          address. A link that stops answering for ``LINK_TIMEOUT`` seconds is
          closed and re-established instead of silently going dead.
        * delivery — retry a partially sent history without waiting for a new
          event.
        """
        while not self._stopping:
            await asyncio.sleep(20)
            await self._watchdog()
            # A phone that never sent anything on this link gets one more
            # announce nudge; a phone that answered is kept warm by the
            # watchdog itself.
            now = time.time()
            for addr, client in list(self.connected.items()):
                if self._last_seen.get(addr):
                    continue
                if now - self._opened_at.get(addr, now) < 45:
                    continue
                nudge = self.last_nudge.get(addr, 0.0)
                if now - nudge < 35:
                    continue
                self.last_nudge[addr] = now
                try:
                    await self._write(client, self.build_announce())
                except Exception as exc:  # noqa: BLE001
                    log.debug("Напоминание для %s не удалось: %s", addr, exc)
            if self.connected and self.meshtastic:
                if any(not e.get("delivered")
                       for e in list(self.meshtastic.history_lora)):
                    await self.flush_undelivered()

    async def _watchdog(self) -> None:
        """Drop dead links and keep the live ones warm."""
        now = time.time()
        for addr, client in list(self.connected.items()):
            alive = True
            try:
                alive = bool(client.is_connected)
            except Exception:  # noqa: BLE001
                alive = False

            # A link that stopped answering for too long is dead even if the
            # stack still reports it as connected.  A link that was just
            # opened has no packet yet; the grace period covers that.
            last = self._last_seen.get(addr, 0.0)
            opened = max(last, self._opened_at.get(addr, 0.0))
            if alive and opened and now - opened > LINK_TIMEOUT:
                log.info("Пир %s молчит %.0f c — переподключаюсь",
                         addr, now - opened)
                alive = False

            if not alive:
                self._drop_link(addr, force=True)
                continue

            # Keepalive: a tiny announce refreshes Bitchat's idle timer, and
            # the phone answers it, which is what the watchdog checks.  A
            # polite spacing of ~15 s proved enough in live tests; a longer
            # gap lets iOS drop the link.
            last_ka = self._last_keepalive.get(addr, 0.0)
            if now - last_ka >= KEEPALIVE_SECONDS:
                try:
                    await self._write(client, self.build_announce())
                except Exception as exc:  # noqa: BLE001
                    log.debug("Keepalive для %s не удался: %s", addr, exc)
                    self._drop_link(addr, force=True)
                self._last_keepalive[addr] = now

    def _drop_link(self, addr: str, force: bool = False) -> None:
        """Forget a link so the scanner can reconnect to this phone."""
        client = self.connected.pop(addr, None)
        self._chars.pop(addr, None)
        self._last_seen.pop(addr, None)
        self._opened_at.pop(addr, None)
        self._last_keepalive.pop(addr, None)
        self.last_nudge.pop(addr, None)
        self.connecting.discard(addr)
        if client is not None:
            with contextlib.suppress(Exception):
                asyncio.get_running_loop().create_task(client.disconnect())

    async def _drop_link(self, addr: str, force: bool = False) -> None:
        client = self.connected.pop(addr, None)
        self._chars.pop(addr, None)
        self._last_seen.pop(addr, None)
        self._opened_at.pop(addr, None)
        self._last_keepalive.pop(addr, None)
        self.last_nudge.pop(addr, None)
        self.connecting.discard(addr)
        if client is not None:
            with contextlib.suppress(Exception):
                await client.disconnect()

    # ------------------------------------------------------------ GUI hooks
    def get_stats(self) -> dict:
        """Live counters for a user interface; no message text, no addresses.

        Called from the GUI thread while the engine runs in its own thread,
        hence: every container is iterated over a copy and nothing is
        mutated here.
        """
        buffered = 0
        blocked = 0
        for entry in list(self.history_bitchat):
            if entry.get("sent_lora") or entry.get("queued_lora"):
                continue
            if self.may_forward(entry.get("peer")):
                buffered += 1
            else:
                blocked += 1
        peers = []
        for peer in _known_peers(self):
            peers.append({
                "id": peer,
                "label": _peer_label(self, peer),
                "fingerprint": self.peer_fingerprints.get(peer, ""),
                "bound": peer == self.bound_peer,
            })
        label = ""
        fingerprint = ""
        if self.bound_peer:
            label = self.peer_nicknames.get(self.bound_peer, "") or \
                "@" + self.bound_peer[:4]
            fingerprint = self.peer_fingerprints.get(self.bound_peer, "")
        return {
            "forward_mode": self.forward_mode,
            "forward_name": _forward_mode_name(self),
            "sources": sorted(self.bitchat_sources),
            "replied": sorted(self.bitchat_replied),
            "full_sync": bool(self.full_sync),
            "bound": bool(self.bound_peer),
            "bound_label": label,
            "bound_fingerprint": fingerprint,
            "connected": list(self.connected),
            "peers": peers,
            "queued_to_lora": buffered,
            "blocked": blocked,
            "_latest": getattr(self, "_gui_latest", None),
            "_sent": getattr(self, "_gui_sent", 0),
            "_dropped": getattr(self, "_gui_dropped", 0),
            "_last_rx": getattr(self, "_gui_last_rx", 0.0),
            "_last_tx": getattr(self, "_gui_last_tx", 0.0),
        }

    def set_forward_mode_gui(self, mode: str,
                             sources: Optional[set] = None) -> bool:
        """Switch the forwarding mode from a user interface.

        The console asks for two confirmations before it calls this; the GUI
        does the same and passes ``sources`` for ``custom``.
        """
        if mode not in ("bound", "custom", "all", "replies"):
            return False
        if mode == "custom":
            chosen = {p for p in (sources or set())
                      if p and p != self.bound_peer}
            if not chosen:
                return False
            self.bitchat_sources = chosen
        self.set_forward_mode(mode)
        return True

    def bind_peer(self, peer: str,
                  nickname: Optional[str] = None,
                  fingerprint: Optional[str] = None,
                  signing_pub: Optional[bytes] = None) -> None:
        """Bind the phone that the owner confirmed in the window.

        The console stores the peer id after two ``yes`` and the scanner
        accepts only that peer; the window hands the same values in here
        instead.  The BLE address is not part of the binding: iOS rotates
        it, so the identity is the peer id plus the announced key.
        """
        peer = (peer or "").strip().lower()
        if not peer:
            return
        self.bound_peer = peer
        self.target_peer = peer
        if nickname:
            self.peer_nicknames[peer] = nickname
        if signing_pub:
            self.peer_keys[peer] = signing_pub
            self.peer_fingerprints[peer] = (fingerprint
                                            or peer_fingerprint(signing_pub))
        elif fingerprint:
            self.peer_fingerprints[peer] = fingerprint

    def reset_binding_gui(self) -> None:
        """Let the bound phone go without stopping the bridge.

        The scanner keeps running, so the next phone that announces can be
        bound; the confirmations are asked again.  Must run on the loop.
        """
        self.bound_peer = None
        self.target_peer = None
        self.private_confirmed = False
        self.bitchat_sources = set()
        self.bitchat_replied = set()
        self._last_public_sender = None
        self.set_forward_mode("bound")
        for addr in list(self.connected):
            asyncio.get_running_loop().create_task(
                self._drop_link(addr, force=True))

    async def stop(self) -> None:
        self._stopping = True
        for client in list(self.connected.values()):
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                pass
        self.connected.clear()
        # Nothing may stay readable in memory after the bridge stops.
        for entry in list(self.history_bitchat):
            entry["sealed"] = b""
            entry["preview"] = ""
        self._fragments.clear()
        if self.meshtastic:
            for entry in list(self.meshtastic.history_lora):
                entry["sealed"] = b""
            for entry in self.meshtastic.pending_texts:
                entry["sealed"] = b""
        wipe_sensitive_memory()
        truncate_logs()


# --------------------------------------------------------------------------
# Interactive menu
# --------------------------------------------------------------------------
def scan_wifi_devices_quiet(port: int = MESHTASTIC_TCP_PORT) -> List[dict]:
    """Same search as ``scan_wifi_devices``, but without printing.

    The window has no console to print to (a frozen windowed build has no
    stdout at all), so it uses this form and shows the outcome in its own
    list.  The console keeps the printing one.
    """
    networks = connected_networks()
    if not networks:
        return []
    mdns_result: dict = {}

    def _mdns() -> None:
        addr = _mdns_host(port)
        if addr:
            mdns_result["addr"] = addr

    mdns_thread = threading.Thread(target=_mdns, daemon=True)
    mdns_thread.start()

    devices = asyncio.run(_discover_tcp_devices(port, networks, quiet=True))
    if not devices and mdns_result.get("addr"):
        devices = asyncio.run(_discover_tcp_devices(
            port, [{"network": ipaddress.IPv4Network(
                f"{mdns_result['addr']}/32", strict=False)}], quiet=True))
    return devices


def parse_transport_text(raw: str) -> Optional[dict]:
    """Turn a typed address into a transport: IP, COM port or BLE address.

    The same rules as the console's "enter the address by hand" item, kept
    in one place so both front ends accept exactly the same input.
    """
    text = (raw or "").strip()
    if not text:
        return None
    upper = text.upper()
    if upper.startswith("COM"):
        return {"kind": "serial", "target": upper,
                "label": f"{upper} (USB)"}
    if text.count(".") == 3 and text.replace(".", "").isdigit():
        return {"kind": "tcp", "target": text,
                "label": f"{text}:{MESHTASTIC_TCP_PORT} (Wi-Fi)"}
    return {"kind": "ble", "target": text, "label": f"{text} (BLE)"}


def _print_devices(devices: List[dict]) -> None:
    for i, dev in enumerate(devices, 1):
        print(f"  {i}) {dev['label']}")
    print("  0) назад")


def _pick_device(devices: List[dict]) -> Optional[dict]:
    if not devices:
        return None
    _print_devices(devices)
    while True:
        try:
            raw = input("Номер устройства: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if raw in ("0", ""):
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(devices):
            return devices[int(raw) - 1]
        print("Нет такого номера.")


def _channel_display_name(ch, index: int) -> str:
    try:
        name = ch.settings.name
    except Exception:  # noqa: BLE001
        name = ""
    return name or ("Primary" if index == 0 else f"канал {index}")


def choose_node(mesh: "MeshtasticHandler") -> Optional[dict]:
    """Pick one node from the radio's full node DB, paginated by 20."""
    nodes = []
    try:
        nodes = [n for n in (mesh.interface.nodes or {}).values()
                 if n.get("num") is not None]
    except Exception:  # noqa: BLE001
        nodes = []
    if not nodes:
        print("Нод-база пуста — радио ещё не собрало список узлов.")
        return None

    nodes.sort(key=lambda n: n.get("lastHeard") or 0, reverse=True)
    total = len(nodes)
    page_size = 20
    pages = (total + page_size - 1) // page_size
    page = 0

    def node_line(n: int, node: dict) -> str:
        user = node.get("user") or {}
        name = user.get("longName") or user.get("shortName") or "?"
        nid = user.get("id") or f"!{int(node['num']):08x}"
        return f"  {n}) {name} — {nid}"

    while True:
        start = page * page_size
        end = min(start + page_size, total)
        print(f"\nУзлы Meshtastic — страница {page + 1}/{pages}, всего {total}:")
        for i in range(start, end):
            print(node_line(i + 1, nodes[i]))
        print("  n) следующая страница   p) предыдущая   "
              "номер — выбрать   0) назад")
        try:
            raw = input("Номер узла (или short name / !id): ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if raw in ("0", ""):
            return None
        low = raw.lower()
        if low in ("n", "н", "next", "дальше"):
            page = min(page + 1, pages - 1)
            continue
        if low in ("p", "п", "prev", "назад"):
            page = max(page - 1, 0)
            continue
        if raw.isdigit() and 1 <= int(raw) <= total:
            node = nodes[int(raw) - 1]
            user = node.get("user") or {}
            name = user.get("longName") or user.get("shortName") or raw
            return {"kind": "dm", "node": node.get("num"), "label": name}
        resolved = mesh.resolve_destination(raw)
        if resolved is not None:
            return {"kind": "dm", "node": resolved,
                    "label": mesh._node_label(resolved)}
        print("Такой узел не найден, попробуйте ещё раз.")


def choose_chat(mesh: "MeshtasticHandler") -> Optional[dict]:
    """Let the user bind the bridge to one of the radio's channels or a DM."""
    entries = []
    for i, ch in enumerate(mesh._channels()):
        if not mesh._is_enabled(ch):
            continue
        name = _channel_display_name(ch, i)
        if name and name.lower() != "primary":
            label = name
        elif i == 0:
            label = "Общий канал"
        else:
            label = f"Канал {i}"
        entries.append((label, {"kind": "channel", "index": i}))

    print("\nВыберите беседу:")
    for n, (label, _target) in enumerate(entries, 1):
        print(f"  {n}) {label}")
    dm_pos = len(entries) + 1
    print(f"  {dm_pos}) Личный чат с узлом…")
    print("  0) назад")

    while True:
        try:
            raw = input("Выбор: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if raw in ("0", ""):
            return None
        if raw.isdigit():
            n = int(raw)
            if 1 <= n <= len(entries):
                return entries[n - 1][1]
            if n == dm_pos:
                picked = choose_node(mesh)
                if picked:
                    return picked
                continue
        print("Нет такого пункта.")


def _ask_scan_port(current: int) -> Optional[int]:
    """After an empty Wi-Fi scan: change the port or return to the menu."""
    print()
    print("  1) Изменить порт поиска")
    print("  2) Вернуться в основное меню")
    while True:
        try:
            raw = input("Выбор [2]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if raw in ("", "2"):
            return None
        if raw == "1":
            try:
                value = input(f"Порт поиска [{current}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                return None
            if not value:
                return current
            if value.isdigit() and 1 <= int(value) <= 65535:
                return int(value)
            print("Порт должен быть числом от 1 до 65535.")
            continue
        print("Введите 1 или 2.")


def choose_transport() -> Optional[dict]:
    while True:
        print()
        print("=" * 60)
        print("  Meshtastic ↔ Bitchat — выбор радио")
        print("=" * 60)
        print("  1) Wi-Fi  — найти Meshtastic в локальной сети")
        print("  2) Bluetooth — найти Meshtastic по BLE")
        print("  3) USB    — список COM-портов")
        print("  4) Ввести адрес вручную (IP / COM / BLE)")
        print("  0) Выход")
        print()
        try:
            choice = input("Выбор: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None

        if choice == "0":
            return None

        if choice == "1":
            port = MESHTASTIC_TCP_PORT
            while True:
                devices = scan_wifi_devices(port)
                if devices:
                    dev = _pick_device(devices)
                    if dev:
                        return dev
                    break
                new_port = _ask_scan_port(port)
                if new_port is None:
                    break
                port = new_port

        elif choice == "2":
            dev = _pick_device(scan_ble_devices())
            if dev:
                return dev

        elif choice == "3":
            dev = _pick_device(scan_serial_devices())
            if dev:
                return dev

        elif choice == "4":
            raw = input("Введите IP / COM-порт / BLE-адрес: ").strip()
            if not raw:
                continue
            if raw.upper().startswith("COM"):
                return {"kind": "serial", "target": raw.upper(),
                        "label": f"{raw.upper()} (USB)"}
            if raw.count(".") == 3 and raw.replace(".", "").isdigit():
                return {"kind": "tcp", "target": raw,
                        "label": f"{raw}:{MESHTASTIC_TCP_PORT} (Wi-Fi)"}
            return {"kind": "ble", "target": raw, "label": f"{raw} (BLE)"}

        else:
            print("Введите цифру из меню.")


def transport_from_config(cfg: dict) -> Optional[dict]:
    tr = cfg.get("transport") or {}
    if tr.get("kind") and tr.get("target"):
        entry = {"kind": tr["kind"], "target": tr["target"],
                 "label": f"{tr['kind']} {tr['target']}"}
        if tr.get("port"):
            entry["port"] = int(tr["port"])
            entry["label"] = f"{tr['kind']} {tr['target']}:{entry['port']}"
        return entry
    return None


def parse_chat(value: str) -> Optional[dict]:
    """Parse --chat: 'all', '0'..'7', 'dm:node' or '!a1b2c3d4'."""
    raw = (value or "").strip()
    if not raw:
        return None
    low = raw.lower()
    if low in ("all", "все", "*"):
        return {"kind": "all"}
    if low.startswith("dm:"):
        return {"kind": "dm", "node": raw.split(":", 1)[1].strip()}
    if raw.isdigit():
        return {"kind": "channel", "index": int(raw)}
    return {"kind": "dm", "node": raw}


def chat_from_config(cfg: dict) -> dict:
    chat = cfg.get("chat")
    if isinstance(chat, dict) and chat.get("kind"):
        return chat
    if isinstance(chat, str):
        return parse_chat(chat) or {"kind": "all"}
    if "meshtastic_channel" in cfg:
        return {"kind": "channel", "index": int(cfg["meshtastic_channel"] or 0)}
    return {"kind": "all"}


def save_transport(path: Optional[str], transport: dict) -> None:
    """Remember the chosen radio, the way the console menu does.

    Only the radio goes into the file.  The phone is confirmed on every start
    and its identity is never written anywhere (see DEVELOPMENT.md §7).
    """
    if not path:
        return
    try:
        cfg = load_config(path)
        cfg["transport"] = {k: v for k, v in transport.items()
                            if k in ("kind", "target", "port")}
        save_config(path, cfg)
    except Exception as exc:  # noqa: BLE001
        log.debug("Не удалось сохранить радио: %s", exc)


def save_forward_mode(path: Optional[str], mode: str) -> None:
    """Remember only the mode, never the list of extra phones."""
    if not path:
        return
    try:
        cfg = load_config(path)
        cfg["bitchat_forward"] = mode
        save_config(path, cfg)
    except Exception as exc:  # noqa: BLE001
        log.debug("Не удалось сохранить режим пересылки: %s", exc)


def describe_chat_target(mesh: "MeshtasticHandler", chat: dict) -> str:
    """Whether *chat* exists on the connected radio, in one honest line.

    The console asks the radio itself when the owner picks a chat; the
    window asks the same question here.  A connection is read, never made:
    an offline radio means "not checked yet", not "wrong".
    """
    kind = (chat or {}).get("kind")
    if kind == "all":
        return "Всё: каналы и личные сообщения — разрешено."
    if kind != "channel":
        return "Личный чат выбирается списком узлов этого радио."
    index = int((chat or {}).get("index", 0))
    try:
        if mesh.interface is None:
            return (f"Канал {index}: радио ещё не на связи, проверка будет "
                    "при запуске.")
        if mesh.channel_exists(index):
            return f"Канал {index} ({mesh.channel_label(index)}): есть на радио."
        return (f"Канала {index} на этом радио нет — выберите другой или "
                "«всё».")
    except Exception as exc:  # noqa: BLE001
        return f"Канал {index} не проверен: {exc}"


def list_chat_entries(mesh: "MeshtasticHandler") -> List[dict]:
    """The radio's chats as pickable items (channels + "all").

    Same labels as the console's "choose a chat" menu; the direct chat with
    one node is a separate item there and in the window, so it is not here.
    """
    entries: List[dict] = []
    for i, ch in enumerate(mesh._channels()):
        if not mesh._is_enabled(ch):
            continue
        name = _channel_display_name(ch, i)
        if name and name.lower() != "primary":
            label = name
        elif i == 0:
            label = "Общий канал"
        else:
            label = f"Канал {i}"
        entries.append({"label": label, "target": {"kind": "channel",
                                                   "index": i}})
    entries.append({"label": "Всё: каналы и личные сообщения",
                    "target": {"kind": "all"}})
    return entries


def list_nodes(mesh: "MeshtasticHandler") -> List[dict]:
    """The radio's node database, most recently heard first."""
    try:
        nodes = [n for n in (mesh.interface.nodes or {}).values()
                 if n.get("num") is not None]
    except Exception:  # noqa: BLE001
        nodes = []
    nodes.sort(key=lambda n: n.get("lastHeard") or 0, reverse=True)
    out = []
    for node in nodes:
        user = node.get("user") or {}
        name = user.get("longName") or user.get("shortName") or "?"
        nid = user.get("id") or f"!{int(node['num']):08x}"
        out.append({"label": f"{name} — {nid}",
                    "target": {"kind": "dm", "node": node.get("num")},
                    "name": name})
    return out


# --------------------------------------------------------------------------
# Manual sync + runtime console
# --------------------------------------------------------------------------
SYNC_COUNTS = (5, 10, 20, 50)


class SyncScheduler:
    """Keeps at most one repeating sync job per direction."""

    def __init__(self) -> None:
        self.jobs: List[dict] = []
        self._lock = threading.Lock()

    def add(self, direction: str, count: int, interval_seconds: float) -> None:
        with self._lock:
            self.jobs = [j for j in self.jobs if j["direction"] != direction]
            if interval_seconds > 0:
                self.jobs.append({
                    "direction": direction,
                    "count": int(count),
                    "interval": float(interval_seconds),
                    "next_at": time.time() + float(interval_seconds),
                })

    def remove(self, direction: str) -> None:
        with self._lock:
            self.jobs = [j for j in self.jobs if j["direction"] != direction]

    def due(self, now: Optional[float] = None) -> List[dict]:
        now = time.time() if now is None else now
        with self._lock:
            return [j for j in self.jobs if j["next_at"] <= now]

    @staticmethod
    def mark_sent(job: dict) -> None:
        job["next_at"] = time.time() + job["interval"]

    def clear(self) -> None:
        with self._lock:
            self.jobs.clear()

    def describe(self) -> str:
        with self._lock:
            if not self.jobs:
                return "периодическая синхронизация выключена"
            parts = []
            for job in self.jobs:
                name = ("Meshtastic → Bitchat" if job["direction"] == "lora2bit"
                        else "Bitchat → Meshtastic")
                parts.append(f"{name}: последние {job['count']} каждые "
                             f"{_format_interval(job['interval'])}")
            return "; ".join(parts)


def _format_interval(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds >= 86400 and seconds % 86400 == 0:
        days = int(seconds // 86400)
        return f"{days} дн."
    if seconds >= 3600 and seconds % 3600 == 0:
        hours = int(seconds // 3600)
        return f"{hours} ч."
    if seconds >= 60 and seconds % 60 == 0:
        minutes = int(seconds // 60)
        return f"{minutes} мин."
    return f"{int(seconds)} с"


def _read_choice(prompt: str, allowed, default=None):
    while True:
        try:
            raw = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            return default
        low = raw.lower()
        if low in ("0", "q", "отмена", "назад"):
            return None
        if raw in allowed:
            return raw
        print("Нет такого пункта.")


PRIVATE_WARNING_1 = (
    "ВНИМАНИЕ. Канал считается приватным.\n"
    "Мост работает как транспорт: он передаёт данные между Bluetooth и LoRa.\n"
    "Для действительно закрытого содержимого шифруйте его заранее отдельным\n"
    "приложением (например, OpenKeychain/PGP) и отправляйте уже шифротекст.\n"
    "Вопрос: включить автоматическую синхронизацию для приватного канала?")

PRIVATE_WARNING_2 = (
    "ВТОРОЕ ПОДТВЕРЖДЕНИЕ.\n"
    "Даже без чтения текста участники обмена, время и объём трафика видны.\n"
    "При автоматической синхронизации это происходит без вашего участия.\n"
    "Вопрос: подтверждаете режим для приватного канала?")


def confirm_private_channel(ble: "BitchatBLEHandler", purpose: str) -> bool:
    """Two explicit confirmations, once per session, for private channels."""
    if ble.private_confirmed:
        return True
    print()
    print(PRIVATE_WARNING_1)
    try:
        first = input("Введите yes для подтверждения: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if first not in ("yes", "да"):
        say(f"[Sync] {purpose}: отменено на первом подтверждении.")
        return False
    print()
    print(PRIVATE_WARNING_2)
    try:
        second = input("Введите yes ещё раз: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if second not in ("yes", "да"):
        say(f"[Sync] {purpose}: отменено на втором подтверждении.")
        return False
    ble.private_confirmed = True
    say("[Sync] приватный канал подтверждён на этот сеанс.")
    return True


# --------------------------------------------------------------------------
# Bitchat -> LoRa forwarding modes ("b" in the console)
# --------------------------------------------------------------------------
# Simple rules, deliberately:
#   bound  — only the phone the bridge is bound to (default);
#   custom — the bound phone plus phones chosen from a list;
#   all    — everything that reaches the phone link.
# Only the *mode* is written to the config file, never the list of phones,
# and the mode never widens a private channel without the usual two "yes".

FORWARD_WARNING_ALL = (
    "ВНИМАНИЕ: режим «всё, что приходит на телефон».\n"
    "Мост будет пересылать в LoRa сообщения любых авторов, которые дойдут\n"
    "до телефона. В цепочке фрагментов нет подписи, поэтому автора в таком\n"
    "режиме можно подделать, а часть сообщений группы до моста не дойдёт.\n"
    "Имена авторов берутся из их announce или остаются в виде @xxxx.")

FORWARD_WARNING_CUSTOM = (
    "ВНИМАНИЕ: пересылка от выбранных телефонов Bitchat.\n"
    "Мост будет пересылать в LoRa сообщения не только привязанного\n"
    "телефона, но и тех пиров, которых вы отметите. Их подпись проверяется\n"
    "по ключу из announce, но увидите вы лишь то, что телефон переслал.")

FORWARD_WARNING_REPLIES = (
    "Режим «те, кому я ответил».\n"
    "В LoRa уходят сообщения привязанного телефона и тех людей, которым вы\n"
    "сами написали в общем чате после их сообщения. Пока вы человеку не\n"
    "ответили, его сообщения в LoRa не идут. Список собирается сам и живёт\n"
    "до конца работы моста; текст сообщений для этого не читается.\n"
    "Общий чат не адресован лично вам, поэтому «ответить» мост понимает\n"
    "только так: ваше сообщение ушло в #mesh после его сообщения.")

FORWARD_HINT = ("(подсказка: список обновляется по мере поступления announce "
                "от Bitchat-пиров)")


def _peer_label(ble: "BitchatBLEHandler", peer: str) -> str:
    """One console line for a known Bitchat peer (never the message text)."""
    peer = (peer or "").lower()
    if not peer:
        return "?"
    if ble.bound_peer and peer == ble.bound_peer:
        mark = " [привязан]"
    elif peer in ble.bitchat_sources:
        mark = " [выбран]"
    else:
        mark = ""
    nick = ble.peer_nicknames.get(peer) or \
        ble.peer_aliases.get(f"peer:{peer}") or ""
    fp = ble.peer_fingerprints.get(peer) or ""
    parts = [peer]
    if nick:
        parts.append(f"«{nick}»")
    if fp:
        parts.append(fp)
    return " — ".join(parts) + mark


def _known_peers(ble: "BitchatBLEHandler") -> List[str]:
    """Peer ids whose announce passed the signature check this session."""
    peers = set(ble.peer_keys.keys())
    if ble.bound_peer:
        peers.add(ble.bound_peer)
    peers.update(ble.bitchat_sources)
    return sorted(peers, key=lambda p: (p != ble.bound_peer, p))


def _scan_new_phones(ble: "BitchatBLEHandler",
                     seconds: float) -> int:
    """Find Bitchat phones nearby and remember the peers that answer.

    A scan is only useful while no link is up: probing a second phone would
    steal airtime from the bound phone and can make iOS drop the bridge.
    The result only fills the peer list; nothing extra is accepted here.
    """
    if ble.connected or ble.connecting:
        print("Телефон уже подключён — сканирование пропущено, чтобы не "
              "мешать связи. Список пополняется announce-пакетами.")
        return 0
    phones = scan_bitchat_peers(seconds)
    added = 0
    for phone in phones:
        peer = (phone.get("peer") or "").lower()
        if not peer or not phone.get("signature_ok", True):
            continue
        if not ble.peer_keys.get(peer) and phone.get("signing_pub"):
            ble.peer_keys[peer] = phone["signing_pub"]
            ble.peer_fingerprints[peer] = phone.get("fingerprint")
        nick = phone.get("nickname")
        if nick:
            key = peer if peer == ble.bound_peer else f"peer:{peer}"
            table = ble.peer_nicknames if peer == ble.bound_peer \
                else ble.peer_aliases
            table[key] = nick
        if peer not in ble.peer_keys:
            continue
        added += 1
    print(f"Найдено телефонов Bitchat: {len(phones)}, с проверенным "
          f"announce: {added}")
    return added


def _pick_sources(ble: "BitchatBLEHandler", want: Optional[int] = None) -> bool:
    """Pick phones for the "custom" mode: numbers in one line, comma-separated.

    ``want`` is the source count the owner asked for ("two phones", "a hundred
    phones").  It is only used for the hint line: a list may hold any number of
    peers, above it the bridge never guesses which ones were meant.  Returns
    True when a non-empty list was stored.
    """
    while True:
        peers = _known_peers(ble)
        print()
        print("Известные Bitchat-пиры (подпись проверена):")
        for i, peer in enumerate(peers, 1):
            print(f"  {i}) {_peer_label(ble, peer)}")
        print("  s) найти телефоны через Bluetooth")
        print("  0) назад")
        if want:
            print(f"Выберите {want} телефонов-источников "
                  "(привязанный и так входит всегда).")
        print(FORWARD_HINT)
        try:
            raw = input("Номера через запятую (125 = 1,2,5): ").strip()
        except (EOFError, KeyboardInterrupt):
            return False
        low = raw.lower()
        if low in ("", "0", "q", "назад", "отмена"):
            return False
        if low in ("s", "scan", "поиск", "сканировать"):
            # The bound phone is skipped on purpose: it already is a source.
            _scan_new_phones(ble, ble.scan_seconds * 2)
            continue
        chosen = set()
        for token in re.split(r"[,\s;]+", raw):
            if not token:
                continue
            if not token.isdigit():
                print(f"Не понял «{token}» — введите номера.")
                chosen.clear()
                break
            index = int(token)
            if not 1 <= index <= len(peers):
                print(f"Нет номера {index}.")
                chosen.clear()
                break
            peer = peers[index - 1]
            if ble.bound_peer and peer == ble.bound_peer:
                continue  # it is always a source in every mode
            chosen.add(peer)
        if not chosen:
            print("Ничего не выбрано.")
            continue
        ble.bitchat_sources = chosen
        print("Выбрано пиров: " + str(len(chosen)))
        return True


def _forward_mode_name(ble: "BitchatBLEHandler") -> str:
    """One human line describing what currently leaves for LoRa."""
    if ble.forward_mode == "all":
        return "любой телефон, чьи сообщения дошли до моста"
    if ble.forward_mode == "custom":
        return (f"привязанный + {len(ble.bitchat_sources)} выбранных "
                "телефонов")
    if ble.forward_mode == "replies":
        return (f"привязанный + {len(ble.bitchat_replied)} телефонов, "
                "которым вы ответили")
    return "только привязанный телефон"


def _confirm_forward(text: str) -> bool:
    """Two explicit "yes", the same rule as for a private channel."""
    print()
    print(text)
    first = _typed_yes("Введите yes для подтверждения: ")
    second = first and _typed_yes("Введите yes ещё раз: ")
    return bool(second)


def console_forward_menu(ble: "BitchatBLEHandler",
                         loop: asyncio.AbstractEventLoop,
                         on_change=None) -> None:
    """Console menu "b": which phones may send to LoRa.

    The owner chooses by *source*, not by an internal mode name, because that
    is how the question is actually asked: one phone, two phones, many phones,
    or anything that reaches the bridge.  "Two" and "a hundred" are the same
    stored mode (``custom``) and differ only in how many peers the list holds;
    the list itself is never written to the config file.
    """
    while True:
        mode = ble.forward_mode
        print()
        print(f"Bitchat → LoRa сейчас: {_forward_mode_name(ble)}")
        print("Откуда брать сообщения для LoRa:")
        print("  1) один телефон — только привязанный")
        print("  2) два телефона — привязанный + ещё один")
        print("  3) много телефонов — привязанный + список")
        print("  4) любой телефон — всё, что доходит до моста")
        print("  5) те, кому я ответил — чужие только после вашего ответа")
        print("  0) назад")
        choice = _read_choice("Пункт: ", {"1", "2", "3", "4", "5"})
        if choice is None:
            return

        # 1) One phone: the plain default, no confirmation needed.
        if choice == "1":
            ble.set_forward_mode("bound")
            print("В LoRa пойдут только сообщения привязанного телефона.")
            if on_change:
                on_change("bound")
            continue

        # 2) and 3) are the same mode with a different size of the list.
        if choice in ("2", "3"):
            want = 1 if choice == "2" else None
            if not _pick_sources(ble, want):
                continue
            count = len(ble.bitchat_sources)
            if choice == "2" and count > 1:
                print(f"Отмечено {count} телефонов: в LoRa пойдут сообщения "
                      "всех отмеченных и привязанного.")
            print()
            print(FORWARD_WARNING_CUSTOM)
            if not _confirm_forward("Подтвердите этот выбор."):
                ble.bitchat_sources = set()
                print("Режим не изменён.")
                continue
            ble.set_forward_mode("custom")
            say(f"[Bitchat] в LoRa идут сообщения от {count} выбранных "
                "пиров + привязанного телефона")
            if on_change:
                on_change("custom")
            continue

        # 5) Only people the owner answered: the list is learned live, so this
        #    mode is available at once and fills up as the owner replies.
        if choice == "5":
            print()
            print(FORWARD_WARNING_REPLIES)
            if ble.bound_peer:
                print(f"Сейчас в списке: {len(ble.bitchat_replied)}")
            if not _confirm_forward("Подтвердите этот выбор."):
                print("Режим не изменён.")
                continue
            ble.set_forward_mode("replies")
            say("[Bitchat] в LoRa идут сообщения привязанного телефона и тех, "
                "кому вы ответили в общем чате")
            if on_change:
                on_change("replies")
            continue
        # 4) Any phone: the widest rule, so it asks for the same two "yes".
        if not _confirm_forward(FORWARD_WARNING_ALL):
            print("Режим не изменён.")
            continue
        ble.set_forward_mode("all")
        say("[Bitchat] в LoRa идут сообщения от любых авторов")
        if on_change:
            on_change("all")


def console_sync_menu(ble: "BitchatBLEHandler", mesh: "MeshtasticHandler",
                      scheduler: SyncScheduler, loop: asyncio.AbstractEventLoop) -> None:
    print()
    print("Синхронизация:")
    print("  1) Meshtastic → Bitchat (телефону)")
    print("  2) Bitchat → Meshtastic (в LoRa)")
    print("  3) Полная синхронизация в обе стороны (сразу)")
    print("  0) отмена")
    choice = _read_choice("Направление: ", {"1", "2", "3"})
    if choice is None:
        return

    if choice == "3":
        print("Полная синхронизация: каждое новое сообщение сразу уходит "
              "на другую сторону.")
        print("  1) включить")
        print("  2) выключить")
        print("  0) отмена")
        toggle = _read_choice("Режим: ", {"1", "2"})
        if toggle is None:
            return
        if toggle == "1" and not confirm_private_channel(
                ble, "полная синхронизация"):
            return
        ble.full_sync = toggle == "1"
        if ble.full_sync:
            say("[Sync] полная синхронизация включена: новые сообщения идут "
                "в обе стороны сразу.")
            # Push anything that is still waiting, so both sides converge now.
            if ble.connected:
                asyncio.run_coroutine_threadsafe(ble.flush_undelivered(), loop)
            queued = 0
            skipped = 0
            for entry in list(ble.history_bitchat):
                if entry.get("sent_lora") or entry.get("queued_lora"):
                    continue
                # The forwarding mode decides what may leave, also here:
                # a full sync must not push a stranger's message out.
                if not ble.may_forward(entry.get("peer")):
                    skipped += 1
                    continue
                mesh.send_history_entry(entry)
                queued += 1
            if queued:
                say(f"[Sync] в очередь LoRa поставлено: {queued}")
            if skipped:
                say(f"[Sync] не отправлено по режиму пересылки: {skipped} "
                    "(меню «b»)")
        else:
            say("[Sync] полная синхронизация выключена: Bitchat → LoRa снова "
                "только вручную.")
        return

    direction = "lora2bit" if choice == "1" else "bit2lora"

    print("Сколько последних сообщений отправить?")
    for i, count in enumerate(SYNC_COUNTS, 1):
        print(f"  {i}) последние {count}")
    print("  0) отмена")
    count_choice = _read_choice("Количество: ",
                                {str(i) for i in range(1, len(SYNC_COUNTS) + 1)})
    if count_choice is None:
        return
    count = SYNC_COUNTS[int(count_choice) - 1]

    print("Повторять автоматически?")
    print("  1) только сейчас (расписание не менять)")
    print("  2) каждые N минут")
    print("  3) каждые N дней")
    print("  4) выключить повтор")
    print("  0) отмена")
    repeat_choice = _read_choice("Период: ", {"1", "2", "3", "4"})
    if repeat_choice is None:
        return
    if repeat_choice == "4":
        scheduler.remove(direction)
        say("[Sync] периодическая синхронизация для этого направления выключена.")
        return

    interval = 0.0
    if repeat_choice == "2":
        try:
            minutes = float(input("Интервал в минутах (например 5): ").strip() or "5")
        except (ValueError, EOFError, KeyboardInterrupt):
            print("Не понял интервал, повтор выключен.")
            minutes = 0
        interval = max(0.0, minutes * 60.0)
    elif repeat_choice == "3":
        try:
            days = float(input("Интервал в днях (например 1): ").strip() or "1")
        except (ValueError, EOFError, KeyboardInterrupt):
            print("Не понял интервал, повтор выключен.")
            days = 0
        interval = max(0.0, days * 86400.0)

    if interval > 0:
        scheduler.add(direction, count, interval)
        if not ble.private_confirmed:
            for job in scheduler.jobs:
                if job["direction"] == direction:
                    job["needs_confirm"] = True

    if direction == "lora2bit":
        coro = ble.resend_lora(count)
        action = f"Отправляю в телефон последние {count} сообщений"
    else:
        coro = ble.resend_bitchat(count)
        action = f"Ставлю в очередь LoRa последние {count} сообщений"

    if repeat_choice == "1":
        suffix = "; без изменения расписания"
    elif interval > 0:
        suffix = f"; повтор каждые {_format_interval(interval)}"
    else:
        suffix = ""
    print(action + suffix)
    if not confirm_private_channel(ble, action.lower()):
        if repeat_choice in ("2", "3") and interval > 0:
            scheduler.remove(direction)
        return
    try:
        future = asyncio.run_coroutine_threadsafe(coro, loop)
    except RuntimeError:
        say("[Sync] мост уже останавливается.")
        return

    def _done(fut) -> None:
        try:
            sent = fut.result()
        except Exception as exc:  # noqa: BLE001
            say(f"[Sync] ошибка: {exc}")
            return
        if direction == "lora2bit":
            say(f"[Sync] отправлено в Bitchat: {sent}")
        else:
            say(f"[Sync] поставлено в очередь LoRa: {sent} "
                f"(интервал между сообщениями {mesh.lora_send_interval:.0f} с)")

    future.add_done_callback(_done)


async def confirm_pending_jobs(ble: "BitchatBLEHandler",
                               scheduler: SyncScheduler) -> None:
    """Ask the private-channel confirmations once, before a scheduled run."""
    for job in list(scheduler.jobs):
        if not job.get("needs_confirm") or ble.private_confirmed:
            continue
        print()
        print(PRIVATE_WARNING_1)
        if not await asyncio.to_thread(_typed_yes,
                                       "Введите yes для подтверждения: "):
            scheduler.remove(job["direction"])
            say("[Sync] периодическая синхронизация отменена.")
            continue
        print()
        print(PRIVATE_WARNING_2)
        if not await asyncio.to_thread(_typed_yes,
                                       "Введите yes ещё раз: "):
            scheduler.remove(job["direction"])
            say("[Sync] периодическая синхронизация отменена.")
            continue
        ble.private_confirmed = True
        job["needs_confirm"] = False


def _typed_yes(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("yes", "да")
    except (EOFError, KeyboardInterrupt):
        return False


async def periodic_sync_loop(ble: "BitchatBLEHandler",
                             mesh: "MeshtasticHandler",
                             scheduler: SyncScheduler) -> None:
    while not ble._stopping and not mesh._stopping:
        await asyncio.sleep(5)
        await confirm_pending_jobs(ble, scheduler)
        for job in scheduler.due():
            if job.get("needs_confirm"):
                scheduler.mark_sent(job)
                continue
            if job["direction"] == "lora2bit":
                sent = await ble.resend_lora(job["count"], only_new=True)
                if sent:
                    say(f"[Sync] по расписанию в Bitchat: {sent}")
            else:
                queued = await ble.resend_bitchat(job["count"], only_new=True)
                if queued:
                    say(f"[Sync] по расписанию в LoRa: {queued}")
            scheduler.mark_sent(job)


def console_loop(ble: "BitchatBLEHandler", mesh: "MeshtasticHandler",
                 scheduler: SyncScheduler, stop_event: asyncio.Event,
                 loop: asyncio.AbstractEventLoop,
                 on_forward_change=None) -> None:
    print()
    print("Мост работает. Команды в консоли:")
    print("  s — синхронизация (направление, 5/10/20/50, период)")
    print("  b — что пересылать из Bitchat в LoRa (телефоны)")
    print("  l — состояние буферов и расписания")
    print("  r — сброс привязки телефона (потребует повторного подтверждения)")
    print("  q — выход")
    print()

    def _help() -> None:
        print("  s — синхронизация, b — источники Bitchat → LoRa, "
              "l — состояние, r — сброс привязки, q — выход")

    while not stop_event.is_set():
        try:
            raw = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            loop.call_soon(stop_event.set)
            return
        if raw in ("q", "quit", "exit", "выход"):
            loop.call_soon(stop_event.set)
            return
        if raw in ("s", "sync", "с", "синхронизация"):
            console_sync_menu(ble, mesh, scheduler, loop)
            continue
        if raw in ("b", "bit", "источники", "б"):
            console_forward_menu(ble, loop, on_change=on_forward_change)
            continue
        if raw in ("l", "list", "status", "состояние"):
            print()
            print(f"  LoRa → Bitchat: {len(mesh.history_lora)} сообщ. в истории, "
                  f"{sum(1 for e in mesh.history_lora if not e.get('delivered'))} "
                  "ещё не доставлено")
            print(f"  Bitchat → LoRa: {len(ble.history_bitchat)} сообщ. в истории, "
                  f"{len(mesh.pending_texts)} в очереди на отправку")
            bound = ble.bound_peer or "не привязан"
            print(f"  Телефон: {bound}")
            names = {"bound": "только привязанный телефон",
                     "custom": "привязанный + выбранные",
                     "all": "любой телефон, дошедший до моста",
                     "replies": "привязанный + те, кому я ответил"}
            print(f"  Bitchat → LoRa: {names.get(ble.forward_mode, ble.forward_mode)}"
                  + (f" ({len(ble.bitchat_sources)} выбранных)"
                     if ble.forward_mode == "custom" else "")
                  + (f" ({len(ble.bitchat_replied)} ответивших)"
                     if ble.forward_mode == "replies" else ""))
            print(f"  Режим: {'полная синхронизация в обе стороны' if ble.full_sync else 'авто только LoRa → Bitchat'}")
            print(f"  {scheduler.describe()}")
            print()
            continue
        if raw in ("r", "reset", "сброс", "перепривязка"):
            # Rebinding is an explicit console action: the confirmations are
            # asked again and the old phone is let go right away.
            print("Сброс привязки: телефон будет отключён, данные Bitchat "
                  "перестанут передаваться.")
            try:
                sure = input("Введите yes, чтобы сбросить привязку: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if sure not in ("yes", "да"):
                print("Сброс отменён.")
                continue
            ble.bound_peer = None
            ble.target_peer = None
            ble.private_confirmed = False
            ble.bitchat_sources = set()
            ble.bitchat_replied = set()
            ble._last_public_sender = None
            ble.set_forward_mode("bound")
            for addr, client in list(ble.connected.items()):
                ble.connected.pop(addr, None)
                ble._last_seen.pop(addr, None)
                ble._chars.pop(addr, None)
                ble.peer_ids.pop(addr, None)
                try:
                    asyncio.run_coroutine_threadsafe(client.disconnect(), loop)
                except Exception:  # noqa: BLE001
                    pass
            print("Привязка сброшена. Остановите мост (q) и запустите снова, "
                  "чтобы подтвердить новый телефон.")
            continue
        if raw in ("h", "?", "help", "помощь"):
            _help()
            continue
        if not raw:
            continue
        _help()


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------
async def run(transport: Optional[dict], name: str, scan_seconds: float,
              channel: int = 0, chat_target: Optional[dict] = None,
              interactive: bool = False, history_limit: int = 100,
              lora_send_interval: float = 10.0,
              lora_stale_seconds: float = 1800.0,
              console: bool = False,
              bitchat_target: Optional[str] = None,
              full_sync: bool = False,
              bitchat_peer: Optional[str] = None,
              forward_mode: str = "bound",
              config_path: Optional[str] = None) -> int:
    loop = asyncio.get_running_loop()
    # Harden the process before any message can arrive: no crash dumps for
    # the interpreter, no debugger or dump tool attached to this process,
    # and message buffers kept in RAM (out of the pagefile).  All of it is
    # best effort and never stops the bridge.
    await asyncio.to_thread(_keep_dumps_off_memory)
    await asyncio.to_thread(_deny_debug)
    await asyncio.to_thread(_lock_process_memory)

    ble = BitchatBLEHandler(loop, name, scan_seconds, history_limit,
                            target_address=bitchat_target,
                            full_sync=full_sync,
                            target_peer=bitchat_peer)
    mesh = MeshtasticHandler(loop, transport, default_channel=channel,
                             lora_send_interval=lora_send_interval,
                             history_limit=history_limit,
                             lora_stale_seconds=lora_stale_seconds)
    mesh.set_chat_target(chat_target or {"kind": "all"})
    ble.set_meshtastic_handler(mesh)
    mesh.set_ble_handler(ble)
    # Which Bitchat senders may reach LoRa.  The mode comes from the user's
    # choice (config file or --bitchat-forward) and decides what the phone
    # part may forward.  Two modes hold a learned or picked list ("custom" and
    # "replies"), and neither list is ever stored: a start therefore falls
    # back to the strict mode, so a restart after a power blip can never
    # silently widen what leaves the radio.
    if forward_mode not in ("bound", "custom", "all", "replies"):
        mode = "bound"
    elif forward_mode in ("custom", "replies"):
        mode = "bound"
    else:
        mode = forward_mode
    ble.set_forward_mode(mode)
    await asyncio.to_thread(mesh.start)

    # Once the radio is reachable, let the user bind the bridge to a chat.
    if interactive and mesh.interface is not None:
        picked = await asyncio.to_thread(choose_chat, mesh)
        if picked:
            mesh.set_chat_target(picked)
    say(f"[Bridge] мост привязан к: {mesh.describe_target()}")

    scan_task = asyncio.create_task(ble.scanner())
    announce_task = asyncio.create_task(ble.announce_loop())
    maintenance_task = asyncio.create_task(ble.maintenance_loop())
    flush_task = asyncio.create_task(mesh.text_flush_loop())
    log_task = asyncio.create_task(log_truncate_loop())
    scheduler = SyncScheduler()
    sync_task = asyncio.create_task(periodic_sync_loop(ble, mesh, scheduler))

    stop_event = asyncio.Event()
    try:
        loop.add_signal_handler(signal.SIGINT, stop_event.set)
        loop.add_signal_handler(signal.SIGTERM, stop_event.set)
    except (NotImplementedError, AttributeError):
        pass

    console_thread = None
    if console:
        # A change of the forwarding mode made in the console is written to
        # the config file, so a power blip (and the restart that follows) does
        # not lose it.  It happens in the console thread and is best effort:
        # a read-only config directory must not break the bridge.
        def _remember_mode(mode: str) -> None:
            if not config_path:
                return
            try:
                cfg = load_config(config_path)
                cfg["bitchat_forward"] = mode
                save_config(config_path, cfg)
            except Exception as exc:  # noqa: BLE001
                log.debug("Не удалось сохранить режим пересылки: %s", exc)

        console_thread = threading.Thread(
            target=console_loop,
            args=(ble, mesh, scheduler, stop_event, loop),
            kwargs={"on_forward_change": _remember_mode},
            daemon=True,
        )
        console_thread.start()

    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        log.info("Останавливаюсь...")
        say("[Bridge] останавливаюсь...")
        await asyncio.to_thread(mesh.stop)
        await ble.stop()
        for task in (scan_task, announce_task, maintenance_task,
                     flush_task, log_task, sync_task):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        truncate_logs()
    return 0


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Meshtastic <-> Bitchat bridge")
    p.add_argument("-c", "--config", default="config.json", help="config file")
    p.add_argument("--menu", action="store_true", help="always show the device menu")
    p.add_argument("--no-menu", action="store_true", help="never show the menu")
    p.add_argument("--host", help="Meshtastic TCP host")
    p.add_argument("--port", help="Meshtastic serial port (COM4)")
    p.add_argument("--ble", dest="ble_address", help="Meshtastic BLE address")
    p.add_argument("--bitchat", metavar="ADDRESS",
                   help="limit the phone search to this BLE address "
                        "(the phone is still confirmed in the console)")
    p.add_argument("--full-sync", action="store_true",
                   help="two-way sync: forward new messages immediately both ways")
    p.add_argument("--no-full-sync", action="store_true",
                   help="disable two-way sync even if config enables it")
    p.add_argument("--bitchat-forward",
                   choices=("bound", "custom", "all", "replies"),
                   metavar="MODE",
                   help="what may be sent from Bitchat to LoRa: 'bound' "
                        "(only the bound phone), 'custom' (list picked in the "
                        "console), 'replies' (phones you answered in the public "
                        "chat), 'all' (everything that reaches the phone)")
    p.add_argument("--name", help="bridge nickname in Bitchat")
    p.add_argument("--channel", type=int, metavar="N",
                   help="default Meshtastic channel index for Bitchat messages")
    p.add_argument("--chat", metavar="TARGET",
                   help="bind to a chat: 'all', channel number 0-7, or dm:NODE")
    p.add_argument("--history", type=int, metavar="N",
                   help="short-lived message buffer size per direction "
                        "(default 100, max 1000)")
    p.add_argument("--lora-interval", type=float, metavar="SEC",
                   help="minimum seconds between messages sent to LoRa (default 10)")
    p.add_argument("--debug", action="store_true", help="verbose logging")
    p.add_argument("--test-send", metavar="TEXT",
                   help="send one message to LoRa and exit")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover
        pass

    args = parse_args(argv if argv is not None else sys.argv[1:])
    cfg = load_config(args.config)
    quiet = bool(cfg.get("quiet", True)) and not args.debug
    truncate_seconds = float(cfg.get("log_truncate_seconds", 300) or 300)
    setup_logging(args.debug, cfg.get("log_file", "bridge.log"),
                  quiet=quiet, truncate_seconds=truncate_seconds)
    log.info("Запуск %s %s", APP_NAME, APP_VERSION)

    name = args.name or cfg.get("name", "MeshBridge")
    scan_seconds = float(cfg.get("ble_scan_seconds", 3.0))
    history_limit = (args.history if args.history is not None
                     else int(cfg.get("history_limit", 100) or 100))
    history_limit = max(1, min(1000, history_limit))
    lora_send_interval = max(0.0, float(cfg.get("lora_send_interval", 10.0) or 0))
    if args.lora_interval is not None:
        lora_send_interval = max(0.0, float(args.lora_interval))
    lora_stale_seconds = max(0.0, float(cfg.get("lora_stale_seconds", 1800) or 0))

    bitchat_target = (args.bitchat or cfg.get("bitchat_target") or "").strip() or None
    # The bound phone is confirmed in the console and never read from the
    # config: on every start the user sees the fingerprint and types yes.
    bitchat_peer = None
    full_sync = bool(cfg.get("full_sync", False))
    if args.full_sync:
        full_sync = True
    if args.no_full_sync:
        full_sync = False

    # What may leave for LoRa from Bitchat.  The mode is remembered in the
    # config file (edited by hand or by the console key "b"); the list of
    # extra phones is never written there, because a person who opens the
    # phone instead of the chat must not be able to widen it silently.
    forward_mode = str(cfg.get("bitchat_forward") or "bound").strip().lower()
    if forward_mode not in ("bound", "custom", "all", "replies"):
        forward_mode = "bound"
    if args.bitchat_forward:
        forward_mode = args.bitchat_forward

    chat_target = parse_chat(args.chat) if args.chat else chat_from_config(cfg)
    if args.channel is not None:
        chat_target = {"kind": "channel",
                       "index": max(0, min(7, args.channel))}
    if chat_target.get("kind") == "channel":
        channel = max(0, min(7, int(chat_target.get("index", 0))))
    else:
        channel = max(0, min(7, int(cfg.get("meshtastic_channel", 0) or 0)))

    cli_transport = None
    if args.host:
        cli_transport = {"kind": "tcp", "target": args.host,
                         "label": f"{args.host} (Wi-Fi)"}
    elif args.port:
        cli_transport = {"kind": "serial", "target": args.port,
                         "label": f"{args.port} (USB)"}
    elif args.ble_address:
        cli_transport = {"kind": "ble", "target": args.ble_address,
                         "label": f"{args.ble_address} (BLE)"}

    if args.test_send:
        mesh = MeshtasticHandler(asyncio.new_event_loop(),
                                 cli_transport or transport_from_config(cfg),
                                 default_channel=channel,
                                 lora_send_interval=lora_send_interval,
                                 history_limit=history_limit,
                                 lora_stale_seconds=lora_stale_seconds)
        mesh.set_chat_target(chat_target)
        ok = mesh.send_text(args.test_send) if mesh._try_connect() else False
        mesh.stop()
        return 0 if ok else 1

    want_menu = args.menu or (not args.no_menu and cli_transport is None
                              and sys.stdin.isatty() and cfg.get("menu", True))
    interactive = want_menu and sys.stdin.isatty()
    console_enabled = not args.no_menu

    while True:
        if want_menu:
            transport = choose_transport()
            if transport is None:
                print("Выход.")
                return 0
            print(f"\nВыбрано: {transport['label']}\n")
            peer = choose_bitchat_peer(scan_seconds * 2)
            # The Bluetooth address chosen earlier belongs to one phone only;
            # re-running the menu must not keep it for a different device.
            bitchat_target = None
            bitchat_peer = None
            if peer and confirm_binding(peer):
                # Only the stable Bitchat identity is used for the binding.
                # The Bluetooth address is shown for reference, but iOS
                # rotates it, so it is not stored and not relied upon.
                bitchat_peer = peer.get("peer")
                print(f"Устройство Bitchat привязано: {peer['label']}\n")
            elif peer:
                print("Привязка отменена — к этому телефону мост не подключится.\n")
            else:
                print("Bitchat-устройство не выбрано — мост ни к чему не "
                      "подключается.\n")
            # Remember the radio only. The phone binding is confirmed again on
            # every start and is never written to the config file.
            cfg["transport"] = {k: v for k, v in transport.items()
                                if k in ("kind", "target", "port")}
            save_config(args.config, cfg)
        else:
            transport = cli_transport or transport_from_config(cfg)
            if cli_transport is not None:
                # A radio was named on the command line, but the phone still
                # has to be confirmed interactively before any data flows.
                interactive = sys.stdin.isatty()
                if interactive:
                    peer = choose_bitchat_peer(scan_seconds * 2)
                    bitchat_target = None
                    bitchat_peer = (peer.get("peer")
                                    if peer and confirm_binding(peer) else None)
                if not bitchat_peer:
                    print("Bitchat-телефон не подтверждён — мост ни к чему не "
                          "подключается. Запустите без --host/--port/--ble, "
                          "чтобы пройти выбор.")
                    return 1

        try:
            asyncio.run(run(transport, name, scan_seconds, channel,
                            chat_target, interactive, history_limit,
                            lora_send_interval, lora_stale_seconds,
                            console=console_enabled,
                            bitchat_target=bitchat_target,
                            full_sync=full_sync,
                            bitchat_peer=bitchat_peer,
                            forward_mode=forward_mode,
                            config_path=args.config))
        except KeyboardInterrupt:
            print("\nОстановлено.")
            return 0

        if not want_menu:
            return 0
        print()
        try:
            again = input("Выбрать другое устройство и запустить снова? [y/N]: ")
        except (EOFError, KeyboardInterrupt):
            return 0
        if again.strip().lower() not in ("y", "yes", "д", "да"):
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
