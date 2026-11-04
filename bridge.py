#!/usr/bin/env python3
"""
Meshtastic <-> Bitchat bridge (Windows-friendly) with an interactive menu.

Features
--------
* Interactive console menu: scan only the connected physical networks (TCP),
  Bluetooth LE or COM ports and pick one by number; a VPN does not slow the
  Wi-Fi scan because virtual adapters are skipped.
* Bitchat phones are discovered automatically over BLE; no manual choice.
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
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
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

# --- Bitchat protocol (BitFoundation / MessageType.swift) ---
BITCHAT_SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"  # mainnet
BITCHAT_CHAR_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

# --- Meshtastic BLE service ---
MESHTASTIC_BLE_SERVICE = "6ba1b218-15a8-461f-9fa8-5dcae273eafd"
MESHTASTIC_TCP_PORT = 4403
BROADCAST_NUM = 0xFFFFFFFF

PACKET_VERSION = 0x01
TYPE_ANNOUNCE = 0x01
TYPE_MESSAGE = 0x02
TYPE_FRAGMENT = 0x20

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
    "full_sync": False,
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


def _is_virtual_iface(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in _VIRTUAL_IFACE_HINTS)


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
            bucket = virtual if _is_virtual_iface(name) else physical
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
                    networks: Optional[List[dict]] = None) -> List[str]:
    """Fast sweep: hosts in the connected networks that accept *port*."""
    hosts: List[str] = []
    for entry in (connected_networks() if networks is None else networks):
        net = entry["network"]
        hosts.extend(str(host) for host in net.hosts())

    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        return []

    sem = asyncio.Semaphore(128)

    async def probe(host: str) -> Optional[str]:
        async with sem:
            return host if await _port_open(host, port) else None

    found = await asyncio.gather(*(probe(h) for h in hosts))
    return [h for h in found if h]


def _verify_hosts(hosts: List[str], port: int) -> List[tuple]:
    """Identify candidate hosts in parallel; keep only real Meshtastic radios."""
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(hosts))) as pool:
        futures = {pool.submit(_probe_tcp_name, host, 2.0, port): host
                   for host in hosts}
        found = []
        for future in futures:
            try:
                name = future.result()
            except Exception:  # noqa: BLE001
                name = None
            if name is not None:
                found.append((futures[future], name))
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

    print(f"Ищу Meshtastic с открытым портом {port} в этих сетях...")
    hosts = asyncio.run(_scan_lan(port, networks))

    if mdns_result.get("addr") and mdns_result["addr"] not in hosts:
        hosts.append(mdns_result["addr"])

    if not hosts:
        print(f"Meshtastic с портом {port} не найден.")
        return []

    if len(hosts) == 1:
        print(f"  проверяю {hosts[0]}...")
    else:
        print(f"  открытый порт найден у {len(hosts)} устройств, "
              "проверяю параллельно...")

    devices = []
    for host, name in _verify_hosts(hosts, port):
        devices.append({"kind": "tcp", "target": host, "port": port,
                        "label": f"{name} — {host}:{port} (Wi-Fi)"})
        print(f"  ок: {name} — {host}:{port}")

    if not devices:
        print(f"Meshtastic с портом {port} не найден.")
    return devices


def scan_ble_devices(seconds: float = 8.0) -> List[dict]:
    print(f"Сканирую Bluetooth {seconds:.0f} c...")

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
        print(f"Bluetooth недоступен: {exc}")
        return []

    if not found:
        print("Meshtastic по Bluetooth не найден "
              "(на ESP32 BLE выключается, когда включён Wi-Fi).")
    return found


def scan_bitchat_peers(seconds: float = 8.0) -> List[dict]:
    """Find nearby phones that run Bitchat (BLE advertisers)."""
    print(f"Ищу телефоны Bitchat по Bluetooth ({seconds:.0f} c)...")

    async def _scan():
        devs = await BleakScanner.discover(timeout=seconds, return_adv=True)
        out = []
        for device, adv in devs.values():
            uuids = {str(u).lower() for u in (adv.service_uuids or [])}
            name = (adv.local_name or getattr(device, "name", "") or "")
            if BITCHAT_SERVICE_UUID in uuids or "bitchat" in name.lower():
                rssi = getattr(adv, "rssi", None)
                out.append({"kind": "bitchat", "target": device.address,
                            "name": name or "Bitchat", "rssi": rssi,
                            "label": f"{name or 'Bitchat'} — {device.address}"
                                     + (f" ({rssi} dBm)" if rssi else "")})
        out.sort(key=lambda d: -(d.get("rssi") or -999))
        return out

    try:
        found = asyncio.run(_scan())
    except Exception as exc:  # noqa: BLE001
        print(f"Bluetooth недоступен: {exc}")
        return []

    if not found:
        print("Телефоны Bitchat рядом не найдены.")
    return found


def choose_bitchat_peer(seconds: float = 8.0) -> Optional[dict]:
    """Let the user pick which Bitchat phone this bridge talks to."""
    devices = scan_bitchat_peers(seconds)
    if not devices:
        print("Мост будет подключаться к любому найденному Bitchat-устройству.")
        return None

    print("\nНайденные устройства Bitchat:")
    for i, dev in enumerate(devices, 1):
        print(f"  {i}) {dev['label']}")
    print("  0) не выбирать — подключаться к любому")

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


def scan_serial_devices() -> List[dict]:
    try:
        import serial.tools.list_ports as list_ports
    except Exception as exc:  # noqa: BLE001
        print(f"pyserial недоступен: {exc}")
        return []

    ports = list(list_ports.comports())
    if not ports:
        print("COM-портов не найдено.")
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
        asyncio.run_coroutine_threadsafe(self._reconnect_loop(), self.loop)

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
            for sent_text, sent_at in list(self._recent_sent):
                if sent_text == text and now - sent_at < 120:
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
            log.info("(LoRa -> BLE) %s, %s: %s", sender, where, text)
            say(f"[LoRa] {sender}: {text}")
            body = f"{prefix} {text}"
            entry = {
                "ts": time.time(),
                "body": body,
                "desc": f"{sender}: {text}",
                "delivered": False,
            }
            self.history_lora.append(entry)
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
            "text": text,
            "channel": ch,
            "destination": dest,
            "manual": bool(manual),
            "history": history_entry,
        }
        self.pending_texts.append(entry)
        target = (f"личное {dest}" if dest is not None else f"канал {ch}")
        log.info("(BLE -> LoRa очередь) [%s] %s", target, text)
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
            log.error("Узел «%s» не найден — сообщение пропущено: %s",
                      unresolved, text)
            self._notify_bitchat(
                f"[Bridge] узел «{unresolved}» не найден, сообщение не отправлено")
            return True
        if self.interface is None:
            self.enqueue_text(text, ch, dest, manual=True)
            return False
        entry = {"ts": time.time(), "queued_at": time.time(), "text": text,
                 "channel": ch, "destination": dest, "manual": True,
                 "history": None}
        ok = self._send_entry(entry)
        if not ok and not self._stopping:
            self.pending_texts.append(entry)
        return ok

    def _send_entry(self, entry: dict) -> bool:
        text = entry["text"]
        ch = int(entry.get("channel") or 0)
        destination = entry.get("destination")
        if isinstance(destination, str) and destination.startswith("@"):
            token = destination[1:]
            resolved = self.resolve_destination(token)
            if resolved is None:
                log.error("Узел «%s» не найден — сообщение из очереди пропущено: %s",
                          token, text)
                self._notify_bitchat(
                    f"[Bridge] узел «{token}» не найден, сообщение не отправлено")
                return True  # drop it instead of retrying forever
            destination = resolved
            entry["destination"] = resolved
        try:
            if destination is not None:
                log.info("(BLE -> LoRa) [личное %s] %s", destination, text)
            elif ch:
                log.info("(BLE -> LoRa) [канал %d %s] %s", ch,
                         self.channel_label(ch), text)
            else:
                log.info("(BLE -> LoRa) %s", text)
            kwargs = {"channelIndex": ch}
            if destination is not None:
                kwargs["destinationId"] = destination
            self.interface.sendText(text, **kwargs)
            self._recent_sent.append((text, time.time()))
            return True
        except Exception as exc:  # noqa: BLE001
            log.error("Отправка в LoRa не удалась: %s", exc)
            self.on_connection_lost()
            return False

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
                    say("[LoRa] устаревшее сообщение пропущено: "
                        f"{str(entry.get('text', ''))[:60]}")
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
        text = entry.get("text") or ""
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
        self._cleanup_interface()


# --------------------------------------------------------------------------
# Bitchat side
# --------------------------------------------------------------------------
class BitchatBLEHandler:
    def __init__(self, loop: asyncio.AbstractEventLoop, nickname: str,
                 scan_seconds: float = 3.0, history_limit: int = 100,
                 target_address: Optional[str] = None,
                 full_sync: bool = False) -> None:
        self.loop = loop
        self.nickname = nickname
        self.scan_seconds = scan_seconds
        self.history_limit = max(1, int(history_limit))
        # When set, only this BLE address may be bridged (other people's
        # phones nearby must never receive our traffic).
        self.target_address = (target_address or "").strip() or None
        # Full two-way sync: forward every incoming message to the other side
        # immediately, in addition to the normal one-way behaviour.
        self.full_sync = bool(full_sync)
        self.connected: Dict[str, BleakClient] = {}
        self.connecting: set = set()
        self.failed: Dict[str, float] = {}
        self.meshtastic: Optional[MeshtasticHandler] = None
        self.peer_nicknames: Dict[str, str] = {}
        self._seen_packets: deque = deque(maxlen=200)
        self._fragments: Dict[bytes, dict] = {}
        self._stopping = False
        self._bluetooth_warned = False
        # Last N Bitchat messages, kept for the manual "send last 5/10/20/50"
        # sync.  They are never sent to LoRa automatically.
        self.history_bitchat: deque = deque(maxlen=self.history_limit)
        # Recently delivered LoRa -> Bitchat bodies, used to filter echoes.
        self._recent_outgoing: deque = deque(maxlen=200)
        self._delivery_lock = asyncio.Lock()
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
                       flags: int, payload: bytes) -> None:
        if sender == self.my_id:
            return
        key = (sender, timestamp, packet_type)
        if key in self._seen_packets:
            return
        self._seen_packets.append(key)

        if flags & FLAG_IS_COMPRESSED:
            text = self._decompress(payload)
            if text is None:
                return
        else:
            text = payload.decode("utf-8", errors="ignore")

        short_id = sender.hex()[-4:]
        if packet_type == TYPE_MESSAGE:
            name = self.peer_nicknames.get(sender.hex(), short_id)
            self._on_bitchat_text(text, name)
        elif packet_type == TYPE_ANNOUNCE:
            self._handle_announce(sender, payload, short_id)

    def _reply_to_bitchat(self, text: str) -> None:
        log.info("(Bridge -> Bitchat) %s", text)
        try:
            asyncio.get_running_loop().create_task(self.broadcast(text))
        except RuntimeError:  # called from a non-async thread
            asyncio.run_coroutine_threadsafe(self.broadcast(text), self.loop)

    def _is_echo(self, text: str) -> bool:
        """Ignore messages that the bridge itself injected into Bitchat."""
        if text.startswith(("[Mesh:", "[Mesh DM:", "[Bridge]")):
            return True
        now = time.time()
        for body, ts in list(self._recent_outgoing):
            if body == text and now - ts < 180:
                return True
        return False

    def _on_bitchat_text(self, text: str, name: str) -> None:
        """Buffer a Bitchat message; never forward it to LoRa automatically."""
        stripped = text.strip()
        if not stripped or self._is_echo(stripped):
            return

        low = stripped.lower()
        if low in ("/help", "/?", "/помощь"):
            self._reply_to_bitchat(
                "[Bridge] Сообщения в LoRa автоматически не уходят. "
                "Они копятся здесь; в консоли нажмите «s» и выберите "
                "«Bitchat → Meshtastic», количество и период. "
                "«/ch» — каналы, «#N текст» и «/dm узел текст» — адресация."
            )
            return

        if low in ("/ch", "/channels", "/каналы"):
            if self.meshtastic:
                self._reply_to_bitchat(self.meshtastic.describe_channels())
            else:
                self._reply_to_bitchat("[Bridge] радио Meshtastic недоступно.")
            return

        if low in ("/sync", "/синхро", "/синхронизация"):
            self._reply_to_bitchat(
                "[Bridge] Синхронизация запускается из консоли моста: "
                "нажмите «s» и выберите направление, количество (5/10/20/50) "
                "и при желании период повтора."
            )
            return

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

        entry = {
            "ts": time.time(),
            "name": name,
            "text": body_text,
            "channel": max(0, min(7, int(channel))),
            "destination": destination,
            "sent_lora": False,
        }
        self.history_bitchat.append(entry)
        log.info("(BLE -> LoRa буфер) %s: %s", name, body_text)
        if self.full_sync and self.meshtastic:
            # Full two-way mode: forward at once, still via the rate-limited
            # LoRa queue so the air is not flooded.
            self.meshtastic.send_history_entry(entry)
            say(f"[Bitchat] {name}: {body_text} (полная синхронизация → LoRa)")
            return
        say(f"[Bitchat] {name}: {body_text} "
            f"(в буфере {len(self.history_bitchat)}, ждёт ручной синхронизации)")

    def _handle_announce(self, sender: bytes, payload: bytes, short_id: str) -> None:
        try:
            offset = 0
            while offset + 2 <= len(payload):
                tag = payload[offset]
                length = payload[offset + 1]
                offset += 2
                if offset + length > len(payload):
                    break
                value = payload[offset:offset + length]
                offset += length
                if tag == 0x01:
                    nickname = value.decode("utf-8", errors="ignore")
                    key = sender.hex()
                    if self.peer_nicknames.get(key) != nickname:
                        self.peer_nicknames[key] = nickname
                        log.info("Пир %s теперь известен как '%s'", short_id, nickname)
                    return
        except Exception as exc:  # noqa: BLE001
            log.debug("Плохой announce: %s", exc)

    def _handle_fragment(self, sender: bytes, payload: bytes, flags: int) -> None:
        if len(payload) < 13:
            return
        frag_id = payload[:8]
        index = int.from_bytes(payload[8:10], "big")
        total = int.from_bytes(payload[10:12], "big")
        inner_type = payload[12]
        chunk = payload[13:]
        if total <= 0 or total > 10000 or index >= total:
            return
        entry = self._fragments.setdefault(
            frag_id, {"total": total, "type": inner_type, "parts": {}, "ts": time.time()}
        )
        entry["parts"][index] = chunk
        entry["ts"] = time.time()

        if len(entry["parts"]) == entry["total"]:
            data = b"".join(entry["parts"][i] for i in range(entry["total"]))
            del self._fragments[frag_id]
            parsed = self._parse_packet(data)
            if parsed:
                self._handle_packet(*parsed)

        now = time.time()
        for k in [k for k, v in self._fragments.items() if now - v["ts"] > 60]:
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
            if packet_type == TYPE_FRAGMENT:
                self._handle_fragment(sender, payload, flags)
            else:
                self._handle_packet(sender, packet_type, timestamp, flags, payload)
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

    async def _write_raw(self, client: BleakClient, packet: bytes) -> None:
        try:
            await client.write_gatt_char(BITCHAT_CHAR_UUID, packet, response=True)
        except Exception:
            await client.write_gatt_char(BITCHAT_CHAR_UUID, packet, response=False)

    def _disconnected(self, client: BleakClient) -> None:
        addr = getattr(client, "address", "?")
        log.info("Пир Bitchat отключился: %s", addr)
        say("[Bitchat] телефон отключился")
        self.connected.pop(addr, None)
        self.connecting.discard(addr)
        truncate_logs()

    async def connect(self, device) -> None:
        addr = device.address
        if self.target_address and addr.lower() != self.target_address.lower():
            return
        if addr in self.connected or addr in self.connecting:
            return
        if addr in self.failed and time.time() - self.failed[addr] < 300:
            return
        self.connecting.add(addr)
        client = BleakClient(addr, timeout=15.0, disconnected_callback=self._disconnected)
        try:
            await client.connect()
            await client.start_notify(BITCHAT_CHAR_UUID,
                                      lambda c, d: self._notification(client, c, d))
            self.connected[addr] = client
            await self._write_raw(client, self.build_announce())
            log.info("Пир Bitchat подключён: %s", getattr(device, "name", None) or addr)
            say("[Bitchat] телефон подключён")
            await self.flush_undelivered(client)
        except Exception as exc:  # noqa: BLE001
            log.debug("BLE-подключение к %s не удалось: %s", addr, exc)
            self.failed[addr] = time.time()
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                pass
        finally:
            self.connecting.discard(addr)

    @staticmethod
    def _is_bitchat(device, adv) -> bool:
        uuids = {str(u).lower() for u in (adv.service_uuids or [])}
        if BITCHAT_SERVICE_UUID in uuids:
            return True
        name = (adv.local_name or getattr(device, "name", "") or "").lower()
        return "bitchat" in name

    async def scanner(self) -> None:
        log.info("Ищу Bitchat-пиры по Bluetooth...")
        while not self._stopping:
            try:
                devices = await BleakScanner.discover(timeout=self.scan_seconds,
                                                      return_adv=True)
                self._bluetooth_warned = False
                for device, adv in devices.values():
                    if self._is_bitchat(device, adv):
                        if (device.address not in self.connected
                                and device.address not in self.connecting):
                            asyncio.create_task(self.connect(device))
            except BleakError as exc:
                if not self._bluetooth_warned:
                    log.error("Проблема с Bluetooth: %s", exc)
                    self._bluetooth_warned = True
                await asyncio.sleep(10)
            except Exception as exc:  # noqa: BLE001
                log.debug("Ошибка BLE-сканирования: %s", exc)
                await asyncio.sleep(2)
            await asyncio.sleep(1.0)

    async def deliver_history(self, entry: dict) -> None:
        """Deliver one LoRa history item to the phone if it is connected."""
        if self._stopping:
            return
        async with self._delivery_lock:
            body = entry.get("body") or ""
            if self.connected:
                packet = self.build_packet(TYPE_MESSAGE, body.encode("utf-8"),
                                           recipient=BROADCAST_ID)
                if await self._broadcast_packet(packet):
                    entry["delivered"] = True
                    self._recent_outgoing.append((body, time.time()))
                    return
            log.info("Нет Bitchat-пира — сообщение остаётся в истории: %s", body)

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
                body = entry.get("body") or ""
                packet = self.build_packet(TYPE_MESSAGE, body.encode("utf-8"),
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
                self._recent_outgoing.append((body, time.time()))
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
                body = entry.get("body") or ""
                packet = self.build_packet(TYPE_MESSAGE, body.encode("utf-8"),
                                           recipient=BROADCAST_ID)
                if await self._broadcast_packet(packet):
                    entry["delivered"] = True
                    self._recent_outgoing.append((body, time.time()))
                    sent += 1
                await asyncio.sleep(0.05)
            return sent

    async def resend_bitchat(self, count: int, only_new: bool = False) -> int:
        """Queue the last N Bitchat messages for rate-limited LoRa sending."""
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
            self.meshtastic.send_history_entry(entry)
            queued += 1
        return queued

    async def broadcast(self, message: str) -> None:
        """Send a bridge notice to connected phones (never stored)."""
        if not self.connected:
            log.debug("Некому отправлять ответ Bitchat: %s", message)
            return
        packet = self.build_packet(TYPE_MESSAGE, message.encode("utf-8"),
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
        """Retry a partially delivered history even without a new event."""
        while not self._stopping:
            await asyncio.sleep(20)
            if self.connected and self.meshtastic:
                if any(not e.get("delivered")
                       for e in list(self.meshtastic.history_lora)):
                    await self.flush_undelivered()

    async def stop(self) -> None:
        self._stopping = True
        for client in list(self.connected.values()):
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                pass
        self.connected.clear()
        truncate_logs()


# --------------------------------------------------------------------------
# Interactive menu
# --------------------------------------------------------------------------
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
        ble.full_sync = toggle == "1"
        if ble.full_sync:
            say("[Sync] полная синхронизация включена: новые сообщения идут "
                "в обе стороны сразу.")
            # Push anything that is still waiting, so both sides converge now.
            if ble.connected:
                asyncio.run_coroutine_threadsafe(ble.flush_undelivered(), loop)
            queued = 0
            for entry in list(ble.history_bitchat):
                if not entry.get("sent_lora") and not entry.get("queued_lora"):
                    mesh.send_history_entry(entry)
                    queued += 1
            if queued:
                say(f"[Sync] в очередь LoRa поставлено: {queued}")
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


async def periodic_sync_loop(ble: "BitchatBLEHandler",
                             mesh: "MeshtasticHandler",
                             scheduler: SyncScheduler) -> None:
    while not ble._stopping and not mesh._stopping:
        await asyncio.sleep(5)
        for job in scheduler.due():
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
                 loop: asyncio.AbstractEventLoop) -> None:
    print()
    print("Мост работает. Команды в консоли:")
    print("  s — синхронизация (направление, 5/10/20/50, период)")
    print("  l — состояние буферов и расписания")
    print("  q — выход")
    print()

    while not stop_event.is_set():
        try:
            raw = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            loop.call_soon_threadsafe(stop_event.set)
            return
        if raw in ("q", "quit", "exit", "выход"):
            loop.call_soon_threadsafe(stop_event.set)
            return
        if raw in ("s", "sync", "с", "синхронизация"):
            console_sync_menu(ble, mesh, scheduler, loop)
            continue
        if raw in ("l", "list", "status", "состояние"):
            print()
            print(f"  LoRa → Bitchat: {len(mesh.history_lora)} сообщ. в истории, "
                  f"{sum(1 for e in mesh.history_lora if not e.get('delivered'))} "
                  "ещё не доставлено")
            print(f"  Bitchat → LoRa: {len(ble.history_bitchat)} сообщ. в истории, "
                  f"{len(mesh.pending_texts)} в очереди на отправку")
            print(f"  Режим: {'полная синхронизация в обе стороны' if ble.full_sync else 'авто только LoRa → Bitchat'}")
            print(f"  {scheduler.describe()}")
            print()
            continue
        if raw in ("h", "?", "help", "помощь"):
            print("  s — синхронизация, l — состояние, q — выход")
            continue
        if not raw:
            continue
        print("Команды: s — синхронизация, l — состояние, q — выход")


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
              full_sync: bool = False) -> int:
    loop = asyncio.get_running_loop()

    ble = BitchatBLEHandler(loop, name, scan_seconds, history_limit,
                            target_address=bitchat_target,
                            full_sync=full_sync)
    mesh = MeshtasticHandler(loop, transport, default_channel=channel,
                             lora_send_interval=lora_send_interval,
                             history_limit=history_limit,
                             lora_stale_seconds=lora_stale_seconds)
    mesh.set_chat_target(chat_target or {"kind": "all"})
    ble.set_meshtastic_handler(mesh)
    mesh.set_ble_handler(ble)

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
        console_thread = threading.Thread(
            target=console_loop,
            args=(ble, mesh, scheduler, stop_event, loop),
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
                   help="bridge only this Bitchat phone (BLE address)")
    p.add_argument("--full-sync", action="store_true",
                   help="two-way sync: forward new messages immediately both ways")
    p.add_argument("--no-full-sync", action="store_true",
                   help="disable two-way sync even if config enables it")
    p.add_argument("--name", help="bridge nickname in Bitchat")
    p.add_argument("--channel", type=int, metavar="N",
                   help="default Meshtastic channel index for Bitchat messages")
    p.add_argument("--chat", metavar="TARGET",
                   help="bind to a chat: 'all', channel number 0-7, or dm:NODE")
    p.add_argument("--history", type=int, metavar="N",
                   help="how many recent messages to keep in each direction (default 100)")
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
    log.info("Запуск %s", APP_NAME)

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
    full_sync = bool(cfg.get("full_sync", False))
    if args.full_sync:
        full_sync = True
    if args.no_full_sync:
        full_sync = False

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
            if peer:
                bitchat_target = peer["target"]
                print(f"Устройство Bitchat: {peer['label']}\n")
            else:
                bitchat_target = None
                print("Bitchat-устройство не выбрано — мост подключится к любому.\n")
            # Remember the choice so the next start can skip the menu.
            cfg["transport"] = {k: v for k, v in transport.items()
                                if k in ("kind", "target", "port")}
            cfg["bitchat_target"] = bitchat_target or ""
            save_config(args.config, cfg)
        else:
            transport = cli_transport or transport_from_config(cfg)

        try:
            asyncio.run(run(transport, name, scan_seconds, channel,
                            chat_target, interactive, history_limit,
                            lora_send_interval, lora_stale_seconds,
                            console=console_enabled,
                            bitchat_target=bitchat_target,
                            full_sync=full_sync))
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
