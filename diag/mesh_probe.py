"""Raw Meshtastic serial API probe (no meshtastic library handshake).

Sends ToRadio.want_config_id repeatedly and decodes any FromRadio frames
that come back. Useful when `meshtastic --info` times out.

Usage:
    python diag/mesh_probe.py COM4 [--reset] [--seconds 30]
"""
import argparse
import struct
import sys
import time

import serial
from meshtastic.protobuf import mesh_pb2

START1 = 0x94
START2 = 0xC3


def frame(payload: bytes) -> bytes:
    return bytes([START1, START2]) + struct.pack(">H", len(payload)) + payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("port")
    ap.add_argument("--reset", action="store_true", help="pulse RTS to reset the board")
    ap.add_argument("--seconds", type=float, default=30.0)
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args()

    s = serial.Serial(args.port, 115200, timeout=0.2)
    if args.reset:
        print("resetting board via RTS...")
        s.dtr = False
        s.rts = True
        time.sleep(0.2)
        s.rts = False
        time.sleep(0.2)

    want = mesh_pb2.ToRadio()
    want.want_config_id = 0x12345678
    want_frame = frame(want.SerializeToString())

    buf = bytearray()
    start = time.time()
    next_send = start
    got = 0
    while time.time() - start < args.seconds:
        now = time.time()
        if now >= next_send:
            s.write(want_frame)
            s.flush()
            print(f"[{now - start:5.1f}s] -> want_config_id")
            next_send = now + args.interval

        chunk = s.read(512)
        if not chunk:
            continue
        buf.extend(chunk)

        # strip text/log noise up to the first valid magic pair
        while True:
            i = buf.find(bytes([START1, START2]))
            if i < 0:
                if len(buf) > 4096:
                    del buf[:-2]
                break
            if i > 0:
                del buf[:i]
            if len(buf) < 4:
                break
            length = struct.unpack(">H", bytes(buf[2:4]))[0]
            if len(buf) < 4 + length:
                break
            payload = bytes(buf[4:4 + length])
            del buf[:4 + length]

            msg = mesh_pb2.FromRadio()
            try:
                msg.ParseFromString(payload)
            except Exception as exc:  # noqa: BLE001
                print("  bad frame:", exc, payload[:24].hex())
                continue
            got += 1
            kind = msg.WhichOneof("payload_variant")
            extra = ""
            if kind == "config_complete_id":
                extra = f" id={msg.config_complete_id}"
            elif kind == "my_info":
                extra = f" my_node_num={msg.my_info.my_node_num}"
            elif kind == "metadata":
                extra = f" fw={msg.metadata.firmware_version}"
            elif kind == "node_info":
                extra = f" num={msg.node_info.num} id={msg.node_info.user.id}"
            print(f"[{time.time() - start:5.1f}s] <- {kind}{extra}")

    s.close()
    print(f"frames received: {got}")
    return 0 if got else 1


if __name__ == "__main__":
    sys.exit(main())
