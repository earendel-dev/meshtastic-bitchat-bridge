"""Dump Meshtastic config over TCP without the meshtastic library handshake timing."""
import socket
import struct
import sys
import time

from meshtastic.protobuf import mesh_pb2

START = b"\x94\xc3"


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "meshtastic.local"
    watch = float(sys.argv[2]) if len(sys.argv) > 2 else 45.0
    s = socket.create_connection((host, 4403), timeout=5)
    s.settimeout(1.0)
    print("connected, waiting 3s for API to settle...")
    time.sleep(3)

    m = mesh_pb2.ToRadio()
    m.want_config_id = 0x55667788
    p = m.SerializeToString()
    s.sendall(START + struct.pack(">H", len(p)) + p)

    buf = b""
    end = time.time() + watch
    seen = {}
    while time.time() < end:
        try:
            d = s.recv(8192)
        except socket.timeout:
            continue
        if not d:
            print("connection closed by device")
            break
        buf += d
        while True:
            i = buf.find(START)
            if i < 0:
                buf = buf[-1:]
                break
            buf = buf[i:]
            if len(buf) < 4:
                break
            length = struct.unpack(">H", buf[2:4])[0]
            if len(buf) < 4 + length:
                break
            payload, buf = buf[4:4 + length], buf[4 + length:]
            fr = mesh_pb2.FromRadio()
            try:
                fr.ParseFromString(payload)
            except Exception:  # noqa: BLE001
                continue
            kind = fr.WhichOneof("payload_variant")
            seen[kind] = seen.get(kind, 0) + 1
            if kind == "my_info":
                print("my_info:", fr.my_info)
            elif kind == "metadata":
                print("metadata:", fr.metadata)
            elif kind == "config_complete_id":
                print(f"[{time.time():.0f}] CONFIG COMPLETE, id =", fr.config_complete_id)
            elif kind == "channel":
                print("channel index", fr.channel.index,
                      "name=", fr.channel.settings.name,
                      "role=", fr.channel.role)
            elif kind == "config":
                pass
    s.close()
    print("frame counts:", seen)
    return 0


if __name__ == "__main__":
    sys.exit(main())
