#!/usr/bin/env python3
"""
NetScope Capture Agent — streams this machine's live network traffic to the NetScope web app.

Run it, then in NetScope pick "ws0 — Live capture (agent)" and press Start.
The app connects to ws://<this-machine>:9000 (any path) and receives raw
Ethernet frames as binary WebSocket messages, which it decodes live.

No pip installs needed on Linux: capture uses the kernel's AF_PACKET socket.
On macOS / Windows the script falls back to Scapy if it is installed
(Windows additionally needs Npcap: https://npcap.com).

Usage:
  sudo python3 capture_agent.py                 # auto-detect interface, port 9000
  sudo python3 capture_agent.py --iface eth0
  python3 capture_agent.py --port 9443
  python3 capture_agent.py --test               # send demo frames (no root needed)
"""
import argparse
import base64
import hashlib
import os
import socket
import struct
import sys
import threading
import time

# Filled in automatically when downloaded from NetScope (remote session relay host).
DEFAULT_SERVER = "__NETSCOPE_SERVER__"

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# ---------------------------------------------------------------- WebSocket hub
def ws_frame(payload: bytes, op: int = 0x82) -> bytes:
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", op, n)            # FIN + opcode (0x82 binary, 0x81 text)
    elif n < 65536:
        head = struct.pack("!BBH", op, 126, n)
    else:
        head = struct.pack("!BBQ", op, 127, n)
    return head + payload


class Hub:
    def __init__(self):
        self.clients = set()
        self.lock = threading.Lock()
        self.sent = 0
        self.bytes = 0

    def add(self, conn):
        with self.lock:
            self.clients.add(conn)

    def remove(self, conn):
        with self.lock:
            self.clients.discard(conn)

    def count(self):
        with self.lock:
            return len(self.clients)

    def broadcast(self, data: bytes, op: int = 0x82):
        if self.remote:
            self.remote.push(data, op)
            if op == 0x82:
                self.sent += 1
                self.bytes += len(data)
        frame = ws_frame(data, op)
        dead = []
        with self.lock:
            for c in self.clients:
                try:
                    c.sendall(frame)
                    if op == 0x82 and not self.remote:
                        self.sent += 1
                        self.bytes += len(data)
                except OSError:
                    dead.append(c)
            for c in dead:
                self.clients.discard(c)

    remote = None

    def send_text(self, text: str):
        self.broadcast(text.encode(), 0x81)


class Remote:
    """Pushes frames over HTTPS to the NetScope cloud relay so a browser anywhere can watch.
    Outbound-only: works behind any home router / mobile network, no port forwarding."""

    def __init__(self, server, room):
        self.url = server.rstrip("/") + "/api/public/relay"
        self.room = room
        self.q = []
        self.lock = threading.Lock()
        self.ok = 0
        self.fail = 0
        threading.Thread(target=self.loop, daemon=True).start()

    def push(self, data, op):
        item = {"kind": "frame", "payload": base64.b64encode(data).decode(), "ts": time.time() * 1000}
        if op == 0x81:
            item = {"kind": "devices", "payload": data.decode(), "ts": time.time() * 1000}
        with self.lock:
            if len(self.q) < 20000:
                self.q.append(item)

    def loop(self):
        import urllib.request
        while True:
            time.sleep(0.5)
            with self.lock:
                batch, self.q = self.q[:400], self.q[400:]
            if not batch:
                continue
            body = json.dumps({"room": self.room, "items": batch}).encode()
            req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json", "User-Agent": "NetScopeAgent/1.0"})
            try:
                urllib.request.urlopen(req, timeout=15).read()
                self.ok += len(batch)
            except Exception as e:  # noqa
                self.fail += 1
                if self.fail % 10 == 1:
                    print(f"[!] Relay upload failed ({e}); retrying…")
                with self.lock:
                    self.q = batch + self.q


def handle_client(conn, addr, hub):
    print(f"[+] NetScope connected: {addr[0]}:{addr[1]}")
    try:
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = conn.recv(4096)
            if not chunk:
                return
            req += chunk
        key = ""
        for line in req.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].strip().decode()
        if not key:
            return
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        hub.add(conn)
        # Keep reading (and ignore) client frames so closes are detected promptly.
        while True:
            if not conn.recv(4096):
                break
    except OSError:
        pass
    finally:
        hub.remove(conn)
        conn.close()
        print(f"[-] NetScope disconnected: {addr[0]}:{addr[1]}")


def ws_server(port, hub):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    print(f"[*] WebSocket server listening on ws://0.0.0.0:{port} (all interfaces)")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr, hub), daemon=True).start()


# ---------------------------------------------------------------- Wi-Fi / LAN device discovery
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))       # no packet is sent; just picks the Wi-Fi/LAN route
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def gateway_ip():
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route") as f:
                for line in f.read().splitlines()[1:]:
                    p = line.split()
                    if len(p) > 2 and p[1] == "00000000":
                        return socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
        except OSError:
            pass
    try:
        cmd = ["route", "print", "0.0.0.0"] if sys.platform == "win32" else ["netstat", "-rn"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 3 and p[0] in ("0.0.0.0", "default") and re.match(r"\d+\.\d+\.\d+\.\d+$", p[2 if p[0] == "0.0.0.0" else 1]):
                return p[2 if p[0] == "0.0.0.0" else 1]
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def poke(ip):
    """Send a tiny UDP packet so the OS resolves the device's MAC via ARP (no root needed)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.sendto(b"\x00", (ip, 9))
        s.close()
    except OSError:
        pass
    # mDNS/NetBIOS-friendly TCP touch on a common port also wakes sleeping phones
    try:
        c = socket.create_connection((ip, 80), timeout=0.3)
        c.close()
    except OSError:
        pass


MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")
IP_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")


def read_arp():
    """Return {ip: mac} from the OS neighbour table."""
    table = {}
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/arp") as f:
                for line in f.read().splitlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                        table[p[0]] = p[3].lower()
            return table
        except OSError:
            pass
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return table
    for line in out.splitlines():
        ip, mac = IP_RE.search(line), MAC_RE.search(line)
        if ip and mac:
            m = ":".join(x.zfill(2) for x in re.split(r"[:-]", mac.group(0))).lower()
            if m not in ("ff:ff:ff:ff:ff:ff",) and not m.startswith("01:00:5e"):
                table[ip.group(0)] = m
    return table


def reverse_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


KNOWN_DEVICES = set()


def discovery_loop(hub, interval=15):
    me = local_ip()
    if not me:
        print("[!] Wi-Fi discovery: could not find this laptop's LAN address")
        return
    gw = gateway_ip()
    prefix = me.rsplit(".", 1)[0]
    targets = [f"{prefix}.{i}" for i in range(1, 255) if f"{prefix}.{i}" != me]
    names = {}
    print(f"[*] Wi-Fi discovery: scanning {prefix}.0/24 (this laptop {me}, router {gw or '?'})")
    first = True
    while True:
        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(poke, targets))
        time.sleep(1)
        arp = read_arp()
        found = {ip: mac for ip, mac in arp.items() if ip.startswith(prefix + ".")}
        KNOWN_DEVICES.update(found)
        with ThreadPoolExecutor(max_workers=16) as ex:
            for ip, n in zip(list(found), ex.map(lambda i: names.get(i) or reverse_name(i), list(found))):
                if n:
                    names[ip] = n
        devices = [{"ip": me, "mac": None, "name": socket.gethostname() + " (this laptop)", "self": True}]
        for ip, mac in sorted(found.items(), key=lambda kv: int(kv[0].rsplit(".", 1)[1])):
            devices.append({"ip": ip, "mac": mac, "name": names.get(ip) or ("Router" if ip == gw else None), "gateway": ip == gw})
        hub.send_text(json.dumps({"type": "devices", "subnet": prefix + ".0/24", "gateway": gw, "self": me, "devices": devices}))
        if first or hub.count():
            print(f"[*] Wi-Fi discovery: {len(devices)} device(s) on the network")
        first = False
        time.sleep(interval)


# ---------------------------------------------------------------- capture
def auto_iface():
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route") as f:
                for line in f.read().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) > 2 and parts[1] == "00000000" and parts[2] != "00000000":
                        return parts[0]
        except OSError:
            pass
        try:
            with open("/proc/net/dev") as f:
                for line in f.read().splitlines()[2:]:
                    name = line.split(":")[0].strip()
                    if name not in ("lo",):
                        return name
        except OSError:
            pass
    elif sys.platform == "win32":
        # Scapy needs a real adapter name on Windows; without one it errors out
        # and no packets ever reach the browser. Pick the highest-traffic
        # non-loopback adapter via the OS interface table.
        try:
            from scapy.all import get_if_list, get_if_addr, conf  # noqa

            best, best_score = None, -1
            for name in get_if_list():
                try:
                    addr = get_if_addr(name)
                except Exception:  # noqa
                    continue
                if name.startswith("lo") or addr in ("0.0.0.0", "127.0.0.1"):
                    continue
                score = 1 if conf.route.route("8.8.8.8")[0] == name else 0
                if score > best_score:
                    best, best_score = name, score
            if best:
                print(f"[*] Auto-detected Windows interface: '{best}'")
                return best
        except Exception:  # noqa
            try:
                from scapy.all import conf  # noqa

                name = conf.iface
                if name:
                    print(f"[*] Auto-detected Windows interface (default route): '{name}'")
                    return name
            except Exception:  # noqa
                pass
    return None


def stats_loop(hub):
    last = (0, 0)
    while True:
        time.sleep(5)
        cur = (hub.sent, hub.bytes)
        if cur != last:
            print(f"[*] {hub.sent} frames, {hub.bytes/1024:.0f} KB sent, {hub.count()} client(s)")
            last = cur


PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
SOL_PACKET = 263


def set_promisc(s, iface):
    """Put the interface in promiscuous mode so every frame on the link is captured."""
    try:
        idx = socket.if_nametoindex(iface)
        mreq = struct.pack("IHH8s", idx, PACKET_MR_PROMISC, 0, b"\x00" * 8)
        s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        print(f"[*] Promiscuous mode enabled on '{iface}' (all devices on the link)")
    except OSError as e:
        print(f"[!] Could not enable promiscuous mode on '{iface}': {e}")


def capture_afpacket(hub, iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((iface, 0))
    set_promisc(s, iface)
    print(f"[*] AF_PACKET capture on '{iface}'")
    while True:
        data = s.recv(65535)
        if data:
            hub.broadcast(data)


def capture_scapy(hub, iface):
    from scapy.all import sniff, conf  # noqa
    conf.sniff_promisc = 1
    print(f"[*] Scapy capture on '{iface or 'default'}' (promiscuous)")
    print("[*] Waiting for packets… (open a website or run a ping to generate traffic)")
    try:
        sniff(prn=lambda p: hub.broadcast(bytes(p)), iface=iface, store=False, promisc=True)
    except OSError as e:
        print(f"[!] Capture failed on '{iface or 'default'}': {e}")
        if sys.platform == "win32":
            print("    On Windows this usually means Npcap is missing or you are not Administrator.")
            print("    Install Npcap from https://npcap.com/#download, then re-run this script")
            print("    in a PowerShell window opened with 'Run as administrator'.")
        else:
            print("    Re-run with sudo, or pick another interface with --iface.")
        sys.exit(1)


def probe_loop(hub, interval=5):
    """Keep every discovered LAN device producing live packets we can see."""
    while True:
        time.sleep(interval)
        targets = list(KNOWN_DEVICES)
        if not targets:
            continue
        with ThreadPoolExecutor(max_workers=32) as ex:
            list(ex.map(poke, targets))


def demo_frames(n=100000):
    """Synthetic Ethernet/IP/UDP/DNS query frames for --test (no root needed)."""
    out = []
    for i in range(n):
        q = struct.pack("!HHHHHH", i & 0xFFFF, 0x0100, 1, 0, 0, 0) + b"\x0dnetscope-test\x03com\x00" + b"\x00\x01\x00\x01"
        udp = struct.pack("!HHHH", 50000 + (i % 1000), 53, 8 + len(q), 0) + q
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0x4000, 64, 17, 0,
                         socket.inet_aton("192.168.1.14"), socket.inet_aton("8.8.8.8"))
        eth = b"\x01\x02\x03\x04\x05\x06" + b"\xaa\xbb\xcc\xdd\xee\x0f" + b"\x08\x00"
        out.append(eth + ip + udp)
    return out


def main():
    ap = argparse.ArgumentParser(description="NetScope live capture agent")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--iface", default=None, help="interface to capture on (default: auto-detect)")
    ap.add_argument("--scapy", action="store_true", help="force the Scapy capture backend")
    ap.add_argument("--test", action="store_true", help="send demo frames instead of capturing")
    ap.add_argument("--no-scan", action="store_true", help="disable Wi-Fi device discovery")
    ap.add_argument("--room", default=None, help="remote session code shown in NetScope (stream over the internet)")
    ap.add_argument("--server", default=DEFAULT_SERVER, help="NetScope app URL for remote sessions")
    args = ap.parse_args()

    hub = Hub()
    if args.room:
        hub.remote = Remote(args.server, args.room.strip().upper())
    threading.Thread(target=ws_server, args=(args.port, hub), daemon=True).start()
    threading.Thread(target=stats_loop, args=(hub,), daemon=True).start()
    if not args.no_scan:
        threading.Thread(target=discovery_loop, args=(hub,), daemon=True).start()
        threading.Thread(target=probe_loop, args=(hub,), daemon=True).start()

    try:
        ips = socket.gethostbyname_ex(socket.gethostname())[2]
        lan = next((ip for ip in ips if not ip.startswith("127.")), "127.0.0.1")
    except OSError:
        lan = "127.0.0.1"

    print("=" * 64)
    print("  NetScope Capture Agent")
    if args.room:
        print(f"  REMOTE session:         {args.room.strip().upper()}")
        print(f"  Streaming to:           {args.server}")
        print("  The NetScope window with this code will start showing packets.")
    print(f"  URL for this PC:        ws://localhost:{args.port}")
    print(f"  URL for phones on LAN:  ws://{lan}:{args.port}")
    print("  In NetScope: pick 'ws0 — Live capture (agent)' -> Start")
    print("=" * 64)

    if args.test:
        print("[*] TEST mode: streaming demo frames at ~25 fps")
        frames = demo_frames(25)
        while True:
            for f in frames:
                hub.broadcast(f)
                time.sleep(0.04)
    else:
        iface = args.iface or auto_iface()
        if sys.platform.startswith("linux") and not args.scapy:
            try:
                capture_afpacket(hub, iface or "eth0")
            except PermissionError:
                print("[!] Permission denied: re-run with sudo")
                sys.exit(1)
        else:
            try:
                capture_scapy(hub, iface)
            except ImportError:
                print("[!] Scapy not installed. Run:  pip install scapy")
                print("    (Windows also needs Npcap: https://npcap.com)")
                sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Bye")
