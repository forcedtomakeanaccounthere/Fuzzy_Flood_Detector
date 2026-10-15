"""Traffic scenario simulator for live demonstrations against the edge detector.

Run this on the ATTACKER/SOURCE machine (usually the laptop, or a second Pi /
phone) while live_detector.py + monitor_dashboard.py run on the target Pi.

Modes
  normal       benign IoT-style traffic: TCP connections to an open service,
               DNS-like UDP queries, periodic telemetry bursts.
  suspicious   low-and-slow half-open SYN probes across ports (stealth scan).
  low-flood    sustained LOW-rate half-open SYN flood from a few rotated fake
               sources — sits in the THROTTLE zone (graduated response demo).
  congestion   high volume of LEGITIMATE traffic — verifies the model does not
               false-positive under load (handshakes actually complete).
  syn-flood    high-rate SYN-only packets, optional spoofed/rotated sources.
  udp-flood    high-rate UDP datagrams (works without root when not spoofing).
  story        timed demo storyline cycling all of the above with ground-truth
               labels written to reports/demo_labels.jsonl for post-demo scoring.

Root privileges are only required for SYN-only / spoofed packets (raw sockets).
Without root, modes that need them degrade with a clear warning.

Examples
  python traffic_simulator.py story --target 192.168.137.211
  python traffic_simulator.py syn-flood --target 192.168.137.211 --rate 400 --spoof
  python traffic_simulator.py normal   --target 192.168.137.211 --duration 60
"""

import argparse
import json
import os
import random
import socket
import sys
import time
from pathlib import Path

try:
    from scapy.all import IP, IPv6, TCP, UDP, send  # type: ignore

    SCAPY = True
except Exception:
    SCAPY = False


def warn_root(reason: str) -> None:
    print(f"[WARN] {reason}")
    if os.name != "nt" and os.geteuid() != 0:
        print("[WARN] re-run with sudo for raw packet support: sudo python3 traffic_simulator.py ...")


def require_scapy() -> bool:
    if SCAPY:
        return True
    warn_root("scapy is not installed — crafted SYN packets unavailable (pip install scapy)")
    return False


def private_target_guard(target: str) -> None:
    """Refuse to aim the generator at anything outside lab ranges."""
    import ipaddress

    ip = ipaddress.ip_address(target.split("%")[0])
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        sys.exit(f"REFUSING to target non-private address {target}. Lab use only.")


class GroundTruth:
    """Append-only ground-truth log: what phase was really running and when."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def phase(self, name: str, kind: str) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "phase": name, "kind": kind}) + "\n")
        print(f"\n=== {time.strftime('%H:%M:%S')} | PHASE: {name} ({kind}) ===")


def make_source_ips(n: int) -> list[str]:
    return [f"10.{random.randint(30, 250)}.{random.randint(1, 254)}.{random.randint(2, 254)}" for _ in range(n)]


def send_scapy(pkt, use_spoof: bool) -> bool:
    """Send one crafted packet; returns False if raw send fails."""
    try:
        send(pkt, verbose=False)
        return True
    except (PermissionError, OSError) as err:
        warn_root(f"raw send failed ({err.__class__.__name__}) — spoofed SYN needs admin/root + scapy")
        return False


# --------------------------------------------------------------------------
# Scenario senders
# --------------------------------------------------------------------------

def normal_traffic(args, stop_at: float, gt: GroundTruth | None) -> None:
    """Benign periodic devices: TCP connects to an open service + DNS-ish UDP."""
    devices = [
        {"name": "sensor-1", "period": 1.0},
        {"name": "sensor-2", "period": 1.7},
        {"name": "controller", "period": 0.8},
    ]
    next_beat = {d["name"]: time.monotonic() for d in devices}
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payloads = [os.urandom(random.randint(16, 90)) for _ in range(8)]

    while time.monotonic() < stop_at:
        now = time.monotonic()
        for d in devices:
            if now >= next_beat[d["name"]]:
                next_beat[d["name"]] = now + d["period"] * random.uniform(0.7, 1.3)
                kind = random.random()
                try:
                    if kind < 0.55:
                        # normal TCP session to the open service (full handshake)
                        s = socket.create_connection((args.target, args.open_port), timeout=0.5)
                        s.sendall(random.choice(payloads))
                        s.close()
                    else:
                        # DNS-like UDP query
                        udp_sock.sendto(random.choice(payloads), (args.target, 53))
                except OSError:
                    pass
        time.sleep(0.05)


def suspicious_scan(args, stop_at: float, gt: GroundTruth | None) -> None:
    """Low-and-slow half-open SYN probes — below any flood threshold."""
    if require_scapy():
        ports = [22, 23, 80, 443, 1883, 5353, 8080, 8443, 9000, 53]
        while time.monotonic() < stop_at:
            sport, dport = random.randint(40000, 60000), random.choice(ports)
            pkt = IP(src=random.choice(make_source_ips(1)), dst=args.target) / TCP(
                sport=sport, dport=dport, flags="S"
            )
            send_scapy(pkt, use_spoof=True)
            time.sleep(1.0 / max(args.rate / 8, 0.5))  # deliberately slow
    else:
        # connect-scan fallback (full handshakes, but port-hopping is still odd)
        ports = range(20, 120)
        while time.monotonic() < stop_at:
            for p in random.sample(list(ports), 8):
                try:
                    socket.create_connection((args.target, p), timeout=0.2).close()
                except OSError:
                    pass
            time.sleep(0.8)


def syn_flood(args, stop_at: float, gt: GroundTruth | None) -> None:
    if not require_scapy():
        print("[WARN] falling back to TCP connect flood (no scapy) — visible but completes handshakes")
        while time.monotonic() < stop_at:
            for _ in range(max(args.rate // 20, 1)):
                try:
                    s = socket.socket()
                    s.setblocking(False)
                    s.connect_ex((args.target, args.port))
                    s.close()
                except OSError:
                    pass
            time.sleep(0.05)
        return

    interval = 1.0 / max(args.rate, 1)
    sources = make_source_ips(args.sources) if args.sources else None
    sent = 0
    while time.monotonic() < stop_at:
        src = random.choice(sources) if sources else (
            f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            if args.spoof else None
        )
        pkt = IP(dst=args.target) / TCP(
            sport=random.randint(30000, 65000), dport=args.port, flags="S",
            seq=random.randint(0, 2**31), window=512,
        )
        if src:
            pkt[IP].src = src
        if not send_scapy(pkt, use_spoof=bool(src)):
            return  # cannot send raw at all
        sent += 1
        # burst pacing to hold an average rate
        if sent % 20 == 0:
            time.sleep(max(0.0, 20 * interval - 0.002))


def low_flood(args, stop_at: float, gt: GroundTruth | None) -> None:
    """Sustained LOW-rate half-open SYN flood at one port.

    Deliberately below full-flood intensity: enough to look hostile to the
    model (THROTTLE territory, sometimes BLOCK on a strict threshold) but not
    enough to saturate the link. Great for showing the graduated response.
    """
    rate = min(args.rate, 80)  # cap: this is the gentle attack
    if not require_scapy():
        print("[WARN] no scapy — low-flood falls back to slow connect probes")
        while time.monotonic() < stop_at:
            try:
                s = socket.socket()
                s.setblocking(False)
                s.connect_ex((args.target, args.port))
                s.close()
            except OSError:
                pass
            time.sleep(1.0 / rate)
        return

    sources = make_source_ips(max(args.sources, 3)) if args.sources else make_source_ips(4)
    interval = 1.0 / rate
    sent = 0
    while time.monotonic() < stop_at:
        pkt = IP(src=random.choice(sources), dst=args.target) / TCP(
            sport=random.randint(30000, 65000), dport=args.port, flags="S",
            seq=random.randint(0, 2**31), window=512,
        )
        if not send_scapy(pkt, use_spoof=True):
            return
        sent += 1
        if sent % 10 == 0:
            time.sleep(max(0.0, 10 * interval - 0.002))


def udp_flood(args, stop_at: float, gt: GroundTruth | None) -> None:
    interval = 1.0 / max(args.rate, 1)
    if args.spoof or args.sources:
        if require_scapy():
            sources = make_source_ips(args.sources or 0) or None
            sent = 0
            while time.monotonic() < stop_at:
                pkt = IP(dst=args.target) / UDP(
                    sport=random.randint(30000, 65000),
                    dport=random.choice([args.port, random.randint(1024, 65000)] if args.random_ports else [args.port]),
                ) / os.urandom(random.randint(8, 120))
                if sources:
                    pkt[IP].src = random.choice(sources)
                elif args.spoof:
                    pkt[IP].src = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                if not send_scapy(pkt, use_spoof=True):
                    return
                sent += 1
                if sent % 20 == 0:
                    time.sleep(max(0.0, 20 * interval - 0.002))
            return
        print("[WARN] falling back to unspoofed UDP flood via sockets")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = os.urandom(random.randint(32, 256))
    sent = 0
    while time.monotonic() < stop_at:
        dport = random.randint(1024, 65000) if args.random_ports else args.port
        try:
            sock.sendto(payload, (args.target, dport))
        except OSError:
            pass
        sent += 1
        if sent % 20 == 0:
            time.sleep(max(0.0, 20 * interval - 0.002))


def congestion(args, stop_at: float, gt: GroundTruth | None) -> None:
    """Many legitimate concurrent flows — high volume, valid handshakes."""
    import threading

    def worker(seed: int) -> None:
        rng = random.Random(seed)
        while time.monotonic() < stop_at:
            try:
                s = socket.create_connection((args.target, args.open_port), timeout=0.5)
                s.sendall(os.urandom(rng.randint(64, 512)))
                s.recv(128)
                s.close()
            except OSError:
                pass
            time.sleep(rng.uniform(0.02, 0.08))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(args.workers)]
    for t in threads:
        t.start()
    while time.monotonic() < stop_at:
        time.sleep(0.25)


# --------------------------------------------------------------------------
# Demo storyline
# --------------------------------------------------------------------------

STORY = [
    ("Normal baseline", "normal", 15),
    ("Suspicious low-and-slow scan", "suspicious", 12),
    ("Normal recovery", "normal", 8),
    ("Network congestion (legit load)", "congestion", 12),
    ("Low-rate flood (graduated response)", "low-flood", 15),
    ("Normal recovery", "normal", 8),
    ("SYN flood burst", "syn-flood", 15),
    ("Normal recovery", "normal", 10),
    ("UDP flood burst", "udp-flood", 15),
    ("Normal recovery / observe release", "normal", 12),
]


def run_story(args) -> None:
    gt = GroundTruth(args.labels)
    senders = {
        "normal": normal_traffic,
        "suspicious": suspicious_scan,
        "congestion": congestion,
        "syn-flood": syn_flood,
        "udp-flood": udp_flood,
        "low-flood": low_flood,
    }
    print("Demo storyline — keep the dashboard visible.")
    for name, kind, dur in STORY:
        gt.phase(name, kind)
        stop_at = time.monotonic() + dur
        senders[kind](args, stop_at, gt)
        time.sleep(1.0)
    print("\nStoryline complete. Ground truth: " + str(Path(args.labels).resolve()))


# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Traffic scenario generator for the edge detector demo")
    parser.add_argument("mode", choices=["normal", "suspicious", "syn-flood", "udp-flood", "low-flood", "congestion", "story"])
    parser.add_argument("--target", required=True, help="target Pi IP (private/lab address only)")
    parser.add_argument("--port", type=int, default=80, help="flood destination port")
    parser.add_argument("--open-port", type=int, default=8080, help="port that accepts real connections (dashboard)")
    parser.add_argument("--rate", type=int, default=300, help="packets per second for floods/scans")
    parser.add_argument("--duration", type=int, default=20, help="seconds for single modes")
    parser.add_argument("--spoof", action="store_true", help="randomize source IP per packet (scapy/root)")
    parser.add_argument("--sources", type=int, default=0, help="rotate among N fixed fake source IPs")
    parser.add_argument("--random-ports", action="store_true", help="UDP flood: vary destination ports")
    parser.add_argument("--workers", type=int, default=12, help="congestion: concurrent connections")
    parser.add_argument("--labels", default="reports/demo_labels.jsonl", help="ground-truth log (story mode)")
    args = parser.parse_args()

    private_target_guard(args.target)

    senders = {
        "normal": normal_traffic,
        "suspicious": suspicious_scan,
        "syn-flood": syn_flood,
        "udp-flood": udp_flood,
        "low-flood": low_flood,
        "congestion": congestion,
    }
    print(f"Traffic simulator | mode={args.mode} target={args.target}:{args.port} rate={args.rate}/s "
          f"spoof={args.spoof} scapy={'yes' if SCAPY else 'NO'}")
    if args.mode == "story":
        run_story(args)
        return

    gt = GroundTruth(args.labels)
    gt.phase(args.mode, args.mode)
    senders[args.mode](args, time.monotonic() + args.duration, gt)
    print(f"Done ({args.mode}, {args.duration}s). Ground truth appended to {args.labels}")


if __name__ == "__main__":
    main()
