"""Edge flood detector for Raspberry Pi — replay OR live capture.

Pipeline (identical features to training):
  packet records -> rolling window (default 50) -> 17 features -> fuzzy forest
  -> score vs threshold -> per-IP mitigation state (ALLOW / THROTTLE / BLOCK)
  -> JSONL events + detector_state.json for the dashboard.

Modes
  --replay-csv FILE   deterministic CSV replay (laptop & Pi bring-up)
  --live              scapy sniffing on the Pi (needs sudo for raw sockets)

Outputs
  --log  reports/monitor_events.jsonl   append-only event stream (packet/window/action)
  --state reports/detector_state.json   atomic snapshot rewritten ~1s for the dashboard
  --control reports/control_commands.json  command queue written by the dashboard UI

Safety
  Blocking is SIMULATED unless --live-firewall is given on Linux. The SSH
  client IP (env SSH_CLIENT), loopback, and --protect IPs are never blocked,
  so an attack aimed at your own management host cannot lock you out.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

import pandas as pd

from fuzzy_inference import FuzzyForestPredictor
from sysstats import process_snapshot, system_snapshot


# --------------------------------------------------------------------------
# Packet records: every source is normalised to the six Wireshark-style
# columns the training pipeline used.
# --------------------------------------------------------------------------

RAW_COLUMNS = ("Time", "Length", "Info", "Protocol", "Source", "Destination")

TCP_FLAG_ORDER = [("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"), ("A", "ACK"), ("U", "URG"), ("E", "ECE"), ("C", "CWR")]


def tcp_info(sport: int, dport: int, flags: str, payload_len: int) -> str:
    names = [n for bit, n in TCP_FLAG_ORDER if bit in flags]
    return f"{sport}  >  {dport} [{', '.join(names) or 'None'}] Seq=0 Win=64240 Len={payload_len}"


def udp_info(sport: int, dport: int, payload_len: int) -> str:
    return f"{sport}  >  {dport} UDP {payload_len}"


def csv_records(csv_path: str):
    """Yield normalised packet dicts from a Wireshark-exported CSV."""
    reader = pd.read_csv(csv_path, chunksize=500)
    for chunk in reader:
        for row in chunk.to_dict("records"):
            yield {
                "Time": float(row.get("Time", 0) or 0),
                "Length": row.get("Length", 0),
                "Info": str(row.get("Info", "")),
                "Protocol": str(row.get("Protocol", "")),
                "Source": str(row.get("Source", "unknown")),
                "Destination": str(row.get("Destination", "unknown")),
            }


def scapy_record(pkt) -> dict | None:
    """Convert a scapy packet into the same six-column record."""
    try:
        from scapy.all import IP, IPv6, TCP, UDP
    except ImportError:
        raise SystemExit("scapy is required for --live mode: pip3 install scapy")

    ts = float(pkt.time)
    length = len(pkt)
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        net = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if net is None:
            return None
        return {
            "Time": ts, "Length": length,
            "Info": tcp_info(int(tcp.sport), int(tcp.dport), str(tcp.flags), int(tcp.payload and len(tcp.payload) or 0)),
            "Protocol": "TCP",
            "Source": str(net.src), "Destination": str(net.dst),
        }
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        net = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if net is None:
            return None
        return {
            "Time": ts, "Length": length,
            "Info": udp_info(int(udp.sport), int(udp.dport), int(udp.payload and len(udp.payload) or 0)),
            "Protocol": "UDP",
            "Source": str(net.src), "Destination": str(net.dst),
        }
    net = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if net is None:
        return None
    return {
        "Time": ts, "Length": length,
        "Info": str(pkt.summary()),
        "Protocol": pkt.lastlayer().name.upper(),
        "Source": str(net.src), "Destination": str(net.dst),
    }


# --------------------------------------------------------------------------
# Window features — must mirror shared_preprocessing.build_clean_dataset()
# exactly for a single rolling slice. Train/serve skew here silently
# disables the UDP/byte fuzzy rules, so keep both files in sync.
# Implemented in pure Python (no pandas) so per-window cost on the Pi stays
# in the ~1ms range even during floods.
# --------------------------------------------------------------------------

_PORT_RE = re.compile(r"(\d+)\s*>\s*(\d+)")


def compute_window_features(rows: list[dict], window: int) -> tuple[dict, dict, str]:
    n = len(rows)
    syn_count = ack_count = udp_count = retrans_count = 0
    half_open = 0
    byte_sum = 0.0
    sq_sum = 0.0
    dst_ports: set[str] = set()
    src_counts: dict[str, int] = {}
    first_syn_t = last_syn_t = None
    syn_seen = 0
    t0 = float(rows[0]["Time"])
    t1 = float(rows[-1]["Time"])
    last = rows[-1]

    for r in rows:
        info = r["Info"]
        proto = r["Protocol"]
        length = float(r["Length"])
        byte_sum += length
        sq_sum += length * length
        src = r["Source"]
        src_counts[src] = src_counts.get(src, 0) + 1

        is_syn = "[SYN]" in info
        if "[ACK]" in info:
            ack_count += 1
        if is_syn:  # "[SYN]" does not match "[SYN, ACK]"
            syn_count += 1
            if syn_seen == 0:
                first_syn_t = float(r["Time"])
            last_syn_t = float(r["Time"])
            syn_seen += 1
            if "[SYN, ACK]" not in info:
                half_open += 1
        if "Retransmission" in info:
            retrans_count += 1
        if proto == "UDP":
            udp_count += 1
        m = _PORT_RE.search(info)
        if m:
            dst_ports.add(m.group(2))

    # Warm-up guard: same 1s span floor for partial windows as training.
    span_full = max(t1 - t0, 0.001)
    span = max(span_full, 1.0) if n < window else span_full

    # Per-packet direction features of the newest packet.
    cur_info = last["Info"]
    m = _PORT_RE.search(cur_info)
    src_port = float(m.group(1)) if m else float("nan")
    dst_port = float(m.group(2)) if m else float("nan")
    is_rst_cur = int("[RST" in cur_info)
    is_icmp_cur = int(last["Protocol"].upper().startswith("ICMP"))
    src_priv = int(src_port == src_port and src_port < 1024)
    dst_priv = int(dst_port == dst_port and dst_port < 1024)

    mean_len = byte_sum / n
    if n > 1:
        var = max(0.0, (sq_sum - n * mean_len * mean_len) / (n - 1))
        std_len = var ** 0.5
    else:
        std_len = 0.0

    features = {
        "packet_length": float(last["Length"]),
        "time_delta": max(t1 - float(rows[-2]["Time"]), 0.0) if n > 1 else 0.0,
        "is_syn_only": int("[SYN]" in cur_info and "[SYN, ACK]" not in cur_info),
        "syn_ack_ratio": syn_count / (ack_count + 1),
        "half_open_conn_count": half_open,
        "same_src_ip_freq": src_counts.get(last["Source"], 0) / n,
        "syn_packet_density": min(syn_count / span, 1000.0),
        "udp_packet_density": min(udp_count / span, 1000.0),
        "total_packet_density": min(n / span, 2000.0),
        "byte_density": min(byte_sum / span, 1_000_000.0),
        "retransmission_rate": retrans_count / n,
        "unique_dst_port_count": len(dst_ports),
        "avg_time_between_syns": (last_syn_t - first_syn_t) / (syn_seen - 1) if syn_seen > 1 else 10.0,
        "pkt_len_mean": mean_len,
        "pkt_len_std": std_len,
        "udp_ratio": udp_count / window,
        "syn_ratio": syn_count / window,
        "dst_port_lt_1024": dst_priv,
        "src_port_lt_1024": src_priv,
        "is_rst_flag": is_rst_cur,
        "is_icmp": is_icmp_cur,
        "response_direction": int(src_priv or is_rst_cur or is_icmp_cur),
    }
    stats = {
        "syn_count": syn_count,
        "ack_count": ack_count,
        "udp_count": udp_count,
        "syn_ack_ratio": round(features["syn_ack_ratio"], 3),
        "half_open_conn_count": half_open,
        "syn_packet_density": round(features["syn_packet_density"], 2),
        "udp_packet_density": round(features["udp_packet_density"], 2),
        "total_packet_density": round(features["total_packet_density"], 2),
        "avg_time_between_syns": round(features["avg_time_between_syns"], 4),
        "same_src_ip_freq": round(features["same_src_ip_freq"], 3),
    }
    dominant = max(src_counts, key=src_counts.get)
    return features, stats, dominant


# --------------------------------------------------------------------------
# Firewall adapter (dry-run by default; real iptables only with --live-firewall)
# --------------------------------------------------------------------------

class FirewallAdapter:
    def __init__(self, live: bool, protected_ips: set[str]) -> None:
        self.live = live and sys.platform == "linux"
        self.protected = {ip for ip in protected_ips if ip}
        self.rules_installed: dict[str, str] = {}

    def _iptables(self, *args: str) -> tuple[bool, str]:
        binary = "sudo -n iptables" if os.geteuid() != 0 else "iptables"
        cmd = [*binary.split(), *args]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return res.returncode == 0, (res.stderr or "").strip()
        except Exception as err:  # noqa: BLE001
            return False, str(err)

    def block(self, ip: str, reason: str) -> str:
        if ip in self.protected:
            return f"REFUSED block of {ip}: protected/management IP"
        if ip in self.rules_installed:
            return f"{ip} already blocked"
        if self.live:
            ok, err = self._iptables("-I", "INPUT", "-s", ip, "-j", "DROP")
            msg = f"[FIREWALL] DROP rule installed for {ip} ({reason})" if ok else f"[FIREWALL-FAIL] {ip}: {err} (treated as simulated block)"
        else:
            msg = f"[SIMULATED] Block {ip} ({reason}) — DROP rule would be installed via iptables"
        self.rules_installed[ip] = msg
        return msg

    def unblock(self, ip: str) -> str:
        if ip not in self.rules_installed:
            return f"{ip} was not blocked"
        if self.live and "[FIREWALL]" in self.rules_installed[ip]:
            ok, err = self._iptables("-D", "INPUT", "-s", ip, "-j", "DROP")
            if not ok:
                return f"[FIREWALL-FAIL] could not remove rule for {ip}: {err}"
        del self.rules_installed[ip]
        return f"[RELEASED] {ip} unblocked — traffic permitted again"


def default_protected_ips() -> set[str]:
    protected = {"127.0.0.1", "::1", "0.0.0.0", "255.255.255.255"}
    for var in ("SSH_CLIENT", "SSH_CONNECTION"):
        val = os.environ.get(var)
        if val:
            protected.add(val.split()[0])
    return protected


# --------------------------------------------------------------------------
# Per-IP mitigation state
# --------------------------------------------------------------------------

STATUS_ALLOWED, STATUS_THROTTLED, STATUS_BLOCKED = "ALLOWED", "THROTTLED", "BLOCKED"


class SourceState:
    __slots__ = ("ip", "packets", "windows", "attack_windows", "throttle_windows",
                 "score_sum", "score_max", "status", "blocked_until", "last_seen",
                 "last_msg", "manual")

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.packets = 0
        self.windows = 0
        self.attack_windows = 0
        self.throttle_windows = 0
        self.score_sum = 0.0
        self.score_max = 0.0
        self.status = STATUS_ALLOWED
        self.blocked_until = 0.0
        self.last_seen = time.time()
        self.last_msg = ""
        self.manual = False


class EdgeDetector:
    def __init__(self, args) -> None:
        self.args = args
        self.predictor = FuzzyForestPredictor(args.artifact)
        self.window = int(self.predictor.artifact.get("window", 50) or 50) if isinstance(self.predictor.artifact, dict) else 50
        self.threshold = self.predictor.threshold

        self.firewall = FirewallAdapter(
            live=args.live_firewall,
            protected_ips=default_protected_ips() | set(args.protect or []),
        )

        self.events_path = Path(args.log)
        self.state_path = Path(args.state)
        self.control_path = Path(args.control)
        for p in (self.events_path, self.state_path, self.control_path):
            p.parent.mkdir(parents=True, exist_ok=True)

        self.sources: dict[str, SourceState] = {}
        self.recent_actions: deque = deque(maxlen=40)
        self.control_results: deque = deque(maxlen=40)
        self._last_control_id = 0

        self.packets_total = 0
        self.windows_evaluated = 0
        self.infer_ms_sum = 0.0
        self.pps = 0.0
        self._pps_count = 0
        self._pps_ts = time.time()
        self._last_state_write = 0.0
        self._packet_event_budget = 0.0

        self.current = {
            "score": 0.0, "model_probability": 0.0, "fuzzy_confidence": 0.0,
            "action": "WARMUP", "dominant_source": "", "packets_in_window": 0,
            "stats": {}, "rules": {},
        }

    # ----- events -----
    def log_event(self, event: dict) -> None:
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")

    def record_action(self, msg: str) -> None:
        entry = {"ts": round(time.time(), 3), "msg": msg}
        self.recent_actions.append(entry)
        self.log_event({"type": "action", **entry})
        print(f"  [{time.strftime('%H:%M:%S')}] {msg}")

    # ----- per-IP bookkeeping -----
    def source(self, ip: str) -> SourceState:
        st = self.sources.get(ip)
        if st is None:
            st = self.sources[ip] = SourceState(ip)
        return st

    def note_packet(self, rec: dict) -> None:
        self.packets_total += 1
        self._pps_count += 1
        st = self.source(rec["Source"])
        st.packets += 1
        st.last_seen = time.time()

    def expire_statuses(self) -> None:
        now = time.time()
        for st in self.sources.values():
            if st.status == STATUS_BLOCKED and not st.manual and now >= st.blocked_until:
                st.status = STATUS_ALLOWED
                st.blocked_until = 0.0
                self.record_action(self.firewall.unblock(st.ip) or f"[RELEASED] {st.ip}")
            elif st.status == STATUS_THROTTLED and now >= st.blocked_until:
                st.status = STATUS_ALLOWED
                st.blocked_until = 0.0
                self.record_action(f"[RELEASED] {st.ip} throttle window elapsed — back to ALLOWED")

    # ----- control commands from dashboard -----
    def consume_controls(self) -> None:
        try:
            data = json.loads(self.control_path.read_text(encoding="utf-8"))
        except Exception:
            return
        for cmd in data.get("commands", []):
            if cmd.get("id", 0) <= self._last_control_id:
                continue
            self._last_control_id = int(cmd["id"])
            op, ip = cmd.get("op"), str(cmd.get("ip", ""))
            if op == "block" and ip:
                st = self.source(ip)
                st.status = STATUS_BLOCKED
                st.manual = True
                st.blocked_until = time.time() + args_manual_ttl(self.args)
                self.control_results.append({"id": cmd["id"], "msg": self.firewall.block(ip, "manual block from dashboard")})
                st.last_msg = self.control_results[-1]["msg"]
            elif op == "unblock" and ip:
                st = self.sources.get(ip)
                if st:
                    st.status = STATUS_ALLOWED
                    st.manual = False
                    st.blocked_until = 0.0
                self.control_results.append({"id": cmd["id"], "msg": self.firewall.unblock(ip)})
            elif op == "unblock_all":
                for st in list(self.sources.values()):
                    if st.status == STATUS_BLOCKED:
                        st.status = STATUS_ALLOWED
                        st.manual = False
                        st.blocked_until = 0.0
                        self.firewall.unblock(st.ip)
                self.control_results.append({"id": cmd["id"], "msg": "[RELEASED] all IPs unblocked"})
            else:
                self.control_results.append({"id": cmd["id"], "msg": f"unknown op {op}"})
            print(f"  [control] {self.control_results[-1]['msg']}")

    # ----- state snapshot for dashboard -----
    def threat_level(self) -> str:
        if any(s.status == STATUS_BLOCKED for s in self.sources.values()):
            return "ATTACK"
        if any(s.status == STATUS_THROTTLED for s in self.sources.values()):
            return "ELEVATED"
        return "CLEAR"

    def update_pps(self, now: float) -> None:
        dt = now - self._pps_ts
        if dt >= 1.0:
            inst = self._pps_count / dt
            self.pps = 0.6 * self.pps + 0.4 * inst if self.pps else inst
            self._pps_count = 0
            self._pps_ts = now

    def write_state(self, warmup: bool, mode: str) -> None:
        now = time.time()
        self.expire_statuses()
        active = [s for s in self.sources.values() if now - s.last_seen < 120 or s.status != STATUS_ALLOWED]
        active.sort(key=lambda s: -s.packets)
        blocked = sum(1 for s in self.sources.values() if s.status == STATUS_BLOCKED)
        throttled = sum(1 for s in self.sources.values() if s.status == STATUS_THROTTLED)
        snapshot = {
            "updated": round(now, 3),
            "mode": mode,
            "warmup": warmup,
            "threat": self.threat_level(),
            "threshold": self.threshold,
            "current": self.current,
            "kpi": {
                "packets_total": self.packets_total,
                "packets_per_sec": round(self.pps, 1),
                "windows_evaluated": self.windows_evaluated,
                "avg_infer_ms": round(self.infer_ms_sum / max(self.windows_evaluated, 1), 2),
                "blocked_ips": blocked,
                "throttled_ips": throttled,
            },
            "sources": [
                {
                    "ip": s.ip, "packets": s.packets, "windows": s.windows,
                    "attacks": s.attack_windows, "throttles": s.throttle_windows,
                    "score_avg": round(s.score_sum / max(s.windows, 1), 3),
                    "score_max": round(s.score_max, 3),
                    "status": s.status,
                    "blocked_until": round(s.blocked_until, 2) if s.blocked_until else None,
                    "last_seen": round(s.last_seen, 2),
                }
                for s in active[:25]
            ],
            "recent_actions": list(self.recent_actions)[-15:],
            "control_results": list(self.control_results)[-15:],
            "system": {**system_snapshot(), **process_snapshot()},
            "model": {
                "artifact": self.args.artifact,
                "threshold": self.threshold,
                "feature_count": len(self.predictor.feature_order),
                "window": self.window,
            },
        }
        _atomic_write(self.state_path, json.dumps(snapshot))

    # ----- decision core -----
    def evaluate_window(self, rows: list[dict], now: float) -> dict:
        t0 = time.perf_counter()
        features, stats, dominant = compute_window_features(rows, self.window)
        result = self.predictor.predict(pd.DataFrame([features]))
        infer_ms = (time.perf_counter() - t0) * 1000
        self.infer_ms_sum += infer_ms
        self.windows_evaluated += 1

        score = result["score"]
        threshold = self.threshold
        if score >= threshold:
            action = "BLOCK"
        elif score >= threshold * 0.5:
            action = "THROTTLE"
        else:
            action = "ALLOW"

        dom_state = self.source(dominant)
        dom_state.windows += 1
        dom_state.score_sum += score
        dom_state.score_max = max(dom_state.score_max, score)

        if action == "BLOCK":
            dom_state.attack_windows += 1
            if dom_state.status != STATUS_BLOCKED:
                dom_state.status = STATUS_BLOCKED
                dom_state.blocked_until = now + self.args.block_ttl
                msg = self.firewall.block(dominant, f"score {score:.3f} >= threshold {threshold:.3f}")
                dom_state.last_msg = msg
                self.record_action(msg)
            else:
                dom_state.blocked_until = max(dom_state.blocked_until, now + self.args.block_ttl)
        elif action == "THROTTLE":
            dom_state.throttle_windows += 1
            if dom_state.status == STATUS_ALLOWED:
                dom_state.status = STATUS_THROTTLED
                dom_state.blocked_until = now + self.args.throttle_ttl
                msg = f"[THROTTLED] {dominant} suspicious traffic (score {score:.3f}) — rate-limit advisory for {int(self.args.throttle_ttl)}s"
                dom_state.last_msg = msg
                self.record_action(msg)
            else:
                dom_state.blocked_until = max(dom_state.blocked_until, now + self.args.throttle_ttl)

        self.current = {
            "score": round(score, 4),
            "model_probability": round(result["model_probability"], 4),
            "fuzzy_confidence": round(result["fuzzy_confidence"], 4),
            "action": action,
            "dominant_source": dominant,
            "packets_in_window": len(rows),
            "stats": stats,
            "rules": result.get("rule_activations", {}),
            "verdict": "ATTACK" if action == "BLOCK" else ("SUSPICIOUS" if action == "THROTTLE" else "SAFE"),
        }

        event = {
            "type": "window",
            "timestamp": round(now, 3),
            "packets_in_window": len(rows),
            "dominant_source": dominant,
            "action": action,
            "infer_ms": round(infer_ms, 2),
            **{k: self.current[k] for k in ("score", "model_probability", "fuzzy_confidence", "stats", "rules")},
            "threshold": threshold,
        }
        self.log_event(event)
        return event

    def maybe_packet_event(self, rec: dict, budget_dt: float = 0.0, force: bool = False) -> None:
        # Rate-limit packet events in live mode so floods don't explode the log.
        self._packet_event_budget = min(self._packet_event_budget + budget_dt, 1.0)
        if not force:
            if self._packet_event_budget < 1.0 / self.args.max_packet_events:
                return
            self._packet_event_budget -= 1.0 / self.args.max_packet_events
        verdict = self.current.get("verdict", "SAFE")
        self.log_event({
            "type": "packet",
            "timestamp": round(time.time(), 3),
            "src": rec["Source"], "dst": rec["Destination"],
            "proto": rec["Protocol"], "length": rec["Length"],
            "verdict": verdict,
            "confidence": self.current.get("score", 0.0),
            "action": self.current.get("action", "WARMUP"),
        })


def _atomic_write(path: Path, data: str) -> None:
    """Write state atomically; retry around concurrent readers.

    On Windows, os.replace() fails with Access Denied if another process
    (the dashboard) holds the target open for reading at that instant.
    A few short retries make the swap effectively race-free; the fallback
    direct write keeps the dashboard fed even if retries are exhausted.
    """
    tmp = path.with_suffix(".tmp")
    tmp.write_text(data, encoding="utf-8")
    for attempt in range(5):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.02 * (attempt + 1))
    try:
        path.write_text(data, encoding="utf-8")
        tmp.unlink(missing_ok=True)
    except OSError:
        pass


def args_manual_ttl(args) -> float:
    return args.block_ttl * 5 if args.block_ttl else 600


# --------------------------------------------------------------------------
# Run loops
# --------------------------------------------------------------------------

def run_replay(det: EdgeDetector, args) -> None:
    window = det.window
    rolling: deque = deque(maxlen=window)
    min_eval = min(window, args.min_eval)
    started = time.time()

    while True:  # supports --loop for continuous demos
        for idx, rec in enumerate(csv_records(args.replay_csv)):
            now = time.time()
            rolling.append(rec)
            det.note_packet(rec)
            det.maybe_packet_event(rec, force=True)  # replay: log every packet
            if len(rolling) >= min_eval and (idx % args.eval_every == 0):
                event = det.evaluate_window(list(rolling), now)
                if det.windows_evaluated % 25 == 0 or event["action"] != "ALLOW":
                    print(f"  [{time.strftime('%H:%M:%S')}] win {det.windows_evaluated:>5} | {event['dominant_source'][:28]:<28} | score {event['score']:.3f} | {event['action']}")
            if now - det._last_state_write > 1.0:
                det._last_state_write = now
                det.update_pps(now)
                det.write_state(warmup=len(rolling) < min_eval, mode="replay")
            det.consume_controls()
            if args.delay:
                time.sleep(args.delay)
        if not args.loop:
            break
        print("  --loop: restarting replay stream")

    det.write_state(warmup=False, mode="replay")
    print(f"Replay finished: {det.packets_total} packets, {det.windows_evaluated} windows "
          f"in {time.time()-started:.1f}s. Events: {det.events_path}")


def run_live(det: EdgeDetector, args) -> None:
    from scapy.all import sniff  # guarded import

    window = det.window
    min_eval = min(window, args.min_eval)
    incoming: deque = deque(maxlen=window * 8)   # sniffer -> engine queue
    rolling: deque = deque(maxlen=window)        # persistent feature window
    stop = threading.Event()

    def keep(pkt):
        rec = scapy_record(pkt)
        if rec is not None:
            incoming.append(rec)
        return stop.is_set()

    iface = args.iface or None
    print(f"Sniffing on {iface or 'default interface'} (BPF: {args.bpf!r}). Ctrl+C to stop.")
    thread = threading.Thread(
        target=sniff,
        kwargs={"iface": iface, "filter": args.bpf, "prn": keep, "stop_filter": lambda *_: stop.is_set()},
        daemon=True,
    )
    thread.start()

    tick = args.tick
    try:
        while True:
            time.sleep(tick)
            now = time.time()
            fresh = []
            while incoming:
                fresh.append(incoming.popleft())
            for rec in fresh:
                det.note_packet(rec)

            # pps EMA
            det.update_pps(now)

            for rec in fresh:
                det.maybe_packet_event(rec, budget_dt=tick / max(len(fresh), 1))
                rolling.append(rec)

            if len(rolling) >= min_eval and fresh:
                det.evaluate_window(list(rolling), now)
            det.expire_statuses()
            det.consume_controls()
            if now - det._last_state_write >= 1.0:
                det._last_state_write = now
                det.write_state(warmup=len(rolling) < min_eval, mode="live")
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        thread.join(timeout=3)
        det.write_state(warmup=False, mode="live")
        print(f"Stopped: {det.packets_total} packets, {det.windows_evaluated} windows evaluated.")


# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Edge flood detector (replay or live capture)")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--replay-csv", help="CSV packet export to replay")
    src.add_argument("--live", action="store_true", help="sniff live packets with scapy")
    parser.add_argument("--artifact", default="fuzzy_forest.pkl")
    parser.add_argument("--log", default="reports/monitor_events.jsonl")
    parser.add_argument("--state", default="reports/detector_state.json")
    parser.add_argument("--control", default="reports/control_commands.json")
    parser.add_argument("--delay", type=float, default=0.01, help="replay: seconds between packets")
    parser.add_argument("--loop", action="store_true", help="replay: restart CSV when finished")
    parser.add_argument("--eval-every", type=int, default=1, help="replay: evaluate every Nth packet (1 = all)")
    parser.add_argument("--min-eval", type=int, default=20, help="warm-up packets before first verdict")
    parser.add_argument("--iface", default=None, help="live: interface to sniff")
    parser.add_argument("--bpf", default="ip or ip6", help="live: BPF capture filter")
    parser.add_argument("--tick", type=float, default=0.2, help="live: evaluation cadence (s)")
    parser.add_argument("--max-packet-events", type=int, default=25, help="live: packet log lines per second cap")
    parser.add_argument("--block-ttl", type=float, default=120, help="seconds an attack source stays blocked")
    parser.add_argument("--throttle-ttl", type=float, default=20, help="seconds a suspicious source stays throttled")
    parser.add_argument("--live-firewall", action="store_true", help="install real iptables DROP rules (Linux only)")
    parser.add_argument("--protect", nargs="*", default=[], help="extra IPs never to block")
    parser.add_argument("--append", action="store_true", help="append to event log instead of rotating")
    args = parser.parse_args()

    if not args.append and Path(args.log).exists():
        rotated = Path(args.log).with_suffix(".jsonl.1")
        Path(args.log).replace(rotated)

    det = EdgeDetector(args)
    print(f"Edge detector | artifact: {args.artifact} | threshold: {det.threshold:.3f} | window: {det.window}")
    print(f"Protected IPs (never blocked): {sorted(det.firewall.protected)}")
    print(f"Events: {det.events_path} | State: {det.state_path}")

    try:
        if args.replay_csv:
            run_replay(det, args)
        else:
            run_live(det, args)
    except KeyboardInterrupt:
        det.write_state(warmup=False, mode="replay" if args.replay_csv else "live")
        print("\nStopped by user.")


if __name__ == "__main__":
    main()
