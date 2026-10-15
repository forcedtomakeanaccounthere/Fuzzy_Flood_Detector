"""Post-demo scoring: merge traffic-simulator ground truth with detector events.

Reads
  reports/demo_labels.jsonl    phases written by traffic_simulator.py
  reports/monitor_events.jsonl window events written by live_detector.py

Reports, per attack phase: time-to-first-THROTTLE, time-to-first-BLOCK,
blocks issued, and (for normal phases) false positives. Saved to
reports/demo_scoring.json and printed as a table.

Usage:  python evaluate_demo.py [--labels ...] [--events ...]
"""

import argparse
import json
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a demo session")
    parser.add_argument("--labels", default="reports/demo_labels.jsonl")
    parser.add_argument("--events", default="reports/monitor_events.jsonl")
    parser.add_argument("--out", default="reports/demo_scoring.json")
    args = parser.parse_args()

    labels = load_jsonl(Path(args.labels))
    events = load_jsonl(Path(args.events))
    windows = [e for e in events if e.get("type") == "window"]
    actions = [e for e in events if e.get("type") == "action"]

    if not labels:
        raise SystemExit("No ground truth found — run traffic_simulator.py story mode first.")
    if not windows:
        raise SystemExit("No detector windows found — run live_detector.py during the demo.")

    results = []
    for i, lab in enumerate(labels):
        start = lab["ts"]
        end = labels[i + 1]["ts"] if i + 1 < len(labels) else float("inf")
        phase_windows = [w for w in windows if start <= w["timestamp"] < end]
        if not phase_windows:
            continue
        first_throttle = next((w["timestamp"] for w in phase_windows if w["action"] == "THROTTLE"), None)
        first_block = next((w["timestamp"] for w in phase_windows if w["action"] == "BLOCK"), None)
        avg_score = sum(w["score"] for w in phase_windows) / len(phase_windows)
        results.append({
            "phase": lab["phase"],
            "kind": lab.get("kind", ""),
            "duration_s": round((min(end, windows[-1]["timestamp"]) - start), 1),
            "windows_evaluated": len(phase_windows),
            "avg_score": round(avg_score, 3),
            "time_to_throttle_s": round(first_throttle - start, 2) if first_throttle else None,
            "time_to_block_s": round(first_block - start, 2) if first_block else None,
            "false_positive_windows": sum(
                1 for w in phase_windows if w["action"] != "ALLOW"
            ) if lab.get("kind") == "normal" else None,
        })

    attack_phases = [r for r in results if r["kind"] in ("syn-flood", "udp-flood")]
    normal_phases = [r for r in results if r["kind"] in ("normal", "congestion")]
    detected = [r for r in attack_phases if r["time_to_block_s"] is not None]
    fp_windows = sum(r["false_positive_windows"] or 0 for r in normal_phases)
    fp_total = sum(r["windows_evaluated"] for r in normal_phases)

    print("\nDemo scoring")
    print("=" * 96)
    print(f"{'Phase':<38}{'Kind':<14}{'Avg score':>10}{'→Throttle(s)':>13}{'→Block(s)':>11}{'FP wins':>9}")
    print("-" * 96)
    for r in results:
        print(f"{r['phase'][:37]:<38}{r['kind'][:13]:<14}{r['avg_score']:>10.3f}"
              f"{str(r['time_to_throttle_s']):>13}{str(r['time_to_block_s']):>11}"
              f"{(r['false_positive_windows'] if r['false_positive_windows'] is not None else '–'):>9}")
    print("=" * 96)
    if attack_phases:
        print(f"Attack phases detected (BLOCK): {len(detected)}/{len(attack_phases)}"
              f" | mean time-to-block: "
              f"{sum(r['time_to_block_s'] for r in detected)/len(detected):.2f}s" if detected else
              f"Attack phases detected (BLOCK): 0/{len(attack_phases)}")
    print(f"False-positive windows in normal/congestion phases: {fp_windows}/{fp_total}")
    print(f"Raw mitigation actions logged: {len(actions)}")

    Path(args.out).write_text(json.dumps({
        "phases": results,
        "attack_phases": len(attack_phases),
        "attack_phases_blocked": len(detected),
        "fp_windows": fp_windows,
        "fp_windows_total": fp_total,
    }, indent=2), encoding="utf-8")
    print(f"Saved: {args.out}")


if __name__ == "__main__":
    main()
