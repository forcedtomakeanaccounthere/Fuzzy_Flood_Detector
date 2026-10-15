"""Direction-aware relabeling to remove victim-response label noise.

Window-based labeling (labels_map.txt) marks EVERY packet inside an attack
window as attack=1. But during a SYN flood roughly half of the packets in the
window are the victim's own defensive responses (SYN-ACK / RST / RST,ACK sent
FROM the victim back to the attacker). Training on those as "attack" teaches
the model to flag the victim's own traffic, which caps recall near 40-50% and
would raise false alarms on the Pi's own replies during a live demo.

This script rewrites the attack label per packet:
  attack = 1  only for packets flowing attacker -> victim inside an attack
              window (identified by direction: Source != victim)
  attack = 0  for the victim's own outgoing responses (Source == victim)

The victim IP is inferred per attack window as the destination that receives
the majority of SYN-only packets, which works both for single-source attacks
(this dataset) and spoofed-source attacks (hping3 --rand-source), because in
both cases the SYNs share one destination.

Usage:
  python relabel_direction_aware.py \
      --input data/syn_udp_flood_attack_data_labeled.csv \
      --output data/syn_udp_flood_attack_data_labeled_diraware.csv
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


def infer_victim(window: pd.DataFrame) -> str | None:
    """Victim inference fallback chain.

    1. Destination receiving the majority of SYN-only packets (SYN flood).
    2. Source of the majority of RST packets — RSTs are emitted by the TCP
       stack that owns the targeted service, i.e. the victim (ACK/PSH floods).
    3. Most common destination of TCP/UDP rows (spoofed UDP floods).
    """
    tcp = window[window["Protocol"].astype(str) == "TCP"]
    if not tcp.empty:
        info = tcp["Info"].astype(str)
        syn_only = tcp[
            info.str.contains(r"\[SYN\]", regex=True, na=False)
            & ~info.str.contains(r"ACK", na=False)
        ]
        if not syn_only.empty:
            return str(syn_only["Destination"].mode().iloc[0])
        rst = tcp[info.str.contains(r"\[RST", regex=False, na=False)]
        if not rst.empty:
            return str(rst["Source"].mode().iloc[0])
    ip_rows = window[window["Protocol"].astype(str).isin(["TCP", "UDP"])]
    if ip_rows.empty:
        return None
    return str(ip_rows["Destination"].mode().iloc[0])


def relabel(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    df = df.copy()
    stats = {
        "windows_total": 0,
        "windows_with_victim": 0,
        "attack_rows_before": int(df["attack"].sum()),
        "response_rows_reverted": 0,
        "background_rows_reverted": 0,
    }

    # Process each contiguous attack window separately so per-window victims
    # are found even if a capture contains multiple attack phases.
    attack_mask = df["attack"] == 1
    # Contiguous runs of attack rows (row index adjacency after time sort).
    windows: list[np.ndarray] = []
    idx = np.flatnonzero(attack_mask.to_numpy())
    if len(idx):
        splits = np.flatnonzero(np.diff(idx) > 1)
        starts = np.concatenate(([0], splits + 1))
        ends = np.concatenate((splits, [len(idx) - 1]))
        for s, e in zip(starts, ends):
            windows.append(idx[s : e + 1])
    stats["windows_total"] = len(windows)

    for win_idx in windows:
        window = df.iloc[win_idx]
        victim = infer_victim(window)
        if victim is None:
            continue
        stats["windows_with_victim"] += 1

        src = window["Source"].astype(str)
        proto = window["Protocol"].astype(str)

        # 1) Victim's own outgoing replies are responses, not attacks.
        responses = src == victim
        # 2) Background non-TCP/UDP chatter captured inside the window
        #    (QUIC/DNS/ICMPv6/MDNS from unrelated hosts) is not flood traffic
        #    unless it targets the victim's flooded port. Keep UDP-based QUIC
        #    ambiguous rows only if they go TO the victim.
        background = ~proto.isin(["TCP", "UDP", "QUIC"]) & (src != victim)
        # QUIC is UDP-encapsulated: treat as attack only when aimed at victim.
        quic_elsewhere = (proto == "QUIC") & (window["Destination"].astype(str) != victim)

        relabel_mask = responses | background | quic_elsewhere
        stats["response_rows_reverted"] += int(responses.sum())
        stats["background_rows_reverted"] += int((background | quic_elsewhere).sum())
        df.iloc[win_idx, df.columns.get_loc("attack")] = np.where(
            relabel_mask, 0, 1
        )

    stats["attack_rows_after"] = int(df["attack"].sum())
    return df, stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remove victim-response label noise via direction-aware relabeling"
    )
    parser.add_argument("--input", default="data/syn_udp_flood_attack_data_labeled.csv")
    parser.add_argument("--output", default="data/syn_udp_flood_attack_data_labeled_diraware.csv")
    parser.add_argument("--report", default="reports/relabel_report.json")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        in_path = Path(args.input).name  # allow running from implementation/
    df = pd.read_csv(in_path)
    df = df.sort_values("Time").reset_index(drop=True)

    df, stats = relabel(df)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as f:
        json.dump({"input": str(in_path), "output": str(out_path), **stats}, f, indent=2)

    print("Direction-aware relabeling complete.")
    print(f"  Attack windows processed:        {stats['windows_total']}")
    print(f"  Victim identified in:            {stats['windows_with_victim']}")
    print(f"  Attack rows before:              {stats['attack_rows_before']}")
    print(f"  Victim responses -> normal:      {stats['response_rows_reverted']}")
    print(f"  Unrelated background -> normal:  {stats['background_rows_reverted']}")
    print(f"  Attack rows after:               {stats['attack_rows_after']}")
    print(f"  Wrote: {out_path}")


if __name__ == "__main__":
    main()
