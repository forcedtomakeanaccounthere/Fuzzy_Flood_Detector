import argparse
import json
import re
from collections import Counter, deque
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.tree import DecisionTreeClassifier


def fit_lightweight_tree(
    X_train,
    y_train,
    random_state: int = 42,
    cv_folds: int = 3,
    tolerance: float = 0.005,
) -> tuple["DecisionTreeClassifier", dict]:
    """Identical training procedure for EVERY tree in the comparison.

    Grid search on train-CV F1 over a deliberately lightweight grid, then
    cost-complexity pruning to the smallest tree whose CV F1 stays within
    `tolerance` of the best. The normal DT and the fuzzy DT are both produced
    by this exact function — the ONLY difference between them is the feature
    space (raw window statistics vs fuzzy memberships + rule activations).
    This keeps the comparison symmetric: no model gets a tuning advantage.
    """
    grid = [
        {"max_depth": d, "min_samples_leaf": l, "class_weight": cw}
        for d in [4, 6, 8, 10, 12]
        for l in [5, 20, 40]
        for cw in [{0: 1, 1: 2}, {0: 1, 1: 3}, {0: 1, 1: 4}, "balanced"]
    ]
    cv = StratifiedKFold(cv_folds, shuffle=True, random_state=random_state)
    best_cv, best_cfg = -1.0, None
    for cfg in grid:
        m = DecisionTreeClassifier(random_state=random_state, min_samples_split=5, **cfg)
        s = cross_val_score(m, X_train, y_train, cv=cv, scoring="f1", n_jobs=cv_folds).mean()
        if s > best_cv:
            best_cv, best_cfg = s, cfg

    base = DecisionTreeClassifier(random_state=random_state, min_samples_split=5, **best_cfg)
    base.fit(X_train, y_train)

    # Cost-complexity pruning: smallest tree within `tolerance` of best CV F1.
    pruned, prune_meta = base, {"selected": False, "unpruned_nodes": int(base.tree_.node_count)}
    try:
        path = base.cost_complexity_pruning_path(X_train, y_train)
        alphas = path.ccp_alphas
        if len(alphas) > 14:
            alphas = np.unique(np.concatenate([
                alphas[:2], np.quantile(alphas[1:-1], np.linspace(0, 1, 10)), alphas[-1:],
            ]))
        best_cv_pruned, best_pick = best_cv, None
        for alpha in alphas:
            cand = DecisionTreeClassifier(
                random_state=random_state, min_samples_split=5,
                ccp_alpha=float(alpha), **best_cfg,
            )
            s = cross_val_score(cand, X_train, y_train, cv=cv, scoring="f1", n_jobs=cv_folds).mean()
            cand.fit(X_train, y_train)
            nodes = cand.tree_.node_count
            if s >= best_cv_pruned - tolerance and (best_pick is None or nodes < best_pick[2]):
                best_cv_pruned, best_pick = s, (cand, float(alpha), nodes)
        if best_pick:
            pruned = best_pick[0]
            prune_meta = {
                **prune_meta,
                "selected": True,
                "ccp_alpha": best_pick[1],
                "nodes": best_pick[2],
                "cv_f1": round(best_cv_pruned, 4),
            }
    except Exception:  # noqa: BLE001 — pruning is best-effort
        pass

    meta = {
        "best_cv_f1": round(best_cv, 4),
        "best_config": {k: str(v) for k, v in best_cfg.items()},
        **prune_meta,
    }
    return pruned, meta


def _extract_ports(info_value: str) -> tuple[float, float]:
    match = re.search(r"(\d+)\s+>\s+(\d+)", str(info_value))
    if match:
        return float(match.group(1)), float(match.group(2))
    return np.nan, np.nan


def _rolling_src_freq(source_series: pd.Series, window: int) -> np.ndarray:
    """Fraction of the last `window` packets that share the current source IP.

    deque+Counter gives the same result as slicing the series each row, but in
    O(1) amortised per row so full-dataset rebuilds stay fast.
    """
    buf: deque = deque()
    counts: Counter = Counter()
    result = np.empty(len(source_series), dtype=float)
    for i, src in enumerate(source_series):
        buf.append(src)
        counts[src] += 1
        if len(buf) > window:
            old = buf.popleft()
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
        result[i] = counts[src] / len(buf)
    return result


def _rolling_unique_dst_ports(dst_port_series: pd.Series, window: int) -> np.ndarray:
    buf: deque = deque()
    counts: Counter = Counter()
    result = np.empty(len(dst_port_series), dtype=float)
    for i, port in enumerate(dst_port_series):
        buf.append(port)
        if port == port:  # not NaN
            counts[port] += 1
        if len(buf) > window:
            old = buf.popleft()
            if old == old:
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
        result[i] = len(counts)
    return result


def _avg_syn_interarrival(df_input: pd.DataFrame, window: int) -> np.ndarray:
    syn_times: deque = deque()
    result = np.empty(len(df_input), dtype=float)
    times = df_input["Time"].to_numpy(dtype=float)
    syn_flags = df_input["syn_flag"].to_numpy(dtype=int)
    for i in range(len(df_input)):
        if syn_flags[i] == 1:
            syn_times.append(times[i])
        start_time = times[max(0, i - window + 1)]
        while syn_times and syn_times[0] < start_time:
            syn_times.popleft()
        if len(syn_times) >= 2:
            diffs = np.diff(np.asarray(syn_times))
            result[i] = float(diffs.mean())
        else:
            result[i] = 10.0
    return result


def tune_threshold(
    y_true,
    y_score,
    min_recall: float = 0.35,
) -> float:
    """Shared operating-point tuner used by EVERY model in the comparison.

    One identical objective for normal DT, fuzzy DT/forest and the MLP, so the
    reported test metrics differ only by model quality — not by threshold
    strategy. Objective: 0.5*F1 + 0.3*accuracy + 0.2*balanced-accuracy with a
    recall floor, tuned on training predictions only.
    """
    best_t, _ = tune_threshold_scored(y_true, y_score, min_recall)
    return best_t


def tune_threshold_scored(
    y_true,
    y_score,
    min_recall: float = 0.35,
) -> tuple[float, float]:
    """Same as tune_threshold but also returns the objective value achieved."""
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, dtype=float)
    thresholds = np.linspace(0.05, 0.95, 181)
    best_t, best_score = 0.5, -1.0
    for t in thresholds:
        pred = (y_score >= t).astype(int)
        rec = recall_score(y_true, pred, zero_division=0)
        if rec < min_recall:
            continue
        score = (
            0.50 * f1_score(y_true, pred, zero_division=0)
            + 0.30 * accuracy_score(y_true, pred)
            + 0.20 * balanced_accuracy_score(y_true, pred)
        )
        if score > best_score:
            best_score = score
            best_t = float(t)
    if best_score < 0:
        return 0.5, 0.0
    return float(best_t), float(best_score)


def _chronological_segment_split(
    df: pd.DataFrame,
    test_size: float,
    buffer: int,
) -> pd.Series:
    """Honest split for rolling-window features.

    Random row splits leak: adjacent packets share window/50 of their rolling
    features, so test rows are near-duplicates of train rows and an unpruned
    tree can memorise the test set. Instead, split EACH contiguous traffic
    segment (label_scenario run) chronologically: first (1-test_size) of the
    segment trains, the final test_size is held out, and `buffer` packets at
    the boundary are dropped so no rolling window straddles the split.
    Rolling features are backward-looking, so train windows can never contain
    held-out packets.
    """
    run_id = (df["label_scenario"] != df["label_scenario"].shift()).cumsum()
    split = pd.Series("buffer", index=df.index)
    for _, run_idx in df.groupby(run_id).groups.items():
        run_idx = np.asarray(run_idx)
        n = len(run_idx)
        boundary = int(round(n * (1.0 - test_size)))
        train_part = run_idx[:boundary]
        test_part = run_idx[boundary + buffer:]
        split.iloc[train_part] = "train"
        split.iloc[np.asarray(test_part)] = "test"
    return split


def build_clean_dataset(
    input_csv: str = "data/syn_udp_flood_attack_data_labeled_diraware.csv",
    output_csv: str = "data/syn_udp_flood_attack_data_clean.csv",
    output_report: str = "reports/clean_dataset_report.json",
    window: int = 50,
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[pd.DataFrame, dict]:
    input_path = Path(input_csv)
    if not input_path.exists():
        # Fall back to the raw window-labeled dataset (noisier labels).
        fallback = Path("data/syn_udp_flood_attack_data_labeled.csv")
        input_path = fallback if fallback.exists() else Path(input_csv).name

    df = pd.read_csv(input_path)

    for col in ["Time", "Length"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    if "attack" not in df.columns:
        raise ValueError("Missing required 'attack' column in labeled dataset")

    if not pd.api.types.is_numeric_dtype(df["attack"]):
        mapped = df["attack"].astype(str).str.lower().map(
            {
                "attack": 1, "malicious": 1, "anomaly": 1, "1": 1, "true": 1,
                "normal": 0, "benign": 0, "0": 0, "false": 0,
            }
        )
        df["attack"] = mapped.fillna(0).astype(int)
    else:
        df["attack"] = (pd.to_numeric(df["attack"], errors="coerce").fillna(0) > 0).astype(int)

    df = df.dropna(subset=["Time", "Length", "Info", "Protocol", "Source", "Destination"]).copy()
    df = df.sort_values("Time").reset_index(drop=True)

    info = df["Info"].astype(str)
    df["syn_flag"] = info.str.contains(r"\[SYN\]", regex=True, na=False).astype(int)
    df["ack_flag"] = info.str.contains(r"\[ACK\]", regex=True, na=False).astype(int)
    df["syn_ack_flag"] = info.str.contains(r"\[SYN, ACK\]", regex=True, na=False).astype(int)
    df["is_retransmission"] = info.str.contains("Retransmission", na=False).astype(int)

    df["is_tcp"] = (df["Protocol"].astype(str) == "TCP").astype(int)
    df["is_udp"] = (df["Protocol"].astype(str) == "UDP").astype(int)

    ports = df["Info"].apply(_extract_ports)
    df["src_port"] = ports.apply(lambda x: x[0])
    df["dst_port"] = ports.apply(lambda x: x[1])

    # Per-packet direction features. Window features cannot tell an attack
    # packet from the victim's reply inside the same flood burst (both share
    # flood-level densities), but direction can: floods travel TO a privileged
    # service port from an ephemeral source, while replies originate FROM the
    # service port, or are RST/ICMP control traffic.
    df["dst_port_lt_1024"] = ((df["dst_port"] < 1024) & df["dst_port"].notna()).astype(int)
    df["src_port_lt_1024"] = ((df["src_port"] < 1024) & df["src_port"].notna()).astype(int)
    df["is_rst_flag"] = info.str.contains(r"\[RST", regex=True, na=False).astype(int)
    df["is_icmp"] = df["Protocol"].astype(str).str.upper().str.startswith("ICMP").astype(int)
    df["response_direction"] = (
        (df["src_port_lt_1024"] == 1) | (df["is_rst_flag"] == 1) | (df["is_icmp"] == 1)
    ).astype(int)

    df["packet_length"] = df["Length"].astype(float)
    df["time_delta"] = df["Time"].diff().fillna(0).clip(lower=0)
    df["is_syn_only"] = ((df["syn_flag"] == 1) & (df["syn_ack_flag"] == 0)).astype(int)

    syn_window = df["syn_flag"].rolling(window=window, min_periods=1).sum()
    ack_window = df["ack_flag"].rolling(window=window, min_periods=1).sum()
    udp_window = df["is_udp"].rolling(window=window, min_periods=1).sum()
    bytes_window = df["packet_length"].rolling(window=window, min_periods=1).sum()

    window_time = df["Time"].rolling(window=window, min_periods=1).apply(
        lambda x: max(float(x.iloc[-1] - x.iloc[0]), 0.0001), raw=False
    )

    # Warm-up fix: while the rolling window is still filling (fewer than
    # `window` packets seen) the elapsed span can be a few milliseconds, which
    # sends every density feature to its clip ceiling and manufactures fake
    # attack signal in the first rows of any capture. Floor the span at 1s for
    # partial windows only; full windows keep their true (possibly tiny) span
    # because a real flood legitimately produces huge densities.
    row_count = np.minimum(np.arange(1, len(df) + 1), window)
    window_time = np.where(
        row_count < window,
        np.maximum(window_time, 1.0),
        np.maximum(window_time, 0.001),
    )
    window_time = pd.Series(window_time, index=df.index)

    df["syn_ack_ratio"] = syn_window / (ack_window + 1)
    df["half_open_conn_count"] = df["is_syn_only"].rolling(window=window, min_periods=1).sum()
    df["same_src_ip_freq"] = _rolling_src_freq(df["Source"], window)
    df["syn_packet_density"] = (syn_window / window_time).fillna(0).clip(upper=1000)
    df["udp_packet_density"] = (udp_window / window_time).fillna(0).clip(upper=1000)
    df["total_packet_density"] = (window / window_time).fillna(0).clip(upper=2000)
    df["byte_density"] = (bytes_window / window_time).fillna(0).clip(upper=1000000)
    df["retransmission_rate"] = df["is_retransmission"].rolling(window=window, min_periods=1).mean()
    df["unique_dst_port_count"] = _rolling_unique_dst_ports(df["dst_port"], window)
    df["avg_time_between_syns"] = _avg_syn_interarrival(df, window)
    df["pkt_len_mean"] = df["packet_length"].rolling(window=window, min_periods=1).mean()
    df["pkt_len_std"] = df["packet_length"].rolling(window=window, min_periods=1).std().fillna(0)
    df["udp_ratio"] = udp_window / window
    df["syn_ratio"] = syn_window / window

    df["label_scenario"] = df.get("label_scenario", "unknown").astype(str)

    # Honest chronological per-segment split (see docstring) — no rolling-window
    # overlap between train and test packets.
    df["split"] = _chronological_segment_split(df, test_size=test_size, buffer=window)

    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)

    runs = (df["label_scenario"] != df["label_scenario"].shift()).cumsum()
    per_segment = (
        df.groupby([runs, "label_scenario", "split"], observed=True).size().unstack(fill_value=0)
    )
    report = {
        "input_csv": str(input_path),
        "output_csv": str(output_path),
        "rows_total": int(len(df)),
        "attack_rows": int((df["attack"] == 1).sum()),
        "normal_rows": int((df["attack"] == 0).sum()),
        "attack_ratio": float(df["attack"].mean()),
        "split_mode": "chronological_per_segment (80/20 with 50-packet buffer)",
        "split_counts": df["split"].value_counts().to_dict(),
        "split_attack_ratio": df.groupby("split")["attack"].mean().to_dict(),
        "per_segment": {
            f"{int(idx[0])}:{idx[1]}": {k: int(v) for k, v in row.items()}
            for idx, row in per_segment.iterrows()
        },
        "window": int(window),
        "random_state": int(random_state),
    }

    report_path = Path(output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return df, report


def main() -> None:
    parser = argparse.ArgumentParser(description="Build clean shared dataset with enriched SYN & UDP flood features")
    parser.add_argument("--input-csv", default="data/syn_udp_flood_attack_data_labeled_diraware.csv")
    parser.add_argument("--output-csv", default="data/syn_udp_flood_attack_data_clean.csv")
    parser.add_argument("--output-report", default="reports/clean_dataset_report.json")
    parser.add_argument("--window", type=int, default=50)
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    _, report = build_clean_dataset(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        output_report=args.output_report,
        window=args.window,
        test_size=args.test_size,
    )

    print("Clean dataset created with enriched SYN & UDP flood features.")
    print(f"Rows: {report['rows_total']} | Split: {report['split_counts']}")
    print(f"Attack ratio per split: {report['split_attack_ratio']}")
    print(f"Output: {report['output_csv']}")


if __name__ == "__main__":
    main()
