"""Cross-model comparison and benchmark generator.

Fairness rules:
- Every model is measured from its SAVED ARTIFACT (fuzzy_forest.pkl,
  normal_dt.pkl, deep_learning_mlp.pkl) — no re-created stand-ins.
- Latency = end-to-end per-packet inference: for the fuzzy models it INCLUDES
  the fuzzy enrichment step (membership grades + rules), because that step is
  part of the method; for the MLP it includes scaling. Median of 5 bulk runs
  on the same 2,000 held-out packets.
- Metrics come from the training reports (identical chronological hold-out,
  identical threshold tuner for all models).

Saved to reports/model_comparison_report.json (rendered in the dashboard).
"""
import io
import json
import pickle
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from fuzzy_inference import FuzzyForestPredictor


CLEAN_CSV = Path("data/syn_udp_flood_attack_data_clean.csv")
REPORTS = {
    "fuzzy_dt_single": Path("reports/fuzzy_dt_results.json"),
    "fuzzy_forest":    Path("reports/fuzzy_dt_results.json"),
    "normal_dt":       Path("reports/normal_dt_results.json"),
    "deep_mlp":        Path("reports/deep_learning_results.json"),
}
N_BATCH = 2_000
N_REPEATS = 5


def _pickle_size_kb(obj) -> float:
    buf = io.BytesIO()
    pickle.dump(obj, buf)
    return round(buf.tell() / 1024, 1)


def _file_size_kb(path: Path) -> float:
    return round(path.stat().st_size / 1024, 1) if path.exists() else 0.0


def _load_fuzzy_metrics() -> tuple[dict, dict]:
    p = REPORTS["fuzzy_dt_single"]
    if not p.exists():
        return {}, {}
    with p.open(encoding="utf-8") as f:
        data = json.load(f)
    return data.get("fuzzy_dt_single_metrics", {}), data.get("fuzzy_forest_metrics", {})


def _load_metrics(key: str) -> dict:
    p = REPORTS[key]
    if not p.exists():
        return {}
    with p.open(encoding="utf-8") as f:
        data = json.load(f)
    return data.get("metrics", {})


def _time_median(fn) -> float:
    fn()  # warm-up
    times = []
    for _ in range(N_REPEATS):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return round(float(np.median(times)) / N_BATCH, 5)


def main() -> None:
    if not CLEAN_CSV.exists():
        print(f"ERROR: {CLEAN_CSV} not found — run shared_preprocessing.py first.")
        return

    df = pd.read_csv(CLEAN_CSV)
    test_df = df[df["split"] == "test"].reset_index(drop=True)
    batch = test_df.iloc[:N_BATCH].copy()

    dt_metrics, forest_metrics = _load_fuzzy_metrics()
    normal_metrics = _load_metrics("normal_dt")
    mlp_metrics = _load_metrics("deep_mlp")

    # ---------- latency on real artifacts ----------
    print(f"[Benchmark] per-packet latency, median of {N_REPEATS} runs on {N_BATCH} held-out packets...")
    latencies = {}

    try:
        predictor = FuzzyForestPredictor("fuzzy_forest.pkl")
        feature_order = predictor.feature_order

        def run_single():
            enriched = predictor._fuzzy_features(batch)
            model_input = enriched.reindex(columns=feature_order, fill_value=0).fillna(0)
            return predictor.model.predict_proba(model_input)

        latencies["fuzzy_dt_single"] = _time_median(run_single)

        if predictor.forest is not None:
            def run_forest():
                enriched = predictor._fuzzy_features(batch)
                model_input = enriched.reindex(columns=feature_order, fill_value=0).fillna(0)
                return predictor.forest.predict_proba(model_input)

            latencies["fuzzy_forest"] = _time_median(run_forest)
    except Exception as e:  # noqa: BLE001
        print(f"  Fuzzy latency error: {e}")

    try:
        nd = joblib.load("normal_dt.pkl")
        nd_features = nd["feature_order"]

        def run_normal():
            X = batch.reindex(columns=nd_features, fill_value=0).fillna(0)
            return nd["model"].predict_proba(X)

        latencies["normal_dt"] = _time_median(run_normal)
    except Exception as e:  # noqa: BLE001
        print(f"  Normal DT latency error: {e}")

    try:
        mlp_art = joblib.load("deep_learning_mlp.pkl")
        mlp_features = mlp_art["feature_order"]

        def run_mlp():
            X = mlp_art["scaler"].transform(batch.reindex(columns=mlp_features, fill_value=0).fillna(0))
            return mlp_art["model"].predict_proba(X)

        latencies["deep_mlp"] = _time_median(run_mlp)
    except Exception as e:  # noqa: BLE001
        print(f"  MLP latency error: {e}")

    # ---------- model sizes ----------
    sizes = {}
    nodes = {}
    try:
        art = joblib.load("fuzzy_forest.pkl")
        sizes["fuzzy_dt_single"] = f"{_pickle_size_kb(art['model'])} KB"
        nodes["fuzzy_dt_single"] = int(art["model"].tree_.node_count)
        if art.get("model_forest") is not None:
            sizes["fuzzy_forest"] = f"{_pickle_size_kb(art['model_forest']) / 1024:.2f} MB (30 trees)"
    except Exception as e:  # noqa: BLE001
        print(f"  Fuzzy size error: {e}")
    try:
        nd = joblib.load("normal_dt.pkl")
        sizes["normal_dt"] = f"{_pickle_size_kb(nd['model'])} KB"
        nodes["normal_dt"] = int(nd["model"].tree_.node_count)
    except Exception as e:  # noqa: BLE001
        print(f"  Normal DT size error: {e}")
    try:
        mlp_path = Path("deep_learning_mlp.pkl")
        sizes["deep_mlp"] = f"{_file_size_kb(mlp_path) / 1024:.2f} MB (256-128-64-32)"
    except Exception as e:  # noqa: BLE001
        print(f"  MLP size error: {e}")

    # ---------- assembled table ----------
    def row(name, m, deployed=False):
        if not m:
            return None
        return {
            "model": name,
            "accuracy_%": round(m.get("accuracy", 0) * 100, 2),
            "balanced_accuracy_%": round(m.get("balanced_accuracy", 0) * 100, 2),
            "precision_%": round(m.get("precision", 0) * 100, 2),
            "recall_%": round(m.get("recall", 0) * 100, 2),
            "F1": round(m.get("f1", 0), 4),
            "AUC": round(m.get("auc", 0), 4),
            "deployed": deployed,
        }

    rows = [
        row("fuzzy_dt_single", dt_metrics, deployed=True),
        row("fuzzy_forest", forest_metrics),
        row("normal_dt", normal_metrics),
        row("deep_mlp", mlp_metrics),
    ]
    rows = [r for r in rows if r]

    print("\n" + "=" * 100)
    print(f"{'Model':<20} {'Acc':>8} {'B-Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8} {'AUC':>8} "
          f"{'ms/pkt':>9} {'Size':>18}")
    print("-" * 100)
    for r in rows:
        k = r["model"]
        lat = latencies.get(k)
        print(f"{k:<20} {r['accuracy_%']:>7}% {r['balanced_accuracy_%']:>7}% "
              f"{r['precision_%']:>7}% {r['recall_%']:>7}% {r['F1']:>8} {r['AUC']:>8} "
              f"{(f'{lat:.4f}' if lat is not None else 'N/A'):>9} {sizes.get(k, '?'):>18}")
    print("=" * 100)
    if nodes:
        print(f"tree nodes: {nodes}")

    report = {
        "models": rows,
        "latency_ms_per_packet": latencies,
        "model_sizes": sizes,
        "tree_nodes": nodes,
        "evaluation": {
            "split": "chronological per-segment 80/20 with 50-packet buffer (no window overlap)",
            "threshold_tuning": "shared objective (0.5*F1 + 0.3*accuracy + 0.2*balanced-accuracy, recall floor 0.35) on train",
            "latency": f"median of {N_REPEATS} vectorized runs on {N_BATCH} test packets, real artifacts, fuzzy enrichment included",
        },
        "fuzzy_dt_single": {
            "accuracy_%": next((r["accuracy_%"] for r in rows if r["model"] == "fuzzy_dt_single"), None),
            "size_kb": sizes.get("fuzzy_dt_single"),
        },
    }
    Path("reports").mkdir(exist_ok=True)
    with Path("reports/model_comparison_report.json").open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("\nSaved: reports/model_comparison_report.json")


if __name__ == "__main__":
    main()
