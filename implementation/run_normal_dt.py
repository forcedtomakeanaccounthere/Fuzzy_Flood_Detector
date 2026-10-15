"""Normal Decision Tree baseline — trained by the IDENTICAL procedure as the
Fuzzy DT (see shared_preprocessing.fit_lightweight_tree).

The only difference between this baseline and the fuzzy model is the feature
space: raw window statistics vs fuzzy membership grades + rule activations.
Same grid, same class weights, same cost-complexity pruning, same shared
threshold tuner — so any metric gap is attributable to the fuzzy
representation alone, not to a tuning advantage.
"""
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from shared_preprocessing import build_clean_dataset, fit_lightweight_tree, tune_threshold


FEATURES = [
    "packet_length", "time_delta", "is_syn_only",
    "syn_ack_ratio", "half_open_conn_count", "same_src_ip_freq",
    "syn_packet_density", "udp_packet_density", "total_packet_density",
    "byte_density", "retransmission_rate", "unique_dst_port_count",
    "avg_time_between_syns", "pkt_len_mean", "pkt_len_std",
    "udp_ratio", "syn_ratio",
    "dst_port_lt_1024", "src_port_lt_1024", "is_rst_flag", "is_icmp", "response_direction",
]


def main() -> None:
    clean_path = Path("data/syn_udp_flood_attack_data_clean.csv")
    if not clean_path.exists():
        build_clean_dataset(
            input_csv="data/syn_udp_flood_attack_data_labeled_diraware.csv",
            output_csv=str(clean_path),
            output_report="reports/clean_dataset_report.json",
        )

    df = pd.read_csv(clean_path)
    train_mask = df["split"] == "train"
    test_mask  = df["split"] == "test"

    X_train = df.loc[train_mask, FEATURES].fillna(0)
    X_test  = df.loc[test_mask,  FEATURES].fillna(0)
    y_train = df.loc[train_mask, "attack"].astype(int)
    y_test  = df.loc[test_mask,  "attack"].astype(int)

    model, meta = fit_lightweight_tree(X_train, y_train)
    print(f"  Config: {meta['best_config']} | CV F1={meta['best_cv_f1']}")
    if meta.get("selected"):
        print(f"  Pruned to {meta['nodes']} nodes (ccp_alpha={meta['ccp_alpha']:.5f})")
    else:
        print(f"  Unpruned: {meta['unpruned_nodes']} nodes")

    proba_train = model.predict_proba(X_train)[:, 1]
    proba_test  = model.predict_proba(X_test)[:, 1]
    threshold   = tune_threshold(y_train, proba_train)
    y_pred      = (proba_test >= threshold).astype(int)

    metrics = {
        "accuracy":          float(accuracy_score(y_test, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "precision":         float(precision_score(y_test, y_pred, zero_division=0)),
        "recall":            float(recall_score(y_test, y_pred, zero_division=0)),
        "f1":                float(f1_score(y_test, y_pred, zero_division=0)),
        "auc":               float(roc_auc_score(y_test, proba_test)),
    }

    joblib.dump(
        {"model": model, "feature_order": FEATURES, "threshold": float(threshold)},
        "normal_dt.pkl",
    )

    report = {
        "model_type": "Normal_DT",
        "training_protocol": "identical to Fuzzy DT (shared grid + CV pruning + threshold tuner)",
        "best_params": meta["best_config"],
        "tree_meta": meta,
        "feature_count": len(FEATURES),
        "threshold": float(threshold),
        "metrics": metrics,
        "classification_report": classification_report(
            y_test, y_pred,
            target_names=["Normal", "Attack"],
            output_dict=True,
        ),
    }
    Path("reports").mkdir(exist_ok=True)
    with Path("reports/normal_dt_results.json").open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("Normal DT training complete.")
    print(f"  Metrics:     {metrics}")
    print("Saved: normal_dt.pkl | reports/normal_dt_results.json")


if __name__ == "__main__":
    main()
