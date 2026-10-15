"""Fuzzy Decision Tree + Fuzzy Forest — lightweight deployed model.

v5 design (selected by train-CV experiments, see explore_fuzzy.py):
- Data-driven membership functions: triangular LOW/MEDIUM/HIGH sets placed at
  the 15/50/85th percentiles of each normalized attribute on TRAIN data. No
  hand-tuned constants.
- The tree consumes ONLY fuzzy features (30 membership grades + 8 rule
  activations + fuzzy confidence). Experiments showed the fuzzy abstraction
  alone generalises better than raw+membership mixing, keeps the model small,
  and makes every decision explainable in fuzzy-rule language.
- Rule fusion: deployed score = max(tree_probability, LAMBDA * fuzzy_confidence),
  LAMBDA picked on train by the shared objective.
- Config + cost-complexity pruning selected by train cross-validation F1,
  preferring the smallest tree within tolerance — the "lightweight" constraint.
- The 30-tree Fuzzy Forest is kept as an accuracy-reference variant.

Artifact (fuzzy_forest.pkl, artifact_version 5):
  model          = deployed pruned single Fuzzy DT
  threshold      = its tuned operating point
  model_forest   = fuzzy forest variant (reference)
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from shared_preprocessing import build_clean_dataset, fit_lightweight_tree, tune_threshold_scored


FUZZY_ATTRS = [
    "syn_ack_ratio",
    "half_open_conn_count",
    "same_src_ip_freq",
    "syn_packet_density",
    "udp_packet_density",
    "total_packet_density",
    "byte_density",
    "unique_dst_port_count",
    "avg_time_between_syns",
    "response_direction",
]

RULE_NAMES = [
    "rule1_syn_ack_halfopen",
    "rule2_density_burst",
    "rule3_spoofed_ip",
    "rule4_retransmit_halfopen",
    "rule5_targeted_port",
    "rule6_udp_density_burst",
    "rule7_high_byte_flood",
    "rule8_stealth_flood",
]

RULE_WEIGHTS = np.array([0.16, 0.15, 0.12, 0.10, 0.10, 0.15, 0.12, 0.10], dtype=float)

LAMBDA_GRID = [0.0, 0.3, 0.5, 0.6, 0.7, 0.8, 1.0]


def _trimf(x: np.ndarray, abc) -> np.ndarray:
    a, b, c = abc
    y = np.zeros_like(x, dtype=float)
    if b > a:
        idx = (x >= a) & (x <= b)
        y[idx] = (x[idx] - a) / (b - a)
    else:
        y[x == a] = 1.0
    if c > b:
        idx = (x >= b) & (x <= c)
        y[idx] = np.maximum(y[idx], (c - x[idx]) / (c - b))
    else:
        y[x == c] = 1.0
    y[x == b] = 1.0
    return np.clip(y, 0.0, 1.0)


def _normalize_with_train_quantiles(
    df: pd.DataFrame,
    train_mask: pd.Series,
    cols: list[str],
    low_q: float = 0.01,
    high_q: float = 0.99,
) -> tuple[pd.DataFrame, dict]:
    out = pd.DataFrame(index=df.index)
    bounds: dict = {}
    for col in cols:
        train_values = df.loc[train_mask, col].fillna(0)
        lo = float(train_values.quantile(low_q))
        hi = float(train_values.quantile(high_q))
        span = hi - lo
        clipped = df[col].fillna(0).clip(lower=lo, upper=hi)
        out[col] = ((clipped - lo) / span).clip(0, 1) if span > 0 else 0.0
        bounds[col] = (lo, hi)
    return out, bounds


def _membership_params_from_quantiles(fuzzy_norm: pd.DataFrame, train_mask: pd.Series) -> dict:
    """Place LOW/MEDIUM/HIGH triangles at the 15/50/85th percentiles of train.

    Data-driven instead of hand-fixed: each attribute's fuzzy sets adapt to the
    traffic distribution actually seen in training, so no per-feature tuning.
    Binary attributes (response_direction) collapse to step functions, which is
    exactly the desired gate behaviour.
    """
    params = {}
    for attr in FUZZY_ATTRS:
        v = fuzzy_norm.loc[train_mask, attr].to_numpy(dtype=float)
        q15, q50, q85 = np.quantile(v, [0.15, 0.50, 0.85])
        params[attr] = {
            "LOW":    [0.0, 0.0, float(q50)],
            "MEDIUM": [float(q15), float(q50), float(q85)],
            "HIGH":   [float(q50), 1.0, 1.0],
        }
    return params


def _fuzzy_layer(df: pd.DataFrame, train_mask: pd.Series) -> tuple[pd.DataFrame, dict, dict]:
    """Normalized attributes -> membership grades -> direction-gated rules."""
    fuzzy_norm, clip_bounds = _normalize_with_train_quantiles(df, train_mask, FUZZY_ATTRS)
    mf_params = _membership_params_from_quantiles(fuzzy_norm, train_mask)

    fuzzy_scores = pd.DataFrame(index=df.index)
    for attr in FUZZY_ATTRS:
        values = fuzzy_norm[attr].to_numpy(dtype=float)
        for level in ["LOW", "MEDIUM", "HIGH"]:
            fuzzy_scores[f"{attr}_{level}"] = _trimf(values, mf_params[attr][level])

    # Every attack rule is gated by response_direction_LOW so the victim's own
    # replies (src port = service port, RST, ICMP) can never fire a rule —
    # window densities alone cannot tell them from attacker packets.
    response_low = fuzzy_scores["response_direction_LOW"]
    rule_results = pd.DataFrame(index=df.index)
    rule_results["rule1_syn_ack_halfopen"]   = np.minimum(np.minimum(fuzzy_scores["syn_ack_ratio_HIGH"], fuzzy_scores["half_open_conn_count_HIGH"]), response_low)
    rule_results["rule2_density_burst"]      = np.minimum(np.minimum(fuzzy_scores["syn_packet_density_HIGH"], fuzzy_scores["avg_time_between_syns_LOW"]), response_low)
    rule_results["rule3_spoofed_ip"]         = np.minimum(np.minimum(fuzzy_scores["same_src_ip_freq_LOW"], fuzzy_scores["syn_ack_ratio_HIGH"]), response_low)
    rule_results["rule4_retransmit_halfopen"]= np.minimum(np.minimum(fuzzy_scores["syn_packet_density_HIGH"], fuzzy_scores["half_open_conn_count_HIGH"]), response_low)
    rule_results["rule5_targeted_port"]      = np.minimum(np.minimum(fuzzy_scores["unique_dst_port_count_LOW"], fuzzy_scores["syn_packet_density_HIGH"]), response_low)
    rule_results["rule6_udp_density_burst"]  = np.minimum(np.minimum(fuzzy_scores["udp_packet_density_HIGH"], fuzzy_scores["total_packet_density_HIGH"]), response_low)
    rule_results["rule7_high_byte_flood"]    = np.minimum(np.minimum(fuzzy_scores["byte_density_HIGH"], fuzzy_scores["total_packet_density_HIGH"]), response_low)
    rule_results["rule8_stealth_flood"]      = np.minimum.reduce([
        fuzzy_scores["udp_packet_density_MEDIUM"],
        fuzzy_scores["syn_ack_ratio_MEDIUM"],
        fuzzy_scores["total_packet_density_MEDIUM"],
        response_low,
    ])

    rule_mat = rule_results[RULE_NAMES].to_numpy(dtype=float)
    rule_results["fuzzy_confidence"] = 0.55 * (rule_mat @ RULE_WEIGHTS) + 0.45 * rule_mat.max(axis=1)

    return pd.concat([fuzzy_scores, rule_results], axis=1), clip_bounds, mf_params


def _metric_bundle(y_true, y_pred, y_score) -> dict:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "auc": float(roc_auc_score(y_true, y_score)),
    }


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
    y_train = df.loc[train_mask, "attack"].astype(int).to_numpy()
    y_test  = df.loc[test_mask,  "attack"].astype(int).to_numpy()

    fuzzy_layer, clip_bounds, mf_params = _fuzzy_layer(df, train_mask)
    memb_feats = [f"{a}_{l}" for a in FUZZY_ATTRS for l in ["LOW", "MEDIUM", "HIGH"]]
    rule_feats = RULE_NAMES + ["fuzzy_confidence"]
    fuzzy_features = memb_feats + rule_feats

    X_train = fuzzy_layer.loc[train_mask, fuzzy_features].fillna(0)
    X_test  = fuzzy_layer.loc[test_mask,  fuzzy_features].fillna(0)
    fconf_train = fuzzy_layer.loc[train_mask, "fuzzy_confidence"].to_numpy()
    fconf_test  = fuzzy_layer.loc[test_mask,  "fuzzy_confidence"].to_numpy()

    # ── Tree trained by the SHARED lightweight procedure (identical to the
    #    normal DT baseline) — config + CV pruning live in one place so the
    #    comparison stays symmetric. ──────────────────────────────────────────
    pruned_model, tree_meta = fit_lightweight_tree(X_train, y_train)
    best_cfg_display = tree_meta["best_config"]
    print(f"  Best CV F1={tree_meta['best_cv_f1']} with {best_cfg_display}")
    if tree_meta.get("selected"):
        print(f"  Pruned Fuzzy DT:   {tree_meta['nodes']} nodes "
              f"(ccp_alpha={tree_meta['ccp_alpha']:.5f}, CV F1={tree_meta['cv_f1']:.4f})")
    else:
        print(f"  Unpruned Fuzzy DT: {tree_meta['unpruned_nodes']} nodes")
    prune_info = tree_meta

    # ── Rule-fusion weight LAMBDA, picked on train by the shared objective ───
    proba_train = pruned_model.predict_proba(X_train)[:, 1]
    proba_test  = pruned_model.predict_proba(X_test)[:, 1]
    best_lam, best_th, best_obj, best_score_train = 0.0, 0.5, -1.0, None
    for lam in LAMBDA_GRID:
        th, obj = tune_threshold_scored(y_train, np.maximum(proba_train, lam * fconf_train))
        if obj > best_obj:
            best_lam, best_th, best_obj = lam, th, obj
    print(f"  Fusion lambda={best_lam} threshold={best_th:.3f} (train objective {best_obj:.4f})")

    y_pred_dt = (np.maximum(proba_test, best_lam * fconf_test) >= best_th).astype(int)
    fuzzy_dt_metrics = _metric_bundle(y_test, y_pred_dt, proba_test)

    # ── Fuzzy Forest reference variant (same fuzzy feature space) ────────────
    forest_model = RandomForestClassifier(
        n_estimators=30,
        max_depth=14,
        min_samples_split=5,
        min_samples_leaf=5,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )
    forest_model.fit(X_train, y_train)
    f_proba_train = forest_model.predict_proba(X_train)[:, 1]
    f_proba_test  = forest_model.predict_proba(X_test)[:, 1]
    th_forest, _ = tune_threshold_scored(y_train, np.maximum(f_proba_train, fconf_train))
    y_pred_forest = (np.maximum(f_proba_test, fconf_test) >= th_forest).astype(int)
    fuzzy_forest_metrics = _metric_bundle(y_test, y_pred_forest, f_proba_test)

    # ── Save deployable artifact ──────────────────────────────────────────────
    artifact = {
        "artifact_version": 5,
        "model": pruned_model,
        "model_kind": "fuzzy_dt_single",
        "model_forest": forest_model,
        "feature_order": fuzzy_features,
        "fuzzy_attributes": FUZZY_ATTRS,
        "membership_params": mf_params,
        "rule_weights": RULE_WEIGHTS.tolist(),
        "clip_bounds": {k: [v[0], v[1]] for k, v in clip_bounds.items()},
        "threshold": float(best_th),
        "fusion_lambda": float(best_lam),
        "fuzzy_dt_threshold": float(best_th),
        "forest_threshold": float(th_forest),
        "window": 50,
    }
    joblib.dump(artifact, "fuzzy_forest.pkl")

    report = {
        "dataset": str(clean_path),
        "artifact": "fuzzy_forest.pkl",
        "artifact_version": 5,
        "feature_count": len(fuzzy_features),
        "feature_space": "fuzzy-only (30 membership grades + 8 rule activations + fuzzy confidence)",
        "membership_placement": "triangular LOW/MEDIUM/HIGH at 15/50/85th percentiles of train",
        "training_protocol": "shared fit_lightweight_tree (identical to the normal DT baseline)",
        "tree_meta": tree_meta,
        "fusion_lambda": best_lam,
        "threshold": best_th,
        "fuzzy_dt_single_metrics": fuzzy_dt_metrics,
        "fuzzy_forest_metrics": fuzzy_forest_metrics,
        "classification_report_dt": classification_report(
            y_test, y_pred_dt, target_names=["Normal", "Attack"], output_dict=True
        ),
        "classification_report_forest": classification_report(
            y_test, y_pred_forest, target_names=["Normal", "Attack"], output_dict=True
        ),
    }
    Path("reports").mkdir(exist_ok=True)
    with Path("reports/fuzzy_dt_results.json").open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("Fuzzy model training complete.")
    print(f"  Fuzzy DT  (deployed single tree): {fuzzy_dt_metrics}")
    print(f"  Fuzzy Forest (reference variant): {fuzzy_forest_metrics}")
    print("Saved: fuzzy_forest.pkl | reports/fuzzy_dt_results.json")


if __name__ == "__main__":
    main()
