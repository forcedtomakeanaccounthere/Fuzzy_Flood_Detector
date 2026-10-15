"""Pi-friendly fast inference for the serialized fuzzy artifact.

The predictor performs the exact transformations used during training
(quantile clipping -> triangular membership grades -> direction-gated fuzzy
rules) and returns both the deployed model probability and the fuzzy rule
activations so the dashboard can EXPLAIN every decision.

Artifact contract (fuzzy_forest.pkl, artifact_version >= 5):
  model            deployed model — the pruned single Fuzzy Decision Tree
  threshold        operating point of the deployed model
  model_forest     30-tree Fuzzy Forest (accuracy reference variant)
  forest_threshold operating point of the forest
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


RULE_COLUMNS = [
    "rule1_syn_ack_halfopen",
    "rule2_density_burst",
    "rule3_spoofed_ip",
    "rule4_retransmit_halfopen",
    "rule5_targeted_port",
    "rule6_udp_density_burst",
    "rule7_high_byte_flood",
    "rule8_stealth_flood",
]

RULE_LABELS = {
    "rule1_syn_ack_halfopen": "SYN/ACK imbalance + half-open surge",
    "rule2_density_burst": "SYN burst rate (short inter-arrival)",
    "rule3_spoofed_ip": "Source-IP dispersion (spoofed fan-in)",
    "rule4_retransmit_halfopen": "Retransmissions + half-open surge",
    "rule5_targeted_port": "Single targeted port under burst",
    "rule6_udp_density_burst": "UDP density burst",
    "rule7_high_byte_flood": "High byte-volume flood",
    "rule8_stealth_flood": "Low-and-slow stealth pattern",
}


def _trimf(x: np.ndarray, abc) -> np.ndarray:
    """Triangular membership function (same math as run_fuzzy_dt)."""
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


class FuzzyForestPredictor:
    def __init__(self, artifact_path: str = "fuzzy_forest.pkl") -> None:
        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Missing {path}. Run run_fuzzy_dt.py on the laptop first."
            )
        self.artifact = joblib.load(path)
        self.model = self.artifact["model"]
        self.model_kind = self.artifact.get("model_kind", "fuzzy_dt_single")
        self.feature_order = self.artifact["feature_order"]
        self.fuzzy_attributes = self.artifact["fuzzy_attributes"]
        self.membership_params = self.artifact["membership_params"]
        self.rule_weights = np.asarray(self.artifact["rule_weights"], dtype=float)
        self.clip_bounds = self.artifact["clip_bounds"]
        self.threshold = float(self.artifact["threshold"])
        self.forest = self.artifact.get("model_forest")
        self.forest_threshold = float(self.artifact.get("forest_threshold", self.threshold))

    def _fuzzy_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """Compute fuzzy membership scores + rule activations. Called ONCE per predict()."""
        result = features.copy()
        fuzzy_scores = pd.DataFrame(index=result.index)

        for attribute in self.fuzzy_attributes:
            values = result.get(attribute, pd.Series(0, index=result.index)).fillna(0).to_numpy(dtype=float)
            low, high = self.clip_bounds[attribute]
            span = high - low
            normalized = (
                np.zeros_like(values)
                if span <= 0
                else np.clip((np.clip(values, low, high) - low) / span, 0, 1)
            )
            for level in ["LOW", "MEDIUM", "HIGH"]:
                fuzzy_scores[f"{attribute}_{level}"] = _trimf(
                    normalized, self.membership_params[attribute][level]
                )

        # Direction gating — identical to training: attack rules may only fire
        # for packets travelling in the attack direction (inbound to a
        # privileged port). The victim's own SYN-ACK/RST/ICMP replies have
        # response_direction = 1, so their gate value is 0.
        resp_low = fuzzy_scores["response_direction_LOW"]

        rules = pd.DataFrame(index=result.index)
        rules["rule1_syn_ack_halfopen"] = np.minimum(
            np.minimum(fuzzy_scores["syn_ack_ratio_HIGH"], fuzzy_scores["half_open_conn_count_HIGH"]), resp_low
        )
        rules["rule2_density_burst"] = np.minimum(
            np.minimum(fuzzy_scores["syn_packet_density_HIGH"], fuzzy_scores["avg_time_between_syns_LOW"]), resp_low
        )
        rules["rule3_spoofed_ip"] = np.minimum(
            np.minimum(fuzzy_scores["same_src_ip_freq_LOW"], fuzzy_scores["syn_ack_ratio_HIGH"]), resp_low
        )
        rules["rule4_retransmit_halfopen"] = np.minimum(
            np.minimum(fuzzy_scores["syn_packet_density_HIGH"], fuzzy_scores["half_open_conn_count_HIGH"]), resp_low
        )
        rules["rule5_targeted_port"] = np.minimum(
            np.minimum(fuzzy_scores["unique_dst_port_count_LOW"], fuzzy_scores["syn_packet_density_HIGH"]), resp_low
        )
        rules["rule6_udp_density_burst"] = np.minimum(
            np.minimum(fuzzy_scores["udp_packet_density_HIGH"], fuzzy_scores["total_packet_density_HIGH"]), resp_low
        )
        rules["rule7_high_byte_flood"] = np.minimum(
            np.minimum(fuzzy_scores["byte_density_HIGH"], fuzzy_scores["total_packet_density_HIGH"]), resp_low
        )
        rules["rule8_stealth_flood"] = np.minimum.reduce([
            fuzzy_scores["udp_packet_density_MEDIUM"],
            fuzzy_scores["syn_ack_ratio_MEDIUM"],
            fuzzy_scores["total_packet_density_MEDIUM"],
            resp_low,
        ])

        rule_matrix = rules[RULE_COLUMNS].to_numpy(dtype=float)
        rules["fuzzy_confidence"] = (
            0.55 * (rule_matrix @ self.rule_weights) + 0.45 * rule_matrix.max(axis=1)
        )

        return pd.concat([result, fuzzy_scores, rules], axis=1)

    def predict(self, features: pd.DataFrame) -> dict:
        # Compute enriched features ONCE, reuse for model + fuzzy confidence.
        enriched = self._fuzzy_features(features)
        model_input = enriched.reindex(columns=self.feature_order, fill_value=0).fillna(0)

        probability = float(self.model.predict_proba(model_input)[0, 1])
        fuzzy_confidence = float(enriched["fuzzy_confidence"].iloc[0])

        activations = {
            RULE_LABELS[name]: round(float(enriched[name].iloc[0]), 3)
            for name in RULE_COLUMNS
        }

        score = max(probability, fuzzy_confidence)

        return {
            "model_probability": probability,
            "fuzzy_confidence": fuzzy_confidence,
            "score": score,
            "threshold": self.threshold,
            "is_attack": score >= self.threshold,
            "rule_activations": activations,
        }
