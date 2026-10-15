# Explainable SYN/UDP Flood Detection in IoT Networks using Lightweight Fuzzy Decision Tree

This project detects SYN and UDP flood behavior in IoT network traffic using
fuzzy membership rules plus supervised tree models. The research workflow is
kept on a laptop; the Raspberry Pi performs lightweight inference, monitoring
and a controlled lab response.

**Read [`implementation/DEMO_GUIDE.md`](implementation/DEMO_GUIDE.md) for the full
step-by-step demonstration playbook (Pi setup, network options, traffic
simulation, dashboard controls).**

## Project layout

- `implementation/shared_preprocessing.py` builds the cleaned, time-ordered
  feature dataset (direction-aware labels, warm-up-safe densities) and writes
  the train/test split. The split is **chronological within each traffic
  segment** (first 80% of every phase trains, last 20% is held out, 50-packet
  buffer) so overlapping rolling windows can never leak between train and test.
  It also hosts `tune_threshold` (one shared operating-point objective for every
  model) and `fit_lightweight_tree` (one shared tree-training procedure).
- `implementation/relabel_direction_aware.py` removes label noise: packets
  flowing victim→attacker inside attack windows (the victim's own SYN-ACK/RST
  replies) are relabeled as normal, and every attack window's victim IP is
  inferred from packet direction.
- `implementation/run_normal_dt.py` trains the plain Decision Tree baseline on
  raw window features with the identical protocol as the fuzzy model.
- `implementation/run_fuzzy_dt.py` trains the fuzzy Decision Tree and the
  deployable fuzzy Random Forest. Membership functions are data-driven
  (triangular LOW/MEDIUM/HIGH placed at the 15/50/85th percentiles of the
  training traffic), rules are gated by `response_direction`, and the tree
  consumes the fuzzy feature space only. Rule fusion
  (`score = max(tree_probability, 0.7 · fuzzy_confidence)`) is selected on
  train by the shared objective.
- `implementation/fuzzy_forest.pkl` is the deployable artifact: the pruned
  single Fuzzy DT (`model`), the 30-tree forest reference variant, feature
  order, membership parameters, quantile bounds, thresholds, window size.
- `implementation/fuzzy_inference.py` loads that artifact and performs the
  same transformations during inference (including the direction gate), returning
  per-rule activations used for the dashboard's explainability panel.
- `implementation/live_detector.py` is the edge detection engine — two input
  modes: `--replay-csv` (deterministic) and `--live` (scapy sniffing on the
  Pi). It computes the full 22-feature training vector per rolling window,
  tracks per-IP mitigation state (ALLOW / THROTTLE / BLOCK with TTLs and
  auto-release), optionally installs iptables DROP rules (`--live-firewall`),
  protects the SSH/management IPs, and streams JSONL events plus a
  `detector_state.json` snapshot for the dashboard.
- `implementation/monitor_dashboard.py` serves the dependency-free monitoring
  UI (light theme): KPI cards, live packet stream, per-IP threat board with
  Block/Release buttons, traffic/score timeline charts, per-decision fuzzy-rule
  explanation, device CPU/RAM telemetry, and the model benchmark table with the
  deployed model highlighted.
- `implementation/traffic_simulator.py` generates demonstration traffic from
  the laptop: `normal`, `suspicious` (low-and-slow scan), `low-flood`
  (sustained gentle half-open flood — THROTTLE-zone demo), `congestion`,
  `syn-flood`, `udp-flood` and a scripted `story` mode with ground-truth
  logging.
- `implementation/evaluate_demo.py` merges simulator ground truth with
  detector events and reports time-to-detect per phase plus false positives.
- `implementation/sysstats.py` small cross-platform CPU/RAM/temperature
  telemetry helper (psutil when available, /proc otherwise).

The existing notebooks remain useful for exploratory analysis and figures.
The command-line scripts are the reproducible path for training and deployment.

## Model results (honest evaluation)

Evaluation protocol: chronological per-segment hold-out (no rolling-window
overlap between train and test), one shared threshold objective for all models,
and one shared tree-training procedure (`fit_lightweight_tree`: same grid,
same CV pruning) for both trees — the only difference is the feature space
(raw statistics vs fuzzy memberships + rules). Latency is end-to-end per
packet on real artifacts, including the fuzzy enrichment step.

| Model | Accuracy | F1 | ROC AUC | Recall | Size |
|---|---|---|---|---|---|
| **Fuzzy DT single — deployed** | **87.7%** | **0.456** | 0.908 | 67% | **9.1 KB (89 nodes)** |
| Fuzzy Forest (30 trees, reference) | 88.3% | 0.442 | 0.912 | 61% | 2.7 MB |
| Plain DT baseline (identical protocol) | 86.4% | 0.438 | 0.917 | 69% | 7.1 KB (71 nodes) |
| Deep MLP (256-128-64-32) | 86.5% | 0.440 | 0.911 | 69% | 1.1 MB |

The deployed Fuzzy DT beats both baselines on accuracy, precision and F1 while
matching the MLP's AUC — at 125× smaller than the MLP and tree-class size —
and it is the only model whose every decision comes with human-readable fuzzy
rule activations.

Run `python compare_models.py` after retraining to refresh
`reports/model_comparison_report.json` (rendered in the dashboard).

## Laptop: train and export

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd implementation
python relabel_direction_aware.py     # once: clean the labels
python shared_preprocessing.py        # build features + split
python run_normal_dt.py
python run_fuzzy_dt.py                # writes fuzzy_forest.pkl
python run_deep_learning.py
python compare_models.py
```

Do not retrain on the Pi. Copy the artifact and the inference/monitor scripts
to the Pi after training. Only load artifacts you created or trust: joblib
files can execute code when loaded.

## Raspberry Pi: live demonstration

See **DEMO_GUIDE.md** for the complete walkthrough. Short version:

```bash
# on the Pi (via SSH), inside tmux
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live --bpf "ip and not port 22"
python3 monitor_dashboard.py --port 8080
# in the laptop browser
open http://<raspberry-pi-ip>:8080
# from the laptop
python traffic_simulator.py story --target <raspberry-pi-ip>
```

For deterministic bring-up without any traffic generation:

```bash
python3 live_detector.py --replay-csv syn_udp_flood_attack_data_clean.csv --delay 0.01
```

## Detection and response states

Each rolling window (50 packets) produces a threat score
`max(model_probability, 0.7 · fuzzy_confidence)` compared against the tuned
threshold (0.48 for the current artifact):

1. `ALLOW` — below 50% of the threshold.
2. `THROTTLE` — suspicious (≥ 50% of threshold): per-IP rate-limit advisory
   with a short TTL.
3. `BLOCK` — at/above threshold: source IP blocked (iptables DROP under
   `--live-firewall`, simulated otherwise) with a TTL and automatic release.

Additional invariants:

- **Warm-up gating** — no verdicts until 20 packets are seen (prevents the
  startup false positives caused by tiny window spans).
- **Direction gating** — fuzzy rules only fire for packets in the attack
  direction (inbound to a privileged port); the Pi's own replies, RSTs and
  ICMP errors cannot trigger mitigation.
- **Protected IPs** — the SSH client IP, loopback and `--protect` addresses
  are never blocked.
- The first ~20 packets of every session are calibration; the dashboard shows
  `CALIBRATING` until then.

## Limitations and next work

- Retransmission detection relies on Wireshark-style Info strings; live
  captures built from scapy cannot mark retransmissions, so that feature is
  near-zero in live mode.
- Spoofed-source attacks cannot be reliably blocked per-IP (the sources do
  not exist); the dashboard still demonstrates per-IP attribution on
  single-source attacks.
- The dataset's "UDP flood" capture segment is actually a PSH/ACK flood;
  UDP-specific fuzzy rules (6/7) are exercised by the traffic simulator.
- This is a research prototype, not a complete network firewall. Validate
  false positives and recovery behavior on the real IoT lab network before
  enabling `--live-firewall`.
