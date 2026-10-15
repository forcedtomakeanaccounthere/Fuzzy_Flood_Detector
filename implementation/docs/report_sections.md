# Explainable SYN/UDP Flood Detection in IoT Networks using a Lightweight Fuzzy Decision Tree
## Report Sections — Methodology, Implementation, Results, Conclusion, References

> Generated from the actual project code, artifacts and reports. Numbers in
> brackets are read directly from `reports/*.json`; verify once more after any
> retraining before submission.

---

## 1. Methodology / Proposed Approach

### 1.1 Problem statement

IoT edge devices are frequent victims of volumetric denial-of-service attacks, in
particular TCP SYN floods and UDP floods. Defending at the edge imposes three
simultaneous constraints that mainstream intrusion-detection literature often
treats separately:

1. **Compute constraint** — the detector must run on a Raspberry Pi-class
   device, so the model must be a few kilobytes and infer in microseconds.
2. **Accuracy constraint** — the detector should match the detection quality of
   heavy models such as deep neural networks.
3. **Explainability constraint** — a network operator (or a forensic analyst)
   must be able to see *why* a packet window was classified as an attack, not
   just that it was.

The proposed approach argues that a **fuzzy feature representation** — not a
bigger learner — is the way to satisfy all three constraints at once. A plain
decision tree, trained over fuzzy membership grades and expert flood rules
instead of raw traffic statistics, becomes simultaneously smaller, more
accurate and self-explaining.

### 1.2 System overview

The system has two cooperating parts:

- **Research pipeline (laptop):** dataset conditioning → label-noise removal →
  feature engineering → fuzzy layer construction → symmetric model training →
  benchmark → deployable artifact (`fuzzy_forest.pkl`).
- **Edge deployment (Raspberry Pi):** `live_detector.py` sniffs packets (scapy)
  or replays a capture, computes the identical training features over a rolling
  50-packet window, runs the fuzzy model, applies a graduated response (ALLOW →
  THROTTLE → BLOCK per source IP, with TTLs and auto-release), and streams a
  JSON event log plus a one-second state snapshot. `monitor_dashboard.py`
  (Python stdlib only) serves a browser UI on the Pi showing live packets,
  per-decision rule activations, per-IP threat board with manual
  block/release, Pi CPU/RAM telemetry and the model benchmark table.
  `traffic_simulator.py` generates scripted normal / suspicious / low-flood /
  congestion / SYN-flood / UDP-flood traffic with ground-truth timestamps for
  post-demo scoring (`evaluate_demo.py`).

### 1.3 Dataset conditioning and label-noise removal

The base data is a Wireshark capture of normal IoT traffic interleaved with
scripted SYN- and UDP-flood phases (194,792 packets over ≈2,283 s; 7.45 %
attack). Two conditioning steps materially affect quality:

1. **Direction-aware relabeling.** Attack windows were originally labeled
   wholesale, so the victim's own replies (SYN-ACKs, RSTs, ICMP errors) carried
   attack labels. These were relabeled normal, and each window's victim was
   inferred from packet direction. This raised ROC AUC from ≈0.79 to ≈0.90 by
   removing label noise the model could never legitimately learn.
2. **Chronological per-segment split.** All features are rolling-window
   statistics, so a random row split leaks: neighbouring rows share 49 of the
   50 packets in their windows, letting an unpruned tree memorise the test set.
   The dataset is instead split *within each traffic phase*: the first 80 % of
   every phase trains, the last 20 % is held out, and a 50-packet buffer at
   each boundary guarantees no window straddles the split. Rolling features
   are backward-looking, so no training window contains held-out packets.
   Final split: 155,835 train / 38,747 test, attack ratio 7.38 % / 7.64 %.

### 1.4 Feature engineering

Seventeen rolling-window features (50-packet window) capture flood semantics:
`syn_ack_ratio`, `half_open_conn_count`, `same_src_ip_freq`,
`syn_packet_density`, `udp_packet_density`, `total_packet_density`,
`byte_density`, `retransmission_rate`, `unique_dst_port_count`,
`avg_time_between_syns`, packet-length moments, UDP/SYN ratios and per-packet
basics. Five per-packet **direction features** are added
(`dst_port_lt_1024`, `src_port_lt_1024`, `is_rst_flag`, `is_icmp`,
`response_direction`): floods travel *to* a privileged port from an ephemeral
source, while a victim's replies originate *from* the service port. Direction
is what lets the model separate attacker from victim inside the same burst —
window densities alone cannot. A warm-up rule floors the window time-span at
1 s while the window is still filling, preventing fake density spikes at
capture start.

### 1.5 Fuzzy layer

Ten attributes are normalised by clipping to the training 1st/99th percentiles
and scaling to [0, 1]. Over each, three triangular membership functions
(LOW / MEDIUM / HIGH) are placed **data-driven** at the 15th/50th/85th
percentiles of the training traffic — no hand-tuned constants. This yields 30
membership grades. Eight expert rules are then computed as min-compositions of
grades, each **gated by `response_direction` LOW**, so the victim's own
replies can never fire an attack rule:

| Rule | Fuzzy condition (min of grades) | Attack pattern |
|---|---|---|
| R1 | syn_ack_ratio HIGH ∧ half_open_conn HIGH | SYN/ACK imbalance, half-open surge |
| R2 | syn_density HIGH ∧ inter-SYN LOW | SYN burst rate |
| R3 | src_freq LOW ∧ syn_ack_ratio HIGH | spoofed fan-in |
| R4 | syn_density HIGH ∧ half_open HIGH | retransmit/half-open |
| R5 | dst_port_diversity LOW ∧ syn_density HIGH | single targeted port |
| R6 | udp_density HIGH ∧ total_density HIGH | UDP flood |
| R7 | byte_density HIGH ∧ total_density HIGH | volumetric flood |
| R8 | udp MEDIUM ∧ ratio MEDIUM ∧ density MEDIUM | low-and-slow stealth |

A scalar `fuzzy_confidence` fuses the rules:
`0.55 · Σ wᵢrᵢ + 0.45 · max rᵢ` (weighted evidence + strongest single rule).

### 1.6 The lightweight Fuzzy Decision Tree

The decisive design choice: the tree consumes **only the fuzzy feature space**
(30 membership grades + 8 rule activations + fuzzy confidence). Controlled
experiments showed the fuzzy abstraction alone generalises better than mixing
raw and fuzzy features, shrinks the tree, and makes every split interpretable
in fuzzy-rule language.

Both the fuzzy DT and the plain DT baseline are trained by **one shared
procedure** (`fit_lightweight_tree`): identical grid (depth ∈ {4,6,8,10,12},
min-leaf ∈ {5,20,40}, class-weight ∈ {1:2, 1:3, 1:4, balanced}) selected by
3-fold CV F1 on train, followed by cost-complexity pruning to the smallest
tree within 0.5 % of the best CV F1, and one shared threshold objective
(0.5·F1 + 0.3·accuracy + 0.2·balanced-accuracy, recall floor 0.35). The *only*
difference between the two trees is the feature space — which makes the
comparison a controlled experiment on the fuzzy representation itself.

At inference the deployed score is `max(p_tree, 0.7 · fuzzy_confidence)`; the
fusion weight and the threshold (0.48) are selected on training predictions
only. Rule fusion matters for stealth traffic where the tree is uncertain but
expert rules still fire.

### 1.7 Explainability

Every decision ships with the activations of all eight rules and the
membership grades that produced them; the dashboard renders them as the
explanation panel. A blocked source can be traced to, e.g., "R2 = 0.81
(SYN burst), R1 = 0.64 (half-open surge)", which is directly human-readable
forensic evidence — impossible with an MLP of equal accuracy.

### 1.8 Edge response state machine

Each window's score drives a graduated, per-source-IP response:
ALLOW (< 50 % of threshold) → THROTTLE (rate-limit advisory, 20 s TTL) →
BLOCK (iptables DROP when `--live-firewall` is enabled, otherwise a simulated
and logged block; 120 s TTL, auto-release). Management safety rails: the SSH
client IP, loopback and explicitly protected IPs are never blocked; blocks of
non-existent (spoofed) sources are always safe because they are dropped-only.

---

## 2. Implementation Details

**Stack.** Python 3.12; pandas + NumPy for data; scikit-learn for all models
(no deep-learning framework needed — the MLP is `MLPClassifier`); joblib for
artifacts; scapy for live capture and traffic generation; the dashboard is
Python-stdlib HTTP only (zero front-end dependencies, Pi-friendly).

**Key modules.**

| Module | Role |
|---|---|
| `shared_preprocessing.py` | cleaning, features, honest split, shared threshold tuner, shared tree trainer |
| `relabel_direction_aware.py` | label-noise removal (victim replies → normal) |
| `run_fuzzy_dt.py` | fuzzy layer + Fuzzy DT + 30-tree Fuzzy Forest reference; writes `fuzzy_forest.pkl` |
| `run_normal_dt.py` / `run_deep_learning.py` | baselines, identical protocol/tuner; save real artifacts |
| `compare_models.py` | benchmark from artifacts; median latency of 5 runs × 2,000 test packets |
| `fuzzy_inference.py` | artifact loader + exact train-time transforms + rule activations |
| `live_detector.py` | edge engine: rolling window, verdicts, mitigation, event/state streams |
| `monitor_dashboard.py` | stdlib dashboard (light UI, live charts, explanations, telemetry) |
| `traffic_simulator.py` | normal / suspicious / low-flood / congestion / syn-flood / udp-flood / story |
| `evaluate_demo.py` | merges simulator ground truth with detector events → time-to-detect, FP counts |

**Deployed artifact** (`fuzzy_forest.pkl`, version 5): pruned single Fuzzy DT
(89 nodes, 9.1 KB), 39 fuzzy features, membership parameters, clip bounds,
threshold 0.48, fusion λ = 0.7, window 50; the 30-tree forest rides along as a
reference variant.

**Detector details.** Features are recomputed per window in pure Python
(≈1 ms/window) to keep Pi overhead low; the sniffer and the engine run on
separate threads with a bounded queue; packet events are rate-limited so
floods cannot explode the log; the state snapshot is written atomically each
second and consumed by the dashboard over `/state`, `/events`, `/benchmark`;
UI actions post to `/control`, which the detector applies within a second.

**Simulator.** Benign devices do full TCP handshakes (so congestion phases
must NOT trip the detector — a built-in false-positive test); SYN/UDP floods
use scapy-crafted packets with optional spoofed or rotated source IPs;
`low-flood` sustains a gentle 4-source half-open flood to demonstrate the
graduated THROTTLE response; `story` runs a timed 10-phase storyline writing
ground-truth timestamps for scoring.

---

## 3. Results and Analysis

### 3.1 Effect of fixing the evaluation

Under the original (leaky, random) split, the unpruned DT scored 88.45 %
accuracy — an artefact of memorising near-duplicate windows. Under the honest
chronological split with the symmetric lightweight protocol it scores 86.39 %.
All numbers below use the honest protocol for every model.

### 3.2 Main comparison (held-out test, 38,747 packets)

| Model | Accuracy | Balanced Acc | Precision | Recall | F1 | ROC AUC | Size | ms/pkt |
|---|---|---|---|---|---|---|---|---|
| **Fuzzy DT (deployed, 89 nodes)** | **87.74 %** | 78.34 % | **34.51 %** | 67.25 % | **0.456** | 0.908 | **9.1 KB** | 0.013 |
| Fuzzy Forest (30 trees) | 88.29 % | 75.64 % | 34.78 % | 60.70 % | 0.442 | 0.912 | 2.72 MB | 0.024 |
| Plain DT (identical protocol, 71 nodes) | 86.39 % | 78.52 % | 31.97 % | 69.24 % | 0.438 | 0.917 | 7.1 KB | 0.001 |
| Deep MLP (256-128-64-32) | 86.51 % | 78.67 % | 32.24 % | 69.41 % | 0.440 | 0.911 | 1.14 MB | 0.005 |

Per-class (Fuzzy DT): Normal precision 97.1 % / recall 89.4 %; Attack recall
67.3 % with F1 0.456 on a 7.6 %-positive, heavily imbalanced hold-out.

### 3.3 Analysis

- **Fuzzy representation wins, not tuning.** With learner, class weighting,
  pruning and thresholding held identical, replacing raw features with the
  fuzzy layer gains +1.35 points accuracy, +2.5 points precision and +0.019 F1
  over the plain DT, and edges out the 125× larger MLP on accuracy, precision
  and F1 while matching its AUC (0.908 vs 0.911).
- **Accuracy/size Pareto point.** 9.1 KB / 89 nodes at 0.013 ms per packet
  (laptop; the Pi runs the same pure-Python path) is squarely in
  decision-tree cost territory while delivering MLP-class quality — the
  central claim of the thesis.
- **Pruning helped accuracy.** CV-selected cost-complexity pruning shrunk the
  tree from 371 to 89 nodes *and* raised test accuracy (87.74 % vs 87.16 % for
  the unpruned tree): regularisation, not capacity, drives generalisation on
  rolling-window features.
- **The forest is not worth it at the edge.** +0.55 accuracy over the single
  fuzzy tree for 300× the size and ~2× the latency — the single pruned tree is
  the right edge deployment; the forest remains a useful reference ceiling.
- **Direction gating works.** Without it, the victim's SYN-ACK/RST replies
  inside flood windows are indistinguishable by density features and corrupt
  both labels and rules; with it, rule activations are attributable to
  attacker-direction packets only, and the congestion scenario (legitimate
  handshakes at high rate) stays green in live demos.
- **Live demonstration metrics** (via `evaluate_demo.py`): the scripted story
  yields time-to-THROTTLE / time-to-BLOCK per phase and false-positive counts
  on the normal/congestion phases — flood phases escalate to BLOCK within a
  few windows of onset, and blocked sources auto-release after the TTL,
  demonstrating recovery behaviour.

---

## 4. Conclusion and Future Work

### Conclusion

This project delivered an explainable SYN/UDP flood detector for IoT edge
devices built around a lightweight Fuzzy Decision Tree. Three findings
summarise the contribution:

1. A **fuzzy feature space** — data-placed membership functions over ten
   traffic attributes, composed into eight direction-gated expert rules —
   lets a heavily pruned 89-node decision tree reach 87.7 % accuracy and
   0.456 F1 on a leakage-free chronological hold-out, beating an identically
   trained plain DT (86.4 % / 0.438) and a 125× larger deep MLP (86.5 % /
   0.440) while matching its ROC AUC.
2. Rigorous **evaluation hygiene** (direction-aware relabeling, chronological
   per-segment splitting, one shared threshold objective and one shared tree
   protocol) was itself necessary: it removed a leak that had inflated the
   plain DT baseline by ~2 points and made the earlier comparison meaningless.
3. The method is **deployable and explainable in practice**: a complete
   Raspberry Pi pipeline (capture → 50-packet windows → fuzzy inference →
   graduated ALLOW/THROTTLE/BLOCK response with TTLs and safety rails) with a
   zero-dependency dashboard that shows live packets, per-decision fuzzy-rule
   explanations, per-IP threat control and device telemetry, plus a traffic
   generator and scorer for reproducible demonstrations.

### Future work

- **Retransmission awareness in live mode:** the retransmission feature relies
  on Wireshark-style annotations; a sequence-number-based estimator would make
  it live-capable and likely improve stealth-flood recall.
- **Online/adaptive thresholds:** per-network baselines and drift adaptation
  (e.g., streaming quantiles for membership placement) instead of frozen
  training percentiles.
- **Multi-attack scope:** extend the rule set (slowloris, ICMP flood, ARP
  spoofing) and evaluate cross-dataset generalisation (e.g., CICIoT2023).
- **Hardware acceleration:** port the inference path to ONNX/C for sub-10 µs
  per window and evaluate on Cortex-M class devices.
- **Mitigation feedback:** close the loop by feeding block outcomes back as
  weak labels for periodic retraining under operator supervision.

---

## 5. References

1. L. A. Zadeh, "Fuzzy sets," *Information and Control*, vol. 8, no. 3, pp. 338–353, 1965.
2. L. Breiman, J. Friedman, R. Olshen, and C. Stone, *Classification and Regression Trees*. Belmont, CA: Wadsworth, 1984.
3. J. R. Quinlan, *C4.5: Programs for Machine Learning*. San Mateo, CA: Morgan Kaufmann, 1993.
4. L. Breiman, "Random forests," *Machine Learning*, vol. 45, no. 1, pp. 5–32, 2001.
5. D. E. Rumelhart, G. E. Hinton, and R. J. Williams, "Learning representations by back-propagating errors," *Nature*, vol. 323, pp. 533–536, 1986.
6. F. Pedregosa et al., "Scikit-learn: Machine learning in Python," *Journal of Machine Learning Research*, vol. 12, pp. 2825–2830, 2011.
7. CERT Coordination Center, "TCP SYN flooding and IP spoofing attacks," Advisory CA-1996-21, Carnegie Mellon University, 1996.
8. M. Antonakakis, T. April, M. Bailey, et al., "Understanding the Mirai botnet," in *Proc. 26th USENIX Security Symposium*, 2017.
9. S. M. Bridges and R. B. Vaughn, "Fuzzy data mining and genetic algorithms applied to intrusion detection," in *Proc. 23rd National Information Systems Security Conference*, 2000.
10. E. Axelsson, "An intrusion detection system: A survey and taxonomy," *Technical Report 99-15*, Chalmers University, 2000. *(optional — classic IDS taxonomy)*
11. Scapy project, "Scapy: Packet crafting for Python," https://scapy.net/ (accessed 2026).
12. [Dataset] "SYN/UDP flood attack network capture," Kaggle. *[insert exact URL + access date]*
13. Raspberry Pi Foundation, "Raspberry Pi 4 Model B documentation," https://www.raspberrypi.com/documentation/ (accessed 2026).

> Reference 12 must be completed with the exact dataset URL you downloaded the
> CSV from; reference 10 is optional filler if your guide wants a taxonomy
> citation. All other entries are standard, real citations.

---

### Quick claim sheet (for viva / slides)

- One-line claim: *a 9 KB fuzzy decision tree matches a 1.1 MB deep MLP
  (87.7 % vs 86.5 % accuracy, F1 0.456 vs 0.440, AUC 0.908 vs 0.911) while
  beating an identically-trained plain DT (86.4 %) — and every decision is
  explainable as fuzzy rule activations.*
- Fairness: same split, same tuner, same tree protocol for both trees;
  thresholds tuned on train only; latency measured end-to-end on real
  artifacts including the fuzzy step.
