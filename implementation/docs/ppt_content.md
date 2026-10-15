# PPT Content — Full Project Deep-Dive
## Explainable SYN/UDP Flood Detection in IoT Networks using a Lightweight Fuzzy Decision Tree

Slide-by-slide content with speaker notes. Every number is taken from the
actual code and `reports/*.json` — safe to put on a slide. Diagrams are given
as ASCII; redraw them as boxes/arrows in PowerPoint.

---

## SLIDE 1 — Title

**Explainable SYN/UDP Flood Detection in IoT Networks using a Lightweight Fuzzy Decision Tree**

- BTP / Project author, guide, institution, date
- One-liner: *A 9 KB fuzzy decision tree that runs on a Raspberry Pi, matches
  a 1.1 MB neural network's accuracy, and explains every decision in
  human-readable fuzzy rules.*

---

## SLIDE 2 — Background & Motivation

- IoT devices are the #1 target of volumetric DDoS: Mirai infected ~600k IoT
  devices and launched record-breaking floods (USENIX Security '17).
- Two attack types dominate edge scenarios:
  - **TCP SYN flood** — half-open connections exhaust the victim's backlog
    (CERT CA-1996-21).
  - **UDP flood** — garbage datagrams saturate bandwidth/CPU.
- Edge defense is different from data-center defense:

| Constraint | Data-center IDS | IoT edge (our problem) |
|---|---|---|
| Compute | GPU clusters | Raspberry Pi-class CPU |
| Memory | GBs | 100s of MB shared with the app |
| Explainability | Nice-to-have | Required for forensic action (block an IP) |
| Latency | ms budget | µs per packet |

- **Research question:** can ONE model be simultaneously accurate (≈NN),
  lightweight (≈DT) and explainable (≈rule system)?

**Speaker notes:** Emphasize that deep models (MLP/CNN/LSTM IDS papers) are
accurate but cannot be deployed or trusted at the edge; rule systems are
explainable but rigid; plain trees are light but weak. Our answer: keep the
tree learner, replace the feature space with fuzzy logic.

---

## SLIDE 3 — Research Gap & Objectives

Gap analysis (see `docs/Research_Gap_Analysis.docx`):
1. Existing IoT-IDS work optimizes accuracy only — deployment cost is an
   afterthought.
2. Fuzzy-logic IDS papers hand-tune membership functions per feature — not
   reproducible, not data-adaptive.
3. Evaluations use random row splits on rolling-window features →
   **data leakage** inflates results (we show a 2-point inflation).
4. Labels in attack captures are noisy: the victim's own replies get labeled
   "attack" (we found 49% of attack rows were victim responses).

**Objectives:**
- O1: Data-conditioned pipeline: honest labels + leakage-free evaluation.
- O2: Fuzzy feature layer with **data-driven** membership placement + expert
  flood rules, gated by packet direction.
- O3: Lightweight Fuzzy DT that beats plain DT and deep MLP on accuracy/F1 at
  KB-scale size, with per-decision rule explanations.
- O4: Full edge deployment on Raspberry Pi: live capture → detection →
  graduated response → dashboard, with a reproducible demo + scoring harness.

---

## SLIDE 4 — System Architecture (redraw as boxes)

```
RESEARCH PIPELINE (laptop)                     EDGE DEPLOYMENT (Raspberry Pi)
════════════════════════                       ══════════════════════════════
hping3 attack cycles ──► Wireshark capture     traffic_simulator.py (laptop)
(simulating_Attack.py)        │                normal/suspicious/low-flood/
        │                     ▼                congestion/syn/udp/story + GT
   network_data.pcap ──► CSV export                  │  WiFi (lab network)
        │                                            ▼
        ▼                                     live_detector.py (sudo scapy)
label_attack_dataset.py                      ┌──────────────────────────────┐
 timeline alignment (labels_map.txt)         │ rolling 50-pkt window        │
        │                                    │ → 22 features (pure Python) │
        ▼                                    │ → fuzzy layer (39 features) │
relabel_direction_aware.py                   │ → Fuzzy DT (9 KB artifact)  │
 direction-aware label cleanup               │ score = max(p, 0.7·fconf)  │
        │                                    │ ALLOW/THROTTLE/BLOCK + TTLs │
        ▼                                    │ iptables DROP (optional)    │
shared_preprocessing.py                      └───────┬──────────────┬──────┘
 22 features + honest split                          │ JSONL events │ state JSON
        │                                            ▼              ▼
        ├──► run_normal_dt.py (baseline)      monitor_dashboard.py :8080
        ├──► run_fuzzy_dt.py ──► fuzzy_forest.pkl   (stdlib HTTP, browser UI:
        ├──► run_deep_learning.py (MLP)              packets, explanations,
        └──► compare_models.py (benchmark)           threat board, telemetry)
                                                   evaluate_demo.py (scoring)
```

- Research never runs on the Pi; the Pi loads only the 9 KB artifact.
- Training→serving parity is enforced: the detector computes the *same*
  feature code path used for training (no train/serve skew).

---

## SLIDE 5 — Dataset & Capture Methodology

**How the data was made (reproducible lab capture):**

- Target: Raspberry Pi at `192.168.137.211` (Windows mobile-hotspot lab LAN).
- Attack tool: **hping3** with spoofed sources (`--rand-source`, 5000 packets
  per phase @ 2000 µs interval ≈ 500 pps):
  - SYN flood: `hping3 -S -p 80 --rand-source` (port 80)
  - UDP flood: `hping3 -2 -p 53 --rand-source` (port 53)
- Interleaved normal/silence phases; every phase boundary timestamped to
  `labels_map.txt` by the generator script.
- Captured with tcpdump/Wireshark → `network_data.pcap` → CSV
  (`Time, Source, Destination, Protocol, Length, Info`).

**Dataset after labeling:**

| Stat | Value |
|---|---|
| Total packets | 194,792 |
| Duration | ≈2,283 s (~38 min) |
| Normal/background rows | 165,849 (92.55%) |
| SYN-flood rows | 20,572 |
| UDP-flood rows | 8,371 |
| Final attack rows (post-cleanup) | 14,520 (7.45%) |

- Timeline auto-alignment: label events are aligned to the capture via the
  pcap start epoch (tshark) or, as fallback, an offset search that maximizes
  attack-vs-normal packet-rate contrast (0.1 s grid).

---

## SLIDE 6 — Data Conditioning I: Timeline Labeling

`label_attack_dataset.py` — how raw capture became labeled data:

1. Read phase-boundary events `(epoch, label, name)` from `labels_map.txt`.
2. Detect complete attack cycles: `[attack → normal → attack]` triples.
3. Build time intervals; align to packet timeline:
   - primary: capture start epoch from pcap (tshark `frame.time_epoch`);
   - fallback: brute-force offset search maximizing rate contrast, penalizing
     empty intervals.
4. Attach per-packet labels + scenario names; emit report JSON.

Result: 28,943 packets labeled attack across 2 attack windows
(SYN 20 s → silence 10 s → UDP 20 s, all late in the capture).

**Speaker notes:** point out this is a *weak-labeling* pipeline — labels come
from wall-clock windows, not per-packet inspection. Weak labels are cheap but
noisy → next slide.

---

## SLIDE 7 — Data Conditioning II: Direction-Aware Relabeling

**Problem:** window-labeling marks EVERY packet in an attack window as attack.
But in a SYN flood, ~half the window is the **victim's own defense**
(SYN-ACKs and RSTs flowing victim→attacker). Training on those teaches the
model to flag the victim — capping recall and causing live false alarms.

**Fix (`relabel_direction_aware.py`):** per attack window,
1. Infer the victim IP: majority destination of SYN-only packets (fallbacks:
   majority RST source; majority TCP/UDP destination).
2. Relabel as **normal**: victim-sourced packets, unrelated background chatter
   (QUIC/DNS/ICMPv6/MDNS from other hosts), QUIC not aimed at the victim.

| Metric | Value |
|---|---|
| Attack rows before | 28,943 |
| Victim responses reverted → normal | **14,208 (49.1%!)** |
| Background rows reverted | 215 |
| Attack rows after | 14,520 |

**Impact:** ROC AUC ≈0.79 → ≈0.90 (label noise the model could never
legitimately learn was removed). This is one of the thesis' key findings:
*nearly half of weakly-labeled attack traffic is the victim's own response
traffic.*

---

## SLIDE 8 — Data Conditioning III: Leakage-Free Split

**Problem:** all features are rolling-window statistics. Neighbor rows share
49/50 packets of their windows. A random row split therefore puts
near-duplicates of test rows in train — an unpruned DT memorizes them and
shows inflated accuracy (we measured DT 88.45% on a random split vs 86.39%
honest).

**Fix (`shared_preprocessing.py`): chronological per-segment split**

- Each contiguous traffic phase (normal run, SYN-flood run, UDP-flood run…)
  is split by time: first 80% → train, last 20% → test.
- A 50-packet buffer at each boundary guarantees no window straddles the split.
- Rolling features look backward ⇒ a training window can never contain a
  held-out packet.

| Split | Rows | Attack ratio |
|---|---|---|
| Train | 155,835 | 7.38% |
| Test (hold-out) | 38,747 | 7.64% |
| Buffer (dropped) | 210 | — |

All models are evaluated on this same hold-out with the same threshold
objective — the comparison is a controlled experiment.

---

## SLIDE 9 — Feature Engineering (22 features)

**Rolling window = 50 packets.** Warm-up guard: window time-span floored at
1 s while filling (prevents fake density spikes at capture start).

*Group A — flood semantics (10):*

| Feature | Captures |
|---|---|
| `syn_ack_ratio` | SYN vs ACK imbalance (handshakes never complete) |
| `half_open_conn_count` | count of SYN-only packets (backlog pressure) |
| `same_src_ip_freq` | repetition of current source (single vs distributed) |
| `syn_packet_density`, `udp_packet_density` | per-second SYN / UDP rates |
| `total_packet_density`, `byte_density` | volumetric pressure (pps, Bps) |
| `unique_dst_port_count` | targeted port vs port scan |
| `avg_time_between_syns` | SYN cadence (burst vs slow) |

*Group B — packet statistics (7):* `packet_length`, `time_delta`,
`is_syn_only`, `pkt_len_mean`, `pkt_len_std`, `udp_ratio`, `syn_ratio`,
`retransmission_rate`.

*Group C — per-packet direction (5) — the key novelty:*
`dst_port_lt_1024`, `src_port_lt_1024`, `is_rst_flag`, `is_icmp`,
`response_direction`.
Floods travel TO a privileged port from an ephemeral source; the victim's
replies come FROM the service port or are RST/ICMP. Direction separates
attacker from victim *inside the same burst* — densities alone cannot.

---

## SLIDE 10 — Fuzzy Layer Design

1. **Normalization:** each of 10 attributes clipped to train 1st/99th
   percentiles → scaled to [0,1] (bounds frozen into the artifact).
2. **Membership functions:** triangular LOW/MEDIUM/HIGH placed **data-driven**
   at the 15th/50th/85th percentiles of the *training* traffic — no
   hand-tuned constants, adapts to any network. → 30 membership grades.
3. **Expert rules (8):** min-compositions of grades, **each gated by
   `response_direction` LOW** — the victim's replies can never fire a rule:

| # | Rule (min of grades) | Attack pattern |
|---|---|---|
| R1 | syn_ack_ratio HIGH ∧ half_open HIGH | half-open surge |
| R2 | syn_density HIGH ∧ inter-SYN LOW | SYN burst |
| R3 | src_freq LOW ∧ syn_ack HIGH | spoofed fan-in |
| R4 | syn_density HIGH ∧ half_open HIGH | retransmit/half-open |
| R5 | port_diversity LOW ∧ syn_density HIGH | single targeted port |
| R6 | udp_density HIGH ∧ total HIGH | UDP flood |
| R7 | byte_density HIGH ∧ total HIGH | volumetric flood |
| R8 | udp MED ∧ syn_ack MED ∧ total MED | low-and-slow stealth |

4. **Fuzzy confidence:** `0.55·Σ wᵢrᵢ + 0.45·max rᵢ`
   (weighted evidence + strongest single rule).

---

## SLIDE 11 — Models Compared (4)

| Model | Feature space | Learner / config |
|---|---|---|
| **Fuzzy DT (deployed)** | 39 fuzzy features only (30 grades + 8 rules + fconf) | depth 10, leaf 5, class-weight 1:4; CV-pruned (ccp α=1.67e-4) → **89 nodes / 9.1 KB** |
| Fuzzy Forest (reference) | same | 30 trees, depth 14, balanced_subsample |
| Plain DT (baseline) | 22 raw features | **identical protocol** as Fuzzy DT |
| Deep MLP | 22 raw features, standardized | 256-128-64-32, Adam, batch 256, dropout+BN-style reg (α=1e-4), early stopping, 1:2 class oversampling |

**Deployment score (Fuzzy DT):** `score = max(p_tree, 0.7 · fuzzy_confidence)`
— fusion weight λ and threshold (0.48) tuned on train predictions only.

**Fairness protocol (same for every model):**
- same chronological hold-out;
- one shared threshold objective: `0.5·F1 + 0.3·Acc + 0.2·BalAcc`, recall
  floor 0.35, tuned on train;
- one shared tree trainer `fit_lightweight_tree` (same grid, same CV pruning)
  for BOTH trees → the only variable is *fuzzy vs raw features*;
- latency measured end-to-end on real artifacts (incl. fuzzy step), median of
  5 runs × 2,000 test packets.

---

## SLIDE 12 — Results: Main Table

Honest chronological hold-out (38,747 packets, 7.64% attack):

| Model | Acc | Prec | Recall | F1 | AUC | Size | ms/pkt |
|---|---|---|---|---|---|---|---|
| **Fuzzy DT (deployed)** | **87.74%** | **34.5%** | 67.3% | **0.456** | 0.908 | **9.1 KB** | 0.013 |
| Fuzzy Forest (30) | 88.29% | 34.8% | 60.7% | 0.442 | 0.912 | 2.72 MB | 0.024 |
| Plain DT (same protocol) | 86.39% | 32.0% | 69.2% | 0.438 | 0.917 | 7.1 KB | 0.001 |
| Deep MLP | 86.51% | 32.2% | 69.4% | 0.440 | 0.911 | 1.14 MB | 0.005 |

Per-class (Fuzzy DT): Normal P=97.1% R=89.4% F1=93.1 (n=35,785);
Attack R=67.3% F1=0.456 (n=2,962) on a 13:1 imbalanced hold-out.

**Headline:** the deployed fuzzy tree beats the identically-trained plain DT
by **+1.35 acc, +2.5 prec, +0.019 F1**, and beats the **125× larger** MLP on
accuracy/precision/F1 while matching its AUC.

---

## SLIDE 13 — Results: Analysis & Ablations

1. **It's the representation, not tuning.** Learner, weights, pruning and
   thresholding are identical between the two trees; only features differ.
2. **Pruning helped accuracy:** unpruned 371 nodes = 87.16% → pruned 89 nodes
   = 87.74%. Regularization, not capacity, drives generalization on
   rolling-window features.
3. **Feature-space ablation (train-CV):** fuzzy-only > raw+fuzzy > raw-only;
   data-placed membership ≈ hand-placed (CV F1 0.383 vs 0.380) → we adopt
   data-driven (no constants to defend in a viva).
4. **Leakage matters:** random split inflated plain DT 88.45% (+2.06 points).
   Honest evaluation is a contribution, not a formality.
5. **Forest not worth it at the edge:** +0.55 acc over the single tree for
   300× size and 2× latency.
6. **Rule fusion (λ=0.7)** mainly helps stealth windows where the tree is
   uncertain but expert rules still fire; λ picked on train.

---

## SLIDE 14 — Explainability (the "X" in the title)

Every verdict ships with its evidence — computed at inference time from the
same fuzzy layer:

```
VERDICT: ATTACK (score 0.599 ≥ threshold 0.480)
window 50 pkts · model 0.412 · fuzzy 0.599 · dominant source 10.128.187.49
R2 SYN burst rate ............ 0.81  ████████████░░░
R1 half-open surge ........... 0.64  █████████░░░░░░
R5 targeted port ............. 0.41  ██████░░░░░░░░░
→ ACTION: BLOCK 10.128.187.49 (iptables DROP, TTL 120 s)
```

- The 8 rules map 1:1 to named attack behaviors → a forensic analyst can
  *read* why an IP was blocked (dashboard renders this live).
- Contrast: an MLP of equal accuracy offers weights/heatmaps only — not
  actionable at the edge.
- Direction gating guarantees attributed rules point at attacker-direction
  traffic, never the victim's replies.

---

## SLIDE 15 — Edge Deployment: live_detector.py

Pipeline per 50-packet window (pure-Python features ≈1 ms — pandas-free):

1. scapy sniffer thread → bounded queue (floods cannot overflow memory).
2. Rolling window → 22 features (identical math to training, incl. warm-up
   floor) → fuzzy layer → Fuzzy DT → `score`.
3. **Graduated response per source IP:**

| State | Condition | Action | TTL |
|---|---|---|---|
| ALLOW | score < 0.5·thr (0.24) | pass | — |
| THROTTLE | ≥ 0.5·thr | rate-limit advisory | 20 s |
| BLOCK | ≥ thr (0.48) | iptables DROP (`--live-firewall`) or simulated+logged | 120 s, auto-release |

4. **Safety rails:** SSH client IP (env `SSH_CLIENT`), loopback and
   `--protect` IPs are never blocked; BPF filter keeps SSH out of capture;
   blocks of spoofed (nonexistent) sources are drop-only → demo-safe.
5. Telemetry: packets/s EMA, per-window inference ms, CPU/RAM/temp.
6. Outputs: JSONL event stream + atomic 1 s state snapshot + control-command
   queue (dashboard Block/Release buttons).

---

## SLIDE 16 — Dashboard & Demo Tooling

**Dashboard (`monitor_dashboard.py`, zero dependencies — Python stdlib):**
- Live KPI cards: traffic rate, threat score, model vs fuzzy confidence,
  current action, mitigations, Pi CPU/RAM/temp + avg inference ms.
- Traffic & threat timeline (canvas chart, attack shading, threshold line).
- **Live decision explanation panel** (the 8 rule bars — see Slide 14).
- Live packet stream with verdict chips & confidence bars.
- Source Threat Board: per-IP packets, max score, status, release countdown,
  manual Block/Release buttons (commands applied <1 s).
- Model benchmark table with the deployed fuzzy DT highlighted.
- Light, animated UI (translucent sticky header, staggered card entrances,
  tweened numbers, reduced-motion support); polls `/state` `/events`
  `/benchmark` every second.

**Traffic simulator (`traffic_simulator.py`) — demo scenes:** `normal`
(full handshakes), `suspicious` (slow port scan), `low-flood` (gentle
4-source half-open flood → THROTTLE zone), `congestion` (12-worker legit
load = false-positive test), `syn-flood`, `udp-flood` (spoof/rotate sources),
and `story` — a 10-phase ~2 min storyline with ground-truth timestamps.

**Scorer (`evaluate_demo.py`):** per phase — time-to-THROTTLE,
time-to-BLOCK, avg score, and false-positive windows in normal/congestion
phases → hard numbers for the report.

---

## SLIDE 17 — Live Demo Flow (what to show)

1. SSH into Pi (`tmux`), start detector: `sudo python3 live_detector.py --live
   --bpf "ip and not port 22"`, start dashboard on :8080.
2. Laptop browser → Pi dashboard: CALIBRATING → CLEAR (green).
3. Laptop: `python traffic_simulator.py story --target <PI_IP>` and narrate
   the dashboard reactions:

| Phase | Dashboard reaction |
|---|---|
| normal | green, low pps, rules quiet |
| suspicious scan | occasional SUSPICIOUS, maybe THROTTLE |
| congestion | high pps, **stays green** (direction gating works) |
| low-flood | THROTTLE chip, advisory log (graduated response) |
| SYN flood | score →1.0, banner ATTACK, source BLOCKED, R1/R2/R4/R5 light |
| recovery | auto-release after TTL, logged |
| UDP flood | R6/R7 fire, second BLOCK |

4. Click Block/Release on the threat board (manual override <1 s).
5. Afterwards: `python evaluate_demo.py` → time-to-detect table + FP counts.

---

## SLIDE 18 — Conclusions

1. **Feasibility of the core claim:** a 9.1 KB / 89-node Fuzzy DT reaches
   87.7% accuracy and 0.456 F1 on a leakage-free chronological hold-out —
   beating an identically-trained plain DT (86.4% / 0.438) and a 125× larger
   deep MLP (86.5% / 0.440) at equal AUC (0.908 vs 0.911).
2. **Fuzzy representation as the accuracy lever:** data-placed membership
   functions + direction-gated expert rules convert weak raw statistics into
   a feature space where a tiny tree generalizes better than big models.
3. **Data hygiene is a first-class contribution:** direction-aware relabeling
   (49% of attack rows were victim replies) and leakage-free splitting
   changed both absolute numbers and model ranking.
4. **Deployability demonstrated end-to-end:** live capture → explainable
   verdict → graduated mitigation with safety rails → browser dashboard, all
   on a Pi, with a reproducible demo harness and quantitative demo scoring.

---

## SLIDE 19 — Future Work

- Live-capable retransmission estimation (sequence-number based) to replace
  Wireshark-annotated training feature.
- Online/adaptive membership placement (streaming quantiles) for per-network
  baselines and drift.
- Broader attack scope (slowloris, ICMP flood, ARP spoofing) + cross-dataset
  generalization (e.g., CICIoT2023).
- Port inference to ONNX/C for sub-10 µs windows; evaluate on Cortex-M.
- Feedback loop: block outcomes as weak labels for supervised periodic
  retraining.

---

## SLIDE 20 — References (same list as report)

1. Zadeh 1965 (Fuzzy sets) · 2. Breiman et al. 1984 (CART) ·
3. Quinlan 1993 (C4.5) · 4. Breiman 2001 (Random Forests) ·
5. Rumelhart/Hinton/Williams 1986 (backprop) · 6. Pedregosa 2011 (scikit-learn)
· 7. CERT CA-1996-21 (SYN flooding) · 8. Antonakakis 2017 (Mirai) ·
9. Bridges & Vaughn 2000 (fuzzy data mining for IDS) · 10. dataset citation
(fill Kaggle URL) · 11. scapy.net · 12. raspberrypi.com/docs

---

## Appendix Slides (optional, for Q&A)

- **A1 Reproduction:** `shared_preprocessing.py → run_normal_dt.py →
  run_fuzzy_dt.py → run_deep_learning.py → compare_models.py` (laptop);
  copy `fuzzy_forest.pkl` + 4 scripts to Pi (see DEMO_GUIDE.md).
- **A2 Threshold/tuning objective formula** and recall-floor rationale.
- **A3 Pruning curve:** 371→89 nodes, acc 87.16→87.74 (CV-selected α).
- **A4 Full feature list** (Slide 9 table extended with formulas).
- **A5 Class imbalance handling:** class-weight 1:4 (trees), 1:2 oversampling
  (MLP), shared recall floor 0.35 in tuning.
