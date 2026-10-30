# Research paper: Explainable SYN/UDP Flood Detection at the IoT Edge

IEEE-format paper (IEEEtran, conference layout) written from this repository's
code, reports and deployed model, the two evaluation decks, and the three base
papers.

| File | What it is |
|---|---|
| `main.tex` | Complete paper. Self-contained: all 11 figures are TikZ/pgfplots, and the bibliography is inline (`thebibliography`). |
| `main.pdf` | Compiled paper (11 pages). |
| `figures/fig*.png`, `figures/fig*.pdf` | Every figure exported on its own (300 dpi PNG plus vector PDF) for slides, poster or report. |
| `IMAGE_PROMPTS.md` | Prompts for optional AI-generated illustrations (graphical abstract, architecture, concepts). |

## Build

- **Overleaf:** upload `main.tex` and compile with pdfLaTeX. No other files are needed.
- **Local:** run `pdflatex main.tex` twice. You need TeX Live with `IEEEtran`,
  `pgfplots`, `algorithmicx` and `microtype`.

## Paper structure

Abstract and keywords. I Introduction (with contributions). II Background and
related work, including Table I positioning against the base papers. III Problem
formulation and design goals. IV Dataset generation and conditioning (testbed,
weak labels, direction-aware relabeling, leakage-free split). V Proposed method
(features, data-driven fuzzification, direction-gated rules, lightweight FDT,
fusion, rule extraction). VI Edge deployment and graduated response. VII
Experimental setup. VIII Results (overall comparison, false alarms, size and
latency, ablations, what the tree learned, case study, manual-to-automated
mapping, edge feasibility). IX Limitations. X Conclusion and future work.
References.

## Where the numbers come from

- `implementation/reports/*.json`: accuracy, F1, AUC, sizes, latency, dataset
  and split counts, relabeling counts.
- New analysis of the deployed artifact `fuzzy_forest.pkl` on the held-out
  split. It used the repo's own `_fuzzy_layer` code and reproduced the reported
  metrics exactly. From it come:
  - the confusion counts and FPR (Table VI);
  - the ablations "rules only" and "tree only" (Table VII);
  - per-rule firing rates (Table IV);
  - feature importances (Fig. 10);
  - the root split (`fuzzy_confidence <= 0.005`), tree depth 9, 45 leaves,
    16 attack leaves and 20 of 39 features used;
  - the real decision path of a held-out SYN packet (Fig. 11).
- `implementation/docs/report_sections.md` and `ppt_content.md`: the
  random-split inflation (88.45%), the AUC gain from relabeling (≈0.79 → ≈0.90),
  data-driven vs hand-placed membership functions (CV-F1 0.383 vs 0.380), and
  unpruned-tree accuracy (87.16%).

## Check before submission

1. **Author e-mails** are left as comments in the author blocks, so add them.
   Also confirm the professors' department (written as "Dept. of CSE").
2. **Edge telemetry** (≈23% CPU, 41% RAM, 52 °C) comes from the evaluation
   deck, not from a logged report in the repo. Keep it only if it matches your
   demo, or replace it with measured values. Also state the exact Raspberry Pi
   model you used.
3. **Normal-row count.** The deck lists "Normal rows 165,849". That is the count
   *before* relabeling. The paper uses the final 180,272 normal / 14,520 attack
   (7.45%), which matches `clean_dataset_report.json`.
4. **Membership placement.** The first deck says K-means. The final code (v5)
   uses the 15/50/85th training percentiles, and the paper describes the code.
5. **Fuzzy-ID3.** The implementation trains CART over fuzzified features, not
   native fuzzy-entropy ID3. The paper says so explicitly and lists native
   Fuzzy-ID3 as future work.
6. **Page count.** The paper is 11 pages. Most IEEE conferences allow 6–8. To
   trim, cut Fig. 2 (handshake), Fig. 9 (scatter) and Table VIII (mapping), and
   shorten Section II.

## Project status (from the repository analysis)

**Done**

- Lab capture: hping3 SYN flood to :80 and UDP flood to :53 against a
  Raspberry Pi, with timestamped phases. 194,792 packets over about 38 minutes.
- Weak timeline labeling (`label_attack_dataset.py`).
- Direction-aware relabeling (`relabel_direction_aware.py`): 14,208 victim
  replies (49.1%) corrected.
- Leakage-free chronological per-segment split with a 50-packet buffer
  (`shared_preprocessing.py`).
- 22 rolling-window features, including 5 direction features.
- Fuzzy layer with 10 attributes, 30 data-driven triangular membership functions,
  8 direction-gated rules and a fused confidence.
- Fuzzy DT with a shared lightweight training protocol (grid-CV plus CCP pruning):
  89 nodes, 9.1 KB, 87.74% accuracy, F1 0.456.
- Baselines under an identical protocol: plain DT, deep MLP, Fuzzy Forest.
- Edge engine `live_detector.py` (scapy capture, ALLOW/THROTTLE/BLOCK with TTLs,
  iptables, safety rails), the dashboard, the traffic simulator and the demo scorer.

**Left / future work** (also in Sections IX–X of the paper)

- Cross-dataset evaluation (CICIoT2023, Bot-IoT) and new captures with
  multi-host, truly spoofed and UDP-dominant floods. In the current capture the
  second phase is TCP-dominated, and the R3 spoofing rule never fired.
- Native Fuzzy-ID3 (fuzzy entropy, soft propagation) compared with
  CART-over-fuzzy.
- Indicators proposed in the first deck but not implemented: TCP window-size
  anomaly (Win=256), Shannon source-IP entropy, ICMP-unreachable rate, and a
  100 ms temporal burst score.
- Sequence-number-based retransmission estimation for live mode.
- A quantitative on-Pi benchmark: time-to-detect and false positives via
  `evaluate_demo.py`, plus CPU/RAM logging.
- Better SYN-phase recall (55.5%) and packet-level precision (34.5%).
