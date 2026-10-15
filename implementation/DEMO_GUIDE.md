# Demo Guide — Live Flood Detection on the Raspberry Pi

This guide is the operational playbook for demonstrating:

> **Explainable SYN/UDP Flood Detection in IoT Networks using Lightweight Fuzzy Decision Tree**

with live traffic, live model verdicts, live mitigation, and the dashboard running in your laptop browser while the inference happens **on the Pi**.

---

## 1. Architecture — what runs where

```
+--------------------+          WiFi / LAN 192.168.x.x           +---------------------------+
|  LAPTOP (attacker  |  -------------------------------------->  |  RASPBERRY PI (IoT edge)  |
|  + presenter)      |      traffic_simulator.py packets         |                           |
|                    |                                           |  live_detector.py         |
|  Browser:          | <--- HTTP :8080 ----------------------->  |   - sniff (scapy, sudo)   |
|   dashboard UI     |        state JSON / events                |   - rolling 50-pkt window |
|   (port 8080)      |                                           |   - fuzzy forest verdict  |
|                    | ---- control (Block/Release) ---------->  |   - throttle / block IPs  |
+--------------------+                                           |  monitor_dashboard.py     |
                                                                 +---------------------------+
```

- The **detector never runs on the laptop** during the demo — the laptop only sends traffic and displays the browser UI. All model inference, mitigation decisions and telemetry are computed on the Pi.
- Files shared between detector and dashboard (both on the Pi, in `implementation/reports/`):
  - `monitor_events.jsonl` — detector writes packet/window/action events (append-only)
  - `detector_state.json` — detector rewrites a snapshot every second (KPIs, per-IP table, CPU/RAM)
  - `control_commands.json` — dashboard UI appends Block/Release commands; the detector consumes them

---

## 2. One-time setup

### 2.1 Laptop (re-run after any model change)

```powershell
cd BTP-project\implementation
python shared_preprocessing.py       # rebuild features + honest chronological split
python run_normal_dt.py              # baseline (same training protocol as fuzzy)
python run_fuzzy_dt.py               # writes fuzzy_forest.pkl  ← deployable artifact
python run_deep_learning.py
python compare_models.py             # writes the benchmark table shown in the dashboard
```

> The normal DT and the Fuzzy DT are trained by the **identical procedure**
> (same grid, same CV-based pruning, same threshold objective) — the only
> difference is the feature space. That symmetry is what makes the benchmark
> table a fair claim for the report/viva.

### 2.2 Raspberry Pi

Install dependencies (system Python is fine):

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv scapy tcpdump
pip3 install --user numpy pandas scikit-learn joblib scapy psutil
```

Copy from the laptop (adjust the Pi IP):

```bash
# run on the laptop (Git Bash / PowerShell)
cd BTP-project/implementation
scp fuzzy_forest.pkl live_detector.py fuzzy_inference.py monitor_dashboard.py sysstats.py traffic_simulator.py evaluate_demo.py pi@<PI_IP>:~/edge/
ssh pi@<PI_IP> "mkdir -p ~/edge/reports"
```

> `fuzzy_forest.pkl` must be the one retrained on your laptop. Never train on the Pi.

Quick sanity check on the Pi (no capture needed — replays the dataset through the whole path):

```bash
# from laptop, send the clean CSV once
scp data/syn_udp_flood_attack_data_clean.csv pi@<PI_IP>:~/edge/data.csv
# on the Pi
cd ~/edge && python3 live_detector.py --replay-csv data.csv --delay 0
```

You should see window lines with scores and ALLOW/THROTTLE/BLOCK decisions. Stop with Ctrl+C.

---

## 3. Network setup (choose one)

| Option | How | Resulting addresses |
|---|---|---|
| **A. Windows Mobile Hotspot** | Laptop: Settings → Mobile hotspot ON → connect the Pi to that hotspot Wi-Fi | Laptop is `192.168.137.1`, Pi gets `192.168.137.x` |
| **B. Home/phone router Wi-Fi** | Connect laptop and Pi to the same router | e.g. `192.168.1.x` — find with `ip route \| grep default` on the Pi |
| **C. Ethernet cable + ICS** | Pi ↔ laptop Ethernet, enable Internet Connection Sharing on the laptop adapter | Pi gets `192.168.137.x` again |

Find the Pi's IP: `hostname -I` on the Pi (or check the hotspot device list on the laptop).
Test from the laptop: `ping <PI_IP>` then `ssh pi@<PI_IP>`.

> Option A is the safest for demos: the network contains only your two devices, so every packet the detector sees is part of the show.

---

## 4. Running the demo (the 5-command flow)

### Step 1 — SSH into the Pi and use tmux so SSH drops don't kill the demo

```bash
ssh pi@<PI_IP>
sudo apt install -y tmux      # once
tmux new -s demo
```

### Step 2 — start the detector (live capture; sudo is required for sniffing)

```bash
cd ~/edge
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live
```

Useful flags:

- `--iface wlan0` — pin the interface (`ip link` to list; default sniffs all)
- `--bpf "ip and not port 22"` — **recommended**: keeps your own SSH session out of the capture (and therefore out of the dashboard feed)
- `--block-ttl 60` — how long a blocked source stays blocked (default 120 s; the auto-release is part of the demo story)
- `--live-firewall` — **omit for demos**; without it blocks are simulated and logged (see §7)

### Step 3 — start the dashboard (second tmux window: Ctrl+B then C)

```bash
cd ~/edge
python3 monitor_dashboard.py --port 8080
```

### Step 4 — open the dashboard on the laptop

`http://<PI_IP>:8080` — you should see **CALIBRATING WINDOW** for ~20 packets, then **CLEAR** with a green banner. Keep this page visible; it updates every second.

### Step 5 — send traffic from the laptop (new laptop terminal)

```bash
cd BTP-project/implementation

# story mode = the full scripted demo (recommended)
python traffic_simulator.py story --target <PI_IP>

# or individual scenes
python traffic_simulator.py normal       --target <PI_IP> --duration 30
python traffic_simulator.py suspicious   --target <PI_IP> --duration 15
python traffic_simulator.py congestion   --target <PI_IP> --duration 20
python traffic_simulator.py syn-flood    --target <PI_IP> --rate 400 --duration 15
python traffic_simulator.py udp-flood    --target <PI_IP> --rate 500 --duration 15
```

> On Windows, spoofed/rotated-source SYN floods additionally need [Npcap](https://npcap.com/#download) ("install in WinPcap API-compatible mode") and an **admin** terminal. Without it, the simulator tells you and falls back to connect-floods / unspoofed UDP — still visible on the dashboard.

### What you will see, phase by phase

| Simulator phase | Dashboard reaction |
|---|---|
| `normal` | Green banner, packets/s low, verdict SAFE, fuzzy rules quiet |
| `suspicious` (slow scan) | Occasional **SUSPICIOUS** packets, maybe THROTTLE on the scanner IP; no block |
| `congestion` | High packets/s but **stays green** — legit handshakes don't trip the direction-gated rules |
| `syn-flood` | Score jumps to ~1.0 → banner **ATTACK** → source **BLOCKED** (red chip + DROP rule), rules 1/2/4/5 light up in the Explain panel |
| recovery (normal) | After `--block-ttl` seconds the source is **RELEASED** and logged in the action log |
| `udp-flood` | Rules 6/7 fire (UDP density burst) — this now works live thanks to the full feature parity fix |

### Manual controls

- **Block** any IP on the Source Threat Board (writes a control command the detector applies within a second; refused for protected/management IPs).
- **Release** to lift a block early, **Release all** to clear everything.

### Step 6 — score the demo afterwards (on the laptop or Pi)

```bash
scp pi@<PI_IP>:~/edge/reports/monitor_events.jsonl reports/
python evaluate_demo.py
```

It prints per-phase detection latency (time to THROTTLE, time to BLOCK) and false-positive counts for the normal phases — great numbers for the report/presentation.

---

## 5. Sending traffic "from different devices / IP addresses"

The detector attributes and blocks **per source IP**, so multi-source attacks make the demo richer. Four ways, easiest first:

1. **Spoofed sources (one machine, many IPs)** — `--spoof` (new random IP per packet) or `--sources 12` (rotate among 12 fixed fake IPs). This reproduces the `--rand-source` behaviour of hping3 and triggers the *Source-IP dispersion (spoofed fan-in)* fuzzy rule. Needs scapy + admin/root on the sender.

   ```bash
   sudo python traffic_simulator.py syn-flood --target <PI_IP> --rate 500 --sources 12
   ```

   The Source Threat Board will show several fake `10.x.x.x` hosts; blocking one of them is safe because it doesn't exist.

2. **A second real device** — run the simulator from another laptop / a Raspberry Pi / an Android phone running [Termux](https://fidoriel.dev/termux) (`pkg install python && pip install scapy`). Real IP, real traffic — the most convincing demo.

3. **Phone in UDP-flood mode from Termux** (no root needed, unspoofed):

   ```bash
   python traffic_simulator.py udp-flood --target <PI_IP> --rate 200 --duration 20
   ```

4. **Ambient IoT traffic** — anything else on the same network (smart bulbs, laptops streaming) is captured too and demonstrates that normal background traffic stays green.

---

## 6. Protected IPs (why you can't lock yourself out)

The detector **refuses to block**:

- the SSH client IP (read from `SSH_CLIENT` — i.e., your laptop while you're SSH'd in),
- loopback / link-local,
- anything you add: `--protect 192.168.137.1 192.168.137.255`.

Blocking is also **simulated by default** (`[SIMULATED]` in the log). Even with `--live-firewall`, rules are installed with `iptables -I INPUT -s <ip> -j DROP` and removed automatically after the TTL, and protected IPs are still refused.

**Never** enable `--live-firewall` while connected over SSH without the BPF/protect settings — a false positive on your management IP would cut your session.

---

## 7. Replaying recorded data (no simulator needed)

```bash
python3 live_detector.py --replay-csv data.csv --delay 0.01 --loop
```

`--loop` restreams the CSV forever — handy when the network setup is broken five minutes before the presentation. The dashboard shows mode `replay` vs `live`.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `live_detector.py --live` fails with "Raw packet capture requires root" | run with `sudo env PATH=$PATH:~/.local/bin python3 ...` |
| Dashboard shows *WAITING FOR DETECTOR* | detector isn't running or paths differ — both must point at the same `reports/` folder |
| Dashboard stuck on CALIBRATING | fewer than 20 packets seen yet — check the BPF filter isn't excluding everything |
| Windows simulator can't send SYN | install Npcap, run terminal as Administrator, `pip install scapy` |
| Pi CPU 100% during flood | normal — sniffing dominates; lower `--rate` on the simulator or add `--tick 0.3` |
| No UDP-flood reaction on dashboard | ensure the flood targets the Pi (not a broadcast) and `--bpf` isn't filtering UDP |
| SSH session freezes during flood | your Wi-Fi is saturated, not the Pi — lower the rate; that's the realistic effect of a flood |
