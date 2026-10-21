# Live Demonstration Checklist - Final Preparation

## 🎯 Demo Day Preparation (24 Hours Before)

### Hardware Setup

#### Raspberry Pi
- [ ] Raspberry Pi 4/5 with power supply
- [ ] microSD card (32GB+) flashed with Raspberry Pi OS
- [ ] SSH enabled during imaging
- [ ] WiFi credentials configured
- [ ] Optional: Monitor + keyboard + mouse (for emergency access)

#### Network Devices
- [ ] WiFi router OR Windows laptop for mobile hotspot
- [ ] All devices can connect to same network
- [ ] Network is isolated from production systems

#### Traffic Generator Systems
- [ ] System 1: Laptop/device for normal light traffic
- [ ] System 2: Laptop/device for normal heavy traffic
- [ ] System 3: Laptop/device for gradual attack (needs admin/sudo)
- [ ] System 4: Laptop/device for stealthy attack (needs admin/sudo)
- [ ] Alternative: 1 laptop with 4 terminal windows works too

---

## 📦 Software Preparation

### On Raspberry Pi (One-Time Setup)

```bash
# Connect and update
ssh pi@<PI_IP>
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3-pip python3-scapy tmux htop
pip3 install --user numpy pandas scikit-learn joblib psutil scapy

# Create directories
mkdir -p ~/edge/reports ~/edge/data

# Verify installations
python3 -c "import numpy, pandas, sklearn, joblib, psutil, scapy; print('✅ All imports OK')"
```

**Status:** [ ] Complete

### On Development Laptop

```powershell
# Train models (if not already done)
cd "C:\Users\Abhishek\Downloads\iot forensics\btp\BTP-project\implementation"

python shared_preprocessing.py
python run_fuzzy_dt.py        # Creates fuzzy_forest.pkl
python compare_models.py

# Verify artifact
ls fuzzy_forest.pkl           # Should be ~2-3 MB
```

**Status:** [ ] Complete

### Transfer to Raspberry Pi

```powershell
$PI_IP = "192.168.137.X"  # UPDATE THIS

# Core files
scp fuzzy_forest.pkl pi@${PI_IP}:~/edge/
scp live_detector.py fuzzy_inference.py monitor_dashboard.py sysstats.py pi@${PI_IP}:~/edge/

# Reports
scp reports/model_comparison_report.json pi@${PI_IP}:~/edge/reports/

# Optional: test data
scp data/syn_udp_flood_attack_data_clean.csv pi@${PI_IP}:~/edge/data/test_data.csv
```

**Status:** [ ] Complete

### On Traffic Generator Systems

```bash
# Verify Python 3.7+
python3 --version

# Install scapy (optional but recommended)
pip3 install scapy

# Windows: Download and install Npcap from https://npcap.com/
# ✅ Check "WinPcap API-compatible mode" during install

# Copy simulation scripts
# Already in: BTP-project/simulation_scripts/
cd BTP-project/simulation_scripts
ls *.py  # Should see 4 scripts
```

**Status:** 
- [ ] System 1 ready
- [ ] System 2 ready  
- [ ] System 3 ready (+ admin/sudo + scapy)
- [ ] System 4 ready (+ admin/sudo + scapy)

---

## 🧪 Pre-Demo Testing (1 Hour Before)

### Test 1: Raspberry Pi Services

```bash
# SSH into Pi
ssh pi@<PI_IP>

# Test model loading
cd ~/edge
python3 -c "
import joblib
artifact = joblib.load('fuzzy_forest.pkl')
print(f'✅ Model: {artifact[\"model_kind\"]}')
print(f'✅ Threshold: {artifact[\"threshold\"]:.3f}')
print(f'✅ Features: {len(artifact[\"feature_order\"])}')
"
```

**Expected output:**
```
✅ Model: fuzzy_dt_single
✅ Threshold: 0.48X
✅ Features: 22
```

**Status:** [ ] Pass

### Test 2: Detector Replay Mode (No Network Needed)

```bash
# On Pi
cd ~/edge
python3 live_detector.py --replay-csv data/test_data.csv --delay 0 --min-eval 10

# Should show:
# Edge detector | artifact: fuzzy_forest.pkl
# Replay finished: XXXX packets, YYY windows...

# Press Ctrl+C to stop
```

**Status:** [ ] Pass

### Test 3: Dashboard Startup

```bash
# On Pi, in new terminal or tmux window
cd ~/edge
python3 monitor_dashboard.py --port 8080

# Should show:
# Serving on 0.0.0.0:8080
```

**Open browser:** `http://<PI_IP>:8080`

**Expected:** Dashboard loads (even if shows "Disconnected")

**Status:** [ ] Pass

### Test 4: Live Detector (Requires sudo)

```bash
# On Pi
cd ~/edge
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live --bpf "ip and not port 22"

# Should start sniffing, shows:
# Sniffing on default interface...

# From laptop, generate test traffic:
ping <PI_IP>

# Dashboard should update! Check browser.

# Press Ctrl+C to stop
```

**Status:** [ ] Pass

### Test 5: Simulation Script (One Example)

```bash
# On any traffic generator system
cd BTP-project/simulation_scripts
python normal_light_traffic.py --target <PI_IP> --duration 30 --devices 3

# Should run for 30 seconds, show:
# All 3 devices started
# Simulation completed
```

**Status:** [ ] Pass

---

## 🎬 Demo Day - Start Sequence

### 30 Minutes Before Presentation

#### Network Setup

**Option A: Windows Mobile Hotspot**
```powershell
# On Windows laptop
Settings → Network & Internet → Mobile hotspot
✅ Turn ON
✅ Note SSID and password
✅ Connect Raspberry Pi to this hotspot
✅ Connect traffic generator devices
✅ Verify all devices show in "Connected devices" list
```

**Your laptop IP:** `192.168.137.1`  
**Raspberry Pi IP:** `192.168.137.X` (check in hotspot settings)

**Status:** [ ] Network ready, all devices connected

#### Start Pi Services

```bash
# SSH into Pi
ssh pi@<PI_IP>

# Start tmux session (survives SSH disconnects!)
tmux new -s demo

# ═══ Window 0: Detector ═══
cd ~/edge
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py \
  --live \
  --bpf "ip and not port 22" \
  --block-ttl 120 \
  --throttle-ttl 30

# Should show: "Sniffing on ... Ctrl+C to stop"

# Create new tmux window: Ctrl+B, then C

# ═══ Window 1: Dashboard ═══
cd ~/edge
python3 monitor_dashboard.py --port 8080

# Should show: "Serving on 0.0.0.0:8080"

# Detach from tmux: Ctrl+B, then D
# (Services keep running in background)
```

**Tmux tips:**
- Reattach: `tmux attach -t demo`
- Switch windows: `Ctrl+B` then `0` or `1`
- Detach: `Ctrl+B` then `D`

**Status:** [ ] Detector running [ ] Dashboard running

#### Open Dashboard

**On presentation laptop/device:**
```
Browser: http://<PI_IP>:8080
```

**Expected:**
- Banner: 🟢 **Live** 
- Status: **CALIBRATING** (waiting for 20 packets)
- After ping test: **CLEAR**

**Test traffic generation:**
```powershell
# From laptop
ping <PI_IP> -n 50
```

Dashboard should update! Banner changes to **CLEAR**.

**Status:** [ ] Dashboard accessible and updating

---

## 🎪 Demo Execution

### Phase 1: Introduction (1 minute)

**What to show:**
- Dashboard on screen
- Explain architecture diagram
- Point to KPI cards
- Show "CLEAR" state

**What to say:**
> "This is live IoT threat detection running on a Raspberry Pi edge device. The fuzzy forest model performs inference locally in under 3 milliseconds per 50-packet window."

### Phase 2: Normal Traffic (2 minutes)

**Start simulators:**

```bash
# Terminal 1 (System 1)
cd BTP-project/simulation_scripts
python normal_light_traffic.py --target <PI_IP> --duration 600

# Terminal 2 (System 2)
python normal_heavy_traffic.py --target <PI_IP> --duration 600
```

**What to show:**
- Traffic rate: 50-200 pps
- Banner stays 🟢 **CLEAR**
- Occasional congestion spikes (200-400 pps)
- System recognizes legitimate handshakes

**What to say:**
> "System 1 simulates typical IoT devices - sensors, controllers. System 2 adds heavy legitimate load. Notice the packet rate spikes to 300 per second, but the dashboard stays green. The model distinguishes high volume from attack patterns."

**Status:** [ ] Demo running smoothly

### Phase 3: Gradual Attack (4 minutes)

**Start attack:**

```bash
# Terminal 3 (System 3) - As Administrator/sudo
cd BTP-project/simulation_scripts

# Windows (as Admin):
python gradual_attack_intervals.py --target <PI_IP> --duration 480 --sources 8

# Linux/Mac:
sudo python3 gradual_attack_intervals.py --target <PI_IP> --duration 480 --sources 8
```

**Timeline:**
- 0:00-1:30 = Stealth reconnaissance → 🟡 **ELEVATED**
- 1:30-2:00 = Pause → 🟢 **CLEAR**
- 2:00-3:00 = Moderate flood → 🔴 **ATTACK**
- 3:00-4:00 = Pause → Auto-release
- 4:00+ = Intense → UDP → Recovery

**What to show:**
- Threat score climbing
- Banner changing colors
- Fuzzy rules activating (Explanation panel)
- Source Threat Board showing blocked IPs
- Action log showing mitigation

**What to say:**
> "Now a sophisticated attacker appears. It starts with stealth reconnaissance - low and slow to evade detection. Watch the threat score... there! It's escalating. The model detects the pattern and blocks the source. During pauses, the system automatically releases blocked IPs to prevent permanent blacklisting. Notice Rules 1, 2, and 4 in the Explanation panel - these show WHY it was detected."

**Status:** [ ] Attack detection working [ ] Blocking visible [ ] Auto-release working

### Phase 4: Stealthy Attack (3 minutes)

**Start attack:**

```bash
# Terminal 4 (System 4) - As Administrator/sudo
cd BTP-project/simulation_scripts

# Windows (as Admin):
python stealthy_qos_attack.py --target <PI_IP> --duration 300 --sources 6

# Linux/Mac:
sudo python3 stealthy_qos_attack.py --target <PI_IP> --duration 300 --sources 6
```

**What to show:**
- Initial: Looks normal (mixed traffic)
- 60s: Fuzzy rules start detecting
- 120s: BLOCK trigger
- Rules 1, 4, 8 specifically activate

**What to say:**
> "This is the hardest attack to detect - mixed with normal traffic, low rate, designed to degrade quality of service without obvious flooding. Traditional rate-based systems might miss this. But watch... after about a minute, our fuzzy rules start detecting the subtle half-open SYN pattern. Rules 1, 4, and 8 are specifically tuned for this type of stealthy attack. And there - BLOCK. This demonstrates why explainability matters."

**Status:** [ ] Stealthy attack detected

### Phase 5: Recovery & Wrap-Up (2 minutes)

**Stop attacks:**
```bash
# In Terminal 3 and 4: Ctrl+C
```

**What to show:**
- Threat scores dropping
- Auto-release countdown
- Return to 🟢 **CLEAR**
- Only normal traffic remains

**What to say:**
> "Now I'm stopping the attacks. Watch the auto-release timers... there! The system returns to normal operation. The entire detection and mitigation pipeline runs locally on this $50 edge device with no cloud dependency."

---

## 📸 Screenshot Checklist

**Must-have screenshots for report/presentation:**

- [ ] Dashboard in CLEAR state (normal traffic, green banner)
- [ ] Dashboard in ATTACK state (red banner, high score)
- [ ] Explanation panel with fuzzy rules activated (colored bars)
- [ ] Source Threat Board showing multiple blocked IPs
- [ ] Traffic & Threat Timeline chart (blue=traffic, red=score, showing spike)
- [ ] Model Benchmark table at bottom (fuzzy DT highlighted)
- [ ] Mitigation Action Log showing block/release timeline
- [ ] Raspberry Pi tmux windows (detector and dashboard running)

---

## 🛑 Emergency Procedures

### If SSH Freezes

**Cause:** Network saturated by attack

**Action:**
1. Wait 30-60 seconds
2. Try reconnecting: `ssh pi@<PI_IP>`
3. If still fails, explain: "This demonstrates the real impact of DDoS"
4. Use backup: Switch to CSV replay mode demo

**Fallback demo:**
```bash
# On laptop only (no Pi needed)
cd BTP-project/implementation
python live_detector.py --replay-csv data/syn_udp_flood_attack_data_clean.csv --loop
# New terminal:
python monitor_dashboard.py --port 8080
# Browser: http://localhost:8080
```

### If Detector Crashes

**Action:**
```bash
# Reconnect to Pi
tmux attach -t demo
# Switch to detector window: Ctrl+B, 0
# Restart:
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live --bpf "ip and not port 22"
```

### If Dashboard Not Updating

**Action:**
```bash
# Check detector is running
tmux attach -t demo
# Check window 0 has detector active

# Restart dashboard (window 1)
Ctrl+B, 1
Ctrl+C
python3 monitor_dashboard.py --port 8080

# Hard refresh browser: Ctrl+Shift+R
```

### If Simulation Scripts Can't Send Packets

**Fallback:**
- Scripts auto-fallback to socket-based traffic
- Works without admin/sudo
- Less realistic but still demonstrates detection
- Explain: "Falling back to non-spoofed mode"

---

## ✅ Post-Demo

### Data Collection

```bash
# On Pi, collect logs
cd ~/edge/reports
tar -czf demo_logs_$(date +%Y%m%d_%H%M%S).tar.gz *.jsonl *.json

# Transfer to laptop
# On laptop:
scp pi@<PI_IP>:~/edge/reports/demo_logs_*.tar.gz .
```

### Generate Report

```bash
# On laptop
cd BTP-project/implementation
cp <path-to-logs>/monitor_events.jsonl reports/
python evaluate_demo.py

# Produces detection latency and false positive metrics
```

### Cleanup

```bash
# On Pi (optional - reset for next demo)
cd ~/edge/reports
rm -f *.jsonl *.json *.tmp

# Clear firewall if used --live-firewall
sudo iptables -F INPUT
sudo iptables -P INPUT ACCEPT
```

---

## 📊 Demo Metrics to Highlight

### Performance Metrics

| Metric | Value | What to Say |
|--------|-------|-------------|
| Inference time | 1-3 ms | "Under 3 milliseconds per 50-packet window" |
| Model size | 9.1 KB | "89 tree nodes, fits in CPU cache" |
| Accuracy | 87.7% | "Best among all tested models" |
| Edge compute | ~10-30% CPU | "Runs efficiently alongside other services" |

### Detection Metrics

| Attack Type | Expected Detection Time | Status |
|-------------|------------------------|---------|
| Stealth scan | Occasional SUSPICIOUS | Not blocked |
| Moderate flood | ~20-40 seconds | THROTTLE → BLOCK |
| Intense flood | ~5-15 seconds | Immediate BLOCK |
| Stealthy QoS | ~60-90 seconds | BLOCK after pattern detection |

### Explainability

| Fuzzy Rule | When It Fires | Example |
|------------|---------------|---------|
| Rule 1 | SYN/ACK imbalance + half-open | SYN flood |
| Rule 2 | SYN burst rate | Rapid flooding |
| Rule 3 | Source IP dispersion | Spoofed attacks |
| Rule 4 | Retransmissions + half-open | Noisy attacks |
| Rule 5 | Targeted single port | Focused attack |
| Rule 6 | UDP density burst | UDP floods |
| Rule 7 | High byte volume | Bandwidth attacks |
| Rule 8 | Low-and-slow stealth | Sophisticated attacks |

---

## 🎓 Q&A Preparation

**Common questions:**

**Q: What happens if the Pi is the target of the attack?**
> A: The detector prioritizes packet processing and can handle 500+ pps sustained. If overwhelmed, it throttles evaluation frequency but continues monitoring. In production, multiple Pis would provide redundancy.

**Q: How does it compare to cloud-based solutions?**
> A: Edge processing provides <3ms detection latency vs 50-200ms for cloud. Reduces bandwidth costs and continues working during network partitions.

**Q: Can it detect zero-day attacks?**
> A: The fuzzy rules detect patterns (half-open connections, burst rates) not signatures, so it can catch novel attacks exhibiting known patterns. But it's not a silver bullet - sophisticated attackers can still evade.

**Q: Why not use deep learning?**
> A: We tested it! The deep MLP has similar accuracy but 125× larger, slower, and provides no explainability. Our fuzzy tree offers the best balance of performance, size, and interpretability for edge deployment.

**Q: What about false positives?**
> A: Direction gating prevents the victim's own replies (SYN-ACK, RST) from triggering rules. Legitimate high-volume traffic stays green. Our test shows <5% false positive rate on diverse traffic.

---

## 📚 Documentation Quick Links

- **Complete guide:** `working.md`
- **Quick start:** `QUICK_START_DEMO.md`
- **Troubleshooting:** `TROUBLESHOOTING.md`
- **Simulation details:** `simulation_scripts/README.md`
- **Original demo guide:** `implementation/DEMO_GUIDE.md`

---

## ✨ Final Pre-Demo Checklist

**Right before you start:**

### Network
- [ ] All devices connected to same network
- [ ] Pi reachable: `ping <PI_IP>` works from all systems
- [ ] Dashboard accessible: `http://<PI_IP>:8080` loads

### Raspberry Pi
- [ ] Detector running in tmux window 0
- [ ] Dashboard running in tmux window 1
- [ ] Dashboard shows "Live" connection

### Traffic Generators
- [ ] 4 terminal windows ready
- [ ] Scripts tested individually
- [ ] Admin/sudo available for attack scripts
- [ ] Can reach Pi: `ping <PI_IP>` from each system

### Presentation
- [ ] Browser window with dashboard on screen
- [ ] Backup slides ready (in case demo fails)
- [ ] Screenshots taken of clean state
- [ ] Timer/watch visible
- [ ] Notes/talking points ready

### Emergency
- [ ] Physical access to Pi (keyboard+monitor nearby)
- [ ] Backup demo on laptop ready (replay mode)
- [ ] Network cable available (if WiFi fails)
- [ ] iptables backup saved: `sudo iptables-save > backup.rules`

---

## 🎤 Opening Lines

> "Good morning/afternoon. Today I'll demonstrate a live IoT network defense system running on a Raspberry Pi edge device. This isn't a simulation or recorded demo - everything you'll see is happening in real-time. [Point to dashboard] This is the live monitoring dashboard. The threat detector is running on this Raspberry Pi [show Pi], performing fuzzy inference on every 50-packet window. I have 4 systems ready to generate different traffic patterns. Let's begin with normal IoT traffic..."

---

**Good luck with your demonstration! You've got this! 🚀🎓**

**Remember:** Stay calm, narrate what's happening, and turn any issues into teaching moments. The preparation you've done ensures success!
