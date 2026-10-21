# Quick Start Demo Guide - 5 Minutes to Live System

## 🚀 Fastest Path to Running Demo

### Step 1: Prepare Raspberry Pi (One-Time Setup)

```bash
# Flash Raspberry Pi OS with SSH enabled
# Boot Pi, find IP address, then:

ssh pi@<PI_IP>

# Install everything
sudo apt update && sudo apt install -y python3-pip python3-scapy tmux
pip3 install --user numpy pandas scikit-learn joblib psutil scapy

# Create directories
mkdir -p ~/edge/reports
```

### Step 2: Transfer Files from Laptop

```powershell
# On laptop (Windows PowerShell)
cd "C:\Users\Abhishek\Downloads\iot forensics\btp\BTP-project\implementation"

$PI_IP = "192.168.137.X"  # CHANGE THIS

# Train model first (if not already done)
python run_fuzzy_dt.py

# Copy to Pi
scp fuzzy_forest.pkl pi@${PI_IP}:~/edge/
scp live_detector.py fuzzy_inference.py monitor_dashboard.py sysstats.py pi@${PI_IP}:~/edge/
scp reports/model_comparison_report.json pi@${PI_IP}:~/edge/reports/
```

### Step 3: Start Pi Services

```bash
# SSH into Pi
ssh pi@<PI_IP>

# Start tmux
tmux new -s demo

# Window 0: Detector
cd ~/edge
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live --bpf "ip and not port 22"

# Press Ctrl+B, then C (new window)
# Window 1: Dashboard
python3 monitor_dashboard.py --port 8080

# Press Ctrl+B, then D (detach from tmux)
```

### Step 4: Open Dashboard

**In any browser:**
```
http://<PI_IP>:8080
```

Should show 🟢 **Live** and **CALIBRATING** → **CLEAR**

### Step 5: Run Traffic Simulations

**On 4 different systems (or 4 terminals on 1 system):**

```bash
# Terminal 1: Normal light traffic
cd BTP-project/simulation_scripts
python normal_light_traffic.py --target <PI_IP> --duration 600

# Terminal 2: Normal heavy traffic  
python normal_heavy_traffic.py --target <PI_IP> --duration 600

# Terminal 3: Attack with intervals (needs admin/sudo)
sudo python gradual_attack_intervals.py --target <PI_IP> --duration 480 --sources 8

# Terminal 4: Stealthy attack (needs admin/sudo)
sudo python stealthy_qos_attack.py --target <PI_IP> --duration 300 --sources 6
```

---

## 🎯 Quick Command Reference

### On Raspberry Pi

```bash
# Reattach to tmux
tmux attach -t demo

# Switch between windows
Ctrl+B, 0  # Detector
Ctrl+B, 1  # Dashboard

# Stop detector
Ctrl+C

# Check if running
ps aux | grep live_detector

# View events live
tail -f ~/edge/reports/monitor_events.jsonl

# Check firewall (if using --live-firewall)
sudo iptables -L INPUT -n -v
```

### On Laptop (Traffic Generation)

```powershell
# Find Pi IP
ping iot-edge-pi.local
# Or check Windows hotspot devices

# Test connectivity
Test-NetConnection <PI_IP> -Port 8080

# Stop simulation
Ctrl+C in each terminal

# Run individual test
cd BTP-project/simulation_scripts
python normal_light_traffic.py --target <PI_IP> --duration 60
```

---

## 📊 What to Watch on Dashboard

### Normal Traffic (Green Phase)
- 🟢 Banner: **CLEAR**
- Traffic: 20-120 pps
- Score: < 0.3
- Action: **ALLOW**

### Attack Detected (Red Phase)
- 🔴 Banner: **ATTACK**
- Traffic: 200-500 pps
- Score: > 0.48 (threshold)
- Action: **BLOCK**
- Fuzzy rules: Bars light up in Explanation panel

### Key Elements
- **Top KPI cards:** Real-time metrics
- **Traffic timeline:** Blue = pps, Red = threat score
- **Explanation panel:** Shows which fuzzy rules fired
- **Source Threat Board:** List of IPs with Block/Release buttons
- **Action Log:** Mitigation timeline

---

## 🛡️ Safety Quick Reference

### Protected by Default
- Your SSH client IP (auto-detected)
- Loopback (127.0.0.1)
- Additional: `--protect IP1 IP2`

### Blocking Modes
- **Default:** Simulated (logged but not enforced)
- **Real:** Add `--live-firewall` flag (use with caution!)

### Emergency Stop
```bash
# On Pi
tmux attach -t demo
# Ctrl+C in detector window

# Or force kill
sudo killall python3

# Clear firewall
sudo iptables -F INPUT
```

---

## ⚡ Troubleshooting in 30 Seconds

| Problem | Solution |
|---------|----------|
| Dashboard shows "Disconnected" | Restart detector: `sudo python3 live_detector.py --live` |
| Stuck on CALIBRATING | Generate traffic: `ping <PI_IP>` |
| Permission denied (detector) | Must use `sudo` for packet capture |
| Scapy errors (simulators) | Install: `pip install scapy` + Run as admin/sudo |
| SSH freezes during flood | Normal! Network saturated. Reconnect after attack stops |
| Can't send SYN packets | Windows: Install Npcap. Linux: Use `sudo` |

---

## 📸 Screenshot Checklist

Must-have screenshots for report:

1. ✅ Dashboard in CLEAR state (normal traffic)
2. ✅ Dashboard in ATTACK state (red banner)
3. ✅ Explanation panel with fuzzy rules activated
4. ✅ Source Threat Board with blocked IPs
5. ✅ Traffic timeline showing attack spike
6. ✅ Model benchmark table (bottom of dashboard)
7. ✅ Mitigation action log

---

## 🎬 Demo Script (5-Minute Version)

**00:00 - Introduction**
> "This is live IoT threat detection on a Raspberry Pi edge device. The model is running locally, making decisions in real-time."

**00:30 - Normal Traffic**
> "System 1 and 2 are simulating normal IoT devices. Notice the green banner - the system recognizes legitimate traffic patterns."

**01:30 - Start Attack**
> "Now I'm launching System 3 - a sophisticated multi-phase attack. Watch the threat score..."

**02:30 - Detection**
> "There! The score crosses the threshold. Source IP is now BLOCKED. Look at the fuzzy rules - Rules 1, 2, and 4 have activated, detecting the SYN flood pattern."

**03:30 - Explanation**
> "The Explanation panel shows WHY this was detected. This is what makes our system explainable - you can see the reasoning, not just a black box decision."

**04:30 - Recovery**
> "During pauses in the attack, the system automatically releases blocked IPs after the timeout. This prevents permanent blacklisting from single-burst attacks."

**05:00 - Conclusion**
> "The entire detection pipeline - packet capture, feature extraction, fuzzy inference, and mitigation - runs on this $50 edge device in under 3 milliseconds per window."

---

## 🔗 Full Documentation

- **Complete Setup:** `working.md`
- **Simulation Scripts:** `simulation_scripts/README.md`
- **Official Demo Guide:** `implementation/DEMO_GUIDE.md`
- **Project Overview:** `README.md`

---

## 💾 Transfer Files Command Block (Copy-Paste)

```powershell
# Copy this entire block and run in PowerShell
$PI_IP = "192.168.137.X"  # ← CHANGE THIS LINE

cd "C:\Users\Abhishek\Downloads\iot forensics\btp\BTP-project\implementation"

# Train if needed
# python run_fuzzy_dt.py

# Transfer
scp fuzzy_forest.pkl pi@${PI_IP}:~/edge/
scp live_detector.py pi@${PI_IP}:~/edge/
scp fuzzy_inference.py pi@${PI_IP}:~/edge/
scp monitor_dashboard.py pi@${PI_IP}:~/edge/
scp sysstats.py pi@${PI_IP}:~/edge/
scp reports/model_comparison_report.json pi@${PI_IP}:~/edge/reports/

echo "Transfer complete!"
```

---

## 🎓 Remember

**The goal:** Demonstrate intelligent, explainable IoT threat detection at the edge.

**Key points to emphasize:**
- ✅ Real-time inference on constrained hardware
- ✅ Explainable decisions (fuzzy rules)
- ✅ Direction-aware detection (no false positives on responses)
- ✅ Automatic mitigation and recovery
- ✅ Edge computing reduces latency and central load

**Good luck! 🚀**
