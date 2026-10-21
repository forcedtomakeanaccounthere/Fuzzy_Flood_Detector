# Live Demonstration Setup Guide - Raspberry Pi Edge Computing IoT Defense

## 📋 Document Summary

**This comprehensive guide provides everything needed for a complete live demonstration of explainable SYN/UDP flood detection on Raspberry Pi edge devices.**

### What You'll Learn

✅ **Complete Raspberry Pi setup** from SD card to running detector  
✅ **Model deployment** - transfer trained fuzzy forest to edge device  
✅ **Network configuration** - 3 options (hotspot, WiFi, Ethernet)  
✅ **4 specialized traffic simulation scripts** for multi-system demo  
✅ **Live dashboard monitoring** with real-time threat visualization  
✅ **Firewall control** - both simulated and real blocking modes  
✅ **Emergency procedures** for when things go wrong  
✅ **Troubleshooting guide** for common issues  

### Available Traffic Simulators

| Script | Type | Purpose | Dashboard |
|--------|------|---------|-----------|
| `normal_light_traffic.py` | Benign | Baseline IoT (sensors, telemetry) | 🟢 CLEAR |
| `normal_heavy_traffic.py` | Benign | High legitimate load testing | 🟢 CLEAR |
| `gradual_attack_intervals.py` | Attack | Multi-phase with pauses | 🟡→🔴 ATTACK |
| `stealthy_qos_attack.py` | Attack | Low-level QoS degradation | 🟢→🟡→🔴 |

### Quick Navigation

- **Fastest setup:** See `QUICK_START_DEMO.md` (5-minute version)
- **Detailed walkthrough:** Continue reading below
- **Simulation guide:** See `simulation_scripts/README.md`
- **Problems?** See `TROUBLESHOOTING.md`
- **Original demo:** See `implementation/DEMO_GUIDE.md`

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Prerequisites](#prerequisites)
4. [Raspberry Pi Setup](#raspberry-pi-setup)
5. [Network Configuration](#network-configuration)
6. [Model Deployment](#model-deployment)
7. [Running the Live Demo](#running-the-live-demo)
8. [Traffic Simulation Scripts](#traffic-simulation-scripts)
9. [Dashboard Monitoring](#dashboard-monitoring)
10. [Firewall Control](#firewall-control)
11. [Emergency Stop Procedures](#emergency-stop-procedures)
12. [Troubleshooting](#troubleshooting)

---

## Overview

This guide provides complete step-by-step instructions for deploying and demonstrating the **Explainable SYN/UDP Flood Detection** system on a Raspberry Pi edge device with live traffic simulation from 4 different systems.

**What runs where:**
- **Raspberry Pi (Edge Device)**: Live detector, fuzzy forest model inference, dashboard server
- **System 1-4 (Attacker/Traffic Generators)**: Traffic simulation scripts sending various patterns

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         DEMONSTRATION SETUP                           │
└──────────────────────────────────────────────────────────────────────┘

    SYSTEM 1 (Laptop)              SYSTEM 2 (Laptop/Phone)
    ┌─────────────────┐            ┌─────────────────┐
    │ Normal Traffic  │            │ Normal Traffic  │
    │ (Light Load)    │────┐   ┌───│ (Heavy Load)    │
    │                 │    │   │   │                 │
    └─────────────────┘    │   │   └─────────────────┘
                           ↓   ↓
                      ┌────────────────┐
    SYSTEM 3           │  RASPBERRY PI  │          SYSTEM 4
    ┌─────────────┐    │  (Edge Device) │      ┌─────────────┐
    │ Attack      │───→│                │←─────│ Stealthy    │
    │ (Intervals) │    │ • Detector     │      │ QoS Attack  │
    └─────────────┘    │ • Fuzzy Model  │      └─────────────┘
                       │ • Dashboard    │
                       │ • Mitigation   │
                       └────────────────┘
                              │
                              ↓
                    ┌──────────────────┐
                    │ Browser Dashboard │
                    │ (Any Device)      │
                    │ http://PI_IP:8080 │
                    └──────────────────┘
```

---

## Prerequisites

### Hardware Required
- **1× Raspberry Pi 4/5** (4GB+ RAM recommended) with power supply
- **1-4× Systems** for traffic generation (laptops, phones with Termux, other Pis)
- **Network:** WiFi router or Windows Mobile Hotspot
- **microSD card** (32GB+) for Raspberry Pi OS

### Software Prerequisites

#### On Development Laptop (Windows):
```powershell
# Git, Python 3.8+, SSH client
# Already have: your trained model artifacts
```

#### On Raspberry Pi:
- Raspberry Pi OS (Debian-based)
- Python 3.7+
- Network connectivity
- SSH enabled

#### On Traffic Generator Systems:
- Python 3.7+
- Optional: Scapy (for advanced attacks)
- Optional: Admin/root privileges (for raw packet crafting)

---

## Raspberry Pi Setup

### Step 1: Flash Raspberry Pi OS

1. **Download Raspberry Pi Imager**: https://www.raspberrypi.com/software/
2. **Flash SD Card:**
   - OS: **Raspberry Pi OS Lite (64-bit)** or Desktop version
   - Click ⚙️ (Settings):
     - ✅ Enable SSH (password authentication)
     - Set hostname: `iot-edge-pi`
     - Username: `pi`, Password: `raspberry` (or your choice)
     - Configure WiFi: Enter your network SSID and password
     - Set timezone
   - Write to SD card

3. **Boot the Pi:**
   - Insert SD card
   - Connect power
   - Wait ~1 minute for boot

4. **Find Pi IP Address:**
   - Check your router's DHCP client list
   - Or use: `ping iot-edge-pi.local`
   - Or if using Windows Mobile Hotspot: typically `192.168.137.x`

### Step 2: Initial Configuration via SSH

```powershell
# From Windows PowerShell on laptop
ssh pi@<PI_IP>
# Enter password when prompted
```

Once logged in to the Pi:

```bash
# Update system
sudo apt update
sudo apt upgrade -y

# Install required packages
sudo apt install -y python3-pip python3-venv git tmux htop

# Install Python dependencies
pip3 install --user numpy pandas scikit-learn joblib psutil

# Install scapy for live packet capture (requires sudo)
sudo apt install -y python3-scapy tcpdump
pip3 install --user scapy

# Verify installations
python3 -c "import numpy, pandas, sklearn, joblib, psutil; print('All imports OK')"
python3 -c "import scapy.all; print('Scapy OK')"
```

### Step 3: Create Project Directory Structure

```bash
# On the Pi
mkdir -p ~/edge/reports
mkdir -p ~/edge/data
cd ~/edge

# Verify structure
ls -la
```

### Step 4: Configure Firewall (Optional - For Real Blocking)

⚠️ **WARNING**: Only proceed if you want REAL iptables blocking during demo.

```bash
# Check if iptables is available
sudo iptables -L -n

# Backup current rules
sudo iptables-save > ~/iptables_backup.rules

# Note: The detector protects SSH connections automatically
# But as a safety measure, explicitly whitelist your laptop:
LAPTOP_IP="192.168.137.1"  # Adjust based on your network
sudo iptables -I INPUT -s $LAPTOP_IP -j ACCEPT
sudo iptables -I OUTPUT -d $LAPTOP_IP -j ACCEPT

# Test SSH still works
# If locked out, physically reboot the Pi to restore
```

---

## Network Configuration

### Option A: Windows Mobile Hotspot (Recommended for Demos)

**Advantages:** Isolated network, full control, easy to set up

**Setup on Windows Laptop:**
1. Open **Settings** → **Network & Internet** → **Mobile hotspot**
2. Click **Edit** and set:
   - Network name: `IoT-Demo-Lab`
   - Password: (your choice)
3. Toggle **Mobile hotspot** to **On**
4. Your laptop gets IP: `192.168.137.1`

**Connect Raspberry Pi:**
- Pi will connect via WiFi (if configured during imaging)
- Or manually: `sudo raspi-config` → System Options → Wireless LAN
- Pi typically gets: `192.168.137.X` (check Settings → Mobile hotspot → Connected devices)

**Connect Other Systems:**
- Connect laptops/phones to the same hotspot
- They'll get IPs like `192.168.137.X`

**Verify connectivity:**
```powershell
# From laptop
ping 192.168.137.X  # Replace with Pi IP
ssh pi@192.168.137.X
```

### Option B: Home/Office WiFi Router

**Connect all devices to the same WiFi network.**

Find Pi IP:
```bash
# On the Pi
hostname -I
# Or
ip addr show wlan0 | grep inet
```

Test from laptop:
```powershell
ping <PI_IP>
ssh pi@<PI_IP>
```

### Option C: Direct Ethernet + ICS (Internet Connection Sharing)

1. Connect Pi to laptop via Ethernet cable
2. On Windows laptop:
   - Settings → Network & Internet → Ethernet
   - Properties → Sharing
   - ✅ Allow other network users to connect
3. Pi gets IP like `192.168.137.X`

**Verify network connectivity from all systems:**
```bash
# Can each system ping the Pi?
ping <PI_IP>
```

---

## Model Deployment

### Step 1: Train Models on Development Laptop

```powershell
# On your Windows laptop (in project directory)
cd C:\Users\Abhishek\Downloads\iot forensics\btp\BTP-project\implementation

# Activate virtual environment (if using)
..\..venv\Scripts\Activate.ps1

# Train all models
python shared_preprocessing.py       # Build features
python run_normal_dt.py              # Baseline Decision Tree
python run_fuzzy_dt.py               # Fuzzy Decision Tree ← DEPLOYED MODEL
python run_deep_learning.py          # Deep Learning baseline
python compare_models.py             # Generate benchmark report

# Verify artifact was created
ls fuzzy_forest.pkl
# Size should be ~2-3 MB
```

### Step 2: Transfer Files to Raspberry Pi

```powershell
# Still on laptop, from implementation directory
$PI_IP = "192.168.137.X"  # Replace with actual Pi IP

# Transfer model artifact
scp fuzzy_forest.pkl pi@${PI_IP}:~/edge/

# Transfer Python scripts
scp live_detector.py pi@${PI_IP}:~/edge/
scp fuzzy_inference.py pi@${PI_IP}:~/edge/
scp monitor_dashboard.py pi@${PI_IP}:~/edge/
scp sysstats.py pi@${PI_IP}:~/edge/
scp evaluate_demo.py pi@${PI_IP}:~/edge/

# Transfer simulation scripts (for testing from Pi if needed)
scp traffic_simulator.py pi@${PI_IP}:~/edge/

# Transfer comparison report for dashboard
scp reports/model_comparison_report.json pi@${PI_IP}:~/edge/reports/

# Optional: Transfer sample dataset for replay testing
scp data/syn_udp_flood_attack_data_clean.csv pi@${PI_IP}:~/edge/data/test_data.csv
```

### Step 3: Verify Files on Pi

```bash
# SSH into Pi
ssh pi@<PI_IP>

cd ~/edge
ls -lh

# Should see:
# fuzzy_forest.pkl (~2-3 MB)
# live_detector.py
# fuzzy_inference.py
# monitor_dashboard.py
# sysstats.py
# reports/model_comparison_report.json
```

### Step 4: Test Model Loading (Sanity Check)

```bash
# On the Pi
cd ~/edge

# Test model artifact loads correctly
python3 -c "
import joblib
artifact = joblib.load('fuzzy_forest.pkl')
print(f'Model loaded: {artifact[\"model_kind\"]}')
print(f'Features: {len(artifact[\"feature_order\"])}')
print(f'Threshold: {artifact[\"threshold\"]:.3f}')
print(f'Window size: {artifact.get(\"window\", 50)}')
"

# Expected output:
# Model loaded: fuzzy_dt_single
# Features: 22
# Threshold: 0.48X
# Window size: 50
```

---

## Running the Live Demo

### Step 1: Start Detector on Raspberry Pi

**Use tmux to keep sessions alive even if SSH disconnects:**

```bash
# SSH into Pi
ssh pi@<PI_IP>

# Install tmux if not already installed
sudo apt install -y tmux

# Start tmux session
tmux new -s demo

# Navigate to project directory
cd ~/edge

# Start the live detector with sudo (required for packet capture)
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py \
  --live \
  --bpf "ip and not port 22" \
  --block-ttl 120 \
  --throttle-ttl 30 \
  --log reports/monitor_events.jsonl \
  --state reports/detector_state.json \
  --control reports/control_commands.json

# Expected output:
# Edge detector | artifact: fuzzy_forest.pkl
# Sniffing on default interface (BPF: 'ip and not port 22'). Ctrl+C to stop.
```

**Detector Command Flags Explained:**
- `--live`: Live packet capture mode (vs replay)
- `--bpf "ip and not port 22"`: Filter out SSH traffic (keeps dashboard clean)
- `--block-ttl 120`: Blocked IPs auto-release after 120 seconds
- `--throttle-ttl 30`: Throttled IPs auto-release after 30 seconds
- `--log`: Event stream file (append-only)
- `--state`: State snapshot file (rewritten every second for dashboard)
- `--control`: Command file for dashboard Block/Release buttons

**Optional flags:**
- `--live-firewall`: Enable REAL iptables blocking (see [Firewall Control](#firewall-control))
- `--protect 192.168.137.1`: Never block specific IPs (your laptop)
- `--iface wlan0`: Specify network interface

**Detach from tmux session:** Press `Ctrl+B`, then `D`

**Reattach later:** `tmux attach -t demo`

### Step 2: Start Dashboard (Second tmux Window)

```bash
# While in tmux session, create new window
# Press Ctrl+B, then C (creates new window)

# Or attach to existing session and create window:
tmux attach -t demo
# Ctrl+B, C

cd ~/edge

# Start dashboard server
python3 monitor_dashboard.py --port 8080

# Expected output:
# Serving on 0.0.0.0:8080
# Dashboard accessible at http://<PI_IP>:8080
```

**Switch between tmux windows:**
- `Ctrl+B` then `N` (next window)
- `Ctrl+B` then `P` (previous window)
- `Ctrl+B` then `0` or `1` (window number)

**Detach from tmux:** `Ctrl+B`, `D`

### Step 3: Open Dashboard in Browser

**On any device (laptop, phone, tablet):**

1. Open web browser
2. Navigate to: `http://<PI_IP>:8080`
3. You should see the **Fuzzy Edge Monitor** dashboard

**Initial state:**
- Banner: **CALIBRATING** (waiting for first 20 packets)
- Connection pill: 🟢 **Live**
- All KPI cards: zero or waiting
- Threat score: — (waiting)

**After ~20 packets arrive:**
- Banner changes to: 🟢 **CLEAR** (if traffic is normal)
- Traffic rate starts showing
- Source table populates

### Step 4: Verify System is Ready

**Checklist:**
- ✅ Detector running on Pi (check tmux window 0)
- ✅ Dashboard running on Pi (check tmux window 1)
- ✅ Browser shows dashboard with "Live" connection
- ✅ Network connectivity from traffic generator systems to Pi

**Quick test - generate some traffic from laptop:**

```powershell
# From laptop PowerShell
$PI_IP = "192.168.137.X"

# Simple connectivity test
Test-NetConnection $PI_IP -Port 8080

# If successful, the dashboard should update immediately
```

---

## Traffic Simulation Scripts

You now have **4 specialized traffic simulation scripts** in `simulation_scripts/`:

### 1. Normal Traffic - Light Load (`normal_light_traffic.py`)

**Purpose:** Baseline benign IoT traffic with mild congestion

**Characteristics:**
- 3-8 simulated IoT devices
- Periodic telemetry (sensors, cameras, controllers)
- Occasional congestion bursts (70-120 pps)
- 100% legitimate traffic
- Dashboard should stay **GREEN**

**Run on System 1:**

```bash
# Navigate to simulation scripts
cd BTP-project/simulation_scripts

# Run simulation
python normal_light_traffic.py --target <PI_IP> --duration 300 --devices 5

# Flags:
#   --target: Raspberry Pi IP
#   --duration: Seconds to run (300 = 5 minutes)
#   --devices: Number of IoT devices (3-8)
#   --no-congestion: Disable congestion bursts
```

**Expected Dashboard Behavior:**
- 🟢 **CLEAR** banner
- Traffic rate: 20-50 pps (baseline) with spikes to 80-120 pps
- Threat score: < 0.3
- Verdict: **SAFE**
- No blocks/throttles

---

### 2. Normal Traffic - Heavy Load (`normal_heavy_traffic.py`)

**Purpose:** High-volume legitimate traffic to test false positive resistance

**Characteristics:**
- 10-15 high-activity devices
- Frequent congestion waves (200-400 pps)
- Complete TCP handshakes (no attack patterns)
- Tests model's ability to distinguish load from attack
- Should **stay GREEN** despite high rate

**Run on System 2:**

```bash
cd BTP-project/simulation_scripts

python normal_heavy_traffic.py --target <PI_IP> --duration 300 --devices 12

# Flags:
#   --devices: 8-15 recommended
#   --no-congestion: Disable congestion waves
```

**Expected Dashboard Behavior:**
- 🟢 **CLEAR** or brief 🟡 **ELEVATED**
- Traffic rate: 100-400 pps during bursts
- Threat score: < threshold (model should recognize legitimate handshakes)
- Occasional **SUSPICIOUS** packets but NO sustained block
- Fuzzy rules should remain quiet (direction gating prevents false triggers)

---

### 3. Gradual Attack with Intervals (`gradual_attack_intervals.py`)

**Purpose:** Sophisticated attacker gradually escalating with pauses

**Characteristics:**
- 8-phase timeline:
  1. Stealth reconnaissance (low-and-slow)
  2. **PAUSE** - recovery observation
  3. Moderate SYN flood
  4. **PAUSE** - auto-release verification
  5. High-intensity burst
  6. **PAUSE** - cool-down
  7. UDP flood variant
  8. Final recovery
- Tests detection across escalation
- Tests auto-release during pauses

**Run on System 3:**

```bash
cd BTP-project/simulation_scripts

# Requires scapy + admin/sudo for best results
sudo python gradual_attack_intervals.py --target <PI_IP> --duration 300 --sources 8

# On Windows (as Administrator):
python gradual_attack_intervals.py --target <PI_IP> --duration 300 --sources 8

# Flags:
#   --sources: Number of spoofed IPs (requires scapy + admin)
#   --port: Target port (default 80)
```

**Expected Dashboard Behavior:**

| Phase | Banner | Action |
|-------|--------|--------|
| Stealth scan | 🟢 CLEAR → 🟡 ELEVATED | Occasional SUSPICIOUS |
| Pause 1 | 🟡 ELEVATED → 🟢 CLEAR | Scores drop |
| Moderate flood | 🟡 ELEVATED → 🔴 ATTACK | THROTTLE → BLOCK |
| Pause 2 | 🔴 ATTACK | Source auto-released after 120s |
| Intense burst | 🔴 ATTACK | Immediate BLOCK |
| Pause 3 | 🔴 ATTACK → 🟢 CLEAR | Release + recovery |
| UDP flood | 🔴 ATTACK | Rules 6/7 activate |
| Final pause | 🟢 CLEAR | Clean slate |

**Demo Talking Points:**
- "Notice the threat score gradually increasing"
- "During pauses, the model automatically releases blocked IPs"
- "Different attack types trigger different fuzzy rules"

---

### 4. Stealthy QoS Attack (`stealthy_qos_attack.py`)

**Purpose:** Low-level flood mixed with normal traffic (subtle attack)

**Characteristics:**
- Combines normal background traffic with low-rate attack
- Attack rate: 40-120 pps (below typical flood thresholds)
- Half-open SYN connections (resource exhaustion)
- Gradually increases attack intensity
- Tests fuzzy rule sensitivity

**Run on System 4:**

```bash
cd BTP-project/simulation_scripts

sudo python stealthy_qos_attack.py --target <PI_IP> --duration 300 --sources 6

# Flags:
#   --sources: Spoofed IPs (requires scapy + admin)
#   --normal-intensity: Background traffic level (0.1-1.0)
#   --port: Attack port (default 80)
#   --open-port: Normal traffic port (default 8080)
```

**Expected Dashboard Behavior:**
- Starts: 🟢 **CLEAR** (mixed traffic looks normal initially)
- After ~60s: 🟡 **ELEVATED** (fuzzy rules detect half-open pattern)
- After ~120s: 🔴 **ATTACK** → **BLOCK** (sustained suspicion threshold exceeded)
- Fuzzy rules activated: 1, 4, 8 (SYN/ACK imbalance, half-open, stealth)

**Demo Talking Points:**
- "This attack is designed to fly under the radar"
- "Traditional rate-based detection might miss this"
- "Our fuzzy rules detect the *pattern* not just the volume"

---

## Dashboard Monitoring

### Understanding Dashboard Data Flow

The dashboard is a **web server** that displays real-time data by reading JSON files. There are two deployment modes:

**Mode 1: Dashboard on Raspberry Pi (Recommended)**

```
┌─────────────────┐
│  Raspberry Pi   │
│                 │
│  live_detector  │ ──writes──→ reports/detector_state.json
│       ↓         │             reports/monitor_events.jsonl
│  dashboard.py   │ ──reads───→ (same files)
│  :8080          │
└────────┬────────┘
         │ HTTP
         ↓
┌─────────────────┐
│ Laptop Browser  │
│ http://PI:8080  │ ──fetches HTML + polls /state endpoint every 1s
└─────────────────┘
```

**How to run:**
```bash
# On Pi
python3 monitor_dashboard.py --port 8080

# Access from laptop browser: http://<PI_IP>:8080
```

**Mode 2: Dashboard on Laptop (Remote Fetch)**

```
┌─────────────────┐
│  Raspberry Pi   │
│                 │
│  live_detector  │ ──writes──→ reports/detector_state.json
│                 │             reports/monitor_events.jsonl
└────────┬────────┘
         │ SCP fetch every 1s
         ↓
┌─────────────────┐
│  Laptop         │
│                 │
│  dashboard_     │ ──fetches via SCP──→ local cache
│  remote.py      │ ──reads──→ cached files
│  :8080          │
└────────┬────────┘
         │ HTTP
         ↓
┌─────────────────┐
│ Laptop Browser  │
│ http://localhost│
│        :8080    │
└─────────────────┘
```

**How to run:**
```powershell
# On laptop (requires passwordless SSH setup)
python monitor_dashboard_remote.py --remote pi@<PI_IP>:~/edge/reports --port 8080

# Access: http://localhost:8080
```

**Which to use for demo?**
- **Mode 1 (Pi):** Faster, no network overhead, simpler setup ✅ Recommended
- **Mode 2 (Laptop):** Useful if presenting from laptop screen, requires SSH keys

### Important: No Dummy Data

The dashboard **does not generate dummy data**. If you see data before starting the detector:

**Problem:** Old report files exist from previous runs

**Solution:**
```bash
# On Pi or laptop (in implementation directory)
cd reports
mkdir backup_old
mv detector_state.json monitor_events.jsonl backup_old/

# Or on Windows:
# implementation\reports> mkdir backup_old
# implementation\reports> move *.json* backup_old\
```

**After cleanup:** Dashboard will show:
- Connection: 🔴 **Disconnected**
- Banner: **WAITING FOR DETECTOR**
- All KPIs: `–` or `0`
- Tables: "No packets yet"

This is **correct** until you start `live_detector.py`!

## Dashboard Monitoring

### Understanding the Dashboard

**Header:**
- **Connection Status:** 🟢 Live / 🔴 Disconnected
- **Threat Banner:** CLEAR / ELEVATED / ATTACK
- **Pause Button:** Freeze display (data still collected)

**KPI Cards (Top Row):**

| Card | Meaning | Color Coding |
|------|---------|--------------|
| **Traffic Rate** | Packets per second | Blue (informational) |
| **Threat Score** | Current window score vs threshold | 🟢 < 50% / 🟡 50-100% / 🔴 ≥ threshold |
| **Model / Fuzzy** | Model probability & fuzzy confidence | Blue |
| **Edge Action** | ALLOW / THROTTLE / BLOCK | 🟢 ALLOW / 🟡 THROTTLE / 🔴 BLOCK |
| **Mitigations** | Blocked / Throttled IP count | Red |
| **Pi Compute** | CPU % + inference time | 🟢 < 60% / 🟡 60-85% / 🔴 > 85% |

**Live Analysis Section:**

1. **Traffic & Threat Timeline**
   - Blue line: Packets per second
   - Red line: Attack score
   - Gray dashed: Threshold
   - Red shading: Attack periods

2. **Live Decision Explanation**
   - Shows current verdict (SAFE / SUSPICIOUS / ATTACK)
   - Top 6 fuzzy rule activations with bars
   - Model probability vs fuzzy confidence

**Traffic & Sources Section:**

3. **Live Packet Stream**
   - Recent packets with source → destination
   - Verdict column color-coded
   - Confidence bar

4. **Source Threat Board**
   - All seen source IPs
   - Max threat score per IP
   - Status: ALLOWED / THROTTLED / BLOCKED
   - Release countdown
   - **Action buttons:** Block / Release

**Response Log:**
- Mitigation timeline
- Block/throttle actions with timestamps

**Model Benchmark:**
- Comparison table from `model_comparison_report.json`
- Deployed model highlighted in blue

---

## Firewall Control

### Simulated Blocking (Default - Safe for Demos)

By **default**, the detector runs in **simulated mode**:
- Logs show `[SIMULATED] Block <IP>` messages
- NO actual iptables rules installed
- Safe for testing, no risk of accidental lockout
- Demonstrates decision-making logic

### Real Blocking (--live-firewall flag)

⚠️ **DANGER ZONE - Use with extreme caution**

**When to use:**
- Final demo with controlled traffic
- Want to show *actual* packet dropping
- Have physical Pi access (in case of lockout)

**Safety mechanisms built-in:**
1. **SSH protection:** Your SSH client IP is auto-detected and protected
2. **Loopback protection:** 127.0.0.1, ::1 never blocked
3. **Manual protection:** `--protect IP1 IP2` flag
4. **Auto-release:** Blocks expire after `--block-ttl` seconds

**Enable real firewall blocking:**

```bash
# On the Pi (in tmux)
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py \
  --live \
  --live-firewall \
  --bpf "ip and not port 22" \
  --protect 192.168.137.1 \
  --block-ttl 120
```

**What happens when IP is blocked:**
1. Detector logs: `[FIREWALL] DROP rule installed for <IP>`
2. Command executed: `sudo iptables -I INPUT -s <IP> -j DROP`
3. All packets from that IP are dropped at kernel level
4. After 120s (or manual release): `sudo iptables -D INPUT -s <IP> -j DROP`

**Manual Firewall Check:**

```bash
# On the Pi - check active rules
sudo iptables -L INPUT -n -v

# Look for lines like:
# 0     0 DROP       all  --  *      *       10.X.X.X         0.0.0.0/0
```

**Emergency Restore:**

```bash
# If something goes wrong
sudo iptables -F INPUT  # Flush all INPUT rules
sudo iptables -P INPUT ACCEPT  # Set default policy to ACCEPT

# Or restore backup
sudo iptables-restore < ~/iptables_backup.rules
```

---

## Emergency Stop Procedures

### Stop Traffic Simulator (From Traffic Generator System)

```bash
# Press Ctrl+C in the terminal running the simulator
# Script will stop gracefully
```

### Stop Detector on Pi

```bash
# Reattach to tmux
tmux attach -t demo

# Switch to detector window (usually window 0)
# Ctrl+B, 0

# Press Ctrl+C

# Expected output:
# Stopped: XXXX packets, XXXX windows evaluated.
```

### Stop Dashboard

```bash
# Switch to dashboard window
# Ctrl+B, 1

# Press Ctrl+C
```

### Emergency: Detector Not Responding

```bash
# Find and kill process
ps aux | grep live_detector
sudo kill -9 <PID>

# Or nuclear option
sudo killall python3

# Then restart fresh
```

### Emergency: Locked Out by Firewall

**If you accidentally blocked your own IP and can't SSH:**

1. **Physical access to Pi:**
   - Connect monitor + keyboard
   - Login directly
   - Run: `sudo iptables -F INPUT`

2. **Power cycle Pi:**
   - Unplug power
   - Wait 10 seconds
   - Reconnect power
   - iptables rules are NOT persistent across reboots (unless explicitly saved)

3. **Prevention:**
   - Always use `--bpf "not port 22"` to exclude SSH
   - Always use `--protect <YOUR_IP>`
   - Test with `--replay-csv` first before live mode

---

## Running Complete Multi-System Demo

### Scenario: 4-System Live Demonstration

**Preparation:**
1. All 4 systems connected to same network
2. Raspberry Pi running detector + dashboard
3. Browser open showing dashboard
4. 4 terminal windows ready (one per system)

**Demo Timeline (20 minutes):**

```
Time    System      Action                              Expected Outcome
─────────────────────────────────────────────────────────────────────────
0:00    ALL        Start recording/presenting           Dashboard shows CALIBRATING
        Pi         Detector + Dashboard running         

0:30    System1    normal_light_traffic.py              🟢 CLEAR
                   duration=300, devices=5              20-50 pps baseline

2:00    System2    normal_heavy_traffic.py              🟢 CLEAR (or brief ELEVATED)
                   duration=300, devices=12             Spikes to 200-400 pps
                                                        Stays green despite volume

5:00    System3    gradual_attack_intervals.py          🟡 ELEVATED during stealth
                   duration=480, sources=8              🔴 ATTACK on moderate flood
                   (8 phases)                           Auto-release during pauses
                                                        Rules 1,2,4,5 activate

10:00   System4    stealthy_qos_attack.py               Starts 🟢 CLEAR
                   duration=300, sources=6              → 🟡 ELEVATED (60s)
                                                        → 🔴 ATTACK → BLOCK (120s)
                                                        Rules 1,4,8 activate

15:00   System3    Ctrl+C (stop attack)                 🔴 ATTACK persists
                                                        Auto-release after 120s

16:00   ALL        Only System1 and System2 running     🟢 CLEAR
                                                        Normal traffic only
                                                        Demonstrates recovery

20:00   ALL        Ctrl+C (stop all simulators)         Dashboard shows clean state
                                                        Ready for Q&A
```

### Demo Talking Points

**For each system:**

**System 1 (Normal Light):**
- "This represents typical IoT device behavior"
- "Sensors uploading telemetry every 30-60 seconds"
- "Notice the dashboard stays green even during mini-congestion bursts"

**System 2 (Normal Heavy):**
- "Now we add significant legitimate load"
- "This could be multiple cameras streaming, or software updates"
- "200-400 packets per second, but all complete valid handshakes"
- "The model distinguishes volume from attack patterns"

**System 3 (Gradual Attack):**
- "This simulates a sophisticated attacker"
- "Starts with stealth reconnaissance - flying under radar"
- "Gradually escalates to moderate then intense flooding"
- "Notice the pauses - attacker trying to evade detection"
- "Watch how the model detects and auto-releases appropriately"

**System 4 (Stealthy QoS):**
- "This is the hardest attack to detect"
- "Mixed with normal traffic, low rate, but very harmful"
- "Traditional systems might miss this"
- "Our fuzzy rules detect the subtle half-open pattern"
- "Rules 1, 4, and 8 are specifically designed for this"

**Fuzzy Rule Explanations (when they activate):**
- Rule 1: "SYN/ACK imbalance + half-open connections"
- Rule 2: "SYN burst rate - very short inter-arrival times"
- Rule 3: "Source IP dispersion - spoofed fanout pattern"
- Rule 4: "Retransmissions + half-open surge"
- Rule 5: "Targeted port under burst"
- Rule 6: "UDP density burst"
- Rule 7: "High byte-volume flood"
- Rule 8: "Low-and-slow stealth pattern"

---

## Troubleshooting

### Problem: Dashboard shows "Disconnected"

**Causes:**
- Detector not running
- Detector crashed
- File path mismatch

**Solutions:**
```bash
# Check if detector is running
ps aux | grep live_detector

# Check detector logs
tmux attach -t demo
# Switch to detector window, check for errors

# Restart detector
# (in tmux window)
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live
```

### Problem: Dashboard stuck on "CALIBRATING"

**Cause:** Detector hasn't seen enough packets (needs 20)

**Solutions:**
- Generate traffic: `ping <PI_IP>` from laptop
- Check BPF filter isn't too restrictive
- Verify network connectivity

### Problem: No Scapy / Import Errors on Pi

```bash
# Reinstall scapy
pip3 uninstall scapy
pip3 install --user scapy

# Or use system package
sudo apt install python3-scapy
```

### Problem: "Permission denied" for packet capture

**Cause:** Live capture needs root for raw sockets

**Solution:**
```bash
# Must use sudo
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live

# The env PATH=$PATH:~/.local/bin part preserves pip-installed packages
```

### Problem: Simulation scripts can't send SYN packets

**On Windows:**
- Install Npcap: https://npcap.com/#download
- During install: ✅ "WinPcap API-compatible mode"
- Run PowerShell **as Administrator**
- `pip install scapy`

**On Linux/Pi:**
- `sudo python3 script.py` (needs root for raw sockets)

**Fallback:**
- Scripts automatically fallback to connect-based simulation
- Less realistic but still demonstrates detection

### Problem: Pi CPU at 100%

**Causes:**
- High packet rate during flood
- Scapy sniffing overhead

**Solutions:**
- This is normal during intense floods
- Lower simulator `--rate` parameter
- Increase detector `--tick` to 0.3 (less frequent evaluation)
- Use `htop` to monitor: `htop` (Press F10 to quit)

### Problem: SSH freezes during demo

**Cause:** Network saturation from high-rate flood

**Solutions:**
- Use lower attack rates: `--rate 200` instead of 500
- This demonstrates the *real* impact of DDoS
- Use tmux so detector keeps running even if SSH drops
- Reconnect after attack phase ends

### Problem: Dashboard not showing packets

**Check detector logs:**
```bash
# On Pi
tail -f ~/edge/reports/monitor_events.jsonl
# Should show lines like {"type":"packet",...}
```

**Check state file:**
```bash
cat ~/edge/reports/detector_state.json
# Should update every second
```

### Problem: Model file not found

```bash
# On Pi
cd ~/edge
ls -lh fuzzy_forest.pkl

# If missing, retransfer from laptop
# On laptop:
scp fuzzy_forest.pkl pi@<PI_IP>:~/edge/
```

### Problem: Wrong Python version

```bash
# Check version
python3 --version
# Should be 3.7+

# If old, update system
sudo apt update && sudo apt upgrade
```

---

## Performance Benchmarks

**Expected Performance on Raspberry Pi 4 (4GB):**

| Metric | Value | Notes |
|--------|-------|-------|
| Inference time | 1-3 ms | Per 50-packet window |
| Packet processing | 500+ pps | Sustained |
| CPU usage | 40-70% | During flood |
| RAM usage | ~150 MB | Detector process |
| Dashboard response | < 1s | State updates |

**Baseline (no attack):**
- CPU: 5-15%
- PPS: 10-50
- Inference: 0.8-1.2 ms

**During intense flood:**
- CPU: 60-90% (scapy overhead)
- PPS: 300-500
- Inference: 1.5-3 ms (still real-time!)

---

## Post-Demo Evaluation

### Collect Logs

```bash
# On Pi
cd ~/edge/reports

# Package all logs
tar -czf demo_logs_$(date +%Y%m%d_%H%M%S).tar.gz \
  monitor_events.jsonl \
  detector_state.json \
  model_comparison_report.json

# Transfer to laptop
# On laptop:
scp pi@<PI_IP>:~/edge/reports/demo_logs_*.tar.gz .
```

### Generate Demo Report

```bash
# On laptop (after collecting logs)
cd BTP-project/implementation

# Copy logs
cp <path-to-logs>/monitor_events.jsonl reports/

# Run evaluation
python evaluate_demo.py

# Produces:
# - Per-phase detection latency
# - False positive counts
# - Precision/recall for demo run
```

### Screenshots for Report

**Recommended dashboard screenshots:**
1. CLEAR state (normal traffic)
2. ELEVATED state (suspicious activity)
3. ATTACK state (during flood)
4. Explanation panel (fuzzy rules activated)
5. Source Threat Board (multiple IPs blocked)
6. Traffic timeline chart (showing attack spike)
7. Model benchmark table

---

## Tips for Successful Demo

### Before the Demo

1. ✅ Test entire flow with `--replay-csv` first
2. ✅ Verify all systems can reach Pi
3. ✅ Practice tmux navigation
4. ✅ Have emergency stop plan ready
5. ✅ Screenshot clean dashboard state
6. ✅ Prepare talking points for each phase

### During the Demo

1. 🎤 Narrate what you're doing
2. 📊 Point to dashboard changes
3. 🔍 Explain fuzzy rule activations
4. ⏸️ Use pause phases to discuss
5. 📈 Highlight model decisions
6. 🛡️ Show Block/Release in action

### Common Demo Mistakes

❌ Starting all simulators at once (chaos)
✅ Start them sequentially with narration

❌ Using too high attack rates (saturates network)
✅ Start with lower rates, increase gradually

❌ Forgetting to exclude SSH from capture
✅ Always use `--bpf "not port 22"`

❌ No fallback plan if network fails
✅ Have `--replay-csv` mode ready

---

## Quick Reference Commands

### Start Full Stack

```bash
# On Pi (all in one)
cd ~/edge && tmux new -s demo

# Window 0: Detector
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live --bpf "ip and not port 22"

# Ctrl+B, C (new window)
# Window 1: Dashboard
python3 monitor_dashboard.py --port 8080

# Ctrl+B, D (detach)
```

### Traffic Generators (on separate systems)

```bash
# System 1
python normal_light_traffic.py --target <PI_IP> --duration 300

# System 2
python normal_heavy_traffic.py --target <PI_IP> --duration 300

# System 3
sudo python gradual_attack_intervals.py --target <PI_IP> --duration 480 --sources 8

# System 4
sudo stealthy_qos_attack.py --target <PI_IP> --duration 300 --sources 6
```

### Monitoring

```bash
# Watch detector events (live)
tail -f ~/edge/reports/monitor_events.jsonl

# Watch state updates
watch -n 1 cat ~/edge/reports/detector_state.json

# Monitor system resources
htop

# Check iptables rules (if using --live-firewall)
sudo iptables -L INPUT -n -v
```

---

## Additional Resources

### Documentation
- Main README: `BTP-project/README.md`
- Demo Guide: `implementation/DEMO_GUIDE.md`
- Simulation Scripts: `simulation_scripts/`

### Support
- Check logs: `~/edge/reports/`
- Test mode: Use `--replay-csv` for deterministic testing
- Verbose mode: Add `print()` statements to scripts for debugging

---

## Conclusion

You now have everything needed to:

✅ Deploy fuzzy forest model to Raspberry Pi  
✅ Run live packet capture and inference  
✅ Generate 4 different traffic patterns from 4 systems  
✅ Monitor via real-time dashboard  
✅ Demonstrate intelligent attack detection and mitigation  
✅ Explain fuzzy rule decision-making  
✅ Show auto-release and recovery behavior  

**Good luck with your demonstration! 🎓🚀**

---

*Last updated: 2025-01-XX*  
*Project: Explainable SYN/UDP Flood Detection in IoT Networks*  
*Raspberry Pi Edge Computing Demo Setup*
