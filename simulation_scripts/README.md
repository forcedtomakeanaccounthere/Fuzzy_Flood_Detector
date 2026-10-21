# Traffic Simulation Scripts for Live IoT Defense Demo

This directory contains 4 specialized traffic simulation scripts designed to run on separate systems for comprehensive live demonstration of the Fuzzy IoT Defense system.

---

## Overview

Each script simulates a different traffic pattern to test various aspects of the detection system:

| Script | Traffic Type | Purpose | Dashboard Expectation |
|--------|-------------|---------|----------------------|
| `normal_light_traffic.py` | Benign (light) | Baseline IoT behavior | 🟢 CLEAR |
| `normal_heavy_traffic.py` | Benign (heavy) | High legitimate load | 🟢 CLEAR |
| `gradual_attack_intervals.py` | Attack (escalating) | Sophisticated multi-phase attack | 🟡 ELEVATED → 🔴 ATTACK |
| `stealthy_qos_attack.py` | Attack (subtle) | Low-level QoS degradation | 🟢 → 🟡 → 🔴 ATTACK |

---

## Prerequisites

### Required on All Systems
```bash
# Python 3.7+
python3 --version

# Basic dependencies (usually pre-installed)
pip3 install --user <none required for basic operation>
```

### Optional (for advanced attacks)
```bash
# Scapy - enables raw packet crafting, IP spoofing
pip3 install --user scapy

# Windows: Also install Npcap from https://npcap.com/#download
```

### Privilege Requirements

| Feature | Windows | Linux/Mac | Raspberry Pi |
|---------|---------|-----------|--------------|
| Normal traffic (sockets) | No admin | No sudo | No sudo |
| SYN packets (scapy) | **Admin** | **sudo** | **sudo** |
| IP spoofing | Admin + Npcap | sudo | sudo |

---

## Quick Start

### 1. Normal Light Traffic (System 1)

**Most basic - no special privileges needed**

```bash
python normal_light_traffic.py --target 192.168.137.X --duration 300 --devices 5
```

**What it does:**
- Simulates 5 IoT devices (sensors, controllers)
- Periodic telemetry every 15-60 seconds
- Occasional mild congestion (70-120 pps)
- Mix of TCP connections and UDP packets
- 100% benign traffic

**Usage:**
```
python normal_light_traffic.py --target <PI_IP> [options]

Required:
  --target IP          Raspberry Pi IP address

Optional:
  --duration SECONDS   How long to run (default: 300)
  --devices COUNT      Number of IoT devices 3-8 (default: 5)
  --open-port PORT     Dashboard/service port (default: 8080)
  --no-congestion      Disable congestion bursts
```

**Expected Dashboard:**
- Banner: 🟢 **CLEAR**
- Traffic: 20-50 pps baseline, spikes to 80-120 pps
- Threat score: < 0.3
- Verdict: **SAFE**

---

### 2. Normal Heavy Traffic (System 2)

**Tests false positive resistance under load**

```bash
python normal_heavy_traffic.py --target 192.168.137.X --duration 300 --devices 12
```

**What it does:**
- Simulates 12 high-activity IoT devices
- Streaming data, frequent uploads
- Congestion waves (200-400 pps for 10-20s)
- All complete TCP handshakes (legitimate)
- Tests model's ability to distinguish load from attack

**Usage:**
```
python normal_heavy_traffic.py --target <PI_IP> [options]

Optional:
  --devices COUNT      8-15 devices (default: 12)
  --duration SECONDS   (default: 300)
  --no-congestion      Disable congestion waves
```

**Expected Dashboard:**
- Banner: 🟢 **CLEAR** or brief 🟡 **ELEVATED**
- Traffic: 100-400 pps during bursts
- Threat score: < threshold (stays below attack zone)
- No sustained BLOCK despite high rate

**Talking Point:** *"Notice how the system stays green even with 300+ pps - it recognizes legitimate handshakes"*

---

### 3. Gradual Attack with Intervals (System 3)

**⚠️ ATTACK SIMULATION - Requires admin/sudo for best results**

```bash
# Windows (as Administrator)
python gradual_attack_intervals.py --target 192.168.137.X --duration 480 --sources 8

# Linux/Mac/Pi
sudo python3 gradual_attack_intervals.py --target 192.168.137.X --duration 480 --sources 8
```

**What it does:**
- 8-phase attack storyline:
  1. Stealth reconnaissance (low-and-slow)
  2. **PAUSE** (recovery test)
  3. Moderate SYN flood
  4. **PAUSE** (auto-release test)
  5. High-intensity burst
  6. **PAUSE** (cool-down)
  7. UDP flood variant
  8. Final recovery
- IP rotation across 8 sources
- Demonstrates escalation, detection, and recovery

**Usage:**
```
python gradual_attack_intervals.py --target <PI_IP> [options]

Optional:
  --duration SECONDS   Total time (default: 300, recommend 480 for full story)
  --sources COUNT      Fake source IPs (default: 8, requires scapy+admin)
  --port PORT          Target port (default: 80)
```

**Expected Dashboard Timeline:**

| Time | Phase | Banner | Notes |
|------|-------|--------|-------|
| 0:00 | Stealth | 🟢 → 🟡 | Occasional SUSPICIOUS |
| 1:30 | Pause | 🟡 → 🟢 | Scores drop |
| 2:00 | Moderate | 🟡 → 🔴 | THROTTLE → BLOCK |
| 3:00 | Pause | 🔴 | Auto-release after TTL |
| 4:00 | Intense | 🔴 | Immediate block |
| 5:00 | Pause | 🔴 → 🟢 | Recovery |
| 6:00 | UDP | 🔴 | Rules 6/7 fire |
| 7:00 | Final | 🟢 | Clean |

**Talking Points:**
- "Sophisticated attacker gradually escalating"
- "Pauses between phases to evade detection"
- "Model detects and automatically releases during pauses"
- "Different attack types trigger different fuzzy rules"

---

### 4. Stealthy QoS Attack (System 4)

**⚠️ ATTACK SIMULATION - Most sophisticated**

```bash
# Windows (as Administrator)
python stealthy_qos_attack.py --target 192.168.137.X --duration 300 --sources 6

# Linux/Mac/Pi
sudo python3 stealthy_qos_attack.py --target 192.168.137.X --duration 300 --sources 6
```

**What it does:**
- Mixes normal traffic with low-rate attack
- Attack rate: 40-120 pps (below typical thresholds)
- Half-open SYN connections (resource exhaustion)
- Gradually increases attack proportion
- Tests fuzzy rule sensitivity to subtle patterns

**Usage:**
```
python stealthy_qos_attack.py --target <PI_IP> [options]

Optional:
  --duration SECONDS       (default: 300)
  --sources COUNT          Spoofed IPs (default: 6, requires scapy+admin)
  --normal-intensity 0.1-1.0  Background traffic level (default: 0.5)
  --port PORT              Attack port (default: 80)
  --open-port PORT         Normal traffic port (default: 8080)
```

**Expected Dashboard:**
- **0-60s:** 🟢 CLEAR (looks normal, mixed traffic)
- **60-120s:** 🟡 ELEVATED (fuzzy rules detecting pattern)
- **120s+:** 🔴 ATTACK → BLOCK (sustained suspicion)
- **Fuzzy rules:** 1, 4, 8 activate (SYN/ACK imbalance, half-open, stealth)

**Talking Points:**
- "This attack is designed to fly under the radar"
- "Low rate, mixed with normal traffic"
- "Traditional rate-based detection might miss this"
- "Our fuzzy rules detect the *pattern* not just volume"
- "Rules 1, 4, 8 are specifically tuned for this"

---

## Multi-System Demo Setup

### Recommended Configuration

```
┌─────────────────────────────────────────────────────────────┐
│                    DEMO NETWORK LAYOUT                       │
└─────────────────────────────────────────────────────────────┘

System 1 (Laptop A)                System 2 (Laptop B / Phone)
┌──────────────────┐               ┌──────────────────┐
│ Normal Light     │──┐         ┌──│ Normal Heavy     │
│ Traffic          │  │         │  │ Traffic          │
│ (Benign)         │  │         │  │ (Benign)         │
└──────────────────┘  │         │  └──────────────────┘
                      ↓         ↓
            ┌───────────────────────────┐
            │    RASPBERRY PI 4/5       │
            │  192.168.137.X (example)  │
            │                           │
            │  • live_detector.py       │
            │  • fuzzy_forest.pkl       │
            │  • monitor_dashboard.py   │
            └───────────────────────────┘
                      ↑         ↑
System 3 (Laptop C)   │         │  System 4 (Laptop D / Pi)
┌──────────────────┐  │         │  ┌──────────────────┐
│ Gradual Attack   │──┘         └──│ Stealthy QoS     │
│ with Intervals   │               │ Attack           │
│ (Attack)         │               │ (Attack)         │
└──────────────────┘               └──────────────────┘

                      ↓
            ┌───────────────────┐
            │  Browser Dashboard │
            │  (Any Device)      │
            │  :8080             │
            └───────────────────┘
```

### Timing the Demo

**Option A: Sequential (20 minutes total)**

```
 0:00 - Start Pi detector + dashboard
 0:30 - System 1: Light traffic (continuous)
 2:00 - System 2: Heavy traffic (continuous)
 5:00 - System 3: Gradual attack (8 min)
13:00 - System 4: Stealthy attack (5 min)
18:00 - Stop System 3 and 4 (observe recovery)
20:00 - Stop all
```

**Option B: Overlapping (15 minutes total)**

```
 0:00 - System 1 + 2 start (baseline)
 3:00 - System 3 starts (attack appears)
 7:00 - System 4 starts (multi-vector attack)
10:00 - Stop System 3 (partial recovery)
12:00 - Stop System 4 (full recovery)
15:00 - Stop all
```

---

## Command Reference

### Start All Simulators (4 terminals)

```bash
# Terminal 1 (System 1)
cd BTP-project/simulation_scripts
python normal_light_traffic.py --target 192.168.137.X --duration 600

# Terminal 2 (System 2)
cd BTP-project/simulation_scripts
python normal_heavy_traffic.py --target 192.168.137.X --duration 600

# Terminal 3 (System 3) - Requires admin/sudo
cd BTP-project/simulation_scripts
sudo python gradual_attack_intervals.py --target 192.168.137.X --duration 480 --sources 8

# Terminal 4 (System 4) - Requires admin/sudo
cd BTP-project/simulation_scripts
sudo python stealthy_qos_attack.py --target 192.168.137.X --duration 300 --sources 6
```

### Stop All

```bash
# In each terminal: Ctrl+C
# Scripts will stop gracefully and print summary
```

---

## Troubleshooting

### "Scapy not found" Error

**Symptoms:**
```
[WARN] scapy is not installed — crafted SYN packets unavailable
```

**Solution:**
```bash
pip3 install --user scapy

# Windows: Also install Npcap
# Download from https://npcap.com/#download
# During install: Check "WinPcap API-compatible mode"
```

**Fallback:** Scripts automatically use socket-based simulation (less realistic but functional)

### "Permission denied" for Raw Sockets

**Symptoms:**
```
[ERROR] Raw packet send failed (PermissionError)
```

**Solution:**
```bash
# Windows: Run PowerShell as Administrator
# Right-click PowerShell → Run as Administrator

# Linux/Mac/Pi: Use sudo
sudo python3 script.py --target <IP>
```

### "Invalid IP address" Error

**Cause:** Target IP validation failed

**Solution:**
- Verify Raspberry Pi IP: `ssh pi@<IP>` should work
- Use actual IP, not hostname
- Must be private IP (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- Scripts refuse to target public IPs (safety feature)

### Scripts Run but No Dashboard Activity

**Checklist:**
1. ✅ Is detector running on Pi? `tmux attach -t demo`
2. ✅ Is dashboard showing "Live"?
3. ✅ Can you ping the Pi? `ping <PI_IP>`
4. ✅ Is firewall blocking traffic? Check Pi: `sudo iptables -L`
5. ✅ Correct target IP? Match with `hostname -I` on Pi

### Script Runs Too Fast / Too Slow

**Adjust duration:**
```bash
--duration 600  # Run for 10 minutes instead of 5
```

**Adjust attack rate:**
```bash
# For gradual_attack_intervals.py and stealthy_qos_attack.py
# Lower rate if network can't handle it
# Edit script and change rate parameters in attack functions
```

### Network Saturates During Attack

**Symptoms:** SSH freezes, dashboard stops updating

**This is actually realistic!** That's what a real DDoS does.

**Solutions:**
- Lower attack rates in scripts (edit .py files)
- Use wired Ethernet for Pi instead of WiFi
- Demonstrate: "This is why DDoS is so effective - even our management connection is affected"

---

## Safety Notes

### ⚠️ Legal and Ethical Use

**ONLY USE THESE SCRIPTS:**
- Against systems you own
- In isolated lab networks
- For educational/research purposes
- With explicit permission

**NEVER:**
- Target production systems
- Target systems you don't own
- Use on public networks
- Use outside controlled lab environment

### Network Safety

Scripts include safety checks:
- Refuse to target public IP addresses
- Validate IP format before starting
- Graceful shutdown on Ctrl+C
- No data exfiltration or payload execution

### Raspberry Pi Safety

- SSH protection built into detector (your laptop IP auto-protected)
- Firewall blocking is **simulated by default**
- Use `--live-firewall` only with extreme caution
- Physical Pi access recommended during first runs

---

## Tips for Successful Demos

### Before Demo

1. ✅ Test each script individually first
2. ✅ Verify Pi can handle the load (`htop` on Pi)
3. ✅ Practice stopping scripts gracefully
4. ✅ Have backup: CSV replay mode ready
5. ✅ Screenshot dashboard in each state

### During Demo

1. 🎤 Narrate what each system is doing
2. 📊 Point to specific dashboard elements
3. 🔍 Explain fuzzy rule activations
4. ⏸️ Use pauses in attack script to discuss
5. 📈 Highlight model decision-making
6. 🛡️ Show Block/Release actions

### Demo Script Example

```
"System 1 is simulating normal IoT devices - sensors, cameras, controllers.
Notice the dashboard stays green - about 30 packets per second baseline.

Now I'm starting System 2 - heavy legitimate traffic. This could be software
updates, video streaming, multiple devices active at once. Watch the packet
rate jump to 200-300 per second... and the system STAYS GREEN. This shows
our model distinguishes volume from attack patterns.

Now here comes the interesting part - System 3 is launching a sophisticated
attack. It starts with stealth reconnaissance... see these occasional
SUSPICIOUS markers? The attacker is probing. Now it's escalating to a
moderate SYN flood... watch the threat score rising... there! BLOCK.
The source IP is now dropped by our edge device.

During this pause in the attack, watch what happens... the auto-release
timer is counting down... there! The IP is released. This prevents
permanent blacklisting from single-burst attacks.

Now System 4 is adding a really sneaky attack - mixed with normal traffic,
low rate, designed to fly under the radar. Traditional systems might miss
this. But look at Rules 1, 4, and 8 activating in the Explanation panel -
our fuzzy logic is detecting the half-open connection pattern... and there's
the BLOCK. The system caught it even though it looked partly legitimate."
```

---

## Advanced Usage

### Custom Duration for Phases

```python
# Edit gradual_attack_intervals.py
# Modify timeline array around line 250
timeline = [
    ('stealth', attack_phase_stealth, 45, "Stealth Reconnaissance"),  # Change 45 to desired seconds
    ('pause', pause_phase, 30, "Observing detector behavior"),
    # ... etc
]
```

### Custom Attack Rates

```python
# Edit any attack script
# Look for rate = random.randint(X, Y)
# Adjust X and Y to control packet rate
```

### Ground Truth Logging

All scripts log phase changes for later evaluation:

```bash
# After demo, on Pi
python evaluate_demo.py

# Analyzes ground truth vs detector events
# Shows per-phase detection latency
```

---

## Files in This Directory

```
simulation_scripts/
├── README.md                        ← You are here
├── normal_light_traffic.py          ← Benign light load
├── normal_heavy_traffic.py          ← Benign heavy load
├── gradual_attack_intervals.py      ← Sophisticated attack with pauses
└── stealthy_qos_attack.py          ← Subtle QoS degradation attack
```

---

## Related Documentation

- **Main Guide:** `../working.md` - Complete Pi setup and deployment
- **Demo Guide:** `../implementation/DEMO_GUIDE.md` - Official demo walkthrough
- **Project README:** `../README.md` - Research overview and results

---

## Support

**If scripts don't work:**
1. Check Prerequisites section above
2. Try CSV replay mode instead: `--replay-csv` on detector
3. Review Troubleshooting section
4. Check network connectivity: `ping <PI_IP>`

**For questions about:**
- Model training: See `../implementation/`
- Detector configuration: See `../implementation/live_detector.py --help`
- Dashboard features: See `../implementation/monitor_dashboard.py`

---

**Remember:** The goal is to demonstrate intelligent, explainable threat detection at the edge. Let the fuzzy rules and model decisions speak for themselves through the dashboard!

🎓 Good luck with your demonstration!
