# Troubleshooting Guide - Raspberry Pi IoT Defense Demo

## Common Issues and Solutions

---

## 🔴 Critical Issues

### Issue: SSH Connection Lost During Demo

**Symptoms:**
- SSH terminal freezes or disconnects
- Can't reconnect to Pi
- Lost access mid-demo

**Causes:**
1. High packet rate saturated WiFi bandwidth
2. Your laptop IP was accidentally blocked
3. Network congestion from attack simulation

**Solutions:**

**Immediate:**
```bash
# Try reconnecting
ssh pi@<PI_IP>

# If fails, try from different device
# Or wait 120s for auto-release

# Physical access: Connect keyboard+monitor to Pi
# Login and run: sudo iptables -F INPUT
```

**Prevention:**
```bash
# Always use BPF filter to exclude SSH
--bpf "ip and not port 22"

# Explicitly protect your IP
--protect 192.168.137.1

# Use wired Ethernet instead of WiFi if possible
```

**Demo recovery:**
> "Notice how the attack is so effective it's affecting even our management connection - this demonstrates the real-world impact of DDoS attacks. Let me reconnect..."

---

### Issue: Detector Crashes or Stops Unexpectedly

**Symptoms:**
- Dashboard shows "Disconnected"
- No events in `monitor_events.jsonl`
- Detector tmux window shows error

**Check detector logs:**
```bash
# Reattach to tmux
tmux attach -t demo

# Switch to detector window
Ctrl+B, 0

# Look for error messages
```

**Common causes:**

**1. Out of Memory**
```bash
# Check memory
free -h

# If low, restart detector with smaller window
sudo python3 live_detector.py --live --min-eval 20
```

**2. Model file corrupted**
```bash
# Re-verify model
cd ~/edge
python3 -c "import joblib; joblib.load('fuzzy_forest.pkl'); print('OK')"

# If fails, retransfer from laptop
# On laptop:
scp fuzzy_forest.pkl pi@<PI_IP>:~/edge/
```

**3. Permission issues**
```bash
# Ensure using sudo for live capture
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live
```

**Quick restart:**
```bash
cd ~/edge
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live --bpf "ip and not port 22"
```

---

### Issue: Dashboard Accessible but Shows No Data

**Symptoms:**
- Browser loads dashboard successfully
- Shows "Disconnected" or "WAITING FOR DETECTOR"
- No packets, no KPIs

**Diagnosis:**
```bash
# On Pi - check if files exist
ls -lh ~/edge/reports/detector_state.json
ls -lh ~/edge/reports/monitor_events.jsonl

# Check if detector is writing
tail -f ~/edge/reports/detector_state.json
# Should update every second
```

**Solutions:**

**1. Detector not running**
```bash
# Check process
ps aux | grep live_detector

# If not found, start it
tmux attach -t demo
# Start detector in window 0
```

**2. File permission issues**
```bash
# Fix permissions
cd ~/edge/reports
chmod 644 *.json *.jsonl
```

**3. Path mismatch**
```bash
# Dashboard and detector must use same path
# Check both are in ~/edge/ directory
pwd  # Should show /home/pi/edge
```

**4. No traffic reaching Pi**
```bash
# Generate test traffic
ping <PI_IP>  # from laptop

# Or minimal test
python3 -c "import socket; s=socket.create_connection(('<PI_IP>', 8080)); s.close()"
```

---

## 🟡 Setup Issues

### Issue: Can't Find Raspberry Pi IP Address

**Methods to find IP:**

**Method 1: Router/Hotspot**
- Windows Hotspot: Settings → Mobile hotspot → View connected devices
- Router: Check DHCP client list in admin page (192.168.1.1)

**Method 2: From Pi directly**
```bash
# Connect monitor+keyboard to Pi
# Login and run:
hostname -I
ip addr show wlan0 | grep inet
```

**Method 3: Network scan**
```powershell
# On Windows (if on same network)
arp -a | findstr "192.168"

# Look for entries in your subnet
```

**Method 4: mDNS**
```bash
# Try hostname
ping raspberrypi.local
ping iot-edge-pi.local  # if you set custom hostname
```

---

### Issue: Can't SSH into Raspberry Pi

**Test connectivity:**
```powershell
# From Windows
Test-NetConnection <PI_IP> -Port 22

# From Linux/Mac
nc -zv <PI_IP> 22
```

**If connection refused:**
```bash
# SSH not enabled
# Solution: Re-flash SD card with SSH enabled in Pi Imager settings
```

**If connection timeout:**
```bash
# Not on same network or wrong IP
# Solution: Verify Pi IP address, check network connection
```

**If "Host key verification failed":**
```powershell
# Old SSH key in cache
# Solution:
ssh-keygen -R <PI_IP>
# Then retry SSH
```

---

### Issue: Python Dependencies Missing on Pi

**Symptoms:**
```
ModuleNotFoundError: No module named 'numpy'
ModuleNotFoundError: No module named 'scapy'
```

**Full reinstall:**
```bash
# Update pip
python3 -m pip install --upgrade pip

# Install all dependencies
pip3 install --user numpy pandas scikit-learn joblib psutil scapy

# Verify
python3 -c "import numpy, pandas, sklearn, joblib, psutil, scapy; print('All OK')"
```

**If pip fails:**
```bash
# Use apt packages (slower but more reliable)
sudo apt install -y python3-numpy python3-pandas python3-sklearn python3-scapy

# Then add remaining
pip3 install --user joblib psutil
```

**If PATH issues:**
```bash
# Add to ~/.bashrc
echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc
source ~/.bashrc

# For sudo commands, use:
sudo env PATH=$PATH:~/.local/bin python3 script.py
```

---

## 🟢 Traffic Simulation Issues

### Issue: Scapy Not Found on Simulator Systems

**Symptoms:**
```
[WARN] scapy is not installed — crafted SYN packets unavailable
```

**Solutions:**

**On Windows:**
```powershell
# Install scapy
pip install scapy

# Install Npcap (required for Windows)
# Download from: https://npcap.com/#download
# During install: ✅ "Install in WinPcap API-compatible mode"

# Restart PowerShell

# Run as Administrator
# Right-click PowerShell → "Run as Administrator"
python script.py --target <PI_IP>
```

**On Linux/Mac:**
```bash
# Install scapy
pip3 install scapy

# Run with sudo (required for raw sockets)
sudo python3 script.py --target <PI_IP>
```

**Fallback (without Scapy):**
- Scripts automatically fallback to socket-based traffic
- Less realistic but still demonstrates detection
- No IP spoofing, but single-source attacks work

---

### Issue: "Permission denied" When Running Simulators

**Symptoms:**
```
[ERROR] Raw packet send failed (PermissionError)
[ERROR] On Windows: run as Administrator + install Npcap
```

**Solutions:**

**Windows:**
1. Close PowerShell
2. Right-click PowerShell icon → "Run as Administrator"
3. Navigate to project directory
4. Run script again

**Linux/Mac/Pi:**
```bash
# Use sudo
sudo python3 script.py --target <PI_IP>
```

**Quick test:**
```python
# Test raw socket permission
python3 -c "from scapy.all import *; send(IP(dst='8.8.8.8')/ICMP())"
# If works: you have permission
# If fails: need admin/sudo
```

---

### Issue: Simulator Refuses to Target IP

**Symptoms:**
```
ERROR: Refusing to target non-private IP X.X.X.X. Lab use only!
```

**Cause:** Safety check prevents targeting public IPs

**Solutions:**
```bash
# Verify Pi IP is in private range
# Valid: 192.168.x.x, 10.x.x.x, 172.16-31.x.x

# If Pi has public IP (shouldn't happen in lab):
# Edit script and remove check (use with extreme caution)
```

---

### Issue: Attack Simulation Runs But Dashboard Stays Green

**Possible causes:**

**1. Attack too weak**
```bash
# Increase rate or duration
python gradual_attack_intervals.py --target <PI_IP> --duration 600
```

**2. Wrong port**
```bash
# Ensure attacking a port Pi listens on
# Port 80 or 8080 typically work
--port 8080
```

**3. IP spoofing not working**
```bash
# Remove --sources flag to use real source IP
python gradual_attack_intervals.py --target <PI_IP> --duration 300
# (no --sources flag)
```

**4. Threshold too high**
```bash
# Check model threshold
# On Pi:
python3 -c "import joblib; print(joblib.load('fuzzy_forest.pkl')['threshold'])"
# Should be around 0.48

# If much higher, retrain model with correct data
```

**5. BPF filter too broad**
```bash
# On detector, check if attack traffic is being filtered out
# Temporarily remove BPF filter:
sudo python3 live_detector.py --live
# (no --bpf flag)
```

---

## 📊 Dashboard Issues

### Issue: Dashboard Loads But Shows Old Data

**Symptoms:**
- KPIs show correct numbers but don't update
- "Updated: X seconds ago" timestamp not changing
- Graphs frozen

**Solutions:**

**1. Hard refresh browser**
```
Ctrl + Shift + R  (Windows/Linux)
Cmd + Shift + R   (Mac)
```

**2. Clear browser cache**
```
F12 → Application/Storage → Clear site data
```

**3. Check dashboard is running**
```bash
# On Pi
ps aux | grep monitor_dashboard

# Should show python3 monitor_dashboard.py

# If not running, restart
tmux attach -t demo
Ctrl+B, 1
python3 monitor_dashboard.py --port 8080
```

---

### Issue: Dashboard CSS Broken / Looks Wrong

**Symptoms:**
- No styling, plain HTML
- Layout completely broken
- Colors missing

**Cause:** Browser cached old version or CSS didn't load

**Solutions:**
```bash
# Hard refresh
Ctrl + Shift + R

# Try different browser
# Chrome, Firefox, Edge all supported

# Check dashboard terminal for errors
# Look for Python exceptions
```

---

### Issue: Can't Access Dashboard from Other Devices

**Symptoms:**
- Works on Pi's browser
- Can't access from laptop/phone

**Check firewall:**
```bash
# On Pi - check if port 8080 is blocked
sudo iptables -L OUTPUT -n -v | grep 8080

# Temporarily disable firewall (for testing)
sudo iptables -F
```

**Check binding:**
```bash
# Dashboard should bind to 0.0.0.0, not 127.0.0.1
# Check dashboard script startup message:
# Should show: "Serving on 0.0.0.0:8080"
# NOT: "Serving on 127.0.0.1:8080"
```

**Network test:**
```powershell
# From laptop
Test-NetConnection <PI_IP> -Port 8080

# Should show "TcpTestSucceeded: True"
```

---

## ⚡ Performance Issues

### Issue: Pi CPU at 100%

**Symptoms:**
- `htop` shows 100% CPU
- Dashboard sluggish
- Detector falling behind

**Causes:**
1. Very high packet rate (500+ pps)
2. Scapy sniffing overhead
3. Concurrent processing

**Solutions:**

**1. Reduce simulation rate**
```bash
# Lower attack intensity on simulators
# Edit scripts: change rate parameters
```

**2. Increase detector tick interval**
```bash
# Process less frequently
sudo python3 live_detector.py --live --tick 0.3
# Default 0.2, increase to 0.3 or 0.5
```

**3. Reduce window evaluation frequency**
```bash
# For replay mode
--eval-every 2  # Evaluate every 2nd packet instead of every packet
```

**4. This is expected during floods!**
> "Notice the Pi CPU at 90% - this demonstrates the computational load of real-time packet analysis during an attack. Even under this load, inference still completes in under 3 milliseconds per window."

---

### Issue: Dashboard Updates Slowly

**Symptoms:**
- KPIs lag by 2-5 seconds
- Packet stream doesn't update smoothly

**Causes:**
1. Detector writing state slowly
2. Many concurrent browsers open
3. Large state files

**Solutions:**

**1. Check detector is keeping up**
```bash
# Monitor detector
tail -f ~/edge/reports/detector_state.json
# Should update every ~1 second
```

**2. Reduce packet event logging**
```bash
# In live_detector.py, comment out packet event logging
# Or use --max-packet-events flag
--max-packet-events 10  # Log fewer packet events
```

**3. Single browser only**
- Close other tabs pointing to dashboard
- Dashboard supports multiple viewers but slower

---

## 🐛 Debug Mode

### Enable Verbose Logging

**Detector:**
```python
# Edit live_detector.py
# Add at top of main():
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Dashboard:**
```python
# Edit monitor_dashboard.py  
# In serve() function, change:
log_message = lambda *args: print(...)
```

---

### Check System Health

```bash
# On Pi

# Memory
free -h

# Disk space
df -h

# Temperature
vcgencmd measure_temp

# Network interfaces
ip addr show

# Active connections
ss -tuln | grep 8080  # Dashboard port
ss -tuln | grep 22    # SSH port

# Process list
ps aux | grep python3

# System logs
journalctl -xe | tail -50
```

---

## 🆘 Emergency Recovery

### Complete Reset (Nuclear Option)

```bash
# On Pi

# 1. Kill all Python processes
sudo killall python3

# 2. Clear firewall rules
sudo iptables -F INPUT
sudo iptables -P INPUT ACCEPT

# 3. Remove old files
cd ~/edge/reports
rm -f *.jsonl *.json *.tmp

# 4. Fresh start
cd ~/edge
sudo env PATH=$PATH:~/.local/bin python3 live_detector.py --live --bpf "ip and not port 22"

# In new terminal/tmux window:
python3 monitor_dashboard.py --port 8080
```

---

### Backup and Restore

**Before demo (backup):**
```bash
# On Pi
cd ~/edge
tar -czf ~/edge_backup_$(date +%Y%m%d).tar.gz \
  fuzzy_forest.pkl \
  live_detector.py \
  fuzzy_inference.py \
  monitor_dashboard.py \
  sysstats.py
```

**After crash (restore):**
```bash
# On Pi
cd ~
tar -xzf edge_backup_*.tar.gz -C ~/edge/
```

---

## 📋 Pre-Demo Checklist

Run this checklist 30 minutes before demo:

```bash
# On Raspberry Pi

# 1. System health
✅ uptime              # Check not recently rebooted
✅ free -h             # Memory available
✅ df -h               # Disk space OK
✅ vcgencmd measure_temp  # Temperature < 70°C

# 2. Network
✅ hostname -I         # Note IP address
✅ ping 8.8.8.8 -c 3   # Internet reachable

# 3. Files
✅ ls -lh ~/edge/fuzzy_forest.pkl  # Exists, ~2-3 MB
✅ ls ~/edge/*.py      # All scripts present

# 4. Python
✅ python3 -c "import numpy, pandas, sklearn, joblib, psutil, scapy; print('OK')"

# 5. Firewall (if using --live-firewall)
✅ sudo iptables -L INPUT -n  # Should be mostly empty
✅ sudo iptables-save > ~/iptables_pre_demo_backup.rules

# 6. Test run
✅ cd ~/edge
✅ sudo python3 live_detector.py --replay-csv ../implementation/data/test_data.csv --delay 0
   # Should run without errors, Ctrl+C to stop
```

**On Laptop:**

```powershell
# 1. Network
✅ ping <PI_IP>                    # Reachable
✅ Test-NetConnection <PI_IP> -Port 8080  # Dashboard port open
✅ ssh pi@<PI_IP> exit             # SSH works

# 2. Simulation scripts
✅ cd BTP-project/simulation_scripts
✅ ls *.py                         # All 4 scripts present

# 3. Dependencies (if using attacks)
✅ python -c "import scapy; print('OK')"  # Optional but recommended

# 4. Browser test
✅ Open http://<PI_IP>:8080        # Loads (even if shows disconnected)
```

---

## 🔍 Diagnostic Commands

Copy-paste these for quick diagnostics:

```bash
# === ON RASPBERRY PI ===

# Check everything at once
echo "=== System ===" && uptime && free -h && df -h ~/edge && \
echo "=== Network ===" && hostname -I && \
echo "=== Processes ===" && ps aux | grep -E "(live_detector|monitor_dashboard)" && \
echo "=== Files ===" && ls -lh ~/edge/ && \
echo "=== Recent events ===" && tail -3 ~/edge/reports/monitor_events.jsonl

# Monitor in real-time
watch -n 1 'tail -5 ~/edge/reports/monitor_events.jsonl'

# Test model loading
python3 -c "
import joblib
artifact = joblib.load('/home/pi/edge/fuzzy_forest.pkl')
print(f'Model: {artifact[\"model_kind\"]}')
print(f'Features: {len(artifact[\"feature_order\"])}')
print(f'Threshold: {artifact[\"threshold\"]:.3f}')
print(f'Window: {artifact.get(\"window\", 50)}')
"
```

---

## 💡 Tips to Avoid Issues

### Before Demo
1. ✅ Test everything with `--replay-csv` first
2. ✅ Use wired Ethernet if available (not WiFi)
3. ✅ Have physical access to Pi (keyboard+monitor)
4. ✅ Backup config: `sudo iptables-save > backup.rules`
5. ✅ Practice tmux navigation

### During Demo
1. 🎯 Start with simple: normal traffic first
2. 🎯 One simulator at a time, not all at once
3. 🎯 Lower attack rates if needed (300 pps, not 500)
4. 🎯 Narrate issues as "features" (e.g., "See how the attack affects even management traffic")
5. 🎯 Have screenshot backup if live demo fails

### Network Safety
1. 🌐 Use isolated network (Windows Hotspot, not production)
2. 🌐 Always use `--bpf "not port 22"`
3. 🌐 Don't use `--live-firewall` for first runs
4. 🌐 Keep laptop IP in `--protect` list

---

## 📞 When All Else Fails

**Fallback Demo Mode:**

```bash
# On Pi - use CSV replay (no live capture needed)
cd ~/edge
python3 live_detector.py --replay-csv test_data.csv --delay 0.005 --loop

# Still start dashboard
python3 monitor_dashboard.py --port 8080

# Deterministic, repeatable, no network issues
# Explain: "This is replay of captured attack traffic for demonstration"
```

**Minimal Working Demo (No Pi Required):**

```powershell
# On laptop only
cd BTP-project/implementation

# Start detector in replay mode
python live_detector.py --replay-csv data/syn_udp_flood_attack_data_clean.csv --delay 0.01 --loop

# In second terminal
python monitor_dashboard.py --port 8080

# Open browser: http://localhost:8080
```

---

**Remember:** The best debugging tool is a calm explanation. Most "errors" are opportunities to demonstrate system behavior!

Good luck! 🎓✨
