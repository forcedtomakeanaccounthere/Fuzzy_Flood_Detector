#!/usr/bin/env python3
"""Diagnostic script to check detector status and packet capture.

Run this ON THE RASPBERRY PI to diagnose why packets aren't being captured.
"""

import json
import subprocess
import sys
from pathlib import Path


def check_file(path: Path, name: str):
    """Check if a file exists and show its status"""
    print(f"\n{'='*60}")
    print(f"Checking: {name}")
    print(f"Path: {path}")
    print(f"{'='*60}")
    
    if not path.exists():
        print(f"❌ File does not exist!")
        return False
    
    print(f"✅ File exists")
    print(f"   Size: {path.stat().st_size:,} bytes")
    print(f"   Modified: {path.stat().st_mtime}")
    
    if path.suffix == '.json':
        try:
            data = json.loads(path.read_text())
            print(f"   ✅ Valid JSON")
            if name == "detector_state.json":
                print(f"\n   Detector Info:")
                print(f"   - Mode: {data.get('mode', 'unknown')}")
                print(f"   - Warmup: {data.get('warmup', 'unknown')}")
                print(f"   - Threat: {data.get('threat', 'unknown')}")
                print(f"   - Packets total: {data.get('kpi', {}).get('packets_total', 0)}")
                print(f"   - Windows evaluated: {data.get('kpi', {}).get('windows_evaluated', 0)}")
                print(f"   - Updated: {data.get('updated', 0)}")
        except Exception as e:
            print(f"   ❌ JSON parse error: {e}")
    
    elif path.suffix == '.jsonl':
        try:
            lines = path.read_text().strip().split('\n')
            print(f"   Lines: {len(lines)}")
            if lines and lines[0]:
                first = json.loads(lines[0])
                print(f"   First event type: {first.get('type', 'unknown')}")
                if len(lines) > 1:
                    last = json.loads(lines[-1])
                    print(f"   Last event type: {last.get('type', 'unknown')}")
        except Exception as e:
            print(f"   ⚠️  Parse error: {e}")
    
    return True


def check_detector_process():
    """Check if live_detector.py is running"""
    print(f"\n{'='*60}")
    print("Checking: Detector Process")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        detector_lines = [
            line for line in result.stdout.split('\n')
            if 'live_detector.py' in line and 'grep' not in line
        ]
        
        if detector_lines:
            print(f"✅ Detector process found:")
            for line in detector_lines:
                print(f"   {line[:120]}")
        else:
            print(f"❌ No detector process found!")
            print(f"   Start it with: sudo python3 live_detector.py --live")
            return False
        
        return True
    except Exception as e:
        print(f"⚠️  Could not check process: {e}")
        return False


def check_network_interface():
    """Check network interfaces and packet capture capability"""
    print(f"\n{'='*60}")
    print("Checking: Network Interfaces")
    print(f"{'='*60}")
    
    try:
        # Check interfaces
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        interfaces = []
        for line in result.stdout.split('\n'):
            if ': ' in line and '<' in line:
                iface = line.split(':')[1].strip().split('@')[0]
                if iface not in ['lo']:
                    interfaces.append(iface)
                    state = "UP" if "UP" in line else "DOWN"
                    print(f"   {iface}: {state}")
        
        print(f"\n   Available interfaces: {', '.join(interfaces)}")
        
        # Check if scapy can be imported
        try:
            import scapy.all
            print(f"   ✅ Scapy available")
        except ImportError:
            print(f"   ❌ Scapy NOT available - install: pip3 install scapy")
            return False
        
        return True
    except Exception as e:
        print(f"⚠️  Could not check network: {e}")
        return False


def check_permissions():
    """Check if running with required permissions"""
    print(f"\n{'='*60}")
    print("Checking: Permissions")
    print(f"{'='*60}")
    
    import os
    uid = os.geteuid()
    print(f"   Current UID: {uid}")
    
    if uid == 0:
        print(f"   ✅ Running as root (required for packet capture)")
    else:
        print(f"   ⚠️  Not running as root")
        print(f"   Note: Detector needs sudo for live packet capture")
        print(f"   Run: sudo python3 live_detector.py --live")


def test_packet_capture():
    """Try to capture a few packets to verify it works"""
    print(f"\n{'='*60}")
    print("Testing: Packet Capture (5 second test)")
    print(f"{'='*60}")
    
    try:
        from scapy.all import sniff
        print("   Starting 5-second capture...")
        packets = sniff(timeout=5, count=10)
        print(f"   ✅ Captured {len(packets)} packets")
        
        if len(packets) == 0:
            print(f"   ⚠️  No packets captured - check:")
            print(f"      1. Is detector running?")
            print(f"      2. Is there network traffic?")
            print(f"      3. Try: ping 8.8.8.8 in another terminal")
        
        return len(packets) > 0
    except ImportError:
        print(f"   ❌ Scapy not available")
        return False
    except PermissionError:
        print(f"   ❌ Permission denied - need sudo!")
        return False
    except Exception as e:
        print(f"   ❌ Capture failed: {e}")
        return False


def main():
    print("\n" + "="*60)
    print(" 🔍 RASPBERRY PI DETECTOR STATUS CHECK")
    print("="*60)
    
    # Determine reports directory
    reports_dir = Path("reports")
    if not reports_dir.exists():
        # Try relative to script location
        reports_dir = Path(__file__).parent / "reports"
    
    if not reports_dir.exists():
        print(f"\n❌ Reports directory not found!")
        print(f"   Expected: {reports_dir.absolute()}")
        print(f"   Current dir: {Path.cwd()}")
        print(f"\n   Run this script from ~/edge/ or ~/BTP-project/implementation/")
        return 1
    
    print(f"\nReports directory: {reports_dir.absolute()}")
    
    # Run checks
    checks = []
    
    checks.append(("Detector State File", 
                   check_file(reports_dir / "detector_state.json", "detector_state.json")))
    
    checks.append(("Events File", 
                   check_file(reports_dir / "monitor_events.jsonl", "monitor_events.jsonl")))
    
    checks.append(("Detector Process", 
                   check_detector_process()))
    
    checks.append(("Network Interfaces", 
                   check_network_interface()))
    
    check_permissions()
    
    # Only test capture if not already running as detector
    import os
    if os.geteuid() == 0:
        checks.append(("Packet Capture Test", 
                       test_packet_capture()))
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    
    for name, passed in checks:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"   {name:30} {status}")
    
    all_passed = all(result for _, result in checks)
    
    if all_passed:
        print(f"\n✅ All checks passed!")
        print(f"\nIf dashboard still shows no packets:")
        print(f"   1. Generate traffic: ping <PI_IP> from laptop")
        print(f"   2. Check detector output: Is it printing window lines?")
        print(f"   3. Hard refresh browser: Ctrl+Shift+R")
    else:
        print(f"\n⚠️  Some checks failed - see above for details")
        print(f"\nCommon fixes:")
        print(f"   • Not running: sudo python3 live_detector.py --live")
        print(f"   • No scapy: pip3 install scapy")
        print(f"   • No traffic: ping 8.8.8.8 in another terminal")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
