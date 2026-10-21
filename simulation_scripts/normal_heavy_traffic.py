"""Normal IoT Traffic Simulator - Heavy Load with High Congestion

Simulates high-volume legitimate traffic with significant congestion periods.
Tests the model's ability to distinguish heavy legitimate load from attacks.

Usage:
    python normal_heavy_traffic.py --target <PI_IP> --duration 300

Characteristics:
- 10-15 simulated IoT devices with high activity
- Frequent congestion bursts (200-400 pps for 10-20s)
- Concurrent connections, streaming data
- Complete TCP handshakes (no half-open connections)
- Should remain GREEN on dashboard despite high volume
- NO attack patterns
"""

import argparse
import os
import random
import socket
import sys
import threading
import time


def heavy_device_worker(device_id: int, target: str, open_port: int, stop_at: float, activity_level: str) -> None:
    """Simulate a single high-activity IoT device."""
    
    activities = {
        'streaming': {'tcp_rate': 0.05, 'udp_rate': 0.1, 'payload_size': (256, 1024)},
        'polling': {'tcp_rate': 0.15, 'udp_rate': 0.2, 'payload_size': (64, 256)},
        'bursty': {'tcp_rate': 0.08, 'udp_rate': 0.12, 'payload_size': (128, 512)},
    }
    
    config = activities.get(activity_level, activities['polling'])
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    while time.monotonic() < stop_at:
        # TCP connection with full handshake
        if random.random() < config['tcp_rate']:
            try:
                s = socket.create_connection((target, open_port), timeout=0.5)
                payload = os.urandom(random.randint(*config['payload_size']))
                s.sendall(payload)
                # Simulate response read to complete the session
                try:
                    s.recv(128)
                except socket.timeout:
                    pass
                s.close()
            except (OSError, socket.timeout):
                pass
        
        # UDP packets
        if random.random() < config['udp_rate']:
            try:
                payload = os.urandom(random.randint(*config['payload_size']))
                sock_udp.sendto(payload, (target, random.choice([53, 1883, 5353, 8883])))
            except OSError:
                pass
        
        time.sleep(random.uniform(0.05, 0.15))
    
    sock_udp.close()


def congestion_wave(target: str, open_port: int, duration: float, pps: int) -> None:
    """Generate a high-rate congestion burst with legitimate complete handshakes."""
    print(f"  [CONGESTION] Wave starting - {pps} pps for {duration:.0f}s (legitimate handshakes)")
    
    stop_at = time.monotonic() + duration
    interval = 1.0 / pps
    sent = 0
    
    # Use multiple worker threads for high concurrency
    def worker():
        sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = os.urandom(random.randint(128, 512))
        
        while time.monotonic() < stop_at:
            action = random.choice(['tcp', 'tcp', 'udp'])  # 66% TCP, 33% UDP
            
            try:
                if action == 'tcp':
                    # Complete handshake
                    s = socket.create_connection((target, open_port), timeout=0.3)
                    s.sendall(payload)
                    s.recv(64)  # Attempt to read response
                    s.close()
                else:
                    sock_udp.sendto(payload, (target, random.choice([53, 5353, open_port])))
            except (OSError, socket.timeout):
                pass
            
            time.sleep(interval * random.uniform(0.8, 1.2))
        
        sock_udp.close()
    
    # Spawn concurrent workers
    workers = []
    for _ in range(min(pps // 50, 15)):  # Up to 15 workers
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        workers.append(t)
    
    # Wait for completion
    time.sleep(duration)
    for w in workers:
        w.join(timeout=1.0)
    
    print(f"  [CONGESTION] Wave completed")


def run_simulation(args) -> None:
    """Main simulation orchestrator."""
    print(f"\n{'='*70}")
    print("Normal IoT Traffic Simulator - Heavy Load")
    print(f"{'='*70}")
    print(f"Target: {args.target}:{args.open_port}")
    print(f"Duration: {args.duration}s")
    print(f"Devices: {args.devices}")
    print(f"Congestion waves: {'enabled' if args.congestion else 'disabled'}")
    print(f"{'='*70}\n")
    
    stop_at = time.monotonic() + args.duration
    
    # Device activity profiles
    activity_profiles = ['streaming', 'polling', 'bursty']
    
    # Start device threads
    threads = []
    for i in range(args.devices):
        profile = random.choice(activity_profiles)
        print(f"  Device {i+1}: {profile} profile")
        t = threading.Thread(
            target=heavy_device_worker,
            args=(i, args.target, args.open_port, stop_at, profile),
            daemon=True
        )
        t.start()
        threads.append(t)
    
    print(f"\n  All {args.devices} devices started.\n")
    
    # Congestion injection
    if args.congestion:
        def inject_congestion():
            # Initial warm-up
            time.sleep(random.uniform(8, 15))
            
            while time.monotonic() < stop_at:
                # High congestion waves
                if random.random() < 0.5:  # 50% chance
                    congestion_wave(
                        args.target,
                        args.open_port,
                        duration=random.uniform(10, 20),
                        pps=random.randint(200, 400)
                    )
                
                # Wait before next wave
                time.sleep(random.uniform(15, 35))
        
        cong_thread = threading.Thread(target=inject_congestion, daemon=True)
        cong_thread.start()
        threads.append(cong_thread)
    
    # Status monitoring
    start_time = time.time()
    try:
        while time.monotonic() < stop_at:
            elapsed = time.time() - start_time
            remaining = args.duration - elapsed
            if int(elapsed) % 20 == 0 and remaining > 0:
                print(f"  [STATUS] Running... {elapsed:.0f}s elapsed, {remaining:.0f}s remaining")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n  [STOP] Interrupted by user")
    
    # Cleanup
    for t in threads:
        t.join(timeout=2.0)
    
    print(f"\n{'='*70}")
    print(f"Simulation completed. Duration: {time.time() - start_time:.1f}s")
    print("Note: All traffic was legitimate with complete handshakes.")
    print("Dashboard should remain GREEN despite high packet rate.")
    print(f"{'='*70}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normal IoT Traffic Simulator - Heavy Load with Congestion"
    )
    parser.add_argument("--target", required=True, help="Target Raspberry Pi IP address")
    parser.add_argument("--open-port", type=int, default=8080, help="Port accepting connections")
    parser.add_argument("--duration", type=int, default=300, help="Simulation duration in seconds")
    parser.add_argument("--devices", type=int, default=12, help="Number of simulated devices (8-15)")
    parser.add_argument("--congestion", action="store_true", default=True, help="Enable congestion waves")
    parser.add_argument("--no-congestion", action="store_false", dest="congestion")
    
    args = parser.parse_args()
    
    # Validation
    if args.devices < 5 or args.devices > 20:
        sys.exit("Error: --devices must be between 5 and 20")
    
    try:
        socket.inet_aton(args.target)
    except socket.error:
        sys.exit(f"Error: Invalid IP address: {args.target}")
    
    run_simulation(args)


if __name__ == "__main__":
    main()
