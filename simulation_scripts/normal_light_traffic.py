"""Normal IoT Traffic Simulator - Light Load with Mild Congestion

Simulates realistic IoT device behavior with occasional congestion periods.
Safe for continuous operation - contains only legitimate traffic patterns.

Usage:
    python normal_light_traffic.py --target <PI_IP> --duration 300

Characteristics:
- 3-8 simulated IoT devices (sensors, controllers, cameras)
- Periodic telemetry bursts (15-60s intervals)
- Occasional mild congestion (70-120 pps bursts for 5-10s)
- Mix of TCP connections and UDP packets
- DNS-like queries, MQTT-style messages
- NO attack traffic - 100% benign
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
    print("[INFO] Scapy not available - using socket-based traffic only")


def simulate_device(device_config: dict, target: str, open_port: int, stop_at: float) -> None:
    """Simulate a single IoT device's traffic pattern."""
    sock_tcp = None
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    payloads = {
        'telemetry': [os.urandom(random.randint(32, 128)) for _ in range(5)],
        'heartbeat': [os.urandom(random.randint(16, 48)) for _ in range(3)],
        'query': [os.urandom(random.randint(24, 80)) for _ in range(4)],
    }
    
    last_telemetry = time.monotonic()
    last_heartbeat = time.monotonic()
    
    while time.monotonic() < stop_at:
        now = time.monotonic()
        
        # Periodic telemetry upload (TCP)
        if now - last_telemetry >= device_config['telemetry_interval']:
            try:
                sock_tcp = socket.create_connection((target, open_port), timeout=1.0)
                sock_tcp.sendall(random.choice(payloads['telemetry']))
                sock_tcp.close()
                last_telemetry = now
            except (OSError, socket.timeout):
                pass
        
        # Heartbeat / status query (UDP)
        if now - last_heartbeat >= device_config['heartbeat_interval']:
            try:
                sock_udp.sendto(
                    random.choice(payloads['heartbeat']),
                    (target, random.choice([53, 5353, 1883, 8883]))
                )
                last_heartbeat = now
            except OSError:
                pass
        
        # Random activity
        if random.random() < 0.15:  # 15% chance per cycle
            activity = random.choice(['tcp_query', 'udp_burst', 'idle'])
            try:
                if activity == 'tcp_query':
                    s = socket.create_connection((target, open_port), timeout=0.5)
                    s.sendall(random.choice(payloads['query']))
                    s.close()
                elif activity == 'udp_burst':
                    for _ in range(random.randint(2, 5)):
                        sock_udp.sendto(
                            random.choice(payloads['query']),
                            (target, random.choice([53, 1883, 5353]))
                        )
            except (OSError, socket.timeout):
                pass
        
        time.sleep(device_config['poll_interval'])
    
    sock_udp.close()


def congestion_burst(target: str, open_port: int, duration: float, intensity: str = 'mild') -> None:
    """Generate a congestion burst with legitimate traffic."""
    rates = {'mild': (70, 120), 'moderate': (150, 250)}
    pps_min, pps_max = rates.get(intensity, rates['mild'])
    
    print(f"  [CONGESTION] Starting {intensity} burst ({pps_min}-{pps_max} pps) for {duration:.0f}s")
    
    stop_at = time.monotonic() + duration
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = os.urandom(random.randint(64, 256))
    
    target_pps = random.randint(pps_min, pps_max)
    interval = 1.0 / target_pps
    sent = 0
    
    while time.monotonic() < stop_at:
        # Mix of TCP and UDP
        if random.random() < 0.4:  # 40% TCP attempts
            try:
                s = socket.create_connection((target, open_port), timeout=0.3)
                s.sendall(payload)
                s.close()
            except (OSError, socket.timeout):
                pass
        else:  # 60% UDP
            try:
                sock_udp.sendto(payload, (target, random.choice([open_port, 53, 5353])))
            except OSError:
                pass
        
        sent += 1
        if sent % 50 == 0:
            time.sleep(max(0.0, 50 * interval - 0.02))
    
    sock_udp.close()
    print(f"  [CONGESTION] Burst completed")


def run_simulation(args) -> None:
    """Main simulation orchestrator."""
    print(f"\n{'='*70}")
    print("Normal IoT Traffic Simulator - Light Load")
    print(f"{'='*70}")
    print(f"Target: {args.target}:{args.open_port}")
    print(f"Duration: {args.duration}s")
    print(f"Devices: {args.devices}")
    print(f"Congestion: {'enabled' if args.congestion else 'disabled'}")
    print(f"{'='*70}\n")
    
    import threading
    
    stop_at = time.monotonic() + args.duration
    
    # Device configurations
    device_configs = []
    device_types = [
        {'name': 'temperature-sensor', 'telemetry_interval': 30.0, 'heartbeat_interval': 15.0, 'poll_interval': 1.0},
        {'name': 'motion-sensor', 'telemetry_interval': 45.0, 'heartbeat_interval': 20.0, 'poll_interval': 1.2},
        {'name': 'camera-feed', 'telemetry_interval': 20.0, 'heartbeat_interval': 10.0, 'poll_interval': 0.8},
        {'name': 'smart-controller', 'telemetry_interval': 60.0, 'heartbeat_interval': 25.0, 'poll_interval': 1.5},
        {'name': 'air-quality-sensor', 'telemetry_interval': 40.0, 'heartbeat_interval': 18.0, 'poll_interval': 1.1},
        {'name': 'door-lock', 'telemetry_interval': 120.0, 'heartbeat_interval': 30.0, 'poll_interval': 2.0},
        {'name': 'thermostat', 'telemetry_interval': 50.0, 'heartbeat_interval': 22.0, 'poll_interval': 1.3},
        {'name': 'smart-plug', 'telemetry_interval': 35.0, 'heartbeat_interval': 15.0, 'poll_interval': 0.9},
    ]
    
    for i in range(args.devices):
        config = random.choice(device_types).copy()
        config['id'] = i
        # Add randomness to intervals
        config['telemetry_interval'] *= random.uniform(0.8, 1.2)
        config['heartbeat_interval'] *= random.uniform(0.8, 1.2)
        device_configs.append(config)
        print(f"  Device {i+1}: {config['name']} (telemetry: {config['telemetry_interval']:.1f}s, "
              f"heartbeat: {config['heartbeat_interval']:.1f}s)")
    
    # Start device threads
    threads = []
    for config in device_configs:
        t = threading.Thread(
            target=simulate_device,
            args=(config, args.target, args.open_port, stop_at),
            daemon=True
        )
        t.start()
        threads.append(t)
    
    print(f"\n  All {args.devices} devices started. Running until {time.strftime('%H:%M:%S', time.localtime(time.time() + args.duration))}")
    
    # Congestion injection thread
    if args.congestion:
        def inject_congestion():
            # Wait for initial stabilization
            time.sleep(random.uniform(10, 20))
            
            while time.monotonic() < stop_at:
                # Random congestion bursts
                if random.random() < 0.3:  # 30% chance
                    congestion_burst(
                        args.target,
                        args.open_port,
                        duration=random.uniform(5, 12),
                        intensity='mild'
                    )
                
                # Wait before next potential burst
                time.sleep(random.uniform(20, 45))
        
        cong_thread = threading.Thread(target=inject_congestion, daemon=True)
        cong_thread.start()
        threads.append(cong_thread)
    
    # Status updates
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
    
    # Wait for threads to complete
    for t in threads:
        t.join(timeout=2.0)
    
    print(f"\n{'='*70}")
    print(f"Simulation completed. Duration: {time.time() - start_time:.1f}s")
    print(f"{'='*70}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normal IoT Traffic Simulator - Light Load with Mild Congestion"
    )
    parser.add_argument("--target", required=True, help="Target Raspberry Pi IP address")
    parser.add_argument("--open-port", type=int, default=8080, help="Port accepting connections (dashboard port)")
    parser.add_argument("--duration", type=int, default=300, help="Simulation duration in seconds")
    parser.add_argument("--devices", type=int, default=5, help="Number of simulated IoT devices (3-8)")
    parser.add_argument("--congestion", action="store_true", default=True, help="Enable mild congestion bursts")
    parser.add_argument("--no-congestion", action="store_false", dest="congestion", help="Disable congestion")
    
    args = parser.parse_args()
    
    # Validation
    if args.devices < 1 or args.devices > 12:
        sys.exit("Error: --devices must be between 1 and 12")
    
    try:
        socket.inet_aton(args.target)
    except socket.error:
        sys.exit(f"Error: Invalid IP address: {args.target}")
    
    run_simulation(args)


if __name__ == "__main__":
    main()
