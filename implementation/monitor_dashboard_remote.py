"""IoT Edge DDoS Perception Dashboard — Remote Mode

This version can run on your LAPTOP and fetch data from Raspberry Pi via network.

Usage on Laptop:
    python monitor_dashboard_remote.py --remote pi@192.168.137.X:~/edge/reports --port 8080

Opens browser: http://localhost:8080
Dashboard fetches data from Pi over network
"""

import argparse
import json
import os
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Import the original dashboard HTML
import monitor_dashboard

class RemoteFileCache:
    """Fetch files from Raspberry Pi via SCP/SSH"""
    
    def __init__(self, remote_path: str, cache_dir: Path):
        self.remote_path = remote_path  # Format: "pi@192.168.1.10:~/edge/reports"
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.last_fetch = {}
        
    def _scp_fetch(self, remote_file: str, local_file: Path) -> bool:
        """Fetch a single file via SCP"""
        remote_full = f"{self.remote_path}/{remote_file}"
        try:
            result = subprocess.run(
                ["scp", "-o", "ConnectTimeout=2", remote_full, str(local_file)],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_file(self, filename: str, max_age: float = 1.0) -> Path:
        """Get file from Pi, using cache if recent"""
        local_file = self.cache_dir / filename
        now = time.time()
        
        # Return cached if fresh
        if filename in self.last_fetch:
            if now - self.last_fetch[filename] < max_age and local_file.exists():
                return local_file
        
        # Fetch from Pi
        if self._scp_fetch(filename, local_file):
            self.last_fetch[filename] = now
            return local_file
        
        # Return stale cache if fetch failed
        return local_file if local_file.exists() else None


def make_remote_handler(cache: RemoteFileCache):
    """Create HTTP handler that fetches from remote Pi"""
    
    class RemoteHandler(monitor_dashboard.make_handler(
        cache.cache_dir / "detector_state.json",
        cache.cache_dir / "monitor_events.jsonl",
        cache.cache_dir / "model_comparison_report.json",
        cache.cache_dir / "control_commands.json"
    )):
        
        def do_GET(self):
            # Fetch fresh data from Pi before serving
            if self.path == "/state":
                cache.get_file("detector_state.json", max_age=0.5)
            elif self.path.startswith("/events"):
                cache.get_file("monitor_events.jsonl", max_age=0.5)
            elif self.path == "/benchmark":
                cache.get_file("model_comparison_report.json", max_age=10.0)
            
            # Call original handler
            super().do_GET()
        
        def do_POST(self):
            # Handle control commands
            super().do_POST()
            # Upload updated control file back to Pi
            control_file = cache.cache_dir / "control_commands.json"
            if control_file.exists():
                cache._scp_fetch("control_commands.json", control_file)  # Reverse: upload
    
    return RemoteHandler


def main():
    parser = argparse.ArgumentParser(description="IoT Edge Flood Monitor Dashboard - Remote Mode")
    parser.add_argument("--remote", required=True, 
                        help="Remote Pi path: pi@192.168.1.10:~/edge/reports")
    parser.add_argument("--host", default="127.0.0.1", 
                        help="Local host to bind (use 0.0.0.0 for network access)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--cache-dir", default=None,
                        help="Local cache directory (default: temp)")
    args = parser.parse_args()
    
    # Setup cache
    cache_dir = Path(args.cache_dir) if args.cache_dir else Path(tempfile.gettempdir()) / "fuzzy_dashboard_cache"
    cache = RemoteFileCache(args.remote, cache_dir)
    
    # Test connection
    print(f"Testing connection to {args.remote}...")
    test_file = cache.get_file("detector_state.json")
    if test_file and test_file.exists():
        print(f"✅ Connection OK - fetched detector_state.json")
    else:
        print(f"⚠️  Warning: Could not fetch files from Pi")
        print(f"    Make sure:")
        print(f"    1. Pi is running at that address")
        print(f"    2. You can SSH without password (ssh-copy-id)")
        print(f"    3. Detector has created files in {args.remote}")
    
    print(f"\n📊 Dashboard URL: http://{args.host}:{args.port}")
    print(f"📂 Cache directory: {cache_dir}")
    print(f"🔄 Fetching from: {args.remote}")
    print(f"\nPress Ctrl+C to stop\n")
    
    server = ThreadingHTTPServer(
        (args.host, args.port),
        make_remote_handler(cache)
    )
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down...")


if __name__ == "__main__":
    main()
