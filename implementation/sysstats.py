"""Tiny cross-platform system telemetry for the edge detector and dashboard.

Used to show how much computation the on-device defence consumes. Prefers
psutil when available; otherwise falls back to /proc (Linux/Raspberry Pi) and
ctypes (Windows). Every function degrades gracefully to None so the pipeline
never breaks on an unsupported platform.
"""

import os
import time

try:
    import psutil  # type: ignore

    _PSUTIL = True
except Exception:
    psutil = None
    _PSUTIL = False

_P = psutil.Process() if _PSUTIL else None


def _last_cpu_time() -> float:
    if _PSUTIL:
        return _P.cpu_times().user + _P.cpu_times().system
    try:
        with open("/proc/self/stat", "rb") as f:
            parts = f.read().split()
        hz = os.sysconf("SC_CLK_TCK")
        utime, stime = int(parts[13]), int(parts[14])
        return (utime + stime) / hz
    except Exception:
        return time.process_time()


def process_snapshot() -> dict:
    """CPU% (vs one core), RSS in MB, and thread count for this process."""
    global _last_sample
    now = time.monotonic()
    cpu_now = _last_cpu_time()
    prev_t, prev_c = _last_sample
    dt = now - prev_t
    cpu_pct = max(0.0, min(100.0 * (cpu_now - prev_c) / dt, 100.0)) if dt > 0 else 0.0
    _last_sample = (now, cpu_now)

    rss_mb = None
    if _PSUTIL:
        rss_mb = _P.memory_info().rss / (1024 * 1024)
    else:
        try:
            with open("/proc/self/status", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss_mb = int(line.split()[1]) / 1024
                        break
        except Exception:
            pass

    return {
        "proc_cpu_percent": round(cpu_pct, 1),
        "proc_rss_mb": round(rss_mb, 1) if rss_mb is not None else None,
        "backend": "psutil" if _PSUTIL else "proc",
    }


_last_sample = (time.monotonic(), _last_cpu_time())


def system_snapshot() -> dict:
    """Whole-device CPU %, RAM used/total, and load average (Pi-friendly)."""
    out: dict = {}
    if _PSUTIL:
        out["cpu_percent"] = psutil.cpu_percent(interval=None)
        vm = psutil.virtual_memory()
        out["ram_used_mb"] = round(vm.used / (1024 * 1024), 1)
        out["ram_total_mb"] = round(vm.total / (1024 * 1024), 1)
        try:
            out["cpu_temp_c"] = psutil.sensors_temperatures().get(
                "cpu_thermal", [None]
            )[0].current
        except Exception:
            out["cpu_temp_c"] = None
        return out

    # /proc/stat fallback (Linux)
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            parts = f.readline().split()[1:]
        vals = list(map(int, parts))
        total = sum(vals)
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        global _sys_prev
        prev = _sys_prev or (total, idle)
        _sys_prev = (total, idle)
        d_tot, d_idle = total - prev[0], idle - prev[1]
        out["cpu_percent"] = round(100.0 * (1 - d_idle / d_tot), 1) if d_tot > 0 else None
    except Exception:
        out["cpu_percent"] = None

    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            info = {ln.split(":")[0]: int(ln.split()[1]) for ln in f.readlines()[:3]}
        total = info.get("MemTotal", 0) * 1024
        avail = info.get("MemAvailable", 0) * 1024
        out["ram_total_mb"] = round(total / (1024 * 1024), 1)
        out["ram_used_mb"] = round((total - avail) / (1024 * 1024), 1)
    except Exception:
        pass

    try:
        out["load_avg"] = round(os.getloadavg()[0], 2)
    except Exception:
        out["load_avg"] = None
    return out


_sys_prev = None


if __name__ == "__main__":
    a = process_snapshot()
    time.sleep(0.5)
    print(process_snapshot(), system_snapshot())
