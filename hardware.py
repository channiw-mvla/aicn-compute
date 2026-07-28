"""Detect what a device can advertise: CPU cores, RAM, and any GPUs.

Everything here degrades gracefully — psutil is used when present, otherwise we
fall back to the standard library and platform-specific calls so the node agent
still reports something sensible on a bare install.
"""

import os
import platform
import shutil
import socket
import subprocess
import sys

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None


def _total_ram_mb() -> int:
    """Best-effort total physical RAM in MB."""
    if psutil is not None:
        return int(psutil.virtual_memory().total / (1024 * 1024))

    # POSIX: sysconf pages * page size
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return int(pages * page_size / (1024 * 1024))
    except (ValueError, AttributeError, OSError):
        pass

    # Windows: GlobalMemoryStatusEx via ctypes
    if sys.platform == "win32":
        try:
            import ctypes

            class MemStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MemStatus()
            stat.dwLength = ctypes.sizeof(MemStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return int(stat.ullTotalPhys / (1024 * 1024))
        except Exception:
            pass

    return 0  # unknown


def _nvidia_smi():
    """Locate nvidia-smi even when it isn't on the agent's PATH."""
    found = shutil.which("nvidia-smi")
    if found:
        return found
    for c in (r"C:\Windows\System32\nvidia-smi.exe",
              r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
              "/usr/bin/nvidia-smi", "/usr/local/nvidia/bin/nvidia-smi"):
        if os.path.exists(c):
            return c
    return None


def _detect_nvidia() -> list:
    smi = _nvidia_smi()
    if smi is None:
        return []
    try:
        out = subprocess.run(
            [smi, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return []
    gpus = []
    for line in out.stdout.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if not parts or not parts[0]:
            continue
        vram = 0
        if len(parts) >= 2:
            try:
                vram = int(float(parts[1]))
            except ValueError:
                vram = 0
        gpus.append({"name": parts[0], "vram_mb": vram, "vendor": "nvidia"})
    return gpus


def _detect_amd() -> list:
    smi = shutil.which("rocm-smi")
    if smi is None:
        return []
    try:
        out = subprocess.run([smi, "--showproductname"],
                             capture_output=True, text=True, timeout=8)
    except Exception:
        return []

    import re
    # Pick the best human-readable name per GPU index. Card Series is ideal, but
    # falls back to the GFX arch (e.g. gfx1201) or model when libdrm can't
    # resolve the marketing name.
    names, gfx, model = {}, {}, {}
    for line in out.stdout.splitlines():
        m = re.search(r"GPU\[(\d+)\]", line)
        if not m:
            continue
        idx = int(m.group(1))
        low = line.lower()
        val = line.split(":")[-1].strip()
        if "card series" in low and val and val.upper() != "N/A":
            names[idx] = val
        elif "gfx version" in low and val:
            gfx[idx] = val
        elif ("card model" in low or "card sku" in low) and val and val.upper() != "N/A":
            model.setdefault(idx, val)

    indices = set(names) | set(gfx) | set(model)
    gpus = []
    for idx in sorted(indices):
        name = names.get(idx) or \
            (f"AMD GPU ({gfx[idx]})" if idx in gfx else None) or \
            model.get(idx) or "AMD GPU"
        gpus.append({"name": name, "vram_mb": _amd_vram_mb(smi, idx), "vendor": "amd"})
    return gpus


def _amd_vram_mb(smi, idx) -> int:
    """Best-effort total VRAM for GPU[idx] in MB (0 if unknown)."""
    try:
        out = subprocess.run([smi, "--showmeminfo", "vram"],
                             capture_output=True, text=True, timeout=8)
    except Exception:
        return 0
    import re
    for line in out.stdout.splitlines():
        m = re.search(r"GPU\[(\d+)\]", line)
        if not m or int(m.group(1)) != idx:
            continue
        if "total" in line.lower():
            nums = re.findall(r"\d+", line.split(":")[-1])
            if nums:
                val = int(nums[-1])
                # rocm-smi usually reports bytes; convert if it looks like bytes.
                return val // (1024 * 1024) if val > 10 ** 7 else val
    return 0


def _detect_gpus() -> list:
    """Best-effort GPU list. NVIDIA (nvidia-smi) first, then AMD (rocm-smi)."""
    gpus = _detect_nvidia()
    if not gpus:
        gpus = _detect_amd()
    return gpus


def _physical_cores():
    """Physical core count (distinct from logical/threads), or None if unknown."""
    if psutil is not None:
        try:
            return psutil.cpu_count(logical=False)
        except Exception:
            return None
    return None


def _cpu_model() -> str:
    """Best-effort human-readable CPU model string."""
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/cpuinfo", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        elif sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                 capture_output=True, text=True, timeout=3)
            if out.stdout.strip():
                return out.stdout.strip()
        elif sys.platform == "win32":
            return os.environ.get("PROCESSOR_IDENTIFIER", "") or platform.processor()
    except Exception:
        pass
    return platform.processor() or "unknown"


def detect_hardware() -> dict:
    """Snapshot of this device's advertisable capabilities."""
    gpus = _detect_gpus()
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}".strip(),
        "arch": platform.machine(),
        "cpu": os.cpu_count() or 1,          # logical processors (threads)
        "cores": _physical_cores(),          # physical cores (may be None)
        "cpu_model": _cpu_model(),
        "ram_mb": _total_ram_mb(),
        "gpu": len(gpus),
        "vram_mb": sum(g.get("vram_mb", 0) for g in gpus),
        "gpus": gpus,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(detect_hardware(), indent=2))
