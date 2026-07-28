"""Owner control — the feature that makes people share (proposal section 04).

The Scheduler decides, at any instant, whether this device is currently
lendable. It reads a small config dict and combines four owner controls:

  * on / off toggle   -> config["enabled"]
  * scheduled hours   -> config["schedule"]  (recurring weekday windows)
  * idle auto-detect  -> config["idle"]      (only share when untouched / quiet)
  * instant reclaim    -> derived: the moment the owner is active again the
                          device reports UNAVAILABLE, and the agent evicts any
                          running borrowed job.

`is_available()` returns (bool, reason). The agent polls it; when the answer
flips from available to unavailable while a job is running, the owner has
effectively reclaimed the machine.
"""

import sys
import time
from datetime import datetime

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None


def _input_idle_seconds():
    """Seconds since the last keyboard/mouse input, or None if we can't tell.

    Windows uses GetLastInputInfo. On other platforms desktop idle time is not
    reliably available without extra tooling, so we return None and let the CPU
    threshold stand in for "the machine is quiet".
    """
    if sys.platform == "win32":
        try:
            import ctypes

            class LastInputInfo(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_ulong)]

            info = LastInputInfo()
            info.cbSize = ctypes.sizeof(LastInputInfo)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
                millis = ctypes.windll.kernel32.GetTickCount() - info.dwTime
                return max(0.0, millis / 1000.0)
        except Exception:
            return None
    return None


class Scheduler:
    def __init__(self, config: dict):
        self.config = config or {}

    # -- individual controls -------------------------------------------------
    def _enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    def _within_hours(self, now: datetime) -> bool:
        """True if `now` falls in a configured window. Empty schedule = always."""
        windows = self.config.get("schedule") or []
        if not windows:
            return True
        minute_of_day = now.hour * 60 + now.minute
        weekday = now.weekday()  # Mon=0 .. Sun=6
        for win in windows:
            days = win.get("days")
            if days is not None and weekday not in days:
                continue
            start = _parse_hhmm(win.get("start", "00:00"))
            end = _parse_hhmm(win.get("end", "24:00"))
            if start <= end:
                if start <= minute_of_day < end:
                    return True
            else:
                # window wraps past midnight, e.g. 00:00 shown as 24:00 handled,
                # but 22:00-06:00 wraps
                if minute_of_day >= start or minute_of_day < end:
                    return True
        return False

    def _is_idle(self):
        """True/False if idle-detect is on; None when it is disabled."""
        idle_cfg = self.config.get("idle") or {}
        if not idle_cfg.get("require_idle", False):
            return None

        idle_seconds = idle_cfg.get("idle_seconds", 300)
        max_cpu = idle_cfg.get("max_cpu_percent", 25)

        # "untouched for a set time" — desktop input idle (Windows only)
        since_input = _input_idle_seconds()
        if since_input is not None and since_input >= idle_seconds:
            return True

        # "or its usage is below a threshold" — cross-platform CPU proxy
        if psutil is not None:
            cpu = psutil.cpu_percent(interval=None)
            if cpu <= max_cpu:
                return True
            return False

        # No input signal and no psutil: can't prove the owner is away.
        return False if since_input is None else since_input >= idle_seconds

    # -- combined decision ---------------------------------------------------
    def is_available(self):
        if not self._enabled():
            return False, "off"
        if not self._within_hours(datetime.now()):
            return False, "outside_hours"
        idle = self._is_idle()
        if idle is False:
            return False, "in_use"
        return True, "available"


def _parse_hhmm(text: str) -> int:
    """'HH:MM' -> minutes since midnight. '24:00' allowed as end-of-day."""
    try:
        hh, mm = text.split(":")
        return int(hh) * 60 + int(mm)
    except Exception:
        return 0


if __name__ == "__main__":
    # quick manual check
    s = Scheduler({"enabled": True, "schedule": [], "idle": {"require_idle": False}})
    for _ in range(3):
        print(s.is_available())
        time.sleep(0.5)
