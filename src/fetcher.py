"""
ThreatWeave — Live Windows Event Log Fetcher
Fetches the latest N logs from this device via wevtutil.exe.
Security channel requires Administrator privileges.

UAC elevation:
  request_admin_elevation(channel) relaunches the app via ShellExecute "runas"
  which triggers the Windows UAC permission popup — no custom dialog needed.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from typing import Optional

from models import WindowsEvent    # type: ignore[import]
from parser import WindowsParser   # type: ignore[import]

_MAIN_CHANNELS  = ["Application", "System", "Security"]
_ADMIN_CHANNELS = {"Security"}


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    if not sys.platform.startswith("win"):
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def request_admin_elevation(channel: str = "") -> bool:
    """
    Trigger the Windows UAC elevation prompt via ShellExecute "runas".

    This relaunches ThreatWeave with Administrator rights.
    The new admin process auto-selects and fetches the requested channel.
    The calling process should close itself after this returns True.

    Returns True  → UAC prompt was shown (user may have approved or denied).
    Returns False → Not on Windows, or ShellExecute failed.
    """
    if not sys.platform.startswith("win"):
        return False

    # Build the executable + parameters to pass to the elevated process
    if getattr(sys, "frozen", False):
        # Running as a PyInstaller .exe
        exe    = sys.executable
        params = f'--channel "{channel}" --autofetch' if channel else "--autofetch"
    else:
        # Running as python app.py
        exe    = sys.executable
        script = str(__import__("pathlib").Path(sys.argv[0]).resolve())
        params = f'"{script}" --channel "{channel}" --autofetch' if channel else f'"{script}" --autofetch'

    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None,      # parent window handle
            "runas",   # verb  →  triggers UAC
            exe,       # executable
            params,    # command-line parameters
            None,      # working directory (None = current)
            1,         # SW_SHOWNORMAL
        )
        # ShellExecute returns > 32 on success
        return int(result) > 32
    except Exception as exc:
        print(f"[UAC] ShellExecuteW failed: {exc}")
        return False


class LiveFetcher:
    """
    Fetch live Windows Event Logs using wevtutil.exe.
    Always returns the latest max_events entries — no time filter.
    """

    def __init__(self) -> None:
        self._parser     = WindowsParser()
        self._is_windows = sys.platform.startswith("win")

    # ── Public API ────────────────────────────────────────────────────────

    def fetch(
        self,
        channel:    Optional[str] = None,
        max_events: int = 500,
    ) -> list[WindowsEvent]:
        """
        Fetch the latest max_events from one or all channels.
        Raises PermissionError("NEEDS_ADMIN") if Security is requested without elevation.
        Returns demo events on non-Windows.
        """
        if not self._is_windows:
            return self._demo_events()

        target = channel if channel and channel != "All Channels" else None

        if target in _ADMIN_CHANNELS and not is_admin():
            raise PermissionError("NEEDS_ADMIN")

        if target is None:
            results: list[WindowsEvent] = []
            per = max(50, max_events // len(_MAIN_CHANNELS))
            for ch in _MAIN_CHANNELS:
                if ch in _ADMIN_CHANNELS and not is_admin():
                    continue
                try:
                    results.extend(self._fetch_channel(ch, per))
                except PermissionError:
                    pass
                except Exception as exc:
                    print(f"[Fetcher] {ch}: {exc}")
            return results

        return self._fetch_channel(target, max_events)

    # ── Internal ──────────────────────────────────────────────────────────

    def _fetch_channel(self, channel: str, max_events: int) -> list[WindowsEvent]:
        """Run wevtutil and parse the XML stream. No time filter — latest N only."""
        cmd = [
            "wevtutil.exe", "qe", channel,
            f"/c:{max_events}",
            "/f:xml",
            "/rd:true",        # newest first
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=120)
        except FileNotFoundError:
            raise RuntimeError("wevtutil.exe not found — ThreatWeave requires Windows.")
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Timeout fetching '{channel}'. Try reducing Max Events.")

        if proc.returncode != 0:
            stderr = self._decode(proc.stderr).lower()
            if any(x in stderr for x in
                   ["access is denied", "error code 5", "1314", "privilege"]):
                raise PermissionError("NEEDS_ADMIN")
            if any(x in stderr for x in
                   ["could not open", "not found", "does not exist"]):
                print(f"[Fetcher] Channel not available: {channel}")
                return []
            raise RuntimeError(
                f"wevtutil error for '{channel}': "
                f"{self._decode(proc.stderr).strip()}")

        xml_text = self._decode(proc.stdout).lstrip("\ufeff")
        if not xml_text.strip():
            return []
        return self._parser.parse_xml_stream(xml_text, channel)

    @staticmethod
    def _decode(data: bytes) -> str:
        for enc in ("utf-8-sig", "utf-16", "latin-1"):
            try:
                return data.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return data.decode("utf-8", errors="replace")

    def _demo_events(self) -> list[WindowsEvent]:
        """Demo events for non-Windows development."""
        from parser import _SEV, _CAT      # type: ignore[import]
        now  = datetime.now()
        host = os.environ.get("COMPUTERNAME", "WIN11-DEMO")
        rows = [
            ("Security","4","4624","jsmith","192.168.1.10",""),
            ("Security","4","4688","jsmith","","powershell.exe"),
            ("Security","4","4698","jsmith","",""),
            ("Security","2","4688","jsmith","","mimikatz.exe"),
            ("Security","4","4624","administrator","192.168.1.50",""),
            ("Security","4","1102","administrator","",""),
            ("System",  "2","7045","","",""),
            ("System",  "3","7034","","","svchost.exe"),
            ("Application","4","1000","","","explorer.exe"),
            ("Application","2","1002","","","chrome.exe"),
            ("Security","4","4688","jsmith","","cmd.exe"),
            ("Security","4","4672","administrator","",""),
        ]
        events: list[WindowsEvent] = []
        for i, (ch, lvl, eid, user, ip, proc) in enumerate(rows):
            ts = (now - timedelta(minutes=i * 10)).strftime("%Y-%m-%dT%H:%M:%S")
            events.append(WindowsEvent(
                timestamp    = ts,
                host         = host,
                channel      = ch,
                severity     = _SEV.get(lvl, "info"),
                event_id     = eid,
                category     = _CAT.get(eid, f"Event {eid}"),
                raw_message  = (
                    f"[Demo] Channel={ch} EventID={eid} "
                    f"User={user} IP={ip} Process={proc}"
                ),
                username     = user or None,
                source_ip    = ip   or None,
                process_name = proc or None,
            ))
        return events
