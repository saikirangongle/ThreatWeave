"""
ThreatWeave — Windows Event Log Parser
Supports: .evtx (binary), .xml (EVTX export), .log / .txt (plain text)
Windows logs ONLY.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from models import WindowsEvent  # type: ignore[import]


# ── Severity map (Level field values) ─────────────────────────────────────────
_SEV: dict[str, str] = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "info",
    "5": "info",
}

# ── Human-readable categories for common Event IDs ────────────────────────────
_CAT: dict[str, str] = {
    "1100": "Event log service shut down",
    "1102": "Security audit log cleared",
    "4608": "Windows starting up",
    "4616": "System time changed",
    "4624": "Successful logon",
    "4625": "Failed logon",
    "4634": "Account logoff",
    "4647": "User-initiated logoff",
    "4648": "Logon with explicit credentials",
    "4656": "Handle to object requested",
    "4657": "Registry value modified",
    "4660": "Object deleted",
    "4663": "Object access attempt",
    "4670": "Permissions on object changed",
    "4672": "Special privileges assigned to new logon",
    "4673": "Privileged service called",
    "4674": "Operation attempted on privileged object",
    "4688": "Process created",
    "4689": "Process exited",
    "4697": "Service installed",
    "4698": "Scheduled task created",
    "4699": "Scheduled task deleted",
    "4700": "Scheduled task enabled",
    "4701": "Scheduled task disabled",
    "4702": "Scheduled task updated",
    "4717": "System security access granted to account",
    "4719": "System audit policy changed",
    "4720": "User account created",
    "4722": "User account enabled",
    "4723": "Password change attempted",
    "4724": "Password reset attempted",
    "4725": "User account disabled",
    "4726": "User account deleted",
    "4728": "Member added to global security group",
    "4729": "Member removed from global security group",
    "4732": "Member added to local security group",
    "4733": "Member removed from local security group",
    "4738": "User account changed",
    "4740": "User account locked out",
    "4756": "Member added to universal security group",
    "4768": "Kerberos TGT requested",
    "4769": "Kerberos service ticket requested",
    "4771": "Kerberos pre-authentication failed",
    "4776": "NTLM credential validation",
    "4946": "Windows Firewall rule added",
    "4950": "Windows Firewall setting changed",
    "5140": "Network share object accessed",
    "5145": "Network share object checked",
    "5156": "Windows Filtering Platform: connection allowed",
    "5158": "Windows Filtering Platform: bind to port allowed",
    "7034": "Service crashed unexpectedly",
    "7035": "Service control request sent",
    "7036": "Service state changed",
    "7045": "New service installed",
}

# XML namespace used by Windows Event Log
_NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Regex to extract individual <Event> blocks from a stream
_BLOCK_RE = re.compile(r"<Event\b[^>]*>.*?</Event>", re.DOTALL | re.IGNORECASE)


class WindowsParser:
    """Parse Windows Event Log entries from .evtx / .xml / .log files."""

    # ── Public entry point ────────────────────────────────────────────────

    def load_file(self, path: str) -> list[WindowsEvent]:
        """Auto-detect format and return list of WindowsEvent objects."""
        suffix = Path(path).suffix.lower()
        if suffix == ".evtx":
            return self._load_evtx(path)
        if suffix == ".xml":
            return self._load_xml(path)
        # .log, .txt — try XML blocks first, then plain text
        return self._load_text(path)

    def parse_xml_stream(self, xml_text: str, channel: str = "") -> list[WindowsEvent]:
        """
        Parse a raw stream of <Event> XML blocks (output from wevtutil /f:xml).
        This is the primary path for live-fetched logs.
        """
        events: list[WindowsEvent] = []
        for block in _BLOCK_RE.findall(xml_text):
            ev = self._parse_block(block, channel)
            if ev is not None:
                events.append(ev)
        return events

    # ── Format-specific loaders ───────────────────────────────────────────

    def _load_evtx(self, path: str) -> list[WindowsEvent]:
        """Parse binary .evtx using python-evtx (optional dependency)."""
        try:
            import Evtx.Evtx as evtx  # type: ignore[import]
        except ImportError:
            print("[Parser] python-evtx not installed. Run: pip install python-evtx")
            return []
        events: list[WindowsEvent] = []
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        ev = self._parse_block(record.xml(), "")
                        if ev is not None:
                            events.append(ev)
                    except Exception:
                        continue
        except Exception as exc:
            print(f"[Parser] EVTX error: {exc}")
        return events

    def _load_xml(self, path: str) -> list[WindowsEvent]:
        """Parse a .xml EVTX export (Event Viewer or wevtutil /f:xml to file)."""
        try:
            raw = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[Parser] Cannot read file: {exc}")
            return []

        # Strip BOM
        raw = raw.lstrip("\ufeff")

        # Try as a well-formed XML document first
        try:
            root = ET.fromstring(raw)
            events: list[WindowsEvent] = []
            for el in root.iter():
                tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
                if tag == "Event":
                    ev = self._parse_element(el)
                    if ev is not None:
                        events.append(ev)
            return events
        except ET.ParseError:
            pass

        # Fall back: extract individual <Event> blocks via regex
        return self.parse_xml_stream(raw)

    def _load_text(self, path: str) -> list[WindowsEvent]:
        """Parse .log or .txt files — try XML blocks first, then plain lines."""
        try:
            raw = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[Parser] Cannot read file: {exc}")
            return []

        # If file contains XML Event blocks
        blocks = _BLOCK_RE.findall(raw)
        if blocks:
            return self.parse_xml_stream(raw)

        # Plain text fallback — one event per non-empty line
        events: list[WindowsEvent] = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                events.append(WindowsEvent(
                    timestamp="",
                    host="unknown",
                    channel="text",
                    severity="info",
                    event_id="",
                    category="Raw log entry",
                    raw_message=line[:3000],
                ))
        return events

    # ── XML parsing helpers ────────────────────────────────────────────────

    def _parse_block(self, xml_text: str, channel: str) -> Optional[WindowsEvent]:
        """Parse a single XML block string into a WindowsEvent."""
        try:
            root = ET.fromstring(xml_text)
            ev = self._parse_element(root)
            if ev is not None and channel:
                ev.channel = channel
            return ev
        except ET.ParseError:
            return None

    def _parse_element(self, evt: ET.Element) -> Optional[WindowsEvent]:
        """Parse a single <Event> Element into a WindowsEvent."""
        try:
            # Try namespaced, then non-namespaced System element
            sys_el = evt.find("w:System", _NS)
            if sys_el is None:
                sys_el = evt.find("System")
            if sys_el is None:
                return None

            def _find(tag: str) -> Optional[ET.Element]:
                el = sys_el.find(f"w:{tag}", _NS)  # type: ignore[union-attr]
                if el is None:
                    el = sys_el.find(tag)           # type: ignore[union-attr]
                return el

            eid_el  = _find("EventID")
            lev_el  = _find("Level")
            tc_el   = _find("TimeCreated")
            comp_el = _find("Computer")
            chan_el = _find("Channel")

            event_id  = eid_el.text.strip()  if eid_el  is not None and eid_el.text  else ""
            level     = lev_el.text.strip()  if lev_el  is not None and lev_el.text  else "4"
            timestamp = tc_el.get("SystemTime", "")  if tc_el  is not None else ""
            host      = comp_el.text.strip() if comp_el is not None and comp_el.text else "unknown"
            channel   = chan_el.text.strip() if chan_el is not None and chan_el.text  else ""

            # Parse EventData / UserData fields
            extra: dict      = {}
            username         = None
            source_ip        = None
            process_name     = None

            for ed_tag in ("w:EventData", "EventData"):
                ns_arg = _NS if ed_tag.startswith("w:") else {}
                ed = evt.find(ed_tag, ns_arg) if ns_arg else evt.find(ed_tag)
                if ed is not None:
                    for d in list(ed):
                        name  = d.get("Name", "")
                        if not name:
                            name = d.tag.split("}")[-1] if "}" in d.tag else d.tag
                        value = (d.text or "").strip()
                        if not value:
                            continue
                        extra[name] = value
                        nl = name.lower()
                        # Extract key fields
                        if nl in ("subjectusername", "targetusername", "username"):
                            if value not in ("-", "SYSTEM", "LOCAL SERVICE",
                                             "NETWORK SERVICE", ""):
                                username = value
                        if nl == "ipaddress" and value not in ("-", "::1",
                                                                "127.0.0.1", ""):
                            source_ip = value
                        if nl == "newprocessname" and value:
                            process_name = Path(value).name
                    break

            raw = ET.tostring(evt, encoding="unicode")[:3000]

            return WindowsEvent(
                timestamp    = timestamp,
                host         = host,
                channel      = channel or "Unknown",
                severity     = _SEV.get(level, "info"),
                event_id     = event_id,
                category     = _CAT.get(event_id,
                                        f"Event {event_id}" if event_id else "Unknown"),
                raw_message  = raw,
                username     = username,
                source_ip    = source_ip,
                process_name = process_name,
                extra        = extra,
            )
        except Exception:
            return None
