"""ThreatWeave — MITRE ATT&CK Mapper (Windows rules)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
except ModuleNotFoundError:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "pyyaml"],
        check=True,
    )
    import yaml  # type: ignore[import]

from models import MITREMatch, WindowsEvent  # type: ignore[import]

_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"


class MITREMapper:
    """Maps WindowsEvent objects to MITRE ATT&CK techniques via YAML rules."""

    def __init__(self, rules_path: Optional[str] = None) -> None:
        path = Path(rules_path) if rules_path else _RULES_PATH
        self.rules: list[dict] = []
        if path.exists():
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self.rules = data.get("rules", [])
            print(f"[Mapper] Loaded {len(self.rules)} rules from {path.name}")
        else:
            print(f"[Mapper] Rules file not found: {path}")

    # ── Public API ────────────────────────────────────────────────────────

    def map_event(self, event: WindowsEvent) -> list[MITREMatch]:
        """Return all MITRE matches for a single event."""
        return [
            MITREMatch(
                rule_id        = rule["id"],
                technique_id   = rule["technique_id"],
                technique_name = rule["technique_name"],
                tactic         = rule["tactic"],
                confidence     = rule["confidence"],
                event          = event,
            )
            for rule in self.rules
            if self._matches(rule, event)
        ]

    def map_events(self, events: list[WindowsEvent]) -> list[MITREMatch]:
        """Return all MITRE matches for a list of events."""
        matches: list[MITREMatch] = []
        for ev in events:
            matches.extend(self.map_event(ev))
        return matches

    def technique_chain(self, matches: list[MITREMatch]) -> list[str]:
        """Return ordered, deduplicated technique IDs from matches."""
        seen: set[str] = set()
        chain: list[str] = []
        for m in matches:
            if m.technique_id not in seen:
                seen.add(m.technique_id)
                chain.append(m.technique_id)
        return chain

    def tactic_summary(self, matches: list[MITREMatch]) -> dict[str, int]:
        """Return tactic → event-count mapping."""
        summary: dict[str, int] = {}
        for m in matches:
            summary[m.tactic] = summary.get(m.tactic, 0) + 1
        return summary

    # ── Internal ──────────────────────────────────────────────────────────

    def _matches(self, rule: dict, event: WindowsEvent) -> bool:
        """Return True if ALL conditions in the rule match the event."""
        for key, val in rule.get("conditions", {}).items():
            v = str(val)
            if key == "event_id":
                if event.event_id != v:
                    return False
            elif key == "process_contains":
                haystack = (
                    (event.process_name or "")
                    + " "
                    + event.raw_message
                ).lower()
                if v.lower() not in haystack:
                    return False
            elif key == "message_contains":
                if v.lower() not in event.raw_message.lower():
                    return False
            elif key == "severity":
                if event.severity != v.lower():
                    return False
            elif key == "username_contains":
                if v.lower() not in (event.username or "").lower():
                    return False
        return True
