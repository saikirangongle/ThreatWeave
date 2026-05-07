"""ThreatWeave — Core data models (Windows-only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ── Windows Event Log entry ────────────────────────────────────────────────────

@dataclass
class WindowsEvent:
    """Represents one normalised Windows Event Log entry."""
    timestamp:    str             # ISO-8601 or raw TimeCreated SystemTime
    host:         str             # Computer name
    channel:      str             # Security | System | Application | …
    severity:     str             # critical | high | medium | low | info
    event_id:     str             # e.g. "4624"
    category:     str             # Human-readable label
    raw_message:  str             # Full XML or text representation
    username:     Optional[str] = None
    source_ip:    Optional[str] = None
    process_name: Optional[str] = None
    extra:        dict = field(default_factory=dict)


# ── MITRE ATT&CK match ────────────────────────────────────────────────────────

@dataclass
class MITREMatch:
    """One MITRE ATT&CK technique match for a WindowsEvent."""
    rule_id:        str
    technique_id:   str     # e.g. "T1059.001"
    technique_name: str
    tactic:         str     # e.g. "execution"
    confidence:     str     # high | medium | low
    event:          WindowsEvent

    @property
    def base_tid(self) -> str:
        """Return base technique without sub-technique, e.g. T1059."""
        return self.technique_id.split(".")[0]


# ── Attack session ─────────────────────────────────────────────────────────────

@dataclass
class AttackSession:
    """A time-windowed group of related MITRE matches."""
    session_id:  int
    events:      list[WindowsEvent] = field(default_factory=list)
    techniques:  list[str] = field(default_factory=list)   # ordered, deduplicated
    start_time:  Optional[datetime] = None
    end_time:    Optional[datetime] = None
    hosts:       set = field(default_factory=set)

    @property
    def duration_minutes(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds() / 60
        return 0.0

    @property
    def event_count(self) -> int:
        return len(self.events)


# ── Prediction result ─────────────────────────────────────────────────────────

@dataclass
class PredictionResult:
    """One predicted next MITRE technique."""
    technique_id:   str
    technique_name: str
    tactic:         str
    probability:    float        # 0.0 – 1.0
    threat_groups:  list[str]
    nist_controls:  list[str]
    reasoning:      str


# ── Narrative result ──────────────────────────────────────────────────────────

@dataclass
class NarrativeResult:
    """AI-generated threat narrative for a session."""
    narrative:       str
    severity:        str          # Critical | High | Medium | Low
    severity_reason: str
    response_actions: list[str]
    raw_response:    str = ""
