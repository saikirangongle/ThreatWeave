"""
ThreatWeave — Core module tests
Run: pytest tests/ -v
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ is on path (also handled by conftest.py)
_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from models  import WindowsEvent, MITREMatch  # type: ignore[import]
from parser  import WindowsParser             # type: ignore[import]
from mapper  import MITREMapper               # type: ignore[import]
from analyzer import AttackChainEngine, SessionClusterer  # type: ignore[import]

_SAMPLE = str(
    Path(__file__).resolve().parent / "sample_logs" / "sample.xml"
)


# ─────────────────────────────────────────────────────────────────────────────
# Parser tests
# ─────────────────────────────────────────────────────────────────────────────

class TestWindowsParser:
    def setup_method(self) -> None:
        self.parser = WindowsParser()

    def test_load_xml_returns_events(self) -> None:
        events = self.parser.load_file(_SAMPLE)
        assert len(events) > 0, "Should parse at least one event"

    def test_events_have_required_fields(self) -> None:
        events = self.parser.load_file(_SAMPLE)
        for ev in events:
            assert isinstance(ev, WindowsEvent)
            assert ev.event_id != "" or ev.category != ""
            assert ev.severity in ("critical", "high", "medium", "low", "info")
            assert isinstance(ev.host, str) and ev.host != ""
            assert isinstance(ev.channel, str) and ev.channel != ""

    def test_known_event_ids_parsed(self) -> None:
        events = self.parser.load_file(_SAMPLE)
        ids = {ev.event_id for ev in events}
        assert "4624" in ids, "Should contain logon event (4624)"
        assert "4688" in ids, "Should contain process creation (4688)"
        assert "1102" in ids, "Should contain log clear event (1102)"
        assert "4698" in ids, "Should contain scheduled task event (4698)"

    def test_powershell_process_extracted(self) -> None:
        events = self.parser.load_file(_SAMPLE)
        ps_events = [
            ev for ev in events
            if ev.process_name and "powershell" in ev.process_name.lower()
        ]
        assert len(ps_events) > 0, "Should detect PowerShell process creation"

    def test_mimikatz_detected(self) -> None:
        events = self.parser.load_file(_SAMPLE)
        mimi = [
            ev for ev in events
            if ev.process_name and "mimikatz" in ev.process_name.lower()
        ]
        assert len(mimi) > 0, "Should detect mimikatz process"

    def test_usernames_extracted(self) -> None:
        events = self.parser.load_file(_SAMPLE)
        with_user = [ev for ev in events if ev.username]
        assert len(with_user) > 0, "Should extract at least one username"

    def test_ip_addresses_extracted(self) -> None:
        events = self.parser.load_file(_SAMPLE)
        with_ip = [ev for ev in events if ev.source_ip]
        assert len(with_ip) > 0, "Should extract at least one IP address"

    def test_parse_xml_stream(self) -> None:
        raw = Path(_SAMPLE).read_text(encoding="utf-8")
        events = self.parser.parse_xml_stream(raw, "Security")
        assert len(events) > 0
        for ev in events:
            assert ev.channel == "Security"

    def test_categories_are_human_readable(self) -> None:
        events = self.parser.load_file(_SAMPLE)
        for ev in events:
            assert not ev.category.startswith("Event ") or ev.event_id not in (
                "4624", "4688", "4698", "1102", "4624", "7045"
            ), f"Known EventID {ev.event_id} should have a human-readable category"


# ─────────────────────────────────────────────────────────────────────────────
# Mapper tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMITREMapper:
    def setup_method(self) -> None:
        self.mapper = MITREMapper()
        self.parser = WindowsParser()
        self.events = self.parser.load_file(_SAMPLE)

    def test_rules_loaded(self) -> None:
        assert len(self.mapper.rules) > 0, "Should load YAML rules"

    def test_logon_maps_to_t1078(self) -> None:
        ev = WindowsEvent(
            timestamp="2026-04-01T08:00:00Z",
            host="test", channel="Security",
            severity="info", event_id="4624",
            category="Successful logon", raw_message="<Event/>",
        )
        matches = self.mapper.map_event(ev)
        assert any(m.technique_id == "T1078" for m in matches)

    def test_powershell_maps_to_t1059(self) -> None:
        ev = WindowsEvent(
            timestamp="2026-04-01T08:00:00Z",
            host="test", channel="Security",
            severity="info", event_id="4688",
            category="Process created",
            raw_message="powershell.exe -encodedCommand aQBlAHgA",
            process_name="powershell.exe",
        )
        matches = self.mapper.map_event(ev)
        assert any("T1059" in m.technique_id for m in matches)

    def test_mimikatz_maps_to_t1003(self) -> None:
        ev = WindowsEvent(
            timestamp="2026-04-01T08:00:00Z",
            host="test", channel="Security",
            severity="high", event_id="4688",
            category="Process created",
            raw_message="mimikatz.exe sekurlsa::logonpasswords",
            process_name="mimikatz.exe",
        )
        matches = self.mapper.map_event(ev)
        assert any("T1003" in m.technique_id for m in matches)

    def test_log_clear_maps_to_t1070(self) -> None:
        ev = WindowsEvent(
            timestamp="2026-04-01T08:00:00Z",
            host="test", channel="Security",
            severity="high", event_id="1102",
            category="Log cleared", raw_message="<Event/>",
        )
        matches = self.mapper.map_event(ev)
        assert any("T1070" in m.technique_id for m in matches)

    def test_scheduled_task_maps_to_t1053(self) -> None:
        ev = WindowsEvent(
            timestamp="2026-04-01T08:00:00Z",
            host="test", channel="Security",
            severity="info", event_id="4698",
            category="Scheduled task created", raw_message="<Event/>",
        )
        matches = self.mapper.map_event(ev)
        assert any("T1053" in m.technique_id for m in matches)

    def test_service_install_maps_to_t1543(self) -> None:
        ev = WindowsEvent(
            timestamp="2026-04-01T08:00:00Z",
            host="test", channel="System",
            severity="info", event_id="7045",
            category="Service installed", raw_message="<Event/>",
        )
        matches = self.mapper.map_event(ev)
        assert any("T1543" in m.technique_id for m in matches)

    def test_map_sample_file(self) -> None:
        matches = self.mapper.map_events(self.events)
        assert len(matches) > 0, "Should find MITRE matches in sample file"

    def test_technique_chain_is_ordered_and_deduplicated(self) -> None:
        matches = self.mapper.map_events(self.events)
        chain = self.mapper.technique_chain(matches)
        assert isinstance(chain, list)
        assert len(chain) == len(set(chain)), "Chain must be deduplicated"

    def test_multiple_tactics_detected(self) -> None:
        matches = self.mapper.map_events(self.events)
        tactics = {m.tactic for m in matches}
        assert len(tactics) >= 2, "Sample log should span multiple tactics"

    def test_confidence_values_valid(self) -> None:
        matches = self.mapper.map_events(self.events)
        valid = {"high", "medium", "low"}
        for m in matches:
            assert m.confidence in valid, f"Unexpected confidence: {m.confidence}"


# ─────────────────────────────────────────────────────────────────────────────
# Session Clusterer tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSessionClusterer:
    def setup_method(self) -> None:
        self.parser    = WindowsParser()
        self.mapper    = MITREMapper()
        self.clusterer = SessionClusterer(window_minutes=30)
        events  = self.parser.load_file(_SAMPLE)
        self.matches = self.mapper.map_events(events)

    def test_cluster_returns_sessions(self) -> None:
        sessions = self.clusterer.cluster(self.matches)
        assert len(sessions) >= 1

    def test_sessions_have_events(self) -> None:
        sessions = self.clusterer.cluster(self.matches)
        for s in sessions:
            assert s.event_count >= 1

    def test_sessions_have_techniques(self) -> None:
        sessions = self.clusterer.cluster(self.matches)
        for s in sessions:
            assert len(s.techniques) >= 1

    def test_techniques_deduplicated_in_session(self) -> None:
        sessions = self.clusterer.cluster(self.matches)
        for s in sessions:
            assert len(s.techniques) == len(set(s.techniques))

    def test_empty_matches_returns_empty(self) -> None:
        sessions = self.clusterer.cluster([])
        assert sessions == []

    def test_wide_window_fewer_sessions(self) -> None:
        narrow = SessionClusterer(window_minutes=1).cluster(self.matches)
        wide   = SessionClusterer(window_minutes=9999).cluster(self.matches)
        assert len(wide) <= len(narrow)


# ─────────────────────────────────────────────────────────────────────────────
# Attack Chain Engine tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackChainEngine:
    def setup_method(self) -> None:
        self.engine = AttackChainEngine()

    def test_graph_has_nodes(self) -> None:
        assert self.engine.graph.number_of_nodes() > 0

    def test_graph_has_edges(self) -> None:
        assert self.engine.graph.number_of_edges() > 0

    def test_predict_from_known_chain(self) -> None:
        chain = ["T1078", "T1059.001", "T1003.001"]
        preds = self.engine.predict_next(chain, top_n=5)
        assert len(preds) > 0

    def test_predictions_are_sorted_by_probability(self) -> None:
        chain = ["T1078", "T1059.001"]
        preds = self.engine.predict_next(chain, top_n=5)
        probs = [p.probability for p in preds]
        assert probs == sorted(probs, reverse=True)

    def test_predictions_sum_to_one_or_less(self) -> None:
        chain = ["T1078", "T1059.001", "T1003.001"]
        preds = self.engine.predict_next(chain, top_n=10)
        total = sum(p.probability for p in preds)
        assert total <= 1.001

    def test_observed_not_in_predictions(self) -> None:
        chain = ["T1078", "T1059.001", "T1003.001"]
        preds = self.engine.predict_next(chain, top_n=5)
        for p in preds:
            assert p.technique_id not in chain

    def test_empty_chain_returns_empty(self) -> None:
        assert self.engine.predict_next([]) == []

    def test_unknown_technique_no_crash(self) -> None:
        preds = self.engine.predict_next(["T9999.999"])
        assert isinstance(preds, list)

    def test_nist_controls_present(self) -> None:
        preds = self.engine.predict_next(["T1078", "T1059.001"])
        for p in preds:
            assert len(p.nist_controls) > 0

    def test_nist_format(self) -> None:
        preds = self.engine.predict_next(["T1078", "T1059.001"])
        for p in preds:
            for ctrl in p.nist_controls:
                assert "-" in ctrl, f"NIST control should be like AC-2, got: {ctrl}"

    def test_reasoning_is_non_trivial(self) -> None:
        preds = self.engine.predict_next(["T1078", "T1059.001"])
        for p in preds:
            assert len(p.reasoning) > 20

    def test_associate_groups_apt29(self) -> None:
        # APT29 uses T1078, T1059.001, T1003.001, T1021.001
        chain  = ["T1078", "T1059.001", "T1003.001", "T1021.001"]
        groups = self.engine.associate_groups(chain)
        assert any("APT29" in g for g in groups), \
            "APT29 should appear for this well-known chain"

    def test_associate_groups_empty_chain(self) -> None:
        groups = self.engine.associate_groups([])
        assert groups == []
