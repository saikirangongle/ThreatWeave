"""
ThreatWeave — AI Engine
=======================
• Gemini free-tier (gemini-1.5-flash)  — 15 req/min, 1M tokens/day, no card
• Auto tier detection (Free vs Paid) via list_models()
• explain_event() returns THREE labelled sections:
    WHAT HAPPENED  /  CAUSE / CONTEXT  /  REMEDIATION
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from typing import Optional

import config as cfg                                             # type: ignore[import]
from models import AttackSession, NarrativeResult, WindowsEvent # type: ignore[import]

try:
    import google.generativeai as genai
    _GENAI_OK = True
except ModuleNotFoundError:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "google-generativeai"], check=True)
    try:
        import google.generativeai as genai   # type: ignore[import]
        _GENAI_OK = True
    except ImportError:
        _GENAI_OK = False


# ── Model lists ───────────────────────────────────────────────────────────────

_PAID_INDICATORS = {
    "models/gemini-1.5-pro-002",
    "models/gemini-ultra",
    "models/gemini-1.0-ultra",
}
_FREE_PREF = ["gemini-1.5-flash","gemini-1.5-flash-latest",
              "gemini-1.5-flash-002","gemini-2.0-flash","gemini-1.5-pro"]
_PAID_PREF = ["gemini-1.5-pro","gemini-1.5-pro-002","gemini-1.5-pro-latest",
              "gemini-2.0-pro","gemini-ultra","gemini-1.5-flash"]


# ── Prompts ───────────────────────────────────────────────────────────────────

_NARRATIVE_PROMPT = """\
You are a senior SOC analyst. Analyse the following Windows Event Log attack session
and respond ONLY with a JSON object — no markdown fences, no preamble.

Required JSON structure:
{{
  "narrative": "<3-5 sentence attack story in plain English>",
  "severity": "<Critical|High|Medium|Low>",
  "severity_reason": "<one sentence explaining the severity>",
  "response_actions": ["<action 1>", "<action 2>", "<action 3>"]
}}

SESSION DATA:
Time range    : {start} -> {end}
Duration      : {duration:.1f} minutes
Hosts affected: {hosts}
Event count   : {count}
MITRE chain   : {chain}
APT similarity: {apts}

Sample events (up to 10):
{events}
"""

_RANGE_PROMPT = """\
You are a SOC analyst. I will give you Windows Event Log entries from a specific time window.
Write a SHORT (3-5 sentence) security summary of this time period.
Focus on: what activity occurred, any suspicious patterns, and one recommended action.

Time window : {start} -> {end}
Event count : {count}
Events:
{events}

Respond in plain English. Be concise and actionable. Do NOT use JSON.
"""

_SINGLE_PROMPT = """\
You are a SOC analyst reviewing a Windows Event Log entry.
Analyse the event and respond with EXACTLY three sections using these exact headings.
Do not add any text before the first heading or after the last section.

WHAT HAPPENED
(2-3 sentences: describe what this event records - who did what, on which host)

CAUSE / CONTEXT
(2-3 sentences: explain what Windows activity or attacker behaviour generates this event
and why it is significant from a security perspective)

REMEDIATION
(2-3 sentences: specific actionable steps - what to check, block, investigate, or escalate)

Event:
{event}
"""


# ── TierInfo ──────────────────────────────────────────────────────────────────

class TierInfo:
    def __init__(self, tier, available_models, best_model, warning, rpm_note):
        self.tier             = tier
        self.available_models = available_models
        self.best_model       = best_model
        self.warning          = warning
        self.rpm_note         = rpm_note

    @property
    def is_paid(self): return self.tier == "paid"

    @property
    def display_label(self):
        return {"free":"Free Tier","paid":"Paid Tier (Billing Enabled)",
                "unknown":"Unknown Tier","invalid":"Invalid Key"}.get(self.tier, self.tier)


def detect_tier(api_key: str) -> TierInfo:
    """Detect Free vs Paid tier by calling list_models()."""
    if not _GENAI_OK:
        return TierInfo("unknown", [], "gemini-1.5-flash",
                        "google-generativeai not installed.", "")
    if not api_key or not api_key.strip():
        return TierInfo("invalid", [], "gemini-1.5-flash", "No API key provided.", "")
    try:
        genai.configure(api_key=api_key.strip())                # type: ignore[union-attr]
        all_models: list[str] = []
        try:
            for m in genai.list_models():                       # type: ignore[union-attr]
                if "generateContent" in getattr(m, "supported_generation_methods", []):
                    all_models.append(m.name)
        except Exception as exc:
            return TierInfo("invalid", [], "gemini-1.5-flash",
                            f"API key validation failed: {exc}", "")

        clean   = [n.replace("models/", "") for n in all_models]
        is_paid = any(n in _PAID_INDICATORS for n in all_models)
        tier    = "paid" if is_paid else "free"
        pref    = _PAID_PREF if is_paid else _FREE_PREF
        best    = next(
            (m for m in pref if m in clean or f"models/{m}" in all_models),
            clean[0] if clean else "gemini-1.5-flash",
        )
        if tier == "free":
            warn = ("WARNING: Free Tier - prompts may be used by Google to improve models.\n"
                    "Rate limits: ~15 req/min, 1M tokens/day.\n"
                    "Enable billing in Google Cloud to upgrade.")
            rpm = "~15 req/min (Free Tier)"
        else:
            warn = ("Paid Tier - prompts are NOT used for training.\n"
                    "Higher rate limits apply (360+ req/min).\n"
                    "Enterprise-grade data privacy active.")
            rpm = "360+ req/min (Paid Tier)"
        return TierInfo(tier, clean, best, warn, rpm)
    except Exception as exc:
        return TierInfo("unknown", [], "gemini-1.5-flash",
                        f"Could not detect tier: {exc}", "")


# ── AI Engine ─────────────────────────────────────────────────────────────────

class AIEngine:
    """Wrapper around Google Gemini for all ThreatWeave AI features."""

    def __init__(self) -> None:
        self._model:     Optional[object]   = None
        self._tier_info: Optional[TierInfo] = None
        self._init()

    def _init(self) -> None:
        if not _GENAI_OK: return
        api_key = cfg.get("gemini_api_key", "")
        if not api_key: return
        try:
            self._tier_info = detect_tier(api_key)
            user_model  = cfg.get("gemini_model", "")
            model_name  = (user_model if user_model and user_model != "auto"
                           else self._tier_info.best_model)
            genai.configure(api_key=api_key.strip())            # type: ignore[union-attr]
            self._model = genai.GenerativeModel(model_name)     # type: ignore[union-attr]
            print(f"[AI] tier={self._tier_info.tier}  model={model_name}")
        except Exception as exc:
            print(f"[AI] init failed: {exc}")
            self._model = None

    def reinit(self) -> None:
        self._model = None
        self._tier_info = None
        self._init()

    @property
    def available(self) -> bool:
        return self._model is not None

    @property
    def tier_info(self) -> Optional[TierInfo]:
        return self._tier_info

    # ── Public ────────────────────────────────────────────────────────────

    def narrative_for_session(
        self, session: AttackSession, apt_groups: list[str]
    ) -> NarrativeResult:
        if not self.available:
            return self._fallback_narrative(session)
        sample = "\n".join(
            f"  [{ev.severity.upper()}] {ev.category} | EventID={ev.event_id} | Host={ev.host}"
            for ev in session.events[:10]
        )
        prompt = _NARRATIVE_PROMPT.format(
            start    = str(session.start_time)[:19] if session.start_time else "unknown",
            end      = str(session.end_time)[:19]   if session.end_time   else "unknown",
            duration = session.duration_minutes,
            hosts    = ", ".join(list(session.hosts)[:5]),
            count    = session.event_count,
            chain    = " -> ".join(session.techniques) or "none",
            apts     = ", ".join(apt_groups[:3]) or "unknown",
            events   = sample,
        )
        return self._parse_narrative(self._call(prompt), session)

    def summary_for_range(
        self, events: list[WindowsEvent], start_str: str, end_str: str
    ) -> str:
        """Short AI summary for a user-selected time range of events."""
        if not self.available:
            sev: dict[str, int] = {}
            for ev in events:
                sev[ev.severity] = sev.get(ev.severity, 0) + 1
            lines = "\n".join(f"  {k}: {v}" for k, v in sorted(sev.items()))
            return (
                f"AI not configured - set Gemini API key in Settings.\n\n"
                f"Time range : {start_str}  ->  {end_str}\n"
                f"Events     : {len(events)}\n"
                f"Channels   : {', '.join(sorted({e.channel for e in events}))}\n\n"
                f"Severity breakdown:\n{lines}"
            )
        event_lines = "\n".join(
            f"  [{e.severity.upper()}] {e.timestamp[:19]:19s} | "
            f"{e.channel:12s} | EventID={e.event_id:6s} | {e.category}"
            for e in events[:100]
        )
        return self._call(_RANGE_PROMPT.format(
            start=start_str, end=end_str, count=len(events), events=event_lines
        ))

    def explain_event(self, event: WindowsEvent) -> str:
        """
        Explain a single event in THREE labelled sections:
            WHAT HAPPENED / CAUSE / CONTEXT / REMEDIATION
        Falls back to a rule-based offline explanation with the same format.
        """
        if not self.available:
            return self._offline_explain(event)
        return self._call(_SINGLE_PROMPT.format(event=event.raw_message[:3000]))

    # ── Offline fallback for explain_event ────────────────────────────────

    def _offline_explain(self, ev: WindowsEvent) -> str:
        """
        Rule-based 3-section explanation when Gemini is not configured.
        Returns text with the exact headings the UI parser expects.
        """
        eid = ev.event_id
        host = ev.host
        user = f"User: {ev.username}. " if ev.username else ""
        ip   = f"Source IP: {ev.source_ip}. " if ev.source_ip else ""
        proc = f"Process: {ev.process_name}. " if ev.process_name else ""

        WHAT = {
            "4624": (
                f"A successful logon was recorded on {host}. {user}{ip}"
                "Windows logged a successful account authentication. "
                "This event fires every time a user or service authenticates successfully."
            ),
            "4625": (
                f"A failed logon attempt was recorded on {host}. {user}{ip}"
                "The credentials supplied were incorrect or the account was locked/disabled. "
                "Windows generates this event each time an authentication attempt is rejected."
            ),
            "4688": (
                f"A new process was started on {host}. {proc}"
                "Windows Process Tracking logged the creation of a new executable. "
                "This event captures the full path, command-line arguments, and parent process."
            ),
            "4698": (
                f"A scheduled task was created on {host}. {user}"
                "The Windows Task Scheduler recorded a new task registration. "
                "Scheduled tasks run at defined times or events and persist across reboots."
            ),
            "1102": (
                f"The Security audit log was cleared on {host}. {user}"
                "All previous Security event log entries were permanently deleted. "
                "This event is generated when an administrator clears the Security log."
            ),
            "7045": (
                f"A new Windows service was installed on {host}. "
                "The Service Control Manager recorded a new service entry. "
                "Services run with elevated privileges and are started automatically by Windows."
            ),
            "4672": (
                f"Special privileges were assigned at logon on {host}. {user}"
                "The account was granted powerful privileges such as SeDebugPrivilege or SeTcbPrivilege. "
                "This event fires when a user authenticates with administrator-equivalent rights."
            ),
            "4719": (
                f"The system audit policy was changed on {host}. {user}"
                "A modification was made to which Windows events are audited. "
                "Changes to audit policy affect what security events are captured going forward."
            ),
            "4732": (
                f"A member was added to a local security group on {host}. {user}"
                "The local group membership was modified. "
                "Group membership changes can elevate an account's access rights."
            ),
        }

        CAUSE = {
            "4624": (
                "Generated on every successful authentication. "
                "Suspicious indicators: logon type 10 (RemoteInteractive/RDP), "
                "unusual hours, unknown source IPs, or high-volume logons suggesting "
                "credential-stuffing (MITRE T1078 - Valid Accounts)."
            ),
            "4625": (
                "Generated on every failed authentication attempt. "
                "A rapid burst of 4625 events from a single source IP is a strong "
                "indicator of brute-force or password-spray attacks (MITRE T1110). "
                "Combined with a subsequent 4624, it may indicate a successful compromise."
            ),
            "4688": (
                "Generated every time an executable starts. "
                "Security teams watch for unusual process names (mimikatz, psexec, mshta), "
                "encoded PowerShell commands (-EncodedCommand), or processes spawned from "
                "unexpected parents (e.g. Word spawning cmd.exe) — MITRE T1059, T1003."
            ),
            "4698": (
                "Attackers create scheduled tasks to maintain persistence after initial access, "
                "ensuring their payload survives reboots (MITRE T1053.005 - Scheduled Task). "
                "Legitimate software also registers tasks, so review the task action and trigger carefully."
            ),
            "1102": (
                "Log clearing is a classic attacker anti-forensics technique (MITRE T1070.001). "
                "It removes evidence of prior activity from the Security log. "
                "In a well-managed environment this event almost never occurs without a formal change request."
            ),
            "7045": (
                "Malicious actors install rogue services to run code with SYSTEM-level "
                "privileges and survive reboots (MITRE T1543.003 - Windows Service). "
                "Red flags: service executable in a TEMP or user directory, randomised names, "
                "or paths matching known RAT/backdoor patterns."
            ),
            "4672": (
                "Powerful privileges enable credential dumping, disabling security tools, "
                "and other high-impact actions (MITRE T1068 - Exploitation for Privilege Escalation). "
                "Legitimate admin logons produce this event, but unexpected accounts are a concern."
            ),
            "4719": (
                "Attackers modify audit policy to disable logging of their activities "
                "(MITRE T1562.001 - Impair Defenses). "
                "Any unexpected change to audit policy warrants immediate investigation."
            ),
            "4732": (
                "Adding accounts to privileged groups (Administrators, Remote Desktop Users) "
                "is a common persistence and privilege escalation technique (MITRE T1098). "
                "Review whether the addition was authorised."
            ),
        }

        REM = {
            "4624": (
                "Verify the logon is from an expected user, device, and IP. "
                "For Logon Type 10 (RDP), confirm remote access is authorised. "
                "If the source IP is external or unknown, block it at the firewall and "
                "force a password reset for the affected account."
            ),
            "4625": (
                "If more than 5 failures occur within 5 minutes from the same source, "
                "temporarily lock the account and block the source IP at the firewall. "
                "Review whether MFA is enforced and check account lockout policy. "
                "Correlate with Event 4624 to detect whether an attempt eventually succeeded."
            ),
            "4688": (
                "Verify the process is expected and authorised on this host. "
                "Check the full command line for encoded or obfuscated arguments. "
                f"{'Immediately isolate the host - ' + (ev.process_name or '') + ' is high-risk. ' if ev.process_name and any(x in (ev.process_name or '').lower() for x in ['mimikatz','psexec','cobalt','meterpreter','beacon']) else ''}"
                "If suspicious, kill the process, quarantine the host, and escalate to incident response."
            ),
            "4698": (
                "Review the task name, action command, trigger, and creating account. "
                "Delete any task not matched to an approved change record: "
                "schtasks /delete /tn <TaskName> /f. "
                "Search other endpoints for the same task name to assess lateral spread."
            ),
            "1102": (
                "Treat this as a critical security incident. "
                "Immediately preserve all remaining logs (System, Application, EDR, firewall). "
                "Identify what account cleared the log and what events preceded the clearing. "
                "Escalate to incident response - assume breach until proven otherwise."
            ),
            "7045": (
                "Review the service name, binary path, and the account that installed it. "
                "Remove the service if not authorised: sc delete <ServiceName>. "
                "Scan the binary with antivirus/EDR. "
                "Check other hosts for the same service installation."
            ),
            "4672": (
                "Confirm the account legitimately requires these elevated privileges. "
                "Apply least-privilege: remove unnecessary rights from the account. "
                "Monitor all subsequent activity by this account in the session. "
                "If unexpected, treat as potential compromise and investigate the full logon chain."
            ),
            "4719": (
                "Immediately revert the audit policy to its approved baseline. "
                "Investigate the account that made the change. "
                "Review what events may have been missed while auditing was reduced. "
                "Consider enabling Windows Event Forwarding to a remote SIEM to prevent tampering."
            ),
            "4732": (
                "Confirm the group modification was authorised through your change process. "
                "If not, remove the account from the group immediately. "
                "Audit the account for subsequent privileged activity. "
                "Review all group membership changes over the past 24 hours."
            ),
        }

        default_what  = (
            f"Windows Event ID {eid} was recorded on host '{host}'. "
            f"Category: {ev.category}. {user}{proc}"
            "Refer to Microsoft Event ID documentation for complete details on this event type."
        )
        default_cause = (
            f"Event ID {eid} is recorded by the Windows {ev.channel} channel. "
            "Consult the MITRE ATT&CK framework and Microsoft Security Event documentation "
            "for the specific techniques associated with this event."
        )
        default_rem   = (
            f"Review Event ID {eid} against your organisation's security baseline. "
            "Correlate with surrounding events using the Time-Range AI Analysis panel. "
            "Escalate to a senior analyst if the event appears anomalous."
        )

        return (
            f"WHAT HAPPENED\n{WHAT.get(eid, default_what)}\n\n"
            f"CAUSE / CONTEXT\n{CAUSE.get(eid, default_cause)}\n\n"
            f"REMEDIATION\n{REM.get(eid, default_rem)}"
        )

    # ── Internal ──────────────────────────────────────────────────────────

    def _call(self, prompt: str) -> str:
        try:
            return self._model.generate_content(prompt).text.strip()  # type: ignore[union-attr]
        except Exception as exc:
            err = str(exc)
            if "429" in err or "quota" in err.lower() or "rate" in err.lower():
                time.sleep(6)
                try:
                    return self._model.generate_content(prompt).text.strip()  # type: ignore[union-attr]
                except Exception as exc2:
                    return f"[Rate limit] {exc2}"
            return f"[AI error] {exc}"

    def _parse_narrative(self, raw: str, session: AttackSession) -> NarrativeResult:
        cleaned = re.sub(r"```(?:json)?|```", "", raw).strip()
        try:
            data = json.loads(cleaned)
            return NarrativeResult(
                narrative        = data.get("narrative", ""),
                severity         = data.get("severity", "Medium"),
                severity_reason  = data.get("severity_reason", ""),
                response_actions = data.get("response_actions", []),
                raw_response     = raw,
            )
        except json.JSONDecodeError:
            return NarrativeResult(
                narrative        = cleaned[:500] if cleaned else "No response.",
                severity         = "Medium",
                severity_reason  = "Could not parse structured response.",
                response_actions = ["Review timeline manually.", "Escalate to senior analyst."],
                raw_response     = raw,
            )

    def _fallback_narrative(self, session: AttackSession) -> NarrativeResult:
        HIGH = {"T1486","T1003.001","T1562.001","T1070.001","T1490"}
        MED  = {"T1059.001","T1021.001","T1021.002","T1041","T1550.002"}
        t    = session.techniques
        if   any(x in HIGH for x in t): severity = "Critical"
        elif any(x in MED  for x in t): severity = "High"
        elif t:                          severity = "Medium"
        else:                            severity = "Low"
        chain = " -> ".join(t[:6]) if t else "no techniques mapped"
        return NarrativeResult(
            narrative = (
                f"Analysis detected {len(t)} MITRE ATT&CK technique(s) across "
                f"{len(session.hosts)} host(s) over {session.duration_minutes:.0f} minutes. "
                f"Observed chain: {chain}. "
                "Set a Gemini API key in Settings for an AI-generated narrative."
            ),
            severity         = severity,
            severity_reason  = f"Based on {len(t)} detected technique(s).",
            response_actions = [
                "Review the full event timeline in the Log Explorer tab.",
                "Cross-reference with your SIEM for corroborating alerts.",
                "Isolate affected hosts if lateral movement is detected.",
                "Set a free Gemini API key in Settings for AI-assisted analysis.",
            ],
            raw_response = "[Fallback - no AI configured]",
        )
