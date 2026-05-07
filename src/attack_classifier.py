"""
ThreatWeave — Attack Type Classifier
=====================================
Classifies the observed sequence of MITRE ATT&CK tactics and techniques
into one or more known attack types based on pattern matching.

Each attack pattern defines:
  - required_tactics:    set of tactic names that MUST appear
  - required_techniques: specific technique IDs that strongly indicate this type
  - bonus_tactics:       additional tactics that increase the confidence score
  - bonus_techniques:    additional technique IDs that boost the score
  - min_score:           minimum score to consider this pattern a match

Output per step in the sequence:
  tactic → technique(s) → attack_phase label

Final verdict:
  Matched attack type, confidence level, brief description.
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ── Attack Phase Labels ─────────────────────────────────────────────────────
# Maps tactic → human-readable attack phase description shown per step
PHASE_LABEL: dict[str, str] = {
    "initial-access":       "Gaining initial foothold on the machine",
    "execution":            "Running malicious code or scripts",
    "persistence":          "Establishing long-term access after reboot",
    "privilege-escalation": "Elevating access rights to Administrator or SYSTEM",
    "defense-evasion":      "Hiding activity and covering tracks",
    "credential-access":    "Stealing account credentials and password hashes",
    "discovery":            "Mapping the environment and finding targets",
    "lateral-movement":     "Moving to other systems on the network",
    "collection":           "Gathering sensitive files and data",
    "command-and-control":  "Communicating with attacker-controlled server",
    "exfiltration":         "Sending stolen data outside the network",
    "impact":               "Causing damage — encryption, destruction, or disruption",
}


# ── Attack Pattern Definitions ──────────────────────────────────────────────
@dataclass
class AttackPattern:
    name:                str
    description:         str
    required_tactics:    set[str]          = field(default_factory=set)
    required_techniques: set[str]          = field(default_factory=set)
    bonus_tactics:       set[str]          = field(default_factory=set)
    bonus_techniques:    set[str]          = field(default_factory=set)
    min_score:           int               = 2
    severity:            str               = "High"   # Critical / High / Medium / Low
    mitre_url:           str               = ""


# Attack patterns ordered from most specific to most general
ATTACK_PATTERNS: list[AttackPattern] = [

    AttackPattern(
        name        = "Ransomware Attack",
        description = (
            "An attacker gained access, established persistence, attempted to "
            "disable defences, and then encrypted or destroyed data. This is a "
            "ransomware-style attack pattern aimed at causing maximum disruption."
        ),
        required_tactics    = {"execution", "impact"},
        required_techniques = {"T1486", "T1490"},
        bonus_tactics       = {"persistence", "defense-evasion", "credential-access"},
        bonus_techniques    = {"T1059.001", "T1070.001", "T1562.001", "T1489"},
        min_score = 3, severity = "Critical",
    ),

    AttackPattern(
        name        = "Credential Theft and Privilege Escalation",
        description = (
            "The attacker focused on stealing credentials — most likely by dumping "
            "LSASS memory or harvesting password hashes — and then used those "
            "credentials to gain elevated privileges on this machine."
        ),
        required_tactics    = {"credential-access"},
        required_techniques = {"T1003.001", "T1003.002", "T1558.003", "T1110"},
        bonus_tactics       = {"privilege-escalation", "execution"},
        bonus_techniques    = {"T1068", "T1078", "T1550.002", "T1059.001"},
        min_score = 2, severity = "Critical",
    ),

    AttackPattern(
        name        = "Persistence and Backdoor Installation",
        description = (
            "The attacker installed one or more persistence mechanisms — scheduled "
            "tasks, rogue services, or registry run keys — to ensure they can return "
            "to the machine even after a reboot or password change."
        ),
        required_tactics    = {"persistence"},
        required_techniques = {"T1053.005", "T1543.003", "T1547.001", "T1098"},
        bonus_tactics       = {"execution", "defense-evasion"},
        bonus_techniques    = {"T1059.001", "T1070.001", "T1027"},
        min_score = 2, severity = "High",
    ),

    AttackPattern(
        name        = "Defense Evasion and Log Tampering",
        description = (
            "The attacker actively worked to hide their presence — clearing the "
            "Security audit log, disabling security tools, or obfuscating their "
            "commands. This behaviour is typically seen after initial compromise "
            "to remove forensic evidence."
        ),
        required_tactics    = {"defense-evasion"},
        required_techniques = {"T1070.001", "T1562.001", "T1027"},
        bonus_tactics       = {"execution", "persistence"},
        bonus_techniques    = {"T1059.001", "T1218.011", "T1055"},
        min_score = 2, severity = "High",
    ),

    AttackPattern(
        name        = "Lateral Movement Campaign",
        description = (
            "Credentials or tokens stolen on this machine were used to authenticate "
            "to other systems on the same network. This indicates the attacker is "
            "spreading beyond the initial point of compromise."
        ),
        required_tactics    = {"lateral-movement"},
        required_techniques = {"T1021.001", "T1021.002", "T1550.002"},
        bonus_tactics       = {"credential-access", "discovery"},
        bonus_techniques    = {"T1003.001", "T1082", "T1016", "T1018"},
        min_score = 2, severity = "Critical",
    ),

    AttackPattern(
        name        = "Data Exfiltration",
        description = (
            "After collecting sensitive files or data from this machine, the "
            "attacker transmitted them outside the network through a command-and-"
            "control channel or direct exfiltration path."
        ),
        required_tactics    = {"exfiltration"},
        required_techniques = {"T1041", "T1048"},
        bonus_tactics       = {"collection", "command-and-control"},
        bonus_techniques    = {"T1005", "T1074.001", "T1071"},
        min_score = 2, severity = "Critical",
    ),

    AttackPattern(
        name        = "Reconnaissance and Discovery",
        description = (
            "The attacker ran discovery commands to map the local environment — "
            "listing accounts, querying system information, or identifying network "
            "shares. This is typically an early post-compromise phase before "
            "further action."
        ),
        required_tactics    = {"discovery"},
        required_techniques = {"T1082", "T1016", "T1018", "T1087.001", "T1135"},
        bonus_tactics       = {"execution"},
        bonus_techniques    = {"T1059.001", "T1059.003"},
        min_score = 2, severity = "Medium",
    ),

    AttackPattern(
        name        = "Execution via Scripting",
        description = (
            "Malicious scripts — most likely PowerShell or Windows CMD — were "
            "used to run attacker code on this machine. This is one of the most "
            "common execution methods seen in both targeted attacks and commodity "
            "malware campaigns."
        ),
        required_tactics    = {"execution"},
        required_techniques = {"T1059.001", "T1059.003", "T1059.005"},
        bonus_tactics       = {"defense-evasion", "persistence"},
        bonus_techniques    = {"T1027", "T1218.011"},
        min_score = 2, severity = "High",
    ),

    AttackPattern(
        name        = "Privilege Escalation Attack",
        description = (
            "The attacker exploited a vulnerability or misconfiguration to elevate "
            "their access from a standard user account to Administrator or SYSTEM "
            "level, significantly expanding what they can do on this machine."
        ),
        required_tactics    = {"privilege-escalation"},
        required_techniques = {"T1068", "T1078"},
        bonus_tactics       = {"execution", "credential-access"},
        bonus_techniques    = {"T1059.001", "T1003.001"},
        min_score = 2, severity = "High",
    ),

    AttackPattern(
        name        = "Multi-Stage APT Intrusion",
        description = (
            "The observed sequence spans multiple kill-chain phases — from initial "
            "access through execution, persistence, and credential theft. This "
            "pattern is consistent with a targeted, multi-stage intrusion by an "
            "Advanced Persistent Threat group rather than opportunistic malware."
        ),
        required_tactics    = {"execution", "persistence", "credential-access"},
        required_techniques = set(),
        bonus_tactics       = {
            "initial-access", "privilege-escalation",
            "defense-evasion", "discovery", "lateral-movement",
        },
        bonus_techniques    = {"T1078", "T1003.001", "T1059.001", "T1070.001"},
        min_score = 4, severity = "Critical",
    ),
]


# ── Classification Result ───────────────────────────────────────────────────
@dataclass
class ClassificationResult:
    attack_type:  str
    description:  str
    confidence:   str          # "High" / "Medium" / "Low"
    severity:     str          # "Critical" / "High" / "Medium" / "Low"
    score:        int
    matched_on:   list[str]    # which tactics/techniques triggered the match


# ── Classifier ──────────────────────────────────────────────────────────────
class AttackClassifier:
    """
    Classifies a set of MITREMatch results into one or more attack types.
    """

    def classify(
        self,
        tactics:    list[str],   # ordered list of tactic names from session
        techniques: list[str],   # ordered list of technique IDs from session
    ) -> list[ClassificationResult]:
        """
        Return a ranked list of matched attack types, best match first.
        Returns at most 3 results.
        """
        tactic_set    = set(tactics)
        technique_set = set(techniques)

        results: list[ClassificationResult] = []

        for pattern in ATTACK_PATTERNS:
            score      = 0
            matched_on = []

            # Required tactics — must all be present
            if not pattern.required_tactics.issubset(tactic_set):
                continue

            # Required techniques — at least ONE must be present (if any defined)
            if pattern.required_techniques:
                matched_techs = pattern.required_techniques & technique_set
                if not matched_techs:
                    continue
                score += len(matched_techs) * 2
                matched_on += [f"technique {t}" for t in sorted(matched_techs)]

            # Required tactics contribute to score
            score += len(pattern.required_tactics)
            matched_on += [f"tactic {t}" for t in sorted(pattern.required_tactics)]

            # Bonus tactics
            bonus_t = pattern.bonus_tactics & tactic_set
            score  += len(bonus_t)
            matched_on += [f"tactic {t}" for t in sorted(bonus_t)]

            # Bonus techniques
            bonus_tech = pattern.bonus_techniques & technique_set
            score     += len(bonus_tech)
            matched_on += [f"technique {t}" for t in sorted(bonus_tech)]

            if score < pattern.min_score:
                continue

            # Confidence based on score vs min_score ratio
            ratio = score / max(pattern.min_score, 1)
            if ratio >= 2.5:
                confidence = "High"
            elif ratio >= 1.5:
                confidence = "Medium"
            else:
                confidence = "Low"

            results.append(ClassificationResult(
                attack_type  = pattern.name,
                description  = pattern.description,
                confidence   = confidence,
                severity     = pattern.severity,
                score        = score,
                matched_on   = matched_on,
            ))

        # Sort by score descending, keep top 3
        results.sort(key=lambda r: -r.score)
        return results[:3]
