# ThreatWeave

**An AI-Powered Windows Event Log Threat Analysis Engine**

ThreatWeave ingests Windows Event Logs, maps every security-relevant event to the MITRE ATT\&CK framework, classifies the observed attack sequence into a named attack type, generates an AI-assisted threat narrative, predicts the attacker's next moves, and exports a complete forensic report — all from a free, standalone desktop application that runs on any Windows laptop with no server infrastructure.

---

## What it does

| Capability | Detail |
|---|---|
| **Log Ingestion** | Live fetch via `wevtutil.exe` or file load (.evtx / .xml) |
| **MITRE ATT\&CK Mapping** | 43 YAML detection rules across 10 ATT\&CK tactics |
| **Session Clustering** | Sliding time-window groups matched events into attack sessions |
| **Attack Sequence View** | Step-by-step tactic cards with technique IDs, names, and attack phase descriptions |
| **Attack Type Classification** | Pattern-matching classifier identifies one of 10 named attack types from the observed tactic-technique chain |
| **AI Threat Narrative** | Google Gemini generates severity rating, APT group attribution, and response actions |
| **Single-Event Explain** | Three-section AI explanation: What Happened · Cause/Context · Remediation |
| **Time-Range Analysis** | AI summary scoped to any analyst-specified time window |
| **Predictive Attack Chain** | NetworkX graph predicts top-5 next attacker techniques with NIST 800-53 controls |
| **Forensic Report Export** | PDF and HTML reports from a single session |
| **Offline Mode** | Rule-based fallback for AI features — works without internet or API key |

---

## Screenshots

### Log Explorer — Live Fetch and MITRE Analysis
Events loaded from any Windows machine, mapped to ATT\&CK techniques, with full event detail on the right.
<img width="1919" height="1079" alt="Main" src="https://github.com/user-attachments/assets/d3c537c2-f272-440b-bdfd-3af29634be3c" />


### Threat Narrative — Attack Sequence and Type Classification
Sequential tactic cards show the attacker's kill-chain path, followed by the **🎯 FINAL VERDICT** attack type card with confidence and severity ratings.
<img width="1918" height="1078" alt="Narrative" src="https://github.com/user-attachments/assets/dc819843-2bb4-4e18-8613-7d6fa8dd8e05" />


### MITRE ATT\&CK Heatmap
Technique frequency visualised across all ATT\&CK tactic columns.
<img width="1918" height="1078" alt="image" src="https://github.com/user-attachments/assets/1b289482-f0eb-4adc-9c6b-97f620bfd1d9" />


### Predictive Attack Chain
Top-5 next techniques ranked by probability, with threat group associations and NIST 800-53 controls.
<img width="1918" height="1078" alt="Prediction" src="https://github.com/user-attachments/assets/263aa547-a579-4885-a04c-a6689a331590" />

---

## Attack Types Detected

The classifier identifies the following attack patterns from the observed MITRE tactic-technique sequence:

1. Ransomware Attack
2. Credential Theft and Privilege Escalation
3. Persistence and Backdoor Installation
4. Defense Evasion and Log Tampering
5. Lateral Movement Campaign
6. Data Exfiltration
7. Reconnaissance and Discovery
8. Execution via Scripting
9. Privilege Escalation Attack
10. Multi-Stage APT Intrusion

---

## Requirements

- **OS:** Windows 11 (21H2 or later) — required for `wevtutil.exe` and UAC elevation
- **Python:** 3.11+
- **RAM:** 8 GB minimum
- **Internet:** Optional — required only for Gemini AI features

> **Note:** ThreatWeave can analyse log files from any Windows machine. Live log fetch works on the local machine only.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/saikirangongle/ThreatWeave.git
cd ThreatWeave

# 2. Create a virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

---

## Quick Start

### Option A — Load a sample log file
```
1. Launch: python app.py
2. Click  Open File  →  browse to  tests/sample_logs/sample.xml
3. Click  🔍 Analyse
4. Open the Threat Narrative tab to see the attack sequence and type verdict
5. Click  ▶ Generate AI Narrative  for the AI threat narrative (API key required)
6. Open the Prediction tab to see the top-5 next predicted techniques
7. Click  Export PDF  or  Export HTML  in the Report tab
```

### Option B — Live fetch from this machine
```
1. Launch: python app.py
2. Select a channel from the dropdown (Application, System, Security)
3. Click  Fetch Live Logs
4. Click  🔍 Analyse
```

> **Security channel:** Requires Administrator rights. ThreatWeave will trigger the Windows UAC elevation prompt automatically.

---

## AI Setup (Optional)

ThreatWeave works fully offline without an API key — the rule-based offline fallback generates three-section explanations for all common Event IDs.

To enable Google Gemini AI features:

1. Go to [https://aistudio.google.com](https://aistudio.google.com)
2. Create a free API key (no credit card required)
3. In ThreatWeave: click ⚙ Settings → paste your API key → Save

**Free tier limits:** 15 requests/minute · 1 million tokens/day · No cost.

---

## Time-Range AI Analysis

The bottom bar of the Log Explorer tab includes a **Time-Range AI Analysis** panel:

```
From: YYYY-MM-DD HH:MM    To: YYYY-MM-DD HH:MM    [Generate AI Summary]
```

Enter times in your **local time** (the same format shown in the event table). ThreatWeave converts the input to UTC internally and returns an AI summary covering only the events in that window.

---

## Project Structure

```
ThreatWeave/
├── app.py                          # Entry point
├── requirements.txt
├── config/
│   ├── rules.yaml                  # 43 MITRE ATT&CK detection rules
│   ├── settings.json               # User settings (API key, window size)
│   └── nist.json                   # NIST 800-53 control mappings
├── src/
│   ├── models.py                   # Shared dataclasses (WindowsEvent, MITREMatch, etc.)
│   ├── parser.py                   # Windows Event Log XML / EVTX parser
│   ├── fetcher.py                  # wevtutil.exe live acquisition
│   ├── mapper.py                   # YAML rule engine → MITREMatch
│   ├── analyzer.py                 # Session clustering + prediction graph
│   ├── attack_classifier.py        # 10-pattern sequential attack type classifier
│   ├── ai_engine.py                # Gemini API + offline fallback
│   ├── reporter.py                 # PDF and HTML forensic report generator
│   └── ui/
│       ├── main.py                 # MainWindow + tab wiring
│       ├── theme.py                # Windows 11 colour palette and fonts
│       └── tabs/
│           ├── explorer.py         # Log Explorer tab (fetch, filter, analyse)
│           ├── heatmap.py          # MITRE ATT&CK heatmap tab
│           ├── narrative.py        # Threat Narrative + attack sequence tab
│           ├── prediction.py       # Predictive attack chain tab
│           └── report.py           # Report export tab
├── tests/
│   └── sample_logs/
│       └── sample.xml              # Sample Windows Event Log (7 events, DESKTOP-WIN11)
└── data/
    └── (attack chain graph data)
```

---

## Detection Rules

Rules are defined in `config/rules.yaml` in a simple YAML schema:

```yaml
- id: T1059-POWERSHELL
  technique_id: T1059.001
  technique_name: Command Scripting — PowerShell
  tactic: execution
  confidence: high
  conditions:
    event_id: "4688"
    process_contains: "powershell"
```

**Conditions are ANDed.** Supported fields:

| Field | Match type |
|---|---|
| `event_id` | Exact match on Windows Event ID |
| `process_contains` | Case-insensitive substring in process name or raw message |
| `message_contains` | Case-insensitive substring in raw event XML |
| `username_contains` | Case-insensitive substring in extracted username |

**Tactics covered:** Initial Access · Execution · Persistence · Privilege Escalation · Defense Evasion · Credential Access · Discovery · Lateral Movement · Collection · Impact

---

## Extending ThreatWeave

### Adding a new detection rule
Edit `config/rules.yaml` and add a new entry following the schema above. No code changes required.

### Adding a new attack pattern
Edit `src/attack_classifier.py` and add a new `AttackPattern` object to the `ATTACK_PATTERNS` list. Specify `required_tactics`, `required_techniques`, `bonus_tactics`, `bonus_techniques`, `min_score`, and `severity`.

### Adding a new log source
Implement a new parser class in `src/parser.py` that returns a `list[WindowsEvent]`. The mapping, classification, AI, and reporting layers require no changes.

---

## Validation

| Component | Validation method | Result |
|---|---|---|
| Detection rules (43) | EVTX-to-MITRE-Attack labelled dataset | 100% accuracy |
| Attack type classifier (10 patterns) | MITRE CTI STIX 2.1 — 5 real campaign sequences | 5/5 correct within top-2 |
| Prediction engine | MITRE CTI — 4 campaign sequences, top-3 | 4/4 correct within top-3 |
| Functional tests | 17 hand-crafted test cases | 17/17 PASS |

---

## Dependencies

| Library | Version | Purpose |
|---|---|---|
| `google-generativeai` | ≥ 0.5.0 | Gemini free-tier AI integration |
| `networkx` | ≥ 3.2.1 | Attack-chain prediction directed graph |
| `pyyaml` | ≥ 6.0.1 | Detection rule loading |
| `reportlab` | ≥ 4.1.0 | PDF forensic report generation |
| `jinja2` | ≥ 3.1.3 | HTML forensic report templating |
| `pillow` | ≥ 10.2.0 | Image support in PDF |
| `python-evtx` | ≥ 0.7.4 | Binary .evtx file parsing (optional) |

All dependencies are free and open-source. No paid tiers are required for any functionality except the optional Gemini API features, which also have a generous free tier.

---

## Known Limitations

- **Windows only** in the current version. Linux, macOS, and cloud log support is planned.
- **Gemini free tier**: 15 API requests per minute. For high-volume analysis sessions, the offline fallback activates automatically.
- **43 detection rules** cover the most commonly observed Windows attack techniques but are not exhaustive — the MITRE ATT\&CK matrix contains over 400 techniques.
- **10 attack patterns** cover major attack categories. Novel or unusual sequences that do not match any pattern produce no verdict rather than an incorrect one.
- **Live fetch** requires the application to run on the machine being monitored. For remote machine analysis, export the .evtx file and load it via Open File.

---

## Academic Context

This project was developed as a capstone project for the degree of **Master of Technology in Cybersecurity** at **REVA University, Bengaluru, India** (2023–2025).

**Student:** Saikiran Gongle (R23MTC13)  
**Guide:** Mr. Sandeep Vijayaraghavan, EVP – CyberSec & Cloud Services, Terralogic

---

## References

Detection rules and prediction graph are grounded in the following datasets and frameworks:

- [MITRE ATT\&CK Enterprise v15](https://attack.mitre.org) — detection taxonomy and technique definitions
- [MITRE CTI STIX 2.1](https://github.com/mitre/cti) — APT campaign profiles used to build the prediction graph
- [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) — labelled Windows EVTX samples used for rule validation
- [Sigma](https://github.com/SigmaHQ/sigma) — detection rule conventions
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — security controls mapped to predictions

---

## License

This project is released for academic and research use. See the repository for full licence details.

---

## Contributing

Contributions are welcome — particularly additional detection rules, new attack patterns, and log source parsers. Please open an issue before submitting a pull request so the change can be discussed first.
