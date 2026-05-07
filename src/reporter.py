"""ThreatWeave — PDF and HTML forensic report generator."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from models import (  # type: ignore[import]
    AttackSession,
    MITREMatch,
    NarrativeResult,
    PredictionResult,
)


# ─────────────────────────────────────────────────────────────────────────────
# HTML Report (self-contained, no external dependencies)
# ─────────────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ThreatWeave Forensic Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#F3F3F3;color:#1A1A1A}}
.page{{max-width:1100px;margin:24px auto;background:#fff;border-radius:8px;
       box-shadow:0 2px 12px rgba(0,0,0,.10);overflow:hidden}}
.header{{background:#0078D4;color:#fff;padding:28px 36px}}
.header h1{{font-size:26px;letter-spacing:.5px}}
.header .sub{{font-size:12px;color:#B8D8F8;margin-top:4px}}
.sev-badge{{display:inline-block;padding:5px 18px;border-radius:20px;
             font-weight:700;font-size:15px;margin-top:12px}}
.sev-Critical{{background:#C42B1C;color:#fff}}
.sev-High{{background:#CA5010;color:#fff}}
.sev-Medium{{background:#9D5D00;color:#fff}}
.sev-Low{{background:#107C10;color:#fff}}
.meta{{display:grid;grid-template-columns:repeat(3,1fr);background:#0067B8}}
.meta-cell{{padding:10px 20px}}
.meta-cell .lbl{{font-size:10px;color:#9EC8F4;text-transform:uppercase}}
.meta-cell .val{{font-size:13px;color:#fff;font-weight:600;margin-top:2px}}
.body{{padding:28px 36px}}
h2{{font-size:17px;color:#0078D4;border-bottom:2px solid #E5E5E5;
    padding-bottom:6px;margin:24px 0 12px}}
p{{line-height:1.7;font-size:14px;color:#3D3D3D;margin-bottom:8px}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0 16px}}
th{{background:#0078D4;color:#fff;padding:8px 10px;text-align:left;font-size:12px}}
td{{padding:7px 10px;border-bottom:1px solid #E5E5E5}}
tr:nth-child(even) td{{background:#F9F9F9}}
.chain{{background:#EBF4FF;border-left:4px solid #0078D4;
         padding:10px 14px;font-family:monospace;font-size:12px;
         border-radius:0 4px 4px 0;margin:8px 0 16px;word-break:break-all}}
.action-list{{list-style:none;padding:0}}
.action-list li{{padding:6px 0 6px 20px;position:relative;font-size:14px;
                  border-bottom:1px solid #F3F3F3}}
.action-list li::before{{content:"→";position:absolute;left:0;
                           color:#0078D4;font-weight:700}}
.apt-tag{{display:inline-block;background:#EBF4FF;color:#0078D4;
           border:1px solid #B8D8F8;padding:2px 10px;border-radius:12px;
           font-size:12px;margin:2px 3px}}
.prob-bar{{background:#E5E5E5;border-radius:3px;height:7px;margin-top:3px}}
.prob-fill{{background:#0078D4;height:7px;border-radius:3px}}
.footer{{background:#F3F3F3;text-align:center;padding:12px;
          font-size:10px;color:#9E9E9E;border-top:1px solid #E5E5E5}}
</style>
</head>
<body>
<div class="page">
<div class="header">
  <div class="sub">THREATWEAVE — FORENSIC INCIDENT REPORT</div>
  <h1>Windows Event Log Threat Analysis</h1>
  <span class="sev-badge sev-{severity}">{severity} Severity</span>
</div>
<div class="meta">
  <div class="meta-cell"><div class="lbl">Generated</div>
    <div class="val">{generated}</div></div>
  <div class="meta-cell"><div class="lbl">Session Time Range</div>
    <div class="val">{time_range}</div></div>
  <div class="meta-cell"><div class="lbl">Events Analysed</div>
    <div class="val">{event_count}</div></div>
  <div class="meta-cell"><div class="lbl">Duration</div>
    <div class="val">{duration}</div></div>
  <div class="meta-cell"><div class="lbl">Affected Hosts</div>
    <div class="val">{hosts}</div></div>
  <div class="meta-cell"><div class="lbl">MITRE Techniques</div>
    <div class="val">{tech_count}</div></div>
</div>
<div class="body">

<h2>1. Threat Narrative</h2>
<p>{narrative}</p>
<p><strong>Severity reason:</strong> {severity_reason}</p>
<h3 style="font-size:14px;color:#3D3D3D;margin:12px 0 6px">Immediate Response Actions</h3>
<ul class="action-list">{actions_html}</ul>

<h2>2. MITRE ATT&amp;CK Technique Chain</h2>
<div class="chain">{chain}</div>
<table>
  <thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th>
    <th>Confidence</th><th>Host</th></tr></thead>
  <tbody>{mitre_rows}</tbody>
</table>

<h2>3. Threat Group Association</h2>
<p>{apt_text}</p>
<div style="margin:8px 0">{apt_tags}</div>

<h2>4. Predicted Next Steps</h2>
<table>
  <thead><tr><th>#</th><th>Technique</th><th>Name</th>
    <th>Probability</th><th>NIST Controls</th></tr></thead>
  <tbody>{pred_rows}</tbody>
</table>

<h2>5. Event Timeline (first 100 events)</h2>
<table>
  <thead><tr><th>Timestamp</th><th>Host</th><th>Severity</th>
    <th>Category</th><th>Event ID</th></tr></thead>
  <tbody>{timeline_rows}</tbody>
</table>

</div>
<div class="footer">
  Generated by ThreatWeave &nbsp;|&nbsp; Windows Event Log Analysis &nbsp;|&nbsp;
  For defensive and educational use only &nbsp;|&nbsp;
  MITRE ATT&amp;CK data used under Apache 2.0 from MITRE Corporation
</div>
</div>
</body>
</html>"""


def _sev_badge(sev: str) -> str:
    cls = {
        "critical": "sev-Critical",
        "high":     "sev-High",
        "medium":   "sev-Medium",
        "low":      "sev-Low",
    }.get(sev.lower(), "")
    return f'<span class="sev-badge {cls}">{sev.upper()}</span>'


def generate_html(
    output_path:      str,
    session:          AttackSession,
    narrative:        NarrativeResult,
    predictions:      list[PredictionResult],
    apt_groups:       list[str],
    mitre_matches:    list[MITREMatch],
) -> bool:
    """Write a self-contained HTML forensic report. Returns True on success."""
    try:
        actions_html = "".join(f"<li>{a}</li>" for a in narrative.response_actions)
        chain = "  →  ".join(session.techniques) if session.techniques else "No techniques mapped"

        seen: set[tuple] = set()
        mitre_rows = ""
        for m in mitre_matches[:60]:
            k = (m.technique_id, m.event.host)
            if k in seen:
                continue
            seen.add(k)
            mitre_rows += (
                f"<tr><td><code>{m.technique_id}</code></td>"
                f"<td>{m.technique_name}</td>"
                f"<td>{m.tactic}</td>"
                f"<td>{m.confidence.upper()}</td>"
                f"<td>{m.event.host}</td></tr>"
            )

        apt_text = (
            f"Pattern matches campaigns attributed to: "
            f"<strong>{', '.join(apt_groups[:4])}</strong>"
            if apt_groups else "No specific threat group matched."
        )
        apt_tags = "".join(
            f'<span class="apt-tag">{g}</span>' for g in apt_groups[:6]
        )

        pred_rows = ""
        for i, p in enumerate(predictions[:5], 1):
            pct = int(p.probability * 100)
            pred_rows += (
                f"<tr><td>{i}</td><td><code>{p.technique_id}</code></td>"
                f"<td>{p.technique_name}</td>"
                f"<td><div>{pct}%</div>"
                f"<div class='prob-bar'>"
                f"<div class='prob-fill' style='width:{pct}%'></div>"
                f"</div></td>"
                f"<td>{', '.join(p.nist_controls[:3])}</td></tr>"
            )

        timeline_rows = ""
        for ev in session.events[:100]:
            timeline_rows += (
                f"<tr><td>{ev.timestamp[:19]}</td>"
                f"<td>{ev.host}</td>"
                f"<td>{ev.severity.upper()}</td>"
                f"<td>{ev.category}</td>"
                f"<td>{ev.event_id}</td></tr>"
            )

        html = _HTML_TEMPLATE.format(
            severity      = narrative.severity,
            generated     = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            time_range    = (
                f"{str(session.start_time)[:19]} → {str(session.end_time)[:19]}"
                if session.start_time else "—"
            ),
            event_count   = session.event_count,
            duration      = f"{session.duration_minutes:.1f} min",
            hosts         = ", ".join(list(session.hosts)[:4]),
            tech_count    = len(session.techniques),
            narrative     = narrative.narrative,
            severity_reason = narrative.severity_reason,
            actions_html  = actions_html,
            chain         = chain,
            mitre_rows    = mitre_rows,
            apt_text      = apt_text,
            apt_tags      = apt_tags,
            pred_rows     = pred_rows,
            timeline_rows = timeline_rows,
        )

        Path(output_path).write_text(html, encoding="utf-8")
        return True

    except Exception as exc:
        print(f"[HTML Report] Error: {exc}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# PDF Report (via ReportLab)
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf(
    output_path:   str,
    session:       AttackSession,
    narrative:     NarrativeResult,
    predictions:   list[PredictionResult],
    apt_groups:    list[str],
    mitre_matches: list[MITREMatch],
) -> bool:
    """Write a PDF forensic report using ReportLab. Returns True on success."""
    try:
        from reportlab.lib import colors                   # type: ignore[import]
        from reportlab.lib.pagesizes import A4             # type: ignore[import]
        from reportlab.lib.styles import (                 # type: ignore[import]
            ParagraphStyle, getSampleStyleSheet,
        )
        from reportlab.lib.units import cm                 # type: ignore[import]
        from reportlab.platypus import (                   # type: ignore[import]
            HRFlowable, PageBreak, Paragraph,
            SimpleDocTemplate, Spacer, Table, TableStyle,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT  # type: ignore[import]
    except ImportError:
        print("[PDF Report] ReportLab not installed. Run: pip install reportlab")
        return False

    # Colours
    NAVY   = colors.HexColor("#0078D4")
    DARK   = colors.HexColor("#1A1A1A")
    GRAY   = colors.HexColor("#6B6B6B")
    LGRAY  = colors.HexColor("#F3F3F3")
    WHITE  = colors.white
    SEV_C  = {
        "Critical": colors.HexColor("#C42B1C"),
        "High":     colors.HexColor("#CA5010"),
        "Medium":   colors.HexColor("#9D5D00"),
        "Low":      colors.HexColor("#107C10"),
    }

    styles = getSampleStyleSheet()
    S = lambda name, **kw: ParagraphStyle(name, parent=styles["Normal"], **kw)  # noqa: E731

    H1   = S("H1",   fontSize=16, textColor=NAVY,   fontName="Helvetica-Bold",
               spaceAfter=4, spaceBefore=12)
    H2   = S("H2",   fontSize=13, textColor=NAVY,   fontName="Helvetica-Bold",
               spaceAfter=3, spaceBefore=8)
    BODY = S("BODY", fontSize=10, textColor=DARK,   leading=15, spaceAfter=4)
    MONO = S("MONO", fontSize=8,  fontName="Courier", textColor=DARK,
               backColor=LGRAY, leading=11, spaceAfter=4)

    brd  = {"style": "SINGLE", "width": 0.3, "color": colors.HexColor("#E5E5E5")}

    def sp(h: float = 6.0) -> Spacer:
        return Spacer(1, h)

    def hr() -> HRFlowable:
        return HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6)

    story = []

    # ── Cover ──────────────────────────────────────────────────────────────
    story.append(sp(20))
    story.append(Paragraph("THREATWEAVE — FORENSIC INCIDENT REPORT",
                            S("cov_sub", fontSize=10, textColor=NAVY,
                              alignment=TA_CENTER)))
    sev   = narrative.severity
    sev_c = SEV_C.get(sev, DARK)
    story.append(Paragraph(
        f'<font color="#{sev_c.hexval()[2:]}"><b>{sev} Severity</b></font>',
        S("sev", fontSize=18, alignment=TA_CENTER, spaceAfter=8),
    ))
    meta = [
        ["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Time range",
         f"{str(session.start_time)[:19]} → {str(session.end_time)[:19]}"],
        ["Events",     str(session.event_count)],
        ["Duration",   f"{session.duration_minutes:.1f} min"],
        ["Hosts",      ", ".join(list(session.hosts)[:4])],
        ["Techniques", str(len(session.techniques))],
    ]
    meta_tbl = Table(meta, colWidths=[4*cm, 12.5*cm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#EBF4FF")),
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#E5E5E5")),
        ("LEFTPADDING",(0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
    ]))
    story.append(meta_tbl)
    story.append(PageBreak())

    # ── Narrative ──────────────────────────────────────────────────────────
    story.append(Paragraph("1. Threat Narrative", H1)); story.append(hr())
    story.append(Paragraph(narrative.narrative, BODY))
    story.append(sp())
    story.append(Paragraph(
        f"<b>Severity reason:</b> {narrative.severity_reason}", BODY))
    story.append(sp())
    story.append(Paragraph("Response Actions", H2))
    for i, a in enumerate(narrative.response_actions, 1):
        story.append(Paragraph(f"{i}. {a}", BODY))

    # ── MITRE chain ────────────────────────────────────────────────────────
    story.append(sp(10))
    story.append(Paragraph("2. MITRE ATT&CK Technique Chain", H1)); story.append(hr())
    chain_str = "  →  ".join(session.techniques) or "No techniques mapped"
    story.append(Paragraph(chain_str, MONO))

    mitre_data = [["Technique ID","Name","Tactic","Confidence","Host"]]
    seen2: set[tuple] = set()
    for m in mitre_matches[:40]:
        k = (m.technique_id, m.event.host)
        if k in seen2: continue
        seen2.add(k)
        mitre_data.append([m.technique_id, m.technique_name[:35],
                            m.tactic, m.confidence.upper(), m.event.host[:18]])
    mt = Table(mitre_data, colWidths=[2.7*cm, 5.5*cm, 4*cm, 2.4*cm, 3.5*cm])
    mt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0), NAVY),
        ("TEXTCOLOR", (0,0),(-1,0), WHITE),
        ("FONTNAME",  (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",  (0,0),(-1,-1), 8),
        ("GRID",      (0,0),(-1,-1), 0.25, colors.HexColor("#E5E5E5")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, LGRAY]),
        ("LEFTPADDING",(0,0),(-1,-1), 4),
        ("TOPPADDING",(0,0),(-1,-1), 3),
        ("BOTTOMPADDING",(0,0),(-1,-1), 3),
    ]))
    story.append(mt)

    # ── APT / Predictions / Timeline ──────────────────────────────────────
    story.append(sp(10))
    story.append(Paragraph("3. Threat Group Association", H1)); story.append(hr())
    story.append(Paragraph(
        f"Matched: {', '.join(apt_groups[:4]) or 'None'}", BODY))

    story.append(sp(10))
    story.append(Paragraph("4. Predicted Next Steps", H1)); story.append(hr())
    if predictions:
        pred_data = [["#","Technique","Name","Probability","NIST Controls"]]
        for i, p in enumerate(predictions[:5], 1):
            pred_data.append([str(i), p.technique_id,
                               p.technique_name[:28], f"{p.probability:.0%}",
                               ", ".join(p.nist_controls[:2])])
        pt = Table(pred_data, colWidths=[1*cm, 2.7*cm, 5.5*cm, 2.5*cm, 6.8*cm])
        pt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), NAVY),
            ("TEXTCOLOR", (0,0),(-1,0), WHITE),
            ("FONTNAME",  (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1), 8),
            ("GRID",      (0,0),(-1,-1), 0.25, colors.HexColor("#E5E5E5")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, LGRAY]),
            ("LEFTPADDING",(0,0),(-1,-1), 4),
            ("TOPPADDING",(0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ]))
        story.append(pt)

    story.append(PageBreak())
    story.append(Paragraph("5. Event Timeline", H1)); story.append(hr())
    tl_data = [["Timestamp","Host","Severity","Category","Event ID"]]
    for ev in session.events[:80]:
        tl_data.append([ev.timestamp[:19], ev.host[:16],
                         ev.severity.upper(), ev.category[:38],
                         ev.event_id or "-"])
    tlt = Table(tl_data, colWidths=[3.8*cm, 3.2*cm, 2*cm, 7.2*cm, 1.8*cm])
    tlt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0), NAVY),
        ("TEXTCOLOR", (0,0),(-1,0), WHITE),
        ("FONTNAME",  (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",  (0,0),(-1,-1), 7.5),
        ("GRID",      (0,0),(-1,-1), 0.2, colors.HexColor("#E5E5E5")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, LGRAY]),
        ("LEFTPADDING",(0,0),(-1,-1), 3),
        ("TOPPADDING",(0,0),(-1,-1), 2),
        ("BOTTOMPADDING",(0,0),(-1,-1), 2),
    ]))
    story.append(tlt)

    story.append(sp(16))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#E5E5E5"), spaceAfter=4))
    story.append(Paragraph(
        "Generated by ThreatWeave | Windows Event Log Analysis | "
        "For defensive and educational use only",
        S("foot", fontSize=7, textColor=GRAY, alignment=TA_CENTER),
    ))

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2*cm,
        title="ThreatWeave Forensic Report",
    )
    try:
        doc.build(story)
        return True
    except Exception as exc:
        print(f"[PDF Report] Build error: {exc}")
        return False
