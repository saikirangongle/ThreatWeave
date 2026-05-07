"""
ThreatWeave — Threat Narrative Tab

Layout (top to bottom):
  1. Header bar + severity badge
  2. Attack Sequence Section:
       Step 1 → Step 2 → Step 3 … (tactic per step)
       Under each step: technique IDs + names + attack phase description
  3. Attack Type Verdict panel:
       Matched attack type(s), confidence, description
  4. AI Narrative text + Response Actions (side by side)
  5. APT Association footer
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable

from ui.theme import C, F_BODY, F_BOLD, F_HEAD, F_SMALL  # type: ignore[import]
from attack_classifier import AttackClassifier, PHASE_LABEL  # type: ignore[import]

_TACTIC_ORDER = [
    "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]

_TACTIC_LABEL = {
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "Command & Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}

_TACTIC_COLOUR = {
    "initial-access":       "#C0392B",
    "execution":            "#E67E22",
    "persistence":          "#D4AC0D",
    "privilege-escalation": "#7D3C98",
    "defense-evasion":      "#1F618D",
    "credential-access":    "#117A65",
    "discovery":            "#1E8449",
    "lateral-movement":     "#2C3E50",
    "collection":           "#626567",
    "command-and-control":  "#922B21",
    "exfiltration":         "#6C3483",
    "impact":               "#78281F",
}

_SEV_COLOUR = {
    "Critical": "#C0392B",
    "High":     "#E67E22",
    "Medium":   "#D4AC0D",
    "Low":      "#27AE60",
}
_CONF_COLOUR = {
    "High":   "#107C10",
    "Medium": "#9D5D00",
    "Low":    "#666666",
}

_classifier = AttackClassifier()


class NarrativeTab:
    """Displays attack sequence, type classification, AI narrative, and response actions."""

    def __init__(
        self,
        frame:      ttk.Frame,
        root:       tk.Tk,
        ai,
        engine,
        set_status: Callable,
    ) -> None:
        self._frame      = frame
        self._root       = root
        self._ai         = ai
        self._engine     = engine
        self._set_status = set_status

        self._sessions:   list = []
        self._matches:    list = []
        self._result            = None
        self._apt_groups: list[str] = []

        self._build()

    def set_data(self, sessions: list, matches: list) -> None:
        self._sessions = sessions
        self._matches  = matches
        self._render_sequence_and_types(matches, sessions)
        count = len(sessions)
        self._hint_lbl.configure(
            text=(f"{count} session(s) detected. Click  ▶ Generate AI Narrative  for AI analysis."
                  if count else
                  "No sessions detected. Load logs and run  🔍 Analyse  first.")
        )

    # ── Build UI ──────────────────────────────────────────────────────────

    def _build(self) -> None:
        f = self._frame

        # Top bar
        hdr = tk.Frame(f, bg=C["surface3"], pady=8)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="🧠  Threat Narrative",
                 bg=C["surface3"], fg=C["text"], font=F_HEAD,
                 padx=16).pack(side=tk.LEFT)
        ttk.Button(hdr, text="▶  Generate AI Narrative",
                   style="Accent.TButton",
                   command=self._generate).pack(side=tk.RIGHT, padx=12)

        # Severity badge row
        row = tk.Frame(f, bg=C["bg"], pady=5)
        row.pack(fill=tk.X, padx=16)
        self._badge = tk.Label(row, text="  —  ",
                               bg=C["surface3"], fg=C["text"],
                               font=("Segoe UI", 13, "bold"), padx=16, pady=4)
        self._badge.pack(side=tk.LEFT)
        self._hint_lbl = tk.Label(
            row,
            text="Run  🔍 Analyse  first, then click  ▶ Generate AI Narrative.",
            bg=C["bg"], fg=C["text_s"], font=F_BODY,
            wraplength=700, justify="left")
        self._hint_lbl.pack(side=tk.LEFT, padx=10)

        ttk.Separator(f).pack(fill=tk.X, padx=16, pady=2)

        # ── Scrollable main body ──────────────────────────────────────────
        outer = tk.Frame(f, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        vbar = ttk.Scrollbar(outer, orient=tk.VERTICAL)
        vbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._main_canvas = tk.Canvas(
            outer, bg=C["bg"], yscrollcommand=vbar.set,
            highlightthickness=0, bd=0)
        self._main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vbar.configure(command=self._main_canvas.yview)

        self._scroll_frame = tk.Frame(self._main_canvas, bg=C["bg"])
        self._canvas_win = self._main_canvas.create_window(
            (0, 0), window=self._scroll_frame, anchor="nw")

        self._scroll_frame.bind(
            "<Configure>",
            lambda e: self._main_canvas.configure(
                scrollregion=self._main_canvas.bbox("all")))
        self._main_canvas.bind(
            "<Configure>",
            lambda e: self._main_canvas.itemconfig(
                self._canvas_win, width=e.width))
        # Mouse wheel
        f.bind_all("<MouseWheel>",
                   lambda e: self._main_canvas.yview_scroll(
                       -1 * (e.delta // 120), "units"))

        # ── Placeholder labels (replaced on set_data) ─────────────────
        self._seq_area    = tk.Frame(self._scroll_frame, bg=C["bg"])
        self._seq_area.pack(fill=tk.X, padx=16, pady=6)

        self._type_area   = tk.Frame(self._scroll_frame, bg=C["bg"])
        self._type_area.pack(fill=tk.X, padx=16, pady=6)

        ttk.Separator(self._scroll_frame).pack(fill=tk.X, padx=16, pady=6)

        # ── AI Narrative + Response Actions ───────────────────────────
        ai_body = tk.Frame(self._scroll_frame, bg=C["bg"])
        ai_body.pack(fill=tk.X, padx=16, pady=4)

        left = tk.Frame(ai_body, bg=C["bg"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(left, text="AI Threat Narrative",
                 bg=C["bg"], fg=C["text_s"], font=F_BOLD,
                 anchor="w").pack(fill=tk.X)
        self._narr_txt = scrolledtext.ScrolledText(
            left, bg=C["surface"], fg=C["text"],
            font=F_BODY, wrap=tk.WORD,
            height=8, relief="flat", borderwidth=0,
            state=tk.DISABLED, padx=10, pady=8)
        self._narr_txt.pack(fill=tk.BOTH, expand=True, pady=4)

        ttk.Separator(ai_body, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=8)

        right = tk.Frame(ai_body, bg=C["bg"], width=290)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)
        tk.Label(right, text="Response Actions",
                 bg=C["bg"], fg=C["text_s"], font=F_BOLD,
                 anchor="w").pack(fill=tk.X)
        self._actions_txt = scrolledtext.ScrolledText(
            right, bg=C["surface"], fg=C["text"],
            font=F_BODY, wrap=tk.WORD,
            relief="flat", borderwidth=0,
            state=tk.DISABLED, padx=10, pady=8)
        self._actions_txt.pack(fill=tk.BOTH, expand=True, pady=4)

        # APT footer
        apt_row = tk.Frame(self._scroll_frame, bg=C["surface2"], pady=6)
        apt_row.pack(fill=tk.X, padx=16, pady=(4, 8))
        tk.Label(apt_row, text="Threat Group Association:",
                 bg=C["surface2"], fg=C["text_s"], font=F_BOLD,
                 padx=10).pack(side=tk.LEFT)
        self._apt_lbl = tk.Label(
            apt_row, text="—",
            bg=C["surface2"], fg=C["accent"], font=F_BODY, padx=8)
        self._apt_lbl.pack(side=tk.LEFT)

    # ── Render Attack Sequence + Type Classification ──────────────────────

    def _render_sequence_and_types(
        self, matches: list, sessions: list
    ) -> None:
        """Rebuild the sequence and type panels from current matches."""

        # Clear old content
        for w in self._seq_area.winfo_children():
            w.destroy()
        for w in self._type_area.winfo_children():
            w.destroy()

        if not matches:
            tk.Label(self._seq_area,
                     text="No attack sequence — load logs and click  🔍 Analyse",
                     bg=C["bg"], fg=C["text_d"], font=F_BODY,
                     pady=20).pack(anchor="w")
            return

        # ── Build ordered tactic → [(tid, tname)] map ─────────────────
        from collections import OrderedDict
        from datetime import datetime

        def _ts(m):
            ts = m.event.timestamp or ""
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S.%f",  "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.strptime(ts[:26].strip(), fmt)
                except ValueError:
                    continue
            return datetime.min

        sorted_m = sorted(matches, key=_ts)

        tactic_map: dict[str, list[tuple[str, str]]] = OrderedDict()
        seen: set[tuple[str, str]] = set()
        for m in sorted_m:
            tac = m.tactic or "unknown"
            key = (tac, m.technique_id)
            if key not in seen:
                seen.add(key)
                tactic_map.setdefault(tac, [])
                tactic_map[tac].append((m.technique_id, m.technique_name))

        ordered = sorted(
            tactic_map.keys(),
            key=lambda t: _TACTIC_ORDER.index(t) if t in _TACTIC_ORDER else 99)

        # For classifier
        tactic_list   = ordered
        technique_list = [tid for tac in ordered for (tid, _) in tactic_map[tac]]

        # ── Section heading ────────────────────────────────────────────
        tk.Label(self._seq_area,
                 text="Attack Sequence  —  Step-by-Step",
                 bg=C["bg"], fg=C["text"], font=F_BOLD,
                 anchor="w").pack(fill=tk.X, pady=(0, 2))
        tk.Label(self._seq_area,
                 text="Each step shows the ATT&CK tactic, the specific technique(s) used, "
                      "and what the attacker was doing at that phase.",
                 bg=C["bg"], fg=C["text_s"], font=F_SMALL,
                 anchor="w", wraplength=900).pack(fill=tk.X, pady=(0, 8))

        # ── One row per step ───────────────────────────────────────────
        for step_no, tactic in enumerate(ordered, 1):
            techniques  = tactic_map[tactic]
            tac_label   = _TACTIC_LABEL.get(tactic, tactic.title())
            tac_col     = _TACTIC_COLOUR.get(tactic, C["accent"])
            phase_desc  = PHASE_LABEL.get(tactic, "")

            row = tk.Frame(self._seq_area, bg=C["bg"])
            row.pack(fill=tk.X, pady=3)

            # Step number circle
            step_lbl = tk.Label(
                row, text=f" {step_no} ",
                bg=tac_col, fg=C["white"],
                font=("Segoe UI", 13, "bold"),
                padx=6, pady=2, relief="flat")
            step_lbl.pack(side=tk.LEFT, padx=(0, 8))

            # Content box
            box = tk.Frame(
                row, bg=C["surface"],
                highlightthickness=2,
                highlightbackground=tac_col)
            box.pack(side=tk.LEFT, fill=tk.X, expand=True)

            # Tactic header inside box
            tac_bar = tk.Frame(box, bg=tac_col, height=26)
            tac_bar.pack(fill=tk.X)
            tac_bar.pack_propagate(False)
            tk.Label(tac_bar,
                     text=f"  TACTIC:  {tac_label.upper()}",
                     bg=tac_col, fg=C["white"],
                     font=("Segoe UI", 11, "bold"),
                     anchor="w").pack(side=tk.LEFT, fill=tk.Y, padx=4)

            # Technique rows
            for tid, tname in techniques:
                t_row = tk.Frame(box, bg=C["surface"])
                t_row.pack(fill=tk.X, padx=8, pady=(3, 0))

                # TID badge
                tk.Label(t_row,
                         text=f"  {tid}  ",
                         bg=tac_col, fg=C["white"],
                         font=("Segoe UI", 9, "bold"),
                         padx=2).pack(side=tk.LEFT)

                # Arrow
                tk.Label(t_row, text=" → ",
                         bg=C["surface"], fg=C["text_s"],
                         font=("Segoe UI", 11)).pack(side=tk.LEFT)

                # Technique name
                tk.Label(t_row,
                         text=tname,
                         bg=C["surface"], fg=C["text"],
                         font=("Segoe UI", 10, "bold"),
                         anchor="w").pack(side=tk.LEFT)

            # Attack phase description
            if phase_desc:
                ph_row = tk.Frame(box, bg=C["surface"])
                ph_row.pack(fill=tk.X, padx=8, pady=(4, 4))
                tk.Label(ph_row,
                         text="📌  Attack Phase: ",
                         bg=C["surface"], fg=C["text_s"],
                         font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
                tk.Label(ph_row,
                         text=phase_desc,
                         bg=C["surface"], fg=C["text_s"],
                         font=("Segoe UI", 9),
                         anchor="w", wraplength=700).pack(
                             side=tk.LEFT, fill=tk.X, expand=True)

            # Arrow to next step
            if step_no < len(ordered):
                tk.Label(self._seq_area,
                         text="          ↓",
                         bg=C["bg"], fg="#AAAAAA",
                         font=("Segoe UI", 14)).pack(anchor="w")

        # ── Attack Type Classification ─────────────────────────────────
        results = _classifier.classify(tactic_list, technique_list)

        tk.Frame(self._type_area, bg=C["border"], height=2).pack(
            fill=tk.X, pady=(4, 8))

        tk.Label(self._type_area,
                 text="Attack Type Classification",
                 bg=C["bg"], fg=C["text"], font=F_BOLD,
                 anchor="w").pack(fill=tk.X)
        tk.Label(self._type_area,
                 text="Based on the sequential pattern of tactics and techniques "
                      "observed on this machine.",
                 bg=C["bg"], fg=C["text_s"], font=F_SMALL,
                 anchor="w", wraplength=900).pack(fill=tk.X, pady=(0, 8))

        if not results:
            tk.Label(self._type_area,
                     text="No known attack pattern matched the observed sequence.",
                     bg=C["bg"], fg=C["text_d"], font=F_BODY,
                     pady=8).pack(anchor="w")
        else:
            for i, r in enumerate(results):
                is_primary = (i == 0)
                sev_col    = _SEV_COLOUR.get(r.severity, C["accent"])
                conf_col   = _CONF_COLOUR.get(r.confidence, C["text_s"])

                card = tk.Frame(
                    self._type_area, bg=C["surface"],
                    highlightthickness=3 if is_primary else 1,
                    highlightbackground=sev_col)
                card.pack(fill=tk.X, pady=(0, 6))

                # Card header
                card_hdr = tk.Frame(card, bg=sev_col, height=32)
                card_hdr.pack(fill=tk.X)
                card_hdr.pack_propagate(False)

                prefix = "🎯  FINAL VERDICT: " if is_primary else f"  Alternative ({i+1}): "
                tk.Label(card_hdr,
                         text=f"{prefix}{r.attack_type}",
                         bg=sev_col, fg=C["white"],
                         font=("Segoe UI", 12, "bold") if is_primary
                         else ("Segoe UI", 10, "bold"),
                         anchor="w", padx=10).pack(
                             side=tk.LEFT, fill=tk.Y)

                # Severity + Confidence badges
                badges = tk.Frame(card_hdr, bg=sev_col)
                badges.pack(side=tk.RIGHT, padx=8)
                tk.Label(badges,
                         text=f"  {r.severity}  ",
                         bg=C["white"], fg=sev_col,
                         font=("Segoe UI", 9, "bold"),
                         padx=4, pady=2).pack(side=tk.LEFT, padx=2)
                tk.Label(badges,
                         text=f"  Confidence: {r.confidence}  ",
                         bg=conf_col, fg=C["white"],
                         font=("Segoe UI", 9, "bold"),
                         padx=4, pady=2).pack(side=tk.LEFT, padx=2)

                # Description
                tk.Label(card,
                         text=r.description,
                         bg=C["surface"], fg=C["text"],
                         font=F_BODY, wraplength=900,
                         justify="left", anchor="w",
                         padx=12, pady=8).pack(fill=tk.X)

                # Matched evidence (collapsed for alternates)
                if is_primary and r.matched_on:
                    ev_row = tk.Frame(card, bg=C["surface2"])
                    ev_row.pack(fill=tk.X)
                    tk.Label(ev_row,
                             text="  Evidence: " + ",  ".join(r.matched_on[:8]),
                             bg=C["surface2"], fg=C["text_s"],
                             font=F_SMALL, anchor="w",
                             padx=8, pady=4).pack(fill=tk.X)

    # ── AI Narrative ──────────────────────────────────────────────────────

    def _generate(self) -> None:
        if not self._sessions:
            messagebox.showinfo("No Data",
                                "Load logs and run  🔍 Analyse  first.")
            return
        if not self._ai.available:
            messagebox.showwarning(
                "API Key Required",
                "Set your Gemini API key in Settings (top-right ⚙).\n"
                "Free tier: 15 req/min · 1M tokens/day · No credit card.",
            )
            return

        self._set_status("Generating AI threat narrative …")
        session = self._sessions[0]
        groups  = self._engine.associate_groups(session.techniques)
        self._apt_groups = groups

        def task() -> None:
            result = self._ai.narrative_for_session(session, groups)
            self._root.after(0, lambda: self._display(result, groups))

        threading.Thread(target=task, daemon=True).start()

    def _display(self, result, groups: list[str]) -> None:
        self._result = result
        self._set_status("Threat narrative ready.")

        sev_cols = {"Critical": C["critical"], "High": C["high"],
                    "Medium": C["medium"], "Low": C["low"]}
        c = sev_cols.get(result.severity, C["text_s"])
        self._badge.configure(
            text=f"  {result.severity}  ", bg=c,
            fg=C["white"] if result.severity != "Medium" else "#FFF4CE")
        self._hint_lbl.configure(text=result.severity_reason)

        self._narr_txt.configure(state=tk.NORMAL)
        self._narr_txt.delete("1.0", tk.END)
        self._narr_txt.insert("1.0", result.narrative)
        self._narr_txt.configure(state=tk.DISABLED)

        self._actions_txt.configure(state=tk.NORMAL)
        self._actions_txt.delete("1.0", tk.END)
        for i, a in enumerate(result.response_actions, 1):
            self._actions_txt.insert(tk.END, f"{i}.  {a}\n\n")
        self._actions_txt.configure(state=tk.DISABLED)

        self._apt_lbl.configure(
            text=", ".join(groups[:4]) if groups else "No pattern matched")
