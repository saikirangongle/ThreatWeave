"""ThreatWeave — Threat Narrative Tab."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable

from ui.theme import C, F_BODY, F_BOLD, F_HEAD, F_SMALL  # type: ignore[import]


class NarrativeTab:
    """Displays AI-generated threat narrative and response actions."""

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

        self._sessions: list = []
        self._matches:  list = []
        self._result           = None
        self._apt_groups: list[str] = []

        self._build()

    def set_data(self, sessions: list, matches: list) -> None:
        self._sessions = sessions
        self._matches  = matches
        count = len(sessions)
        hint = f"{count} session(s) ready." if count else "No sessions detected."
        self._hint_lbl.configure(text=hint)

    # ─────────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        f = self._frame

        # Header bar
        hdr = tk.Frame(f, bg=C["surface3"], pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="🧠  Threat Narrative",
                 bg=C["surface3"], fg=C["text"], font=F_HEAD,
                 padx=16).pack(side=tk.LEFT)
        ttk.Button(hdr, text="▶  Generate Narrative",
                   style="Accent.TButton",
                   command=self._generate).pack(side=tk.RIGHT, padx=12)

        # Severity badge row
        sev_row = tk.Frame(f, bg=C["bg"], pady=8)
        sev_row.pack(fill=tk.X, padx=16)

        self._badge = tk.Label(
            sev_row, text="  —  ",
            bg=C["surface3"], fg=C["text"],
            font=("Segoe UI", 14, "bold"),
            padx=16, pady=6,
        )
        self._badge.pack(side=tk.LEFT)

        self._hint_lbl = tk.Label(
            sev_row,
            text="Run analysis first, then click Generate Narrative.",
            bg=C["bg"], fg=C["text_s"], font=F_BODY,
            wraplength=700, justify="left",
        )
        self._hint_lbl.pack(side=tk.LEFT, padx=12)

        ttk.Separator(f).pack(fill=tk.X, padx=16, pady=4)

        # Two-column body
        body = tk.Frame(f, bg=C["bg"])
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        left = tk.Frame(body, bg=C["bg"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(left, text="Threat Narrative",
                 bg=C["bg"], fg=C["text_s"], font=F_BOLD,
                 anchor="w").pack(fill=tk.X)
        self._narr_txt = scrolledtext.ScrolledText(
            left, bg=C["surface"], fg=C["text"],
            font=F_BODY, wrap=tk.WORD,
            height=10, relief="flat", borderwidth=0,
            state=tk.DISABLED, padx=10, pady=8,
        )
        self._narr_txt.pack(fill=tk.BOTH, expand=True, pady=4)

        ttk.Separator(body, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10)

        right = tk.Frame(body, bg=C["bg"], width=310)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)
        tk.Label(right, text="Response Actions",
                 bg=C["bg"], fg=C["text_s"], font=F_BOLD,
                 anchor="w").pack(fill=tk.X)
        self._actions_txt = scrolledtext.ScrolledText(
            right, bg=C["surface"], fg=C["text"],
            font=F_BODY, wrap=tk.WORD,
            relief="flat", borderwidth=0,
            state=tk.DISABLED, padx=10, pady=8,
        )
        self._actions_txt.pack(fill=tk.BOTH, expand=True, pady=4)

        # APT association footer
        apt_row = tk.Frame(f, bg=C["surface2"], pady=7)
        apt_row.pack(fill=tk.X, padx=16, pady=(0, 8))
        tk.Label(apt_row, text="Threat Group Association:",
                 bg=C["surface2"], fg=C["text_s"], font=F_BOLD,
                 padx=10).pack(side=tk.LEFT)
        self._apt_lbl = tk.Label(
            apt_row, text="—",
            bg=C["surface2"], fg=C["accent"], font=F_BODY, padx=8,
        )
        self._apt_lbl.pack(side=tk.LEFT)

    # ─────────────────────────────────────────────────────────────────────

    def _generate(self) -> None:
        if not self._sessions:
            messagebox.showinfo("No Data",
                                "Load logs and run 🔍 Analyse first.")
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
        self._result    = result
        self._set_status("Threat narrative ready.")

        sev_colours = {
            "Critical": C["critical"],
            "High":     C["high"],
            "Medium":   C["medium"],
            "Low":      C["low"],
        }
        c = sev_colours.get(result.severity, C["text_s"])
        self._badge.configure(
            text=f"  {result.severity}  ",
            bg=c,
            fg=C["white"] if result.severity != "Medium" else "#FFF4CE",
        )
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
            text=", ".join(groups[:4]) if groups else "No pattern matched"
        )
