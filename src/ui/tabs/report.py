"""ThreatWeave — Report Export Tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from ui.theme import C, F_BODY, F_BOLD, F_HEAD, F_SMALL  # type: ignore[import]


class ReportTab:
    """Export PDF and HTML forensic reports."""

    def __init__(
        self,
        frame:      ttk.Frame,
        root:       tk.Tk,
        set_status: Callable,
    ) -> None:
        self._frame      = frame
        self._root       = root
        self._set_status = set_status

        self._sessions:   list = []
        self._matches:    list = []
        self._narrative         = None
        self._predictions: list = []
        self._apt_groups:  list[str] = []

        self._build()

    def set_data(self, sessions: list, matches: list) -> None:
        self._sessions = sessions
        self._matches  = matches
        n = len(sessions)
        self._session_lbl.configure(
            text=f"{n} session(s) ready for export."
            if n else "No sessions yet — run analysis first."
        )

    # ─────────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        f = self._frame

        hdr = tk.Frame(f, bg=C["surface3"], pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="📄  Forensic Report Export",
                 bg=C["surface3"], fg=C["text"], font=F_HEAD,
                 padx=16).pack(side=tk.LEFT)

        body = tk.Frame(f, bg=C["bg"], padx=32, pady=24)
        body.pack(fill=tk.BOTH, expand=True)

        self._session_lbl = tk.Label(
            body,
            text="No sessions yet — run analysis first.",
            bg=C["bg"], fg=C["text_s"], font=F_BODY, anchor="w",
        )
        self._session_lbl.pack(anchor="w", pady=(0, 16))

        tk.Label(
            body,
            text=(
                "Generate a Threat Narrative (Tab 3) before exporting "
                "for AI-powered content.\n"
                "Reports include:\n"
                "  • Executive threat narrative with severity rating\n"
                "  • MITRE ATT&CK technique chain\n"
                "  • Threat group association\n"
                "  • Predicted next steps with NIST 800-53 controls\n"
                "  • Full event timeline"
            ),
            bg=C["bg"], fg=C["text_s"], font=F_BODY,
            justify="left", anchor="w",
        ).pack(anchor="w", pady=(0, 24))

        btn_row = tk.Frame(body, bg=C["bg"])
        btn_row.pack(anchor="w")

        ttk.Button(
            btn_row, text="📄  Export PDF Report",
            style="Accent.TButton",
            command=self._export_pdf,
        ).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Button(
            btn_row, text="🌐  Export HTML Report",
            command=self._export_html,
        ).pack(side=tk.LEFT)

        self._status_lbl = tk.Label(
            body, text="", bg=C["bg"], fg=C["low"],
            font=F_BOLD, anchor="w",
        )
        self._status_lbl.pack(anchor="w", pady=(16, 0))

    # ─────────────────────────────────────────────────────────────────────

    def _check_ready(self) -> bool:
        if not self._sessions:
            messagebox.showinfo(
                "No Data",
                "Load logs, run Analyse, then export.",
            )
            return False
        return True

    def _get_narrative(self):
        """Return narrative result, creating a fallback if none exists."""
        if self._narrative is not None:
            return self._narrative
        # Build a fallback from the first session
        from ai_engine import AIEngine  # type: ignore[import]
        dummy = AIEngine()              # no API key → always fallback
        return dummy._fallback_narrative(self._sessions[0])

    def _export_pdf(self) -> None:
        if not self._check_ready():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            initialfile="ThreatWeave_Report.pdf",
        )
        if not path:
            return
        self._set_status("Generating PDF …")
        from reporter import generate_pdf  # type: ignore[import]
        ok = generate_pdf(
            path,
            self._sessions[0],
            self._get_narrative(),
            self._predictions,
            self._apt_groups,
            self._matches,
        )
        msg = f"✓  PDF saved: {path}" if ok else "✗  PDF export failed — check console."
        self._status_lbl.configure(
            text=msg, fg=C["low"] if ok else C["critical"])
        self._set_status(msg)

    def _export_html(self) -> None:
        if not self._check_ready():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html")],
            initialfile="ThreatWeave_Report.html",
        )
        if not path:
            return
        self._set_status("Generating HTML …")
        from reporter import generate_html  # type: ignore[import]
        ok = generate_html(
            path,
            self._sessions[0],
            self._get_narrative(),
            self._predictions,
            self._apt_groups,
            self._matches,
        )
        msg = f"✓  HTML saved: {path}" if ok else "✗  HTML export failed — check console."
        self._status_lbl.configure(
            text=msg, fg=C["low"] if ok else C["critical"])
        self._set_status(msg)
