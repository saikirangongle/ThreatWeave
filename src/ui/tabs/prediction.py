"""ThreatWeave — Prediction Tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from ui.theme import C, F_BODY, F_BOLD, F_HEAD, F_MONO, F_SMALL  # type: ignore[import]


class PredictionTab:
    """Shows predicted next MITRE techniques based on observed chain."""

    def __init__(self, frame: ttk.Frame, root: tk.Tk, engine) -> None:
        self._frame   = frame
        self._root    = root
        self._engine  = engine
        self._sessions: list = []
        self._preds:  list   = []
        self._build()

    def set_data(self, sessions: list) -> None:
        self._sessions = sessions

    def _build(self) -> None:
        f = self._frame

        # Header
        hdr = tk.Frame(f, bg=C["surface3"], pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="🔮  Predictive Attack-Chain Analysis",
                 bg=C["surface3"], fg=C["text"], font=F_HEAD,
                 padx=16).pack(side=tk.LEFT)
        ttk.Button(hdr, text="▶  Run Prediction",
                   style="Accent.TButton",
                   command=self._predict).pack(side=tk.RIGHT, padx=12)

        # Observed chain display
        obs = tk.Frame(f, bg=C["bg"], pady=8)
        obs.pack(fill=tk.X, padx=16)
        tk.Label(obs, text="Observed technique chain:",
                 bg=C["bg"], fg=C["text_s"], font=F_BOLD,
                 anchor="w").pack(anchor="w")
        self._chain_lbl = tk.Label(
            obs, text="—",
            bg=C["surface2"], fg=C["accent"],
            font=F_MONO, wraplength=1100,
            justify="left", pady=7, padx=10, anchor="w",
        )
        self._chain_lbl.pack(fill=tk.X)

        ttk.Separator(f).pack(fill=tk.X, padx=16, pady=6)

        tk.Label(f, text="Predicted next techniques:",
                 bg=C["bg"], fg=C["text_s"], font=F_BOLD,
                 padx=16, anchor="w").pack(anchor="w")

        # Predictions table
        cols = ("rank", "technique", "name", "tactic",
                "probability", "groups", "controls")
        self._pred_tree = ttk.Treeview(
            f, columns=cols, show="headings", height=8,
        )
        for col, w, lbl in [
            ("rank",        48, "#"),
            ("technique",  100, "Technique"),
            ("name",       200, "Name"),
            ("tactic",     160, "Tactic"),
            ("probability", 95, "Probability"),
            ("groups",     220, "Threat Groups"),
            ("controls",   180, "NIST Controls"),
        ]:
            self._pred_tree.heading(col, text=lbl)
            self._pred_tree.column(col, width=w, minwidth=40)
        self._pred_tree.pack(fill=tk.X, padx=16, pady=4)
        self._pred_tree.bind("<<TreeviewSelect>>", self._on_pred_select)

        ttk.Separator(f).pack(fill=tk.X, padx=16, pady=4)

        tk.Label(f, text="Reasoning:",
                 bg=C["bg"], fg=C["text_s"], font=F_BOLD,
                 padx=16, anchor="w").pack(anchor="w")
        self._reason_txt = scrolledtext.ScrolledText(
            f, bg=C["surface"], fg=C["text"],
            font=F_BODY, wrap=tk.WORD,
            height=6, relief="flat", borderwidth=0,
            state=tk.DISABLED, padx=10, pady=8,
        )
        self._reason_txt.pack(fill=tk.BOTH, expand=True, padx=16, pady=4)

    def _predict(self) -> None:
        if not self._sessions:
            messagebox.showinfo("No Data",
                                "Load logs and run 🔍 Analyse first.")
            return

        chain = self._sessions[0].techniques
        self._chain_lbl.configure(
            text="  →  ".join(chain) if chain else "No techniques detected"
        )

        import config as cfg  # type: ignore[import]
        top_n = cfg.get("prediction_top_n", 5)
        self._preds = self._engine.predict_next(chain, top_n=top_n)

        self._pred_tree.delete(*self._pred_tree.get_children())
        for i, p in enumerate(self._preds, 1):
            self._pred_tree.insert("", tk.END, iid=str(i), values=(
                i,
                p.technique_id,
                p.technique_name,
                p.tactic,
                f"{p.probability:.0%}",
                ", ".join(p.threat_groups[:2]),
                ", ".join(p.nist_controls[:3]),
            ))

        if not self._preds:
            self._reason_txt.configure(state=tk.NORMAL)
            self._reason_txt.delete("1.0", tk.END)
            self._reason_txt.insert(
                "1.0",
                "No predictions available for this technique chain.\n"
                "The chain may not match any known APT transition patterns.\n"
                "Run  scripts/build_graph.py  to build the full MITRE CTI graph.",
            )
            self._reason_txt.configure(state=tk.DISABLED)

    def _on_pred_select(self, _event: object = None) -> None:
        sel = self._pred_tree.selection()
        if not sel or not self._preds:
            return
        try:
            idx = int(sel[0]) - 1
            p   = self._preds[idx]
        except (ValueError, IndexError):
            return

        text = (
            f"{p.reasoning}\n\n"
            f"Threat groups  :  {', '.join(p.threat_groups) or 'unknown'}\n"
            f"NIST controls  :  {', '.join(p.nist_controls)}\n"
            f"Tactic         :  {p.tactic}\n"
            f"Probability    :  {p.probability:.1%}"
        )
        self._reason_txt.configure(state=tk.NORMAL)
        self._reason_txt.delete("1.0", tk.END)
        self._reason_txt.insert("1.0", text)
        self._reason_txt.configure(state=tk.DISABLED)
