"""
ThreatWeave — Main Application Window
Windows 11-compatible Tkinter UI with Gemini tier detection.
"""

from __future__ import annotations

import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import config as cfg                            # type: ignore[import]
from ui.theme import C, F_BODY, F_BOLD, F_HEAD, F_SMALL, apply_theme  # type: ignore[import]
from ui.tabs.explorer   import ExplorerTab      # type: ignore[import]
from ui.tabs.heatmap    import HeatmapTab       # type: ignore[import]
from ui.tabs.narrative  import NarrativeTab     # type: ignore[import]
from ui.tabs.prediction import PredictionTab    # type: ignore[import]
from ui.tabs.report     import ReportTab        # type: ignore[import]

from fetcher    import LiveFetcher, is_admin    # type: ignore[import]
from mapper     import MITREMapper              # type: ignore[import]
from analyzer   import AttackChainEngine, SessionClusterer  # type: ignore[import]
from ai_engine  import AIEngine                 # type: ignore[import]


class MainWindow:
    """Root Tkinter window for ThreatWeave."""

    def __init__(self, start_channel=None, autofetch=False) -> None:
        self.root = tk.Tk()
        self.root.title("ThreatWeave — Windows Event Log Threat Analysis")
        self.root.geometry("1400x860")
        self.root.minsize(1100, 700)

        apply_theme(self.root)
        self.root.configure(bg=C["bg"])

        # Shared services
        self.fetcher   = LiveFetcher()
        self.mapper    = MITREMapper()
        self.clusterer = SessionClusterer(cfg.get("session_window_minutes", 30))
        self.engine    = AttackChainEngine()
        self.ai        = AIEngine()

        self._start_channel = start_channel
        self._autofetch    = autofetch
        self._build_admin_banner()
        self._build_titlebar()
        self._build_notebook()
        self._build_statusbar()

        self.root.bind("<Control-o>", lambda _: self.explorer.open_file())
        self.root.bind("<Control-l>", lambda _: self.explorer.fetch_live())
        self.root.bind("<F5>",        lambda _: self.explorer.fetch_live())

    # ── Admin banner ──────────────────────────────────────────────────────

    def _build_admin_banner(self) -> None:
        if not sys.platform.startswith("win"):
            return
        if is_admin():
            return
        bar = tk.Frame(self.root, bg="#FFF4CE", height=34)
        bar.pack(fill=tk.X, side=tk.TOP)
        bar.pack_propagate(False)
        tk.Label(
            bar,
            text=(
                "⚠   Not running as Administrator — "
                "Security channel unavailable.  "
                "Restart as Admin to access Security logs."
            ),
            bg="#FFF4CE", fg="#9D5D00", font=F_SMALL, anchor="w", padx=12,
        ).pack(side=tk.LEFT, fill=tk.Y)
        tk.Button(
            bar, text="✕", bg="#FFF4CE", fg="#9D5D00",
            relief="flat", font=F_SMALL, cursor="hand2",
            command=bar.destroy, bd=0, padx=8,
        ).pack(side=tk.RIGHT, fill=tk.Y)

    # ── Title bar ─────────────────────────────────────────────────────────

    def _build_titlebar(self) -> None:
        bar = tk.Frame(self.root, bg=C["accent"], height=48)
        bar.pack(fill=tk.X, side=tk.TOP)
        bar.pack_propagate(False)

        tk.Label(bar, text="🛡  ThreatWeave",
                 bg=C["accent"], fg=C["white"], font=F_HEAD,
                 padx=16).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(bar, text="Windows Event Log Threat Analysis Engine",
                 bg=C["accent"], fg="#B8D8F8",
                 font=F_SMALL).pack(side=tk.LEFT, fill=tk.Y)

        tk.Button(
            bar, text="⚙  Settings",
            bg=C["accent_h"], fg=C["white"], font=F_SMALL,
            relief="flat", cursor="hand2", padx=12, bd=0,
            command=self._open_settings,
        ).pack(side=tk.RIGHT, padx=8, pady=8)

    # ── Notebook ──────────────────────────────────────────────────────────

    def _build_notebook(self) -> None:
        tk.Frame(self.root, bg=C["border"], height=1).pack(fill=tk.X)

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill=tk.BOTH, expand=True)

        f_explorer   = ttk.Frame(self.nb, style="Surface.TFrame")
        f_heatmap    = ttk.Frame(self.nb, style="Surface.TFrame")
        f_narrative  = ttk.Frame(self.nb, style="Surface.TFrame")
        f_prediction = ttk.Frame(self.nb, style="Surface.TFrame")
        f_report     = ttk.Frame(self.nb, style="Surface.TFrame")

        self.nb.add(f_explorer,   text="  📋  Log Explorer  ")
        self.nb.add(f_heatmap,    text="  🗺  MITRE Heatmap  ")
        self.nb.add(f_narrative,  text="  🧠  Threat Narrative  ")
        self.nb.add(f_prediction, text="  🔮  Prediction  ")
        self.nb.add(f_report,     text="  📄  Report  ")

        self.explorer   = ExplorerTab(
            f_explorer, self.root,
            fetcher=self.fetcher, mapper=self.mapper, ai=self.ai,
            on_analysed=self._on_analysed, set_status=self.set_status,
            start_channel=self._start_channel,
            autofetch=self._autofetch,
        )
        self.heatmap    = HeatmapTab(f_heatmap,    self.root, engine=self.engine)
        self.narrative  = NarrativeTab(f_narrative, self.root, ai=self.ai,
                                        engine=self.engine, set_status=self.set_status)
        self.prediction = PredictionTab(f_prediction, self.root, engine=self.engine)
        self.report_tab = ReportTab(f_report, self.root, set_status=self.set_status)

    # ── Status bar ────────────────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self.root, bg=C["surface3"], height=28)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)

        self._status_var = tk.StringVar(
            value="Ready — choose a channel and Fetch Logs, or open a file."
        )
        tk.Label(bar, textvariable=self._status_var,
                 bg=C["surface3"], fg=C["text_s"], font=F_SMALL,
                 anchor="w", padx=12).pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._ai_var = tk.StringVar()
        self._ai_lbl = tk.Label(bar, textvariable=self._ai_var,
                                  bg=C["surface3"], font=F_SMALL, padx=12)
        self._ai_lbl.pack(side=tk.RIGHT)
        self._update_ai_indicator()

    def set_status(self, msg: str) -> None:
        self.root.after(0, lambda: self._status_var.set(msg))

    def _update_ai_indicator(self) -> None:
        if self.ai.available:
            tier = self.ai.tier_info
            label = f"● AI: {tier.display_label if tier else 'Ready'}"
            colour = C["low"] if (tier and tier.is_paid) else C["medium"]
        else:
            label  = "● AI: Not configured"
            colour = C["high"]
        self._ai_var.set(label)
        self._ai_lbl.configure(fg=colour)

    def _on_analysed(self, matches: list, sessions: list) -> None:
        self.heatmap.update(matches, self.mapper)
        self.narrative.set_data(sessions, matches)
        self.prediction.set_data(sessions)
        self.report_tab.set_data(sessions, matches)

    # ── Settings dialog with tier detection ───────────────────────────────

    def _open_settings(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.geometry("560x520")
        win.resizable(False, False)
        win.configure(bg=C["bg"])
        win.grab_set()

        # Header
        hdr = tk.Frame(win, bg=C["accent"], height=48)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="⚙  Settings", bg=C["accent"], fg=C["white"],
                 font=F_HEAD, padx=16).pack(side=tk.LEFT, fill=tk.Y)

        frm = tk.Frame(win, bg=C["bg"], padx=24, pady=16)
        frm.pack(fill=tk.BOTH, expand=True)

        # API Key
        tk.Label(frm, text="Google Gemini API Key",
                 bg=C["bg"], fg=C["text"], font=F_BOLD,
                 anchor="w").grid(row=0, column=0, columnspan=3,
                                   sticky="w", pady=(0, 2))
        tk.Label(frm,
                 text="Free: ~15 req/min · 1M tokens/day · No credit card needed  "
                      "→  aistudio.google.com/app/apikey",
                 bg=C["bg"], fg=C["text_s"], font=F_SMALL,
                 anchor="w").grid(row=1, column=0, columnspan=3,
                                   sticky="w", pady=(0, 6))

        key_var = tk.StringVar(value=cfg.get("gemini_api_key", ""))
        key_ent = ttk.Entry(frm, textvariable=key_var, width=42, show="•")
        key_ent.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 2))

        show_var = tk.BooleanVar()
        ttk.Checkbutton(
            frm, text="Show", variable=show_var,
            command=lambda: key_ent.configure(show="" if show_var.get() else "•"),
        ).grid(row=2, column=2, sticky="w", padx=(6, 0))

        # Detect Tier button
        ttk.Button(
            frm, text="🔍  Detect Tier & Available Models",
            command=lambda: _detect(),
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # Tier result box
        tier_frame = tk.Frame(frm, bg=C["surface2"], relief="flat")
        tier_frame.grid(row=4, column=0, columnspan=3, sticky="ew",
                        pady=(6, 12))
        tier_lbl = tk.Label(
            tier_frame,
            text="Click 'Detect Tier' after entering your API key.",
            bg=C["surface2"], fg=C["text_s"],
            font=F_SMALL, justify="left",
            wraplength=490, padx=10, pady=8,
        )
        tier_lbl.pack(fill=tk.X)

        # Model selector
        tk.Label(frm, text="Gemini Model",
                 bg=C["bg"], fg=C["text"], font=F_BOLD,
                 anchor="w").grid(row=5, column=0, sticky="w")
        model_var = tk.StringVar(
            value=cfg.get("gemini_model", "gemini-1.5-flash"))
        model_cb = ttk.Combobox(
            frm, textvariable=model_var, width=32, state="readonly",
            values=["gemini-1.5-flash", "gemini-1.5-pro",
                    "gemini-2.0-flash", "gemini-1.5-pro-002"],
        )
        model_cb.grid(row=5, column=1, columnspan=2, sticky="w",
                      padx=(12, 0), pady=(0, 4))
        tk.Label(frm,
                 text="Tip: Run 'Detect Tier' to see only models available for your key.",
                 bg=C["bg"], fg=C["text_s"], font=F_SMALL,
                 anchor="w").grid(row=6, column=0, columnspan=3, sticky="w",
                                   pady=(0, 14))

        # Session window
        tk.Label(frm, text="Session window  (minutes)",
                 bg=C["bg"], fg=C["text"], font=F_BOLD,
                 anchor="w").grid(row=7, column=0, sticky="w")
        win_var = tk.IntVar(value=cfg.get("session_window_minutes", 30))
        ttk.Spinbox(frm, from_=5, to=120, textvariable=win_var,
                    width=8).grid(row=7, column=1, sticky="w",
                                  padx=(12, 0), pady=(0, 16))

        frm.columnconfigure(0, weight=1)
        frm.columnconfigure(1, weight=2)

        # ── Detect tier inline ─────────────────────────────────────────────
        def _detect() -> None:
            key = key_var.get().strip()
            if not key:
                tier_lbl.configure(
                    text="Enter an API key first.",
                    fg=C["high"], bg=C["surface2"])
                return
            tier_lbl.configure(
                text="Detecting tier … (this takes a few seconds)",
                fg=C["text_s"], bg=C["surface2"])
            win.update_idletasks()

            def task() -> None:
                from ai_engine import detect_tier  # type: ignore[import]
                info = detect_tier(key)
                win.after(0, lambda: _show_tier(info))

            threading.Thread(target=task, daemon=True).start()

        def _show_tier(info) -> None:
            if info.tier == "invalid":
                bg = "#FEE2E2"; fg = C["critical"]
            elif info.tier == "paid":
                bg = "#DCFCE7"; fg = C["low"]
            elif info.tier == "free":
                bg = "#FFF4CE"; fg = "#9D5D00"
            else:
                bg = C["surface2"]; fg = C["text_s"]

            tier_frame.configure(bg=bg)
            tier_lbl.configure(
                text=(
                    f"Tier: {info.display_label}   "
                    f"Rate: {info.rpm_note}\n"
                    f"{info.warning}"
                ),
                bg=bg, fg=fg,
            )

            # Update model dropdown with available models
            if info.available_models:
                model_cb.configure(values=info.available_models)
                if info.best_model in info.available_models:
                    model_var.set(info.best_model)
                elif info.available_models:
                    model_var.set(info.available_models[0])

        # ── Save / Cancel ──────────────────────────────────────────────────
        btn_row = tk.Frame(win, bg=C["bg"])
        btn_row.pack(pady=8)

        def _save() -> None:
            cfg.set_value("gemini_api_key",         key_var.get().strip())
            cfg.set_value("gemini_model",           model_var.get())
            cfg.set_value("session_window_minutes", win_var.get())
            self.ai.reinit()
            self.clusterer = SessionClusterer(win_var.get())
            self._update_ai_indicator()
            win.destroy()
            messagebox.showinfo("Saved", "Settings saved successfully.")

        ttk.Button(btn_row, text="Save",
                   style="Accent.TButton",
                   command=_save).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_row, text="Cancel",
                   command=win.destroy).pack(side=tk.LEFT, padx=8)

    def run(self) -> None:
        self.root.mainloop()
