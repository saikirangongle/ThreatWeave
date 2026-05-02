"""
ThreatWeave — Log Explorer Tab

Key behaviours:
  • Security channel with no admin → triggers Windows UAC popup (ShellExecuteW "runas")
    instead of a custom "restart as admin" dialog.
    The app relaunches elevated, auto-selects the channel, and auto-fetches.
  • Timestamp: UTC → local time conversion via _fmt_ts()
  • File load: resets time filter to "All time" so all events are visible.
  • iid = str(original_index) — stable, never str(id(ev)).
  • Time-range AI analysis panel at the bottom.
"""

from __future__ import annotations

import sys
import threading
import tkinter as tk
from datetime import datetime, timedelta, timezone
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Callable, Optional

from fetcher    import LiveFetcher, is_admin, request_admin_elevation  # type: ignore[import]
from mapper     import MITREMapper                                      # type: ignore[import]
from models     import WindowsEvent                                     # type: ignore[import]
from ai_engine  import AIEngine                                         # type: ignore[import]
from ui.theme   import (                                                # type: ignore[import]
    C, F_BODY, F_BOLD, F_HEAD, F_MONO, F_SMALL,
    configure_severity_tags,
)

# ── Constants ─────────────────────────────────────────────────────────────────

LOG_CHANNELS = [
    "All Channels",
    "Application",
    "Security",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-DNS-Client/Operational",
]

TIME_PRESETS = [
    "All time",
    "Last 1 hour",
    "Last 6 hours",
    "Last 24 hours",
    "Last 7 days",
    "Last 30 days",
]

MAX_OPTS = ["100", "250", "500", "1000", "2500", "5000"]
_DT_FMT  = "%Y-%m-%d %H:%M"

# Section colours for AI explain popup
_EXPLAIN_SECTIONS = {
    "WHAT HAPPENED":   ("#0078D4", "#EBF4FF"),
    "CAUSE / CONTEXT": ("#9D5D00", "#FFF4CE"),
    "REMEDIATION":     ("#107C10", "#E8F5E9"),
}


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def _parse_event_ts(ts: str) -> datetime:
    """Parse raw UTC timestamp string -> naive UTC datetime (used for sorting only)."""
    if not ts:
        return datetime.min
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",  "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts[:26].strip(), fmt)
        except ValueError:
            continue
    return datetime.min


def _event_local_ts(ts: str) -> datetime:
    """
    Convert a raw UTC event timestamp to a NAIVE local datetime.
    Used when comparing against user-entered From/To times, which are
    entered in local time (matching what is shown in the table).

    Example (IST = UTC+5:30):
        Raw UTC stored:  2026-04-22T10:16:00Z
        Table shows:     2026-04-22 15:46:00 India Standard Time
        User enters:     2026-04-22 15:46
        Both are 15:46 local -> comparison works correctly.
    """
    if not ts:
        return datetime.min
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",  "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S"):
        try:
            dt_utc   = datetime.strptime(ts[:26].strip(), fmt).replace(tzinfo=timezone.utc)
            dt_local = dt_utc.astimezone()
            return dt_local.replace(tzinfo=None)   # naive local datetime
        except ValueError:
            continue
    return datetime.min


def _fmt_ts(ts: str) -> str:
    """Convert UTC timestamp from wevtutil to machine local time."""
    if not ts:
        return ""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",  "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S"):
        try:
            dt_utc   = datetime.strptime(ts[:26].strip(), fmt).replace(tzinfo=timezone.utc)
            dt_local = dt_utc.astimezone()
            tz_name  = dt_local.tzname() or ""
            return dt_local.strftime("%Y-%m-%d  %H:%M:%S") + (
                f"  {tz_name}" if tz_name else "")
        except ValueError:
            continue
    return ts[:19]


def _parse_dt(s: str) -> Optional[datetime]:
    for fmt in (_DT_FMT, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    return None


def _hours(preset: str) -> int:
    return {"Last 1 hour": 1, "Last 6 hours": 6, "Last 24 hours": 24,
            "Last 7 days": 168, "Last 30 days": 720, "All time": 0}.get(preset, 0)


# ── Explorer Tab ──────────────────────────────────────────────────────────────

class ExplorerTab:
    """Log Explorer — fetch, display and filter Windows Event Logs."""

    def __init__(
        self,
        frame:        ttk.Frame,
        root:         tk.Tk,
        fetcher:      LiveFetcher,
        mapper:       MITREMapper,
        ai:           AIEngine,
        on_analysed:  Callable,
        set_status:   Callable,
        start_channel: Optional[str] = None,
        autofetch:     bool = False,
    ) -> None:
        self._frame       = frame
        self._root        = root
        self._fetcher     = fetcher
        self._mapper      = mapper
        self._ai          = ai
        self._on_analysed = on_analysed
        self._set_status  = set_status

        self._events: list[WindowsEvent] = []
        self._build()

        # Handle UAC relaunch args — auto-select channel and fetch
        if start_channel:
            if start_channel in LOG_CHANNELS:
                self._channel_var.set(start_channel)
            self._on_channel_selected()
        if autofetch:
            # Small delay so the window finishes drawing first
            self._root.after(800, self.fetch_live)

    # ── Build UI ──────────────────────────────────────────────────────────

    def _build(self) -> None:
        f = self._frame

        # ── Source toolbar ────────────────────────────────────────────────
        src = tk.Frame(f, bg=C["surface3"], pady=7)
        src.pack(fill=tk.X)

        tk.Label(src, text="Log Channel:", bg=C["surface3"],
                 fg=C["text_s"], font=F_BOLD, padx=12).pack(side=tk.LEFT)

        self._channel_var = tk.StringVar(value="All Channels")
        self._channel_cb  = ttk.Combobox(
            src, textvariable=self._channel_var,
            values=LOG_CHANNELS, state="readonly", width=40)
        self._channel_cb.pack(side=tk.LEFT, padx=4)
        self._channel_cb.bind("<<ComboboxSelected>>", self._on_channel_selected)

        self._badge_var = tk.StringVar(value="")
        tk.Label(src, textvariable=self._badge_var,
                 bg=C["accent"], fg=C["white"], font=F_BOLD,
                 padx=10, pady=2).pack(side=tk.LEFT, padx=6)

        ttk.Separator(src, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=8, pady=4)

        tk.Label(src, text="Max events:", bg=C["surface3"],
                 fg=C["text_s"], font=F_SMALL).pack(side=tk.LEFT)
        self._max_var = tk.StringVar(value="500")
        ttk.Combobox(src, textvariable=self._max_var,
                     values=MAX_OPTS, state="readonly",
                     width=6).pack(side=tk.LEFT, padx=4)

        ttk.Separator(src, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=8, pady=4)

        ttk.Button(src, text="⟳  Fetch Live Logs",
                   style="Accent.TButton",
                   command=self.fetch_live).pack(side=tk.LEFT, padx=4)
        ttk.Button(src, text="📂  Open File",
                   command=self.open_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(src, text="✖  Clear",
                   command=self._clear).pack(side=tk.LEFT, padx=4)

        self._src_lbl = tk.Label(src, text="No logs loaded",
                                  bg=C["surface3"], fg=C["text_s"],
                                  font=F_SMALL, padx=12)
        self._src_lbl.pack(side=tk.RIGHT)

        # ── Filter toolbar ────────────────────────────────────────────────
        flt = tk.Frame(f, bg=C["surface2"], pady=5)
        flt.pack(fill=tk.X)

        tk.Label(flt, text="Show:", bg=C["surface2"],
                 fg=C["text_s"], font=F_SMALL, padx=10).pack(side=tk.LEFT)
        self._time_var = tk.StringVar(value="All time")
        ttk.Combobox(flt, textvariable=self._time_var,
                     values=TIME_PRESETS, state="readonly",
                     width=14).pack(side=tk.LEFT, padx=4)
        self._time_var.trace_add("write", lambda *_: self._apply_filter())

        ttk.Separator(flt, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=6, pady=3)

        tk.Label(flt, text="Sort:", bg=C["surface2"],
                 fg=C["text_s"], font=F_SMALL).pack(side=tk.LEFT)
        self._sort_var = tk.StringVar(value="Newest first")
        ttk.Combobox(flt, textvariable=self._sort_var,
                     values=["Newest first", "Oldest first"],
                     state="readonly", width=12).pack(side=tk.LEFT, padx=4)
        self._sort_var.trace_add("write", lambda *_: self._apply_filter())

        ttk.Separator(flt, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=6, pady=3)

        tk.Label(flt, text="Severity:", bg=C["surface2"],
                 fg=C["text_s"], font=F_SMALL).pack(side=tk.LEFT)
        self._sev_var = tk.StringVar(value="All")
        ttk.Combobox(flt, textvariable=self._sev_var,
                     values=["All","critical","high","medium","low","info"],
                     state="readonly", width=9).pack(side=tk.LEFT, padx=4)
        self._sev_var.trace_add("write", lambda *_: self._apply_filter())

        ttk.Separator(flt, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=6, pady=3)

        tk.Label(flt, text="Search:", bg=C["surface2"],
                 fg=C["text_s"], font=F_SMALL).pack(side=tk.LEFT)
        self._search_var = tk.StringVar()
        ttk.Entry(flt, textvariable=self._search_var,
                  width=24).pack(side=tk.LEFT, padx=4)
        self._search_var.trace_add("write", lambda *_: self._apply_filter())

        ttk.Separator(flt, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=6, pady=3)

        ttk.Button(flt, text="🔍  Analyse",
                   style="Accent.TButton",
                   command=self._run_analysis).pack(side=tk.LEFT, padx=4)
        ttk.Button(flt, text="💡  Explain Event",
                   command=self._explain_single).pack(side=tk.LEFT, padx=4)

        self._count_lbl = tk.Label(flt, text="0 events",
                                    bg=C["surface2"], fg=C["text_s"],
                                    font=F_SMALL, padx=12)
        self._count_lbl.pack(side=tk.RIGHT)

        # ── Main area: table + detail panel ───────────────────────────────
        main_area = tk.Frame(f, bg=C["bg"])
        main_area.pack(fill=tk.BOTH, expand=True)

        tbl_frame = tk.Frame(main_area, bg=C["surface"])
        tbl_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        cols = ("timestamp","channel","severity","event_id","category","host")
        self._tree = ttk.Treeview(tbl_frame, columns=cols,
                                   show="headings", selectmode="browse")
        for col, width, label in [
            ("timestamp",  215, "Timestamp (Local)"),
            ("channel",    130, "Channel"),
            ("severity",    85, "Severity"),
            ("event_id",    80, "Event ID"),
            ("category",   260, "Category"),
            ("host",       130, "Host"),
        ]:
            self._tree.heading(col, text=label,
                               command=lambda c=col: self._sort_column(c))
            self._tree.column(col, width=width, minwidth=50)

        vsb = ttk.Scrollbar(tbl_frame, orient=tk.VERTICAL, command=self._tree.yview)
        hsb = ttk.Scrollbar(tbl_frame, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        configure_severity_tags(self._tree)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tbl_frame.rowconfigure(0, weight=1)
        tbl_frame.columnconfigure(0, weight=1)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Detail panel
        det = tk.Frame(main_area, bg=C["surface"], width=360)
        det.pack(side=tk.RIGHT, fill=tk.Y)
        det.pack_propagate(False)

        det_hdr = tk.Frame(det, bg=C["surface3"], height=36)
        det_hdr.pack(fill=tk.X)
        det_hdr.pack_propagate(False)
        tk.Label(det_hdr, text="Event Detail", bg=C["surface3"],
                 fg=C["text_s"], font=F_BOLD, padx=12,
                 anchor="w").pack(side=tk.LEFT, fill=tk.Y)

        self._detail_txt = scrolledtext.ScrolledText(
            det, bg=C["surface"], fg=C["text"], font=F_MONO,
            wrap=tk.WORD, relief="flat", borderwidth=0,
            state=tk.DISABLED, padx=8, pady=8)
        self._detail_txt.pack(fill=tk.BOTH, expand=True)

        # ── Time-Range AI Analysis ────────────────────────────────────────
        ai_sec = tk.Frame(f, bg=C["surface2"])
        ai_sec.pack(fill=tk.X)

        tk.Frame(ai_sec, bg=C["border"], height=1).pack(fill=tk.X)

        ai_hdr = tk.Frame(ai_sec, bg=C["surface2"], pady=6)
        ai_hdr.pack(fill=tk.X)

        tk.Label(ai_hdr, text="⏱  Time-Range AI Analysis",
                 bg=C["surface2"], fg=C["text"], font=F_BOLD,
                 padx=12).pack(side=tk.LEFT)

        tk.Label(ai_hdr, text="From:", bg=C["surface2"],
                 fg=C["text_s"], font=F_SMALL).pack(side=tk.LEFT, padx=(12,2))
        now = datetime.now()
        self._ai_from_var = tk.StringVar(
            value=(now - timedelta(hours=1)).strftime(_DT_FMT))
        ttk.Entry(ai_hdr, textvariable=self._ai_from_var,
                  width=17).pack(side=tk.LEFT, padx=2)

        tk.Label(ai_hdr, text="To:", bg=C["surface2"],
                 fg=C["text_s"], font=F_SMALL).pack(side=tk.LEFT, padx=(8,2))
        self._ai_to_var = tk.StringVar(value=now.strftime(_DT_FMT))
        ttk.Entry(ai_hdr, textvariable=self._ai_to_var,
                  width=17).pack(side=tk.LEFT, padx=2)

        tk.Label(ai_hdr, text="Max:", bg=C["surface2"],
                 fg=C["text_s"], font=F_SMALL).pack(side=tk.LEFT, padx=(8,2))
        self._ai_max_var = tk.StringVar(value="100")
        ttk.Combobox(ai_hdr, textvariable=self._ai_max_var,
                     values=["50","100","250","500"],
                     state="readonly", width=5).pack(side=tk.LEFT, padx=2)

        ttk.Button(ai_hdr, text="▶  Generate AI Summary",
                   style="Accent.TButton",
                   command=self._run_range_ai).pack(side=tk.LEFT, padx=12)

        tk.Label(ai_hdr, text="Format: YYYY-MM-DD HH:MM",
                 bg=C["surface2"], fg=C["text_d"],
                 font=F_SMALL).pack(side=tk.LEFT)

        self._ai_out_frame = tk.Frame(ai_sec, bg=C["surface"])
        self._ai_out_txt = scrolledtext.ScrolledText(
            self._ai_out_frame, bg=C["surface"], fg=C["text"],
            font=F_BODY, wrap=tk.WORD, relief="flat", borderwidth=0,
            height=6, state=tk.DISABLED, padx=10, pady=8)
        self._ai_out_txt.pack(fill=tk.X)

    # ── Handlers ──────────────────────────────────────────────────────────

    def _on_channel_selected(self, _event: object = None) -> None:
        ch    = self._channel_var.get()
        short = ch.split("/")[0]
        self._badge_var.set(f"  {short}  " if ch != "All Channels" else "")

    def _on_select(self, _event: object = None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        try:
            idx = int(sel[0])
            ev  = self._events[idx]
        except (ValueError, IndexError):
            return

        detail = (
            f"Timestamp  : {_fmt_ts(ev.timestamp)}\n"
            f"UTC (raw)  : {ev.timestamp}\n"
            f"Host       : {ev.host}\n"
            f"Channel    : {ev.channel}\n"
            f"Severity   : {ev.severity.upper()}\n"
            f"Event ID   : {ev.event_id}\n"
            f"Category   : {ev.category}\n"
            f"Username   : {ev.username or '—'}\n"
            f"Source IP  : {ev.source_ip or '—'}\n"
            f"Process    : {ev.process_name or '—'}\n"
            "\n── Raw Message ─────────────────\n"
            f"{ev.raw_message[:3000]}"
        )
        self._detail_txt.configure(state=tk.NORMAL)
        self._detail_txt.delete("1.0", tk.END)
        self._detail_txt.insert("1.0", detail)
        self._detail_txt.configure(state=tk.DISABLED)

    # ── Fetch ─────────────────────────────────────────────────────────────

    def fetch_live(self) -> None:
        """
        Fetch latest N logs.
        If Security is selected without admin rights:
          → show a small confirmation dialog
          → if confirmed, trigger Windows UAC popup via ShellExecuteW "runas"
          → the elevated relaunch auto-fetches and then this instance closes
        """
        ch     = self._channel_var.get()
        target = None if ch == "All Channels" else ch
        max_ev = int(self._max_var.get())

        # ── Security without admin → UAC elevation ────────────────────────
        if sys.platform.startswith("win") and not is_admin():
            needs_elevation = ch == "Security" or (
                ch == "All Channels"  # All Channels also hits Security
            )
            if ch == "Security":
                # Direct Security request → ask to elevate, block if denied
                if not self._confirm_and_elevate(ch):
                    return
                # User agreed → elevation launched → close this instance
                self._root.after(500, self._root.quit)
                return
            elif ch == "All Channels":
                # Silently skip Security, fetch the others
                pass

        self._set_status(f"Fetching latest {max_ev} logs from {ch} …")

        def task() -> None:
            try:
                events = self._fetcher.fetch(channel=target, max_events=max_ev)
                self._root.after(
                    0, lambda: self._on_loaded(events, f"Live: {ch}",
                                               reset_filter=False))
            except PermissionError:
                # Shouldn't normally reach here, but handle gracefully
                self._root.after(0, lambda: self._confirm_and_elevate(ch))
            except Exception as exc:
                msg = str(exc)
                self._root.after(0, lambda: self._on_fetch_error(msg))

        threading.Thread(target=task, daemon=True).start()

    def _confirm_and_elevate(self, channel: str) -> bool:
        """
        Show a small Windows-style confirmation dialog, then trigger UAC.
        Returns True if elevation was initiated (caller should close this instance).
        Returns False if user cancelled.
        """
        answer = messagebox.askyesno(
            "Permission Required",
            f"ThreatWeave needs Administrator access to read Security logs.\n\n"
            f"Windows will ask for your permission.\n\n"
            f"Allow?",
            icon="question",
        )
        if not answer:
            return False

        self._set_status("Requesting Administrator permission …")
        launched = request_admin_elevation(channel)

        if launched:
            self._set_status(
                "Administrator window launched. This window will close.")
        else:
            messagebox.showwarning(
                "Permission Denied",
                "Administrator access was not granted.\n"
                "Security logs require you to approve the Windows permission prompt.",
            )
        return launched

    # ── File load ─────────────────────────────────────────────────────────

    def open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Windows Event Log File",
            filetypes=[
                ("All supported",  "*.evtx *.xml *.log *.txt"),
                ("Windows EVTX",   "*.evtx"),
                ("XML export",     "*.xml"),
                ("Text / log",     "*.log *.txt"),
            ])
        if not path:
            return
        name = path.replace("\\", "/").split("/")[-1]
        self._set_status(f"Loading {name} …")

        from parser import WindowsParser  # type: ignore[import]

        def task() -> None:
            try:
                events = WindowsParser().load_file(path)
                self._root.after(
                    0, lambda: self._on_loaded(events, f"File: {name}",
                                               reset_filter=True))
            except Exception as exc:
                msg = str(exc)
                self._root.after(0, lambda: self._on_fetch_error(msg))

        threading.Thread(target=task, daemon=True).start()

    def _on_loaded(
        self,
        events:       list[WindowsEvent],
        source:       str,
        reset_filter: bool = False,
    ) -> None:
        self._events = events
        if reset_filter:
            self._time_var.set("All time")
        self._src_lbl.configure(text=source)
        self._apply_filter()
        self._set_status(
            f"✓  {len(events)} events loaded from {source}. "
            "Click  🔍 Analyse  to run MITRE mapping.")

    def _on_fetch_error(self, msg: str) -> None:
        self._set_status(f"Error: {msg}")
        messagebox.showerror("Fetch Error",
            f"Could not fetch logs:\n\n{msg}")

    def _clear(self) -> None:
        self._events = []
        self._tree.delete(*self._tree.get_children())
        self._count_lbl.configure(text="0 events")
        self._src_lbl.configure(text="No logs loaded")
        self._badge_var.set("")
        self._detail_txt.configure(state=tk.NORMAL)
        self._detail_txt.delete("1.0", tk.END)
        self._detail_txt.configure(state=tk.DISABLED)
        self._ai_out_frame.pack_forget()
        self._set_status("Cleared.")

    # ── Filter ────────────────────────────────────────────────────────────

    def _apply_filter(self) -> None:
        self._tree.delete(*self._tree.get_children())

        search = self._search_var.get().lower()
        fsev   = self._sev_var.get()
        newest = self._sort_var.get() == "Newest first"
        preset = self._time_var.get()

        apply_time = preset != "All time"
        if apply_time:
            t_from = datetime.now() - timedelta(hours=_hours(preset))
            t_to   = datetime.now()
        else:
            t_from = t_to = None

        filtered: list[tuple[int, WindowsEvent]] = []
        for orig_idx, ev in enumerate(self._events):
            if fsev != "All" and ev.severity.lower() != fsev:
                continue
            if search:
                hay = (ev.category + ev.host + (ev.event_id or "")
                       + ev.raw_message + ev.channel).lower()
                if search not in hay:
                    continue
            if apply_time and t_from and t_to:
                ts = _event_local_ts(ev.timestamp)
                if ts != datetime.min and not (t_from <= ts <= t_to):
                    continue
            filtered.append((orig_idx, ev))

        filtered.sort(key=lambda x: _parse_event_ts(x[1].timestamp),
                      reverse=newest)

        for pos, (orig_idx, ev) in enumerate(filtered):
            tag  = ev.severity.lower()
            tags = (tag, "alt") if pos % 2 == 1 else (tag,)
            self._tree.insert(
                "", tk.END,
                iid=str(orig_idx),
                values=(
                    _fmt_ts(ev.timestamp),
                    ev.channel,
                    ev.severity.upper(),
                    ev.event_id or "",
                    ev.category,
                    ev.host,
                ),
                tags=tags,
            )

        total  = len(self._events)
        shown  = len(filtered)
        hidden = total - shown
        note   = f"  (time filter hiding {hidden})" if hidden > 0 and apply_time else ""
        self._count_lbl.configure(text=f"{shown} / {total} events{note}")

    def _sort_column(self, col: str) -> None:
        rows = [(self._tree.set(k, col), k) for k in self._tree.get_children()]
        rows.sort()
        for i, (_, k) in enumerate(rows):
            self._tree.move(k, "", i)

    # ── MITRE Analysis ────────────────────────────────────────────────────

    def _run_analysis(self) -> None:
        if not self._events:
            messagebox.showinfo("No Events",
                                "Fetch live logs or open a file first.")
            return
        self._set_status("Running MITRE ATT&CK analysis …")

        from analyzer import SessionClusterer  # type: ignore[import]
        import config as cfg                   # type: ignore[import]
        clusterer = SessionClusterer(cfg.get("session_window_minutes", 30))
        events    = list(self._events)

        def task() -> None:
            matches  = self._mapper.map_events(events)
            sessions = clusterer.cluster(matches)
            self._root.after(0, lambda: self._after_analysis(matches, sessions))

        threading.Thread(target=task, daemon=True).start()

    def _after_analysis(self, matches: list, sessions: list) -> None:
        n_tech = len({m.technique_id for m in matches})
        self._set_status(
            f"Analysis complete — {len(matches)} matches · "
            f"{n_tech} unique techniques · {len(sessions)} session(s).")
        self._on_analysed(matches, sessions)

    # ── Single-event AI Explanation ───────────────────────────────────────

    def _explain_single(self) -> None:
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Select Event",
                                "Click on an event in the table first.")
            return
        try:
            idx = int(sel[0])
            ev  = self._events[idx]
        except (ValueError, IndexError):
            return

        self._set_status("Generating AI explanation …")

        def task() -> None:
            text = self._ai.explain_event(ev)
            self._root.after(0, lambda: self._show_explanation(text, ev))

        threading.Thread(target=task, daemon=True).start()

    def _show_explanation(self, text: str, ev: WindowsEvent) -> None:
        self._set_status("Explanation ready.")

        win = tk.Toplevel(self._root)
        win.title(f"AI Explanation — Event {ev.event_id}")
        win.geometry("700x545")
        win.configure(bg=C["bg"])
        win.resizable(True, True)
        win.grab_set()

        hdr = tk.Frame(win, bg=C["accent"], height=48)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr,
                 text=f"💡  AI Explanation  —  EventID {ev.event_id}  ·  {ev.category}",
                 bg=C["accent"], fg=C["white"], font=F_BOLD,
                 padx=14).pack(side=tk.LEFT, fill=tk.Y)

        meta = tk.Frame(win, bg=C["surface3"], pady=4)
        meta.pack(fill=tk.X)
        tk.Label(meta,
                 text=(f"  Host: {ev.host}   Channel: {ev.channel}   "
                       f"Severity: {ev.severity.upper()}   "
                       f"Time: {_fmt_ts(ev.timestamp)}"),
                 bg=C["surface3"], fg=C["text_s"], font=F_SMALL,
                 anchor="w").pack(fill=tk.X)

        def _parse_sections(raw: str) -> dict[str, str]:
            parts: dict[str, str] = {}
            current_key   = None
            current_lines: list[str] = []
            for line in raw.splitlines():
                stripped = line.strip()
                matched  = None
                for key in _EXPLAIN_SECTIONS:
                    if stripped.upper().startswith(key):
                        matched = key
                        break
                if matched:
                    if current_key:
                        parts[current_key] = "\n".join(current_lines).strip()
                    current_key   = matched
                    current_lines = []
                    remainder = stripped[len(matched):].strip().lstrip(":").strip()
                    if remainder:
                        current_lines.append(remainder)
                elif current_key is not None:
                    current_lines.append(line)
            if current_key:
                parts[current_key] = "\n".join(current_lines).strip()
            return parts

        sections = _parse_sections(text)
        content  = tk.Frame(win, bg=C["bg"])
        content.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        if sections:
            for sec_title, (title_bg, card_bg) in _EXPLAIN_SECTIONS.items():
                body = sections.get(sec_title, "")
                card = tk.Frame(content, bg=card_bg,
                                highlightthickness=1,
                                highlightbackground=title_bg)
                card.pack(fill=tk.X, pady=4)
                tbar = tk.Frame(card, bg=title_bg, height=28)
                tbar.pack(fill=tk.X)
                tbar.pack_propagate(False)
                tk.Label(tbar, text=f"  {sec_title}",
                         bg=title_bg, fg=C["white"], font=F_BOLD,
                         anchor="w").pack(fill=tk.Y, side=tk.LEFT)
                tk.Label(card, text=body if body else "(No content.)",
                         bg=card_bg,
                         fg=C["text"] if body else C["text_d"],
                         font=F_BODY, justify="left", anchor="nw",
                         wraplength=650, padx=12, pady=8).pack(
                             fill=tk.X, anchor="w")
        else:
            txt = scrolledtext.ScrolledText(
                content, bg=C["surface"], fg=C["text"], font=F_BODY,
                wrap=tk.WORD, relief="flat", borderwidth=0)
            txt.pack(fill=tk.BOTH, expand=True)
            txt.insert("1.0", text)
            txt.configure(state=tk.DISABLED)

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=8)

    # ── Time-Range AI Analysis ────────────────────────────────────────────

    def _run_range_ai(self) -> None:
        from_str = self._ai_from_var.get().strip()
        to_str   = self._ai_to_var.get().strip()
        max_ev   = int(self._ai_max_var.get())

        t_from_local = _parse_dt(from_str)
        t_to_local   = _parse_dt(to_str)

        if t_from_local is None or t_to_local is None:
            messagebox.showwarning(
                "Invalid Date",
                f"Enter dates as YYYY-MM-DD HH:MM\n"
                f"From: {from_str!r}\nTo: {to_str!r}")
            return
        if t_from_local >= t_to_local:
            messagebox.showwarning("Invalid Range",
                                   "'From' must be earlier than 'To'.")
            return
        if not self._events:
            messagebox.showinfo("No Events", "Load some events first.")
            return

        # Strategy: convert the user's LOCAL typed times → UTC, then compare
        # against the raw UTC timestamps stored in ev.timestamp.
        # This avoids any reliance on astimezone() for event comparison, which
        # can raise OSError on certain Windows timezone configurations.
        try:
            utc_offset = datetime.now(timezone.utc).astimezone().utcoffset()
        except Exception:
            utc_offset = timedelta(0)   # fall back to UTC if offset unreadable

        t_from_utc = t_from_local - utc_offset
        t_to_utc   = t_to_local   - utc_offset

        in_range = [
            ev for ev in self._events
            if t_from_utc <= _parse_event_ts(ev.timestamp) <= t_to_utc
        ]
        if not in_range:
            messagebox.showinfo(
                "No Events in Range",
                f"No events between {from_str} and {to_str}.\n"
                "Try setting 'Show' to 'All time'.")
            return

        selected = in_range[:max_ev]
        self._ai_out_frame.pack(fill=tk.X)
        self._ai_out_txt.configure(state=tk.NORMAL)
        self._ai_out_txt.delete("1.0", tk.END)
        self._ai_out_txt.insert(
            "1.0",
            f"Analysing {len(selected)} events "
            f"({from_str}  →  {to_str}) …\n"
            f"Total in range: {len(in_range)}  |  Sending to AI: {len(selected)}")
        self._ai_out_txt.configure(state=tk.DISABLED)
        self._set_status(f"Generating AI summary for {len(selected)} events …")

        def task() -> None:
            summary = self._ai.summary_for_range(selected, from_str, to_str)
            self._root.after(0, lambda: self._show_range_summary(
                summary, from_str, to_str, len(selected), len(in_range)))

        threading.Thread(target=task, daemon=True).start()

    def _show_range_summary(
        self, summary: str, from_str: str, to_str: str,
        sent: int, total: int,
    ) -> None:
        self._set_status(f"Range AI summary ready — {from_str} → {to_str}.")
        header = (
            "─── Time-Range AI Summary ───────────────────────────────\n"
            f"Range  : {from_str}  →  {to_str}\n"
            f"Events : {total} in range  (analysed: {sent})\n"
            "─────────────────────────────────────────────────────────\n\n"
        )
        self._ai_out_txt.configure(state=tk.NORMAL)
        self._ai_out_txt.delete("1.0", tk.END)
        self._ai_out_txt.insert("1.0", header + summary)
        self._ai_out_txt.configure(state=tk.DISABLED)
