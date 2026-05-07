"""ThreatWeave — MITRE ATT&CK Heatmap Tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ui.theme import C, F_BODY, F_BOLD, F_HEAD, F_SMALL  # type: ignore[import]

_TACTICS = [
    "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]

_TACTIC_LABELS = {
    "initial-access":       "Initial\nAccess",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege\nEscalation",
    "defense-evasion":      "Defense\nEvasion",
    "credential-access":    "Credential\nAccess",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral\nMovement",
    "collection":           "Collection",
    "command-and-control":  "C&C",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}


class HeatmapTab:
    """Displays an ATT&CK Navigator-style heatmap of detected techniques."""

    def __init__(self, frame: ttk.Frame, root: tk.Tk, engine) -> None:
        self._frame  = frame
        self._root   = root
        self._engine = engine
        self._build()

    def _build(self) -> None:
        f = self._frame

        # Header
        hdr = tk.Frame(f, bg=C["surface3"], pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="MITRE ATT&CK Heatmap",
                 bg=C["surface3"], fg=C["text"], font=F_HEAD,
                 padx=16).pack(side=tk.LEFT)
        tk.Label(hdr,
                 text="Colour intensity = technique frequency in loaded session",
                 bg=C["surface3"], fg=C["text_s"],
                 font=F_SMALL, padx=16).pack(side=tk.LEFT)

        # Scrollable canvas
        container = tk.Frame(f, bg=C["bg"])
        container.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        self._canvas = tk.Canvas(container, bg=C["surface"],
                                  highlightthickness=0)
        h_sb = ttk.Scrollbar(container, orient=tk.HORIZONTAL,
                              command=self._canvas.xview)
        v_sb = ttk.Scrollbar(container, orient=tk.VERTICAL,
                              command=self._canvas.yview)
        self._canvas.configure(xscrollcommand=h_sb.set,
                                yscrollcommand=v_sb.set)

        h_sb.pack(side=tk.BOTTOM, fill=tk.X)
        v_sb.pack(side=tk.RIGHT,  fill=tk.Y)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._draw_empty()

    def _draw_empty(self) -> None:
        self._canvas.delete("all")
        w = self._canvas.winfo_width() or 800
        self._canvas.create_text(
            w // 2, 200,
            text="No analysis data yet.\nLoad logs and click  🔍 Analyse.",
            fill=C["text_d"], font=F_BODY, justify=tk.CENTER,
        )

    def update(self, matches: list, mapper) -> None:
        """Redraw the heatmap with new match data."""
        from collections import defaultdict
        self._canvas.delete("all")

        if not matches:
            self._draw_empty()
            return

        # Count occurrences per tactic → technique
        tactic_data: dict[str, dict[str, int]] = defaultdict(dict)
        for m in matches:
            tac = m.tactic
            tid = m.technique_id
            tactic_data[tac][tid] = tactic_data[tac].get(tid, 0) + 1

        max_count = max(
            (v for td in tactic_data.values() for v in td.values()),
            default=1,
        )

        CW, CH, GAP = 114, 54, 3
        x0, y0 = 8, 56

        self._canvas.create_text(
            x0, 18,
            text="ATT&CK Heatmap  —  darker fill = higher event frequency",
            anchor="w", fill=C["text_s"], font=F_SMALL,
        )

        for ti, tac in enumerate(_TACTICS):
            tx = x0 + ti * (CW + GAP)
            # Column header
            self._canvas.create_rectangle(
                tx, y0, tx + CW, y0 + 42,
                fill=C["surface3"], outline=C["border"],
            )
            self._canvas.create_text(
                tx + CW // 2, y0 + 21,
                text=_TACTIC_LABELS.get(tac, tac),
                fill=C["accent"], font=("Segoe UI", 8, "bold"),
                justify=tk.CENTER,
            )

            techniques = tactic_data.get(tac, {})
            for ri, (tid, count) in enumerate(
                sorted(techniques.items(), key=lambda x: -x[1])[:14]
            ):
                ry    = y0 + 48 + ri * (CH + GAP)
                ratio = count / max_count
                # Colour: white → deep blue
                blue  = int(0x0078D4)
                b_r   = 0xFF - int((0xFF - ((blue >> 16) & 0xFF)) * ratio)
                b_g   = 0xFF - int((0xFF - ((blue >> 8)  & 0xFF)) * ratio)
                b_b   = 0xFF - int((0xFF - ( blue        & 0xFF)) * ratio)
                fill  = f"#{b_r:02x}{b_g:02x}{b_b:02x}"
                # Text colour — white on dark, dark on light
                text_c = "#FFFFFF" if ratio > 0.45 else C["text"]

                self._canvas.create_rectangle(
                    tx, ry, tx + CW, ry + CH,
                    fill=fill, outline=C["border"], width=0.5,
                )
                name = self._engine.meta.get(tid, {}).get("name", "")
                short_name = name[:16] if len(name) > 16 else name
                self._canvas.create_text(
                    tx + CW // 2, ry + 16,
                    text=tid, fill=text_c,
                    font=("Consolas", 8, "bold"),
                )
                self._canvas.create_text(
                    tx + CW // 2, ry + 36,
                    text=short_name, fill=text_c,
                    font=("Segoe UI", 7),
                )

        total_w = x0 + len(_TACTICS) * (CW + GAP) + 20
        total_h = y0 + 48 + 14 * (CH + GAP) + 20
        self._canvas.configure(
            scrollregion=(0, 0, total_w, total_h)
        )
