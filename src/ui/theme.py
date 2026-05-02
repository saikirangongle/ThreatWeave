"""
ThreatWeave — Windows 11 UI Theme
Applies a clean Windows 11-compatible style to all ttk widgets.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# ── Windows 11 colour palette ─────────────────────────────────────────────────

C: dict[str, str] = {
    # Surfaces
    "bg":        "#F3F3F3",   # window / page background
    "surface":   "#FFFFFF",   # card / panel background
    "surface2":  "#F9F9F9",   # alternating row / secondary surface
    "surface3":  "#F0F0F0",   # toolbar / header band

    # Accent — Windows 11 default blue
    "accent":    "#0078D4",
    "accent_h":  "#106EBE",   # hover
    "accent_p":  "#005A9E",   # pressed / active

    # Borders
    "border":    "#E5E5E5",
    "border_f":  "#0078D4",   # focused border

    # Text
    "text":      "#1A1A1A",
    "text_s":    "#6B6B6B",   # secondary / muted
    "text_d":    "#ADADAD",   # disabled / placeholder

    # Severity colours
    "critical":  "#C42B1C",
    "high":      "#CA5010",
    "medium":    "#9D5D00",   # dark amber — readable on white
    "low":       "#107C10",
    "info":      "#6B6B6B",

    # Misc
    "white":     "#FFFFFF",
    "selection": "#CCE4F7",   # selected row background
    "sel_text":  "#1A1A1A",
}

# ── Fonts — simple constant tuples (always available on Windows 11) ───────────
# Segoe UI is the Windows 11 system font and is always installed.
# Consolas is also always available on Windows.
# Using plain tuples avoids any dependency on a running Tk instance.

F_BODY:  tuple = ("Segoe UI", 10)
F_BOLD:  tuple = ("Segoe UI", 10, "bold")
F_HEAD:  tuple = ("Segoe UI", 13, "bold")
F_SMALL: tuple = ("Segoe UI",  9)
F_MONO:  tuple = ("Consolas",  9)


# ── Apply full theme ──────────────────────────────────────────────────────────

def apply_theme(root: tk.Tk) -> None:
    """Apply the Windows 11 theme to the root window and all ttk widgets."""

    root.configure(bg=C["bg"])

    s = ttk.Style(root)
    s.theme_use("clam")

    # ── Base ──────────────────────────────────────────────────────────────
    s.configure(
        ".",
        background       = C["bg"],
        foreground       = C["text"],
        font             = F_BODY,
        borderwidth      = 0,
        relief           = "flat",
        fieldbackground  = C["surface"],
        troughcolor      = C["border"],
        selectbackground = C["accent"],
        selectforeground = C["white"],
        insertcolor      = C["text"],
    )

    # ── Notebook (tabs) ───────────────────────────────────────────────────
    s.configure("TNotebook",
        background = C["surface3"],
        tabmargins = [0, 0, 0, 0],
    )
    s.configure("TNotebook.Tab",
        background = C["surface3"],
        foreground = C["text_s"],
        font       = F_BOLD,
        padding    = [16, 8],
    )
    s.map("TNotebook.Tab",
        background = [("selected", C["surface"]), ("active", C["surface2"])],
        foreground = [("selected", C["accent"]),  ("active", C["text"])],
    )

    # ── Frame / Label ─────────────────────────────────────────────────────
    s.configure("TFrame",         background = C["bg"])
    s.configure("TLabel",         background = C["bg"],      foreground = C["text"])
    s.configure("Surface.TFrame", background = C["surface"])
    s.configure("Toolbar.TFrame", background = C["surface3"])

    # ── Buttons ───────────────────────────────────────────────────────────
    s.configure("TButton",
        background  = C["surface3"],
        foreground  = C["text"],
        font        = F_BODY,
        padding     = [10, 5],
        relief      = "flat",
        borderwidth = 1,
    )
    s.map("TButton",
        background = [("pressed", C["border"]), ("active", C["surface2"])],
        relief     = [("pressed", "flat")],
    )

    s.configure("Accent.TButton",
        background  = C["accent"],
        foreground  = C["white"],
        font        = F_BOLD,
        padding     = [12, 6],
        relief      = "flat",
    )
    s.map("Accent.TButton",
        background = [("pressed", C["accent_p"]), ("active", C["accent_h"])],
        foreground = [("pressed", C["white"]),    ("active", C["white"])],
    )

    s.configure("Subtle.TButton",
        background  = C["surface"],
        foreground  = C["accent"],
        font        = F_BODY,
        padding     = [10, 5],
        relief      = "flat",
        borderwidth = 1,
    )
    s.map("Subtle.TButton",
        background = [("active", C["selection"])],
    )

    # ── Entry ─────────────────────────────────────────────────────────────
    s.configure("TEntry",
        fieldbackground = C["surface"],
        foreground      = C["text"],
        insertcolor     = C["text"],
        relief          = "flat",
        borderwidth     = 1,
        padding         = [6, 4],
    )

    # ── Combobox ──────────────────────────────────────────────────────────
    s.configure("TCombobox",
        fieldbackground = C["surface"],
        foreground      = C["text"],
        background      = C["surface"],
        arrowcolor      = C["accent"],
        relief          = "flat",
        padding         = [6, 4],
    )
    s.map("TCombobox",
        fieldbackground = [("readonly", C["surface"]), ("disabled", C["surface2"])],
        foreground      = [("readonly", C["text"]),    ("disabled", C["text_d"])],
        selectforeground= [("readonly", C["text"])],
        selectbackground= [("readonly", C["surface"])],
    )
    # Dropdown list colours
    root.option_add("*TCombobox*Listbox.background",       C["surface"])
    root.option_add("*TCombobox*Listbox.foreground",       C["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", C["accent"])
    root.option_add("*TCombobox*Listbox.selectForeground", C["white"])
    root.option_add("*TCombobox*Listbox.font",             F_BODY)

    # ── Treeview ──────────────────────────────────────────────────────────
    s.configure("Treeview",
        background      = C["surface"],
        foreground      = C["text"],
        fieldbackground = C["surface"],
        rowheight       = 28,
        font            = F_BODY,
        relief          = "flat",
        borderwidth     = 0,
    )
    s.configure("Treeview.Heading",
        background = C["surface3"],
        foreground = C["text_s"],
        font       = F_BOLD,
        relief     = "flat",
        padding    = [6, 6],
    )
    s.map("Treeview",
        background = [("selected", C["selection"])],
        foreground = [("selected", C["sel_text"])],
    )
    s.map("Treeview.Heading",
        background = [("active", C["border"])],
    )

    # ── Scrollbar ─────────────────────────────────────────────────────────
    s.configure("TScrollbar",
        background  = C["surface3"],
        troughcolor = C["bg"],
        arrowcolor  = C["text_s"],
        borderwidth = 0,
        relief      = "flat",
        arrowsize   = 12,
    )
    s.map("TScrollbar",
        background = [("active", C["border"])],
    )

    # ── Spinbox ───────────────────────────────────────────────────────────
    s.configure("TSpinbox",
        fieldbackground = C["surface"],
        foreground      = C["text"],
        arrowcolor      = C["accent"],
        relief          = "flat",
        padding         = [6, 4],
    )

    # ── Separator ─────────────────────────────────────────────────────────
    s.configure("TSeparator", background = C["border"])

    # ── Progressbar ───────────────────────────────────────────────────────
    s.configure("TProgressbar",
        troughcolor = C["border"],
        background  = C["accent"],
        thickness   = 4,
    )

    # ── Checkbutton ───────────────────────────────────────────────────────
    s.configure("TCheckbutton",
        background = C["bg"],
        foreground = C["text"],
    )
    s.map("TCheckbutton",
        background = [("active", C["bg"])],
    )


# ── Severity tag helpers ──────────────────────────────────────────────────────

def configure_severity_tags(tree: ttk.Treeview) -> None:
    """Apply foreground colour tags for severity levels on a Treeview."""
    tree.tag_configure("critical", foreground=C["critical"])
    tree.tag_configure("high",     foreground=C["high"])
    tree.tag_configure("medium",   foreground=C["medium"])
    tree.tag_configure("low",      foreground=C["low"])
    tree.tag_configure("info",     foreground=C["info"])
    tree.tag_configure("alt",      background=C["surface2"])   # alternating row


def sev_colour(severity: str) -> str:
    """Return the hex colour for a severity string."""
    return C.get(severity.lower(), C["info"])
