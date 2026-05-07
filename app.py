"""
ThreatWeave — Entry Point
=========================
Run:  python app.py

Supports optional CLI args injected by UAC-elevation relaunch:
  --channel <name>   auto-select this channel on start
  --autofetch        automatically fetch logs on start
"""
import sys
import os
from pathlib import Path

# Add src/ to sys.path
_SRC = str(Path(__file__).resolve().parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from ui.main import MainWindow  # type: ignore[import]


def _parse_args() -> dict:
    """Parse optional args passed by the UAC relaunch."""
    args = sys.argv[1:]
    result = {"channel": None, "autofetch": False}
    i = 0
    while i < len(args):
        if args[i] == "--channel" and i + 1 < len(args):
            result["channel"] = args[i + 1]
            i += 2
        elif args[i] == "--autofetch":
            result["autofetch"] = True
            i += 1
        else:
            i += 1
    return result


def main() -> None:
    parsed = _parse_args()
    window = MainWindow(
        start_channel=parsed["channel"],
        autofetch=parsed["autofetch"],
    )
    window.run()


if __name__ == "__main__":
    main()
