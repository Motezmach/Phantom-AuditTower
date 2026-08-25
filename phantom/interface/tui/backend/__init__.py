"""Backend bridge for external TUI clients."""

from phantom.interface.tui.backend.controller import TuiController
from phantom.interface.tui.backend.server import TuiBackendServer


__all__ = ["TuiBackendServer", "TuiController"]
