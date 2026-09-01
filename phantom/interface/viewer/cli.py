"""Local Phantom dashboard and run-viewer commands."""

from __future__ import annotations

import argparse
import logging
import time
from typing import TYPE_CHECKING

from rich.console import Console

from phantom.core.paths import (
    RUNS_DIR_NAME,
    latest_run_dir,
    run_dir_for,
    run_record_path,
    runs_base_dir,
)
from phantom.interface.viewer.server import authorized_url, bundle_is_built, serve
from phantom.interface.viewer.transcript import read_run_summary


if TYPE_CHECKING:
    from pathlib import Path
    from typing import NoReturn


logger = logging.getLogger(__name__)


def run_view(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="phantom view",
        description="Open a local web view of a Phantom run (live or finished).",
    )
    parser.add_argument(
        "run",
        nargs="?",
        default=None,
        help=f"Run name under ./{RUNS_DIR_NAME} (defaults to the most recent run).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port to serve on (default: an available ephemeral port).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1; use 0.0.0.0 for all IPv4 interfaces).",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the browser automatically.",
    )
    args = parser.parse_args(argv)

    console = Console()

    if not bundle_is_built():
        console.print(
            "[bold red]Viewer UI is not built.[/]\n"
            "From the repository root, build it with: [cyan]cd phantom/interface/viewer/frontend && npm ci && npm run build[/]"
        )
        raise SystemExit(1)

    run_dir = _resolve_run_dir(args.run, console)

    httpd, url, token = serve(
        run_dir,
        host=args.host,
        port=args.port,
        open_browser=not args.no_open,
    )
    # The tokened URL is what authorizes the browser (steering, report sending,
    # history). Print it rather than the bare URL so the operator -- and only
    # the operator -- can open or share an authorized link.
    open_url = authorized_url(url, token)

    run_name = run_dir.name
    summary = read_run_summary(run_dir)
    live = not summary.get("finished", False)

    from phantom.telemetry import posthog

    posthog.viewer_opened(source="cli", live=live)

    state_label = "[#eab308]live[/]" if live else "[#22c55e]finished[/]"
    console.print()
    console.print(f"Serving [bold white]{run_name}[/] ({state_label}) at:")
    # Print the URL alone on its own line with soft_wrap so Rich never inserts a
    # wrap into the (long, tokened) link -- that keeps it selectable/copyable.
    console.print(f"  [#60a5fa]{open_url}[/]", soft_wrap=True)
    console.print("[dim]This link authorizes the browser; anyone you share it with can steer[/]")
    console.print("[dim]a live scan and browse history. Press Ctrl-C to stop the viewer.[/]")
    console.print()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        console.print("\n[dim]Viewer stopped.[/]")
    finally:
        httpd.shutdown()
        httpd.server_close()


def _resolve_run_dir(run: str | None, console: Console) -> Path:
    if run:
        run_dir = run_dir_for(run)
        if not run_record_path(run_dir).is_file():
            _fail_no_run(console, requested=run)
        return run_dir

    latest = latest_run_dir()
    if latest is None:
        _fail_no_run(console, requested=None)
    return latest


def _fail_no_run(console: Console, *, requested: str | None) -> NoReturn:
    base = runs_base_dir()
    available = (
        sorted(
            (child.name for child in base.iterdir() if run_record_path(child).is_file()),
            reverse=True,
        )
        if base.is_dir()
        else []
    )

    if requested:
        console.print(f"[bold red]No run named '{requested}' under ./{RUNS_DIR_NAME}.[/]")
    else:
        console.print(f"[bold red]No runs found under ./{RUNS_DIR_NAME}.[/]")

    if available:
        console.print("Available runs:")
        for name in available[:20]:
            console.print(f"  [cyan]{name}[/]")
    raise SystemExit(1)


def run_serve(argv: list[str]) -> None:
    """Serve the persistent Phantom dashboard without requiring a run."""
    parser = argparse.ArgumentParser(
        prog="phantom serve",
        description="Run the persistent Phantom dashboard locally.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=53149,
        help="Port to serve on (default: 53149; falls back if it is busy).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1; use 0.0.0.0 only when intended).",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the browser automatically.",
    )
    args = parser.parse_args(argv)

    console = Console()
    if not bundle_is_built():
        console.print(
            "[bold red]Dashboard UI is not built.[/]\n"
            "Build it with: [cyan]cd phantom/interface/viewer/frontend && npm ci && "
            "npm run build[/]"
        )
        raise SystemExit(1)

    httpd, url, token = serve(
        None,
        host=args.host,
        port=args.port,
        open_browser=not args.no_open,
    )
    open_url = authorized_url(url, token)

    console.print()
    console.print("Serving [bold white]Phantom dashboard[/] at:")
    console.print(f"  [#60a5fa]{open_url}[/]", soft_wrap=True)
    console.print("[dim]The dashboard stays available while you manage targets and review runs.[/]")
    console.print("[dim]Press Ctrl-C to stop the dashboard.[/]")
    console.print()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard stopped.[/]")
    finally:
        httpd.shutdown()
        httpd.server_close()


__all__ = ["run_serve", "run_view"]
