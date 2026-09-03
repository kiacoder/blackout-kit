"""Beginner-friendly, explicit Blackout Kit setup workflow."""
from __future__ import annotations

from dataclasses import dataclass
import sys
from typing import Any, Callable

from .capabilities import build_capability_matrix, get_capability
from .demo import GOLDEN_PATH
from .terminal_menu import MenuItem, run_menu


@dataclass(frozen=True)
class SetupPlan:
    """Read-only setup checklist; actions are never implicit."""

    platform: str
    recommended_engine: str | None
    steps: tuple[str, ...]
    blockers: tuple[str, ...]
    requires_upstream: bool
    requires_confirmation: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "recommended_engine": self.recommended_engine,
            "steps": list(self.steps),
            "blockers": list(self.blockers),
            "requires_upstream": self.requires_upstream,
            "requires_confirmation": list(self.requires_confirmation),
            "golden_path": list(GOLDEN_PATH),
            "read_only": True,
        }


MenuRunner = Callable[..., str | None]
TextEditor = Callable[..., str | None]
ConfirmRunner = Callable[[str], bool]


def _route_recommendation(
    settings: dict,
    installed: dict[str, bool],
    configs: list[Any],
    platform: str,
) -> tuple[str | None, list[str]]:
    from .routing import recommend_routes

    candidates = recommend_routes(
        settings,
        installed=installed,
        protocols={str(config.protocol).lower() for config in configs},
        configs=configs,
        stability_scores={},
        platform=platform,
    )
    candidate = next((item for item in candidates if item.ready), candidates[0] if candidates else None)
    if candidate is None:
        return None, [f"No engine is supported on {platform}."]
    return candidate.engine, list(candidate.blockers) if not candidate.ready else []


def build_setup_plan(
    *,
    platform: str,
    settings: dict[str, Any],
    installed: dict[str, bool],
    configs: list[Any],
) -> SetupPlan:
    """Create a local checklist without starting or probing anything."""
    engine, route_blockers = _route_recommendation(settings, installed, configs, platform)
    matrix = build_capability_matrix(
        platform,
        settings=settings,
        installed=installed,
        configs=configs,
    )
    row = next((item for item in matrix if item["name"] == engine), None)
    blockers = route_blockers or (list(row["blockers"]) if row else [])
    requires_upstream = bool(
        row and row["upstream_requirement"] in {"saved_config", "vpn_profile", "remote_service"}
    )
    return SetupPlan(
        platform=platform,
        recommended_engine=engine,
        steps=GOLDEN_PATH,
        blockers=tuple(blockers),
        requires_upstream=requires_upstream,
        requires_confirmation=(
            "download runtime components",
            "save or import configuration",
            "connect and change local network state",
        ),
    )


def build_current_setup_plan(*, read_only: bool = False) -> SetupPlan:
    """Build a plan from local files without doctor or network probes."""
    from . import settings as cfg
    from .config.manager import load_configs
    from .downloader import check_installed

    settings = cfg._load_plain_settings() if read_only else cfg.load()
    return build_setup_plan(
        platform=sys.platform,
        settings=settings,
        installed=check_installed(),
        configs=load_configs(),
    )


def render_setup_plan(plan: SetupPlan, console) -> None:
    from rich.panel import Panel

    body = (
        "[bold]Blackout Kit is a local coordinator.[/bold]\n"
        "It does not provide a remote VPN or proxy server.\n\n"
        f"Platform: [bold cyan]{plan.platform}[/bold cyan]\n"
        f"Recommended local target: [bold cyan]{plan.recommended_engine or 'none'}[/bold cyan]\n"
    )
    if plan.requires_upstream:
        body += "\nThis path needs a trusted upstream configuration or service.\n"
    if plan.blockers:
        body += "\n[warning]Current blockers:[/warning]\n" + "\n".join(
            f"  • {item}" for item in plan.blockers
        )
    body += "\n\n[bold]Golden path:[/bold] " + " → ".join(plan.steps)
    body += "\n\n[muted]Setup is checklist-first. Downloads and network changes always require explicit confirmation.[/muted]"
    console.print(Panel(body, title="Blackout Kit Setup", border_style="cyan"))


def _setup_actions() -> list[MenuItem]:
    return [
        MenuItem("config", "Add or import upstream config", "Use the keyboard-safe config editor"),
        MenuItem("settings", "Review local settings", "Change ports, engine choice, or vault options"),
        MenuItem("runtime", "Install missing runtime", "Download only the selected engine's missing component"),
        MenuItem("recheck", "Run the checklist again", "Re-read local files and configuration"),
        MenuItem("back", "Back", "Leave setup without connecting"),
    ]


def _confirm(question: str, menu_runner: MenuRunner | None, confirm_runner: ConfirmRunner | None) -> bool:
    if confirm_runner is not None:
        return bool(confirm_runner(question))
    choice = (menu_runner or run_menu)(
        question,
        [
            MenuItem("yes", "Yes", "Continue with this change"),
            MenuItem("no", "No", "Keep the current state"),
        ],
    )
    return choice == "yes"


def _missing_runtime(plan: SetupPlan) -> list[str]:
    if not plan.recommended_engine:
        return []
    from . import settings as cfg
    from .downloader import check_installed

    capability = get_capability(plan.recommended_engine)
    if capability is None:
        return []
    settings = cfg.load()
    installed = check_installed()
    missing = []
    for component in capability.runtime_for(
        "linux" if sys.platform.startswith("linux") else sys.platform,
        settings,
    ):
        available = installed.get(component, False)
        if component == "sni-spoofing":
            available = bool(available or installed.get("mhrv"))
        if not available:
            missing.append(component)
    return missing


def _install_missing_runtime(
    plan: SetupPlan,
    *,
    menu_runner: MenuRunner | None,
    confirm_runner: ConfirmRunner | None,
    console,
) -> None:
    from . import downloader

    missing = _missing_runtime(plan)
    if not missing:
        console.print("[success]No missing runtime component was found for this target.[/success]")
        return
    if not _confirm(
        "Download only the missing runtime component(s) for the recommended engine?",
        menu_runner,
        confirm_runner,
    ):
        console.print("[muted]Runtime download cancelled.[/muted]")
        return

    for component in missing:
        info = downloader.BIN_REGISTRY.get(component)
        if info is None:
            console.print(f"[warning]No download entry exists for {component}; supply it manually.[/warning]")
            continue
        if not info.github_repo:
            console.print(
                f"[warning]{info.display_name} is manual-only.[/warning] {info.manual_url}\n"
                f"  {info.manual_note or 'Place the verified runtime in bins/.'}"
            )
            continue
        ok, message = downloader.download_binary(component)
        console.print(f"[success]✓ {message}[/success]" if ok else f"[error]✗ {message}[/error]")


def run_setup(
    *,
    menu_runner: MenuRunner | None = None,
    text_editor: TextEditor | None = None,
    confirm_runner: ConfirmRunner | None = None,
    console=None,
) -> SetupPlan:
    """Run the interactive checklist and return the final local plan."""
    if console is None:
        from .theme import console as theme_console
        console = theme_console
    from .theme import is_interactive

    while True:
        plan = build_current_setup_plan()
        render_setup_plan(plan, console)
        if not plan.blockers:
            return plan
        if menu_runner is None and not is_interactive():
            return plan

        choose = menu_runner or run_menu
        action = choose("Setup actions", _setup_actions())
        if action in (None, "back"):
            return plan
        if action == "recheck":
            continue
        if action == "runtime":
            _install_missing_runtime(
                plan,
                menu_runner=menu_runner,
                confirm_runner=confirm_runner,
                console=console,
            )
            continue
        if action == "config":
            from .interactive import run_config_menu
            run_config_menu(
                menu_runner=menu_runner,
                text_editor=text_editor,
                confirm_runner=confirm_runner,
                require_confirmation=True,
            )
            continue
        if action == "settings":
            from .interactive import run_settings_menu
            run_settings_menu(
                menu_runner=menu_runner,
                text_editor=text_editor,
                confirm_runner=confirm_runner,
                require_confirmation=True,
            )
            continue


def is_first_run() -> bool:
    from . import settings as cfg

    if not cfg.SETTINGS_FILE.exists():
        return True
    return bool(cfg._load_plain_settings().get("show_first_run", False))


def render_first_run_welcome(console) -> bool:
    """Render the welcome panel without creating settings or user data."""
    if not is_first_run():
        return False
    from rich.panel import Panel

    console.print(Panel(
        "[bold]Welcome to Blackout Kit.[/bold]\n\n"
        "Blackout Kit coordinates local engines; it does not provide a VPN server.\n"
        "Start with the safe checklist, add a trusted upstream when needed, and\n"
        "connect only after local readiness checks pass.\n\n"
        "[bold]First steps:[/bold]\n"
        "  [cyan]blackout setup[/cyan]       guided setup\n"
        "  [cyan]blackout demo[/cyan]        read-only demonstration\n"
        "  [cyan]blackout capabilities[/cyan]  full engine catalog",
        title="First Run",
        border_style="green",
    ))
    return True


def _first_run_hint():
    from .theme import console

    return render_first_run_welcome(console)


__all__ = [
    "SetupPlan",
    "build_current_setup_plan",
    "build_setup_plan",
    "is_first_run",
    "render_first_run_welcome",
    "render_setup_plan",
    "run_setup",
]
