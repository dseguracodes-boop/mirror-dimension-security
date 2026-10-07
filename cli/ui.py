from typing import Any, Dict, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def print_banner() -> None:
    banner = Text()
    banner.append("🪞 DIMENSIÓN ESPEJO", style="bold cyan")
    banner.append(" — ", style="dim")
    banner.append("Developer Shield V0.3\n", style="bold green")
    banner.append("Active Cyber-Resilience, Docker Shield & Deception Engine", style="italic white")
    console.print(Panel(banner, border_style="cyan", expand=False))


def print_status(status_data: Dict[str, Any]) -> None:
    table = Table(title="Protected Assets Matrix", border_style="bright_blue", show_header=True)
    table.add_column("Asset ID", style="bold white")
    table.add_column("Type", style="cyan")
    table.add_column("Criticality", justify="center")
    table.add_column("Protections Active", style="green")

    for asset in status_data.get("assets", []):
        crit = asset["criticality"]
        crit_style = "bold red" if crit == "CRITICAL" else "bold yellow" if crit == "HIGH" else "blue"

        active_prots = [k.capitalize() for k, v in asset.get("protections", {}).items() if v]
        prots_str = ", ".join(active_prots) if active_prots else "Standard"

        table.add_row(
            asset["id"].upper(),
            asset["type"],
            Text(crit, style=crit_style),
            prots_str,
        )

    console.print(table)

    # Summary box
    threat = status_data.get("threat_level", "NORMAL")
    threat_style = "bold red" if threat == "CRITICAL" else "bold yellow" if threat in ("HIGH", "MEDIUM") else "bold green"
    docker_status = status_data.get("docker_engine", "UNAVAILABLE")
    docker_style = "bold green" if docker_status == "ACTIVE" else "bold yellow"
    canaries_count = status_data.get("canaries_active", 0)

    summary_text = (
        f"[bold]System State:[/bold] {status_data.get('status', 'ONLINE')}  |  "
        f"[bold]Docker Shield:[/bold] [{docker_style}]{docker_status}[/{docker_style}]  |  "
        f"[bold]Canaries:[/bold] [bold cyan]{canaries_count} ACTIVE[/bold cyan]  |  "
        f"[bold]Threat Level:[/bold] [{threat_style}]{threat}[/{threat_style}]  |  "
        f"[bold]Total Events:[/bold] {status_data.get('total_events', 0)}  |  "
        f"[bold]Active Incidents:[/bold] {status_data.get('open_incidents_count', 0)}  |  "
        f"[bold]Mirror World:[/bold] {status_data.get('mirror_state', 'STANDBY')}"
    )
    console.print(Panel(summary_text, title="Core, Shield & Deception Metrics", border_style="magenta", expand=False))


def print_incidents(incidents: List[Dict[str, Any]]) -> None:
    if not incidents:
        console.print("[green]No incidents recorded. All assets running smoothly.[/green]")
        return

    table = Table(title="Security Incidents Journal", border_style="red", show_header=True)
    table.add_column("Incident ID", style="bold red")
    table.add_column("Threat", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Assets Involved", style="white")
    table.add_column("Events Count", justify="right")
    table.add_column("Actions Triggered", style="yellow")
    table.add_column("Evidence Seal (SHA-256)", style="dim cyan")

    for inc in incidents:
        seal = inc.get("evidence_id")
        seal_str = f"{seal[:12]}..." if seal else "N/A"
        table.add_row(
            inc["id"],
            inc["threat_level"].upper(),
            inc["status"].upper(),
            ", ".join(inc.get("asset_ids", [])) or "N/A",
            str(len(inc.get("event_ids", []))),
            ", ".join([a.upper() for a in inc.get("actions", [])]),
            seal_str,
        )

    console.print(table)
