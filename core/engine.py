import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from adapters.docker.listener import DockerEventListener
from core.assets import AssetRegistry
from core.bus import EventBus
from core.decision import ThreatDecisionEngine
from core.incidents import IncidentManager
from core.models import ActionType, Incident, IncidentStatus, MirrorEvent, ThreatLevel
from core.orchestrator import MirrorOrchestrator
from core.policies import PolicyEngine
from core.storage import StorageEngine
from deception.canary_manager import CanaryManager
from evidence.forensics_collector import ForensicsCollector
from isolation.docker import DockerIsolationManager
from isolation.network import NetworkIsolationManager
from mirror.runtime import MirrorRuntime
from mirror.traffic_switch import TrafficSwitch
from recovery.manager import RecoveryManager

logger = logging.getLogger("mirror.engine")


class MirrorEngine:
    """Master engine instance coordinating all subsystems of Dimensión Espejo."""

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        self.config_dir = config_dir or (Path(__file__).resolve().parent.parent / "config")
        project_root = self.config_dir.parent

        # Production ACID Storage Engine (SQLite WAL)
        self.storage = StorageEngine(
            db_path=project_root / "evidence_vault" / "mirror_shield.db"
        )

        self.assets = AssetRegistry()
        self.policies = PolicyEngine()
        self.bus = EventBus()
        self.incidents = IncidentManager(storage=self.storage)

        # Isolation & Forensics Subsystems
        self.docker_isolation = DockerIsolationManager()
        self.network_isolation = NetworkIsolationManager()
        self.forensics = ForensicsCollector()

        # Mirror World Runtime, Traffic Switch & Recovery
        self.mirror_runtime = MirrorRuntime(client=self.docker_isolation.client)
        self.traffic_switch = TrafficSwitch(storage=self.storage)
        self.recovery = RecoveryManager(storage=self.storage)

        # Deception Engine (Canary Files & Port Honeypots)
        self.canary_manager = CanaryManager(self.bus, base_dir=project_root)

        # Telemetry Adapters
        self.docker_listener = DockerEventListener(self.bus, self.assets)

        self.decision_engine = ThreatDecisionEngine(self.assets, self.policies)
        self.orchestrator = MirrorOrchestrator(
            decision_engine=self.decision_engine,
            incident_manager=self.incidents,
            isolation_handler=self._execute_isolation,
            forensic_handler=self._execute_forensics,
            mirror_handler=self._execute_mirror_instantiation,
            traffic_switch_handler=self._execute_traffic_diversion,
        )

        self._running: bool = False
        self._load_configs()
        self._bind_bus()

    def _load_configs(self) -> None:
        assets_file = self.config_dir / "assets.yaml"
        policies_file = self.config_dir / "policies.yaml"

        if assets_file.exists():
            self.assets.load_from_yaml(assets_file)
            logger.info("Loaded assets configuration from %s", assets_file)
            for asset in self.assets.list_all():
                if asset.container and asset.container.ports:
                    port = asset.container.ports[0]
                    self.traffic_switch.register_route(
                        asset_id=asset.id,
                        primary_host_port=f"{asset.container.name}:{port}",
                        default_mirror_host_port=f"mirror-{asset.container.name}:{port}",
                    )
                if asset.container and asset.container.image:
                    self.recovery.register_baseline(
                        asset_id=asset.id,
                        known_good_image=asset.container.image,
                        config_payload={"ports": asset.container.ports, "volumes": asset.container.volumes},
                    )

        if policies_file.exists():
            self.policies.load_from_yaml(policies_file)
            logger.info("Loaded policies configuration from %s", policies_file)

    def _bind_bus(self) -> None:
        """Bind orchestrator to all events flowing through the EventBus."""
        @self.bus.subscribe("*")
        async def on_event(event: MirrorEvent) -> None:
            await self.orchestrator.handle_event(event)

    async def _execute_isolation(self, asset_id: str, action: ActionType) -> Dict[str, Any]:
        """Execute real Docker network and process isolation on the asset."""
        asset = self.assets.get(asset_id)
        container_name = asset.container.name if (asset and asset.container) else asset_id

        results = {
            "asset_id": asset_id,
            "container": container_name,
            "frozen": False,
            "network_isolated": False,
        }

        # 1. Freeze container if critical
        if action in (ActionType.EMERGENCY_FREEZE, ActionType.ISOLATE):
            results["frozen"] = self.docker_isolation.freeze_container(container_name)

        # 2. Sever network interfaces and move to quarantine bridge
        if action in (ActionType.ISOLATE, ActionType.QUARANTINE, ActionType.EMERGENCY_FREEZE):
            net_res = self.network_isolation.isolate_container(container_name)
            results["network_isolated"] = net_res.get("success", False)

        return results

    async def _execute_forensics(self, event: MirrorEvent, incident: Incident) -> Optional[Dict[str, Any]]:
        """Collect and cryptographically seal forensic evidence."""
        asset = self.assets.get(event.asset_id) if event.asset_id else None
        container_name = asset.container.name if (asset and asset.container) else (event.container_id or "unknown")

        snapshot = self.forensics.collect_snapshot(
            incident_id=incident.id,
            container_identifier=container_name,
            trigger_reason=f"{event.event_type} (Threat: {incident.threat_level.value})",
        )
        if snapshot:
            incident.evidence_id = snapshot.get("sha256_integrity_seal")
        return snapshot

    async def _execute_mirror_instantiation(self, asset_id: str) -> Optional[str]:
        """Instantiate a clean mirror instance from a known-good image in the sandboxed network."""
        asset = self.assets.get(asset_id)
        container_name = asset.container.name if (asset and asset.container) else asset_id
        return self.mirror_runtime.instantiate_mirror(asset, container_name)

    async def _execute_traffic_diversion(self, asset_id: str, mirror_target: Optional[str] = None) -> bool:
        """Divert incoming traffic upstream to the Mirror instance seamlessly."""
        return self.traffic_switch.divert_to_mirror(asset_id, mirror_target)

    def rollback_incident(self, incident_id: str) -> Dict[str, Any]:
        """Perform verified rollback for an incident to restore clean baseline and routing."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return {"status": "ERROR", "error": f"Incident {incident_id} not found"}

        reports = []
        for asset_id in incident.asset_ids:
            res = self.recovery.execute_rollback(
                asset_id=asset_id,
                incident_id=incident_id,
                traffic_switch=self.traffic_switch,
                mirror_runtime=self.mirror_runtime,
                isolation_manager=self.docker_isolation,
                incident_manager=self.incidents,
            )
            reports.append(res)

        return {"status": "SUCCESS", "incident_id": incident_id, "reports": reports}

    async def ingest_event(self, event: MirrorEvent) -> None:
        """Entry point for sensors and deception tripwires to send events."""
        await self.bus.publish(event)

    def get_status(self) -> Dict[str, Any]:
        """Return system status for CLI or dashboard."""
        all_incidents = self.incidents.list_all()
        open_incidents = [i for i in all_incidents if i.status == IncidentStatus.OPEN]

        # Determine current aggregate threat level
        if any(i.threat_level == ThreatLevel.CRITICAL for i in open_incidents):
            current_threat = ThreatLevel.CRITICAL
        elif any(i.threat_level == ThreatLevel.HIGH for i in open_incidents):
            current_threat = ThreatLevel.HIGH
        elif any(i.threat_level == ThreatLevel.MEDIUM for i in open_incidents):
            current_threat = ThreatLevel.MEDIUM
        else:
            current_threat = ThreatLevel.LOW

        docker_ready = self.docker_isolation.is_available()
        canary_info = self.canary_manager.get_summary()
        active_mirrors = self.mirror_runtime.list_active_mirrors()

        return {
            "status": "ONLINE" if self._running else "STANDBY",
            "threat_level": current_threat.value.upper(),
            "protected_assets_count": len(self.assets.list_all()),
            "assets": [
                {
                    "id": a.id,
                    "type": a.type.value,
                    "criticality": a.criticality.value.upper(),
                    "protections": a.protections.model_dump(),
                }
                for a in self.assets.list_all()
            ],
            "total_events": len(self.bus.history),
            "open_incidents_count": len(open_incidents),
            "total_incidents_count": len(all_incidents),
            "docker_engine": "ACTIVE" if docker_ready else "UNAVAILABLE",
            "canaries_active": canary_info.get("total_canaries", 0),
            "canary_details": canary_info,
            "mirror_state": f"{len(active_mirrors)} ACTIVE" if active_mirrors else "STANDBY",
            "mirror_instances": active_mirrors,
        }

    async def start(self) -> None:
        self._running = True
        loop = asyncio.get_running_loop()
        await self.docker_listener.start()
        await self.canary_manager.start(loop=loop)
        logger.info("Dimensión Espejo Engine ONLINE with Deception, Docker & Mirror World Active")

    async def stop(self) -> None:
        self._running = False
        self.docker_listener.stop()
        await self.canary_manager.stop()
        logger.info("Dimensión Espejo Engine OFFLINE")
