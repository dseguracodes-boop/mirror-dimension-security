import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4
from datetime import datetime, timezone

from core.bus import EventBus
from core.models import MirrorEvent

logger = logging.getLogger("mirror.adapters.opencanary")


class OpenCanaryAdapter:
    """Adapter bridging the OpenCanary deception engine from repos/opencanary to Dimensión Espejo."""

    def __init__(self, bus: EventBus, repo_path: Optional[Path] = None) -> None:
        self.bus = bus
        self.repo_path = repo_path
        self.config_path = Path("/tmp/opencanary.conf")

    def generate_config(self, active_modules: Optional[list] = None) -> Dict[str, Any]:
        """Generate OpenCanary configuration for local decoy services."""
        modules = active_modules or ["redis", "http", "mysql", "ssh"]
        config = {
            "device.node_id": "mirror-deception-node-01",
            "ip.ignorelist": ["127.0.0.1"],
            "logger": {
                "class": "PyDotLogger",
                "kwargs": {
                    "formatters": {
                        "plain": {
                            "format": "%(message)s"
                        }
                    }
                }
            },
            "redis.enabled": "redis" in modules,
            "redis.port": 16379,
            "http.enabled": "http" in modules,
            "http.port": 18080,
            "http.skin": "nas",
            "mysql.enabled": "mysql" in modules,
            "mysql.port": 13306,
            "ssh.enabled": "ssh" in modules,
            "ssh.port": 12222,
        }
        return config

    async def handle_opencanary_log_line(self, raw_log: str) -> Optional[MirrorEvent]:
        """Parse an alert emitted by an OpenCanary service and publish to Mirror EventBus."""
        try:
            data = json.loads(raw_log)
        except Exception:
            data = {"raw": raw_log}

        logdata = data.get("logdata", {})
        msg = logdata.get("msg", {})
        logtype = data.get("logtype", "unknown")

        # Map OpenCanary event to normalized MirrorEvent
        event = MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="opencanary",
            sensor=f"decoy_{logtype}",
            event_type="fake_port_probe" if "port" in logtype else "canary_trigger",
            attack_stage="credential_access" if "login" in str(msg) else "discovery",
            asset_id="redis" if "redis" in logtype else "api",
            severity="high",
            confidence=0.98,
            source_ip=data.get("src_host"),
            destination_ip=data.get("dst_host"),
            evidence={
                "node_id": data.get("node_id"),
                "logtype": logtype,
                "msg": msg,
                "utc_time": data.get("utc_time"),
            },
        )

        await self.bus.publish(event)
        logger.info("OpenCanary event ingested: %s from %s", logtype, event.source_ip)
        return event
