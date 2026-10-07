"""Network decoy sensor and port probe monitor."""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional
from uuid import uuid4

from core.bus import EventBus
from core.models import MirrorEvent

logger = logging.getLogger("mirror.adapters.network")


class NetworkPortSensor:
    """Listens on decoy/trap ports and emits port probe events upon unauthorized connections."""

    def __init__(self, bus: EventBus, asset_id: str = "network") -> None:
        self.bus = bus
        self.asset_id = asset_id
        self._servers: List[asyncio.Server] = []

    async def start_decoy_listener(self, host: str, port: int, service_name: str = "decoy") -> asyncio.Server:
        """Open a honeypot decoy socket on host:port."""
        async def handle_probe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = writer.get_extra_info("peername")
            source_ip = peer[0] if peer else "unknown"
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                payload = data.decode("utf-8", errors="replace").strip()
            except Exception:
                payload = ""

            logger.warning("Decoy port %d accessed by %s (Service: %s)", port, source_ip, service_name)
            event = MirrorEvent(
                id=uuid4(),
                timestamp=datetime.now(timezone.utc),
                source="network",
                sensor="port_sensor",
                event_type="fake_port_probe",
                attack_stage="discovery",
                asset_id=self.asset_id,
                severity="high",
                confidence=0.90,
                source_ip=source_ip,
                evidence={"target_port": port, "service": service_name, "payload": payload[:120]},
            )
            await self.bus.publish(event)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        server = await asyncio.start_server(handle_probe, host, port)
        self._servers.append(server)
        logger.info("Decoy listener started on %s:%d (%s)", host, port, service_name)
        return server

    async def close_all(self) -> None:
        for s in self._servers:
            s.close()
            await s.wait_closed()
        self._servers.clear()
