import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from core.bus import EventBus
from core.models import MirrorEvent

logger = logging.getLogger("mirror.deception.services")


class DecoyServiceManager:
    """Runs lightweight async honeypot service ports (Redis, SSH, HTTP) to catch local scanners."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._servers: List[asyncio.Server] = []
        self._active_services: List[str] = []

    async def start_services(
        self,
        redis_port: int = 16379,
        ssh_port: int = 12222,
        http_port: int = 18080,
    ) -> None:
        """Launch all lightweight honeypot service ports."""
        try:
            # 1. Fake Redis Honeypot
            redis_server = await asyncio.start_server(
                self._handle_redis_client, "127.0.0.1", redis_port
            )
            self._servers.append(redis_server)
            self._active_services.append(f"fake_redis:{redis_port}")
            logger.info("Fake Redis honeypot listening on 127.0.0.1:%s", redis_port)
        except Exception as e:
            logger.warning("Could not bind fake Redis port %s: %s", redis_port, e)

        try:
            # 2. Fake SSH Honeypot Banner
            ssh_server = await asyncio.start_server(
                self._handle_ssh_client, "127.0.0.1", ssh_port
            )
            self._servers.append(ssh_server)
            self._active_services.append(f"fake_ssh:{ssh_port}")
            logger.info("Fake SSH honeypot listening on 127.0.0.1:%s", ssh_port)
        except Exception as e:
            logger.warning("Could not bind fake SSH port %s: %s", ssh_port, e)

        try:
            # 3. Fake HTTP Admin Honeypot
            http_server = await asyncio.start_server(
                self._handle_http_client, "127.0.0.1", http_port
            )
            self._servers.append(http_server)
            self._active_services.append(f"fake_http:{http_port}")
            logger.info("Fake HTTP honeypot listening on 127.0.0.1:%s", http_port)
        except Exception as e:
            logger.warning("Could not bind fake HTTP port %s: %s", http_port, e)

    async def _handle_redis_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "unknown"

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            payload = data.decode("utf-8", errors="replace").strip()
        except Exception:
            payload = "<no data / timeout>"

        logger.critical("🚨 HONEYPOT TRIGGERED! Fake Redis accessed by %s: %s", src_ip, payload)

        event = MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="deception",
            sensor="fake_redis_honeypot",
            event_type="fake_port_probe",
            attack_stage="discovery",
            asset_id="redis",
            severity="high",
            confidence=0.98,
            source_ip=src_ip,
            evidence={"service": "redis", "port": 16379, "payload": payload},
        )
        await self.bus.publish(event)

        # Respond like Redis
        try:
            writer.write(b"-ERR authentication required\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def _handle_ssh_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "unknown"

        logger.critical("🚨 HONEYPOT TRIGGERED! Fake SSH accessed by %s", src_ip)

        event = MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="deception",
            sensor="fake_ssh_honeypot",
            event_type="fake_port_probe",
            attack_stage="initial_access",
            asset_id="api",
            severity="high",
            confidence=0.98,
            source_ip=src_ip,
            evidence={"service": "ssh", "port": 12222, "banner_sent": "SSH-2.0-OpenSSH_9.3"},
        )
        await self.bus.publish(event)

        try:
            writer.write(b"SSH-2.0-OpenSSH_9.3\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def _handle_http_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "unknown"

        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=5.0)
            request_text = data.decode("utf-8", errors="replace")
            first_line = request_text.splitlines()[0] if request_text else ""
        except Exception:
            first_line = "GET /"

        logger.critical("🚨 HONEYPOT TRIGGERED! Fake HTTP accessed by %s: %s", src_ip, first_line)

        event = MirrorEvent(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="deception",
            sensor="fake_http_honeypot",
            event_type="fake_port_probe",
            attack_stage="initial_access",
            asset_id="api",
            severity="high",
            confidence=0.97,
            source_ip=src_ip,
            evidence={"service": "http", "port": 18080, "request_line": first_line},
        )
        await self.bus.publish(event)

        try:
            response = (
                "HTTP/1.1 401 Unauthorized\r\n"
                "WWW-Authenticate: Basic realm=\"Internal Management Console\"\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 26\r\n\r\n"
                "401 Unauthorized - Access Denied"
            )
            writer.write(response.encode("utf-8"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def stop_services(self) -> None:
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()
        self._active_services.clear()
        logger.info("Decoy honeypot services STOPPED")

    @property
    def active_services(self) -> List[str]:
        return list(self._active_services)
