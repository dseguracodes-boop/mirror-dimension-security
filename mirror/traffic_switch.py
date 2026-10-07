import asyncio
import json
import logging
from pathlib import Path
import ssl
import time
from typing import Any, Callable, Dict, Optional, Tuple

from core.storage import StorageEngine

logger = logging.getLogger("mirror.mirror.traffic_switch")


class UpstreamRoute:
    def __init__(
        self,
        asset_id: str,
        primary_target: str,
        mirror_target: Optional[str] = None,
        active_target: Optional[str] = None,
        is_diverted: bool = False,
        diverted_at: Optional[float] = None,
        request_count: int = 0,
        diverted_request_count: int = 0,
    ) -> None:
        self.asset_id = asset_id
        self.primary_target = primary_target
        self.mirror_target = mirror_target
        self.active_target = active_target or primary_target
        self.is_diverted = is_diverted
        self.diverted_at = diverted_at
        self.request_count = request_count
        self.diverted_request_count = diverted_request_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "primary": self.primary_target,
            "mirror": self.mirror_target,
            "active": self.active_target,
            "is_diverted": self.is_diverted,
            "diverted_at": self.diverted_at,
            "total_requests": self.request_count,
            "diverted_requests": self.diverted_request_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UpstreamRoute":
        return cls(
            asset_id=data["asset_id"],
            primary_target=data["primary"],
            mirror_target=data.get("mirror"),
            active_target=data.get("active"),
            is_diverted=data.get("is_diverted", False),
            diverted_at=data.get("diverted_at"),
            request_count=data.get("total_requests", 0),
            diverted_request_count=data.get("diverted_requests", 0),
        )


class TrafficSwitch:
    """Manages dynamic upstream routing, ACID persistence, and live reverse proxying with TLS support."""

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        storage: Optional[StorageEngine] = None,
    ) -> None:
        self.storage_path = storage_path or (
            Path(__file__).resolve().parent.parent / "evidence_vault" / "routes.json"
        )
        if storage is not None:
            self.storage = storage
        elif storage_path is not None:
            self.storage = StorageEngine(db_path=self.storage_path.parent / "mirror_shield.db")
        else:
            self.storage = StorageEngine()
        self._routes: Dict[str, UpstreamRoute] = {}
        self._load()

    def _load(self) -> None:
        """Load persisted routes from ACID SQLite storage, with fallback to JSON."""
        try:
            db_routes = self.storage.list_all_routes()
            if db_routes:
                for route_dict in db_routes.values():
                    route = UpstreamRoute.from_dict(route_dict)
                    self._routes[route.asset_id] = route
                return
        except Exception as e:
            logger.warning("Error reading routes from SQLite: %s", e)

        if not self.storage_path.exists():
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for route_dict in data.values():
                    route = UpstreamRoute.from_dict(route_dict)
                    self._routes[route.asset_id] = route
                    self.storage.save_route(route.to_dict())
            logger.debug("Loaded %d routes from %s", len(self._routes), self.storage_path)
        except Exception as e:
            logger.warning("Failed to load routes from %s: %s", self.storage_path, e)

    def _save(self) -> None:
        """Persist current routing table to SQLite and JSON mirror."""
        try:
            # 1. Primary ACID save to SQLite
            for r in self._routes.values():
                self.storage.save_route(r.to_dict())

            # 2. JSON mirror for export
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(self.list_routes(), f, indent=2)
        except Exception as e:
            logger.warning("Failed to persist routes: %s", e)

    def register_route(
        self,
        asset_id: str,
        primary_host_port: str,
        default_mirror_host_port: Optional[str] = None,
    ) -> UpstreamRoute:
        """Register a proxy upstream route for a protected asset."""
        existing = self._routes.get(asset_id)
        if existing:
            # Preserve state if already diverted
            existing.primary_target = primary_host_port
            if not existing.is_diverted:
                existing.active_target = primary_host_port
            if default_mirror_host_port and not existing.mirror_target:
                existing.mirror_target = default_mirror_host_port
            self._save()
            return existing

        route = UpstreamRoute(
            asset_id=asset_id,
            primary_target=primary_host_port,
            mirror_target=default_mirror_host_port,
        )
        self._routes[asset_id] = route
        self._save()
        logger.info(
            "Registered upstream route for '%s' -> %s (Mirror default: %s)",
            asset_id,
            primary_host_port,
            default_mirror_host_port,
        )
        return route

    def divert_to_mirror(self, asset_id: str, mirror_host_port: Optional[str] = None) -> bool:
        """Instantly divert all incoming traffic for an asset to its Mirror World clone."""
        route = self._routes.get(asset_id)
        if not route:
            target = mirror_host_port or f"mirror-{asset_id}:8000"
            route = self.register_route(asset_id, f"{asset_id}:8000", target)

        target = mirror_host_port or route.mirror_target or f"mirror-{asset_id}:8000"
        route.mirror_target = target
        route.active_target = target
        route.is_diverted = True
        route.diverted_at = time.time()
        self._save()

        logger.critical(
            "🔀 TRAFFIC DIVERTED: Asset '%s' routed to Mirror clone at '%s'. Attacker session preserved.",
            asset_id,
            target,
        )
        return True

    def restore_route(self, asset_id: str) -> bool:
        """Restore traffic back to the clean real asset after rollback and remediation."""
        route = self._routes.get(asset_id)
        if not route:
            return False

        route.active_target = route.primary_target
        route.is_diverted = False
        route.diverted_at = None
        self._save()
        logger.info("Restored upstream route for '%s' to primary '%s'", asset_id, route.primary_target)
        return True

    def get_route(self, asset_id: str) -> Optional[UpstreamRoute]:
        return self._routes.get(asset_id)

    def resolve_target(self, asset_id: str) -> str:
        """Return current active target endpoint for incoming requests."""
        route = self._routes.get(asset_id)
        if not route:
            return f"{asset_id}:8000"
        route.request_count += 1
        if route.is_diverted:
            route.diverted_request_count += 1
        self._save()
        return route.active_target

    def list_routes(self) -> Dict[str, Dict[str, Any]]:
        """Return status matrix of all active and diverted routes."""
        return {asset_id: r.to_dict() for asset_id, r in self._routes.items()}

    @staticmethod
    def generate_self_signed_cert(output_dir: Path) -> Tuple[Path, Path]:
        """Generate a production-compatible self-signed TLS cert and key for staging/testing."""
        output_dir.mkdir(parents=True, exist_ok=True)
        cert_path = output_dir / "mirror_tls_cert.pem"
        key_path = output_dir / "mirror_tls_key.pem"
        if not cert_path.exists() or not key_path.exists():
            import subprocess
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "365", "-nodes",
                "-subj", "/CN=localhost/O=Dimension-Espejo/OU=Shield",
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info("Generated self-signed TLS certificate at %s", cert_path)
        return cert_path, key_path

    @staticmethod
    def create_ssl_context(certfile: Path, keyfile: Path) -> ssl.SSLContext:
        """Create a hardened TLS context from PEM certificate and private key."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    async def forward_stream(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        asset_id: str,
        is_tls: bool = False,
    ) -> None:
        """Bidirectionally pipe client TCP/HTTP traffic with header injection and zero-drop diversion."""
        target = self.resolve_target(asset_id)
        peer = client_writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "127.0.0.1"

        try:
            if ":" in target:
                host, port_str = target.split(":", 1)
                port = int(port_str)
            else:
                host = target
                port = 80

            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0,
            )
        except Exception as e:
            logger.error("Failed to connect to upstream %s for asset '%s': %s", target, asset_id, e)
            try:
                # Return standard 502 Bad Gateway if HTTP
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await client_writer.drain()
            except Exception:
                pass
            client_writer.close()
            return

        async def _client_to_upstream() -> None:
            first_chunk = True
            try:
                while True:
                    data = await client_reader.read(8192)
                    if not data:
                        break

                    # Header injection for HTTP traffic
                    if first_chunk:
                        first_chunk = False
                        http_methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")
                        if any(data.startswith(m) for m in http_methods) and b"\r\n\r\n" in data:
                            proto = b"https" if is_tls else b"http"
                            shield_headers = (
                                f"\r\nX-Forwarded-For: {client_ip}\r\n"
                                f"X-Forwarded-Proto: {proto.decode()}\r\n"
                                f"X-Mirror-Shield: active\r\n"
                            ).encode("utf-8")
                            header_end = data.find(b"\r\n\r\n")
                            data = data[:header_end] + shield_headers + data[header_end:]

                    upstream_writer.write(data)
                    await upstream_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    upstream_writer.close()
                except Exception:
                    pass

        async def _upstream_to_client() -> None:
            try:
                while True:
                    data = await upstream_reader.read(8192)
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    client_writer.close()
                except Exception:
                    pass

        try:
            await asyncio.gather(
                _client_to_upstream(),
                _upstream_to_client(),
                return_exceptions=True,
            )
        finally:
            try:
                client_writer.close()
                upstream_writer.close()
            except Exception:
                pass

    async def start_proxy_server(
        self,
        listen_host: str,
        listen_port: int,
        asset_id: str,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> asyncio.Server:
        """Start a live dynamic reverse proxy listener for a protected asset with optional TLS."""
        is_tls = ssl_context is not None

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await self.forward_stream(reader, writer, asset_id, is_tls=is_tls)

        server = await asyncio.start_server(
            handle_client,
            listen_host,
            listen_port,
            ssl=ssl_context,
        )
        mode = "HTTPS/TLS" if is_tls else "HTTP/TCP"
        logger.info(
            "🚀 Mirror Reverse Proxy [%s] listening on %s:%d (routing asset '%s')",
            mode,
            listen_host,
            listen_port,
            asset_id,
        )
        return server

