import asyncio
from pathlib import Path
import pytest
from mirror.traffic_switch import TrafficSwitch


def test_traffic_switch_registration_and_diversion(tmp_path):
    storage = tmp_path / "routes.json"
    switch = TrafficSwitch(storage_path=storage)
    route = switch.register_route(
        asset_id="api",
        primary_host_port="developer-api:8000",
        default_mirror_host_port="mirror-developer-api:8000",
    )

    # Initial state: points to real container
    assert switch.resolve_target("api") == "developer-api:8000"
    assert route.is_diverted is False
    assert route.request_count == 1
    assert route.diverted_request_count == 0

    # Incident occurs -> Divert to mirror
    success = switch.divert_to_mirror("api")
    assert success is True
    assert route.is_diverted is True

    # Next incoming requests must resolve to the clean mirror clone without dropping
    assert switch.resolve_target("api") == "mirror-developer-api:8000"
    assert route.request_count == 2
    assert route.diverted_request_count == 1

    # Recovery rollback -> Restore to real asset
    restored = switch.restore_route("api")
    assert restored is True
    assert route.is_diverted is False
    assert switch.resolve_target("api") == "developer-api:8000"


def test_traffic_switch_persistence(tmp_path):
    storage = tmp_path / "routes.json"
    switch1 = TrafficSwitch(storage_path=storage)
    switch1.register_route("database", "postgres:5432", "mirror-postgres:5432")
    switch1.divert_to_mirror("database")

    assert storage.exists()

    # Create new instance pointing to same file -> must retain diverted state
    switch2 = TrafficSwitch(storage_path=storage)
    assert "database" in switch2._routes
    saved_route = switch2.get_route("database")
    assert saved_route is not None
    assert saved_route.is_diverted is True
    assert saved_route.active_target == "mirror-postgres:5432"


@pytest.mark.asyncio
async def test_traffic_switch_live_stream_proxy(tmp_path):
    """Test real live bidirectional TCP proxying with dynamic switching between primary and mirror."""
    storage = tmp_path / "routes.json"
    switch = TrafficSwitch(storage_path=storage)

    # 1. Start primary mock server
    async def handle_primary(r, w):
        data = await r.readline()
        w.write(b"PRIMARY_SERVER_RESPONSE\n")
        await w.drain()
        w.close()

    primary_server = await asyncio.start_server(handle_primary, "127.0.0.1", 19871)

    # 2. Start mirror mock server
    async def handle_mirror(r, w):
        data = await r.readline()
        w.write(b"MIRROR_SERVER_RESPONSE\n")
        await w.drain()
        w.close()

    mirror_server = await asyncio.start_server(handle_mirror, "127.0.0.1", 19872)

    # 3. Register route and start reverse proxy
    switch.register_route("web", "127.0.0.1:19871", "127.0.0.1:19872")
    proxy_server = await switch.start_proxy_server("127.0.0.1", 19870, "web")

    try:
        # Request 1: Target is primary
        cr, cw = await asyncio.open_connection("127.0.0.1", 19870)
        cw.write(b"PING\n")
        await cw.drain()
        resp1 = await cr.readline()
        cw.close()
        assert resp1 == b"PRIMARY_SERVER_RESPONSE\n"

        # Trigger diversion to mirror clone!
        switch.divert_to_mirror("web")

        # Request 2: Exactly same public port (19870), but silently forwarded to mirror!
        cr, cw = await asyncio.open_connection("127.0.0.1", 19870)
        cw.write(b"PING\n")
        await cw.drain()
        resp2 = await cr.readline()
        cw.close()
        assert resp2 == b"MIRROR_SERVER_RESPONSE\n"

        # Restore route
        switch.restore_route("web")

        # Request 3: Seamlessly back to primary
        cr, cw = await asyncio.open_connection("127.0.0.1", 19870)
        cw.write(b"PING\n")
        await cw.drain()
        resp3 = await cr.readline()
        cw.close()
        assert resp3 == b"PRIMARY_SERVER_RESPONSE\n"

    finally:
        proxy_server.close()
        primary_server.close()
        mirror_server.close()
        await proxy_server.wait_closed()
        await primary_server.wait_closed()
        await mirror_server.wait_closed()


@pytest.mark.asyncio
async def test_traffic_switch_tls_proxy_and_header_injection(tmp_path):
    """Test production TLS/HTTPS termination and HTTP header forwarding."""
    import ssl
    cert_path, key_path = TrafficSwitch.generate_self_signed_cert(tmp_path / "certs")
    assert cert_path.exists()
    assert key_path.exists()

    server_ssl = TrafficSwitch.create_ssl_context(cert_path, key_path)

    # 1. Primary mock upstream HTTP backend
    received_headers = []

    async def handle_upstream(r, w):
        data = await r.read(4096)
        received_headers.append(data.decode("utf-8", errors="replace"))
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nHello From App!")
        await w.drain()
        w.close()

    backend_server = await asyncio.start_server(handle_upstream, "127.0.0.1", 19881)

    # 2. Start proxy with TLS
    storage = tmp_path / "routes.json"
    switch = TrafficSwitch(storage_path=storage)
    switch.register_route("api_tls", "127.0.0.1:19881")
    proxy_server = await switch.start_proxy_server("127.0.0.1", 19880, "api_tls", ssl_context=server_ssl)

    # 3. Client connects via SSL
    client_ssl = ssl.create_default_context()
    client_ssl.check_hostname = False
    client_ssl.verify_mode = ssl.CERT_NONE

    try:
        cr, cw = await asyncio.open_connection("127.0.0.1", 19880, ssl=client_ssl)
        cw.write(b"GET /api/v1/users HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await cw.drain()
        resp = await cr.read(1024)
        cw.close()

        assert b"200 OK" in resp
        assert b"Hello From App!" in resp

        # Verify proxy injected production forward headers
        assert len(received_headers) == 1
        raw_req = received_headers[0]
        assert "X-Forwarded-For: 127.0.0.1" in raw_req
        assert "X-Forwarded-Proto: https" in raw_req
        assert "X-Mirror-Shield: active" in raw_req

    finally:
        proxy_server.close()
        backend_server.close()
        await proxy_server.wait_closed()
        await backend_server.wait_closed()


