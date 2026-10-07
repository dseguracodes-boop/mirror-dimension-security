import asyncio
import pytest
from core.bus import EventBus
from core.models import MirrorEvent
from deception.decoy_services import DecoyServiceManager


@pytest.mark.asyncio
async def test_decoy_redis_probe_event():
    bus = EventBus()
    received_events = []

    @bus.subscribe("fake_port_probe")
    async def on_probe(event: MirrorEvent):
        received_events.append(event)

    mgr = DecoyServiceManager(bus=bus)
    # Pick random high ports for testing
    await mgr.start_services(redis_port=26379, ssh_port=22222, http_port=28080)

    try:
        # Connect to fake Redis port and send PING
        reader, writer = await asyncio.open_connection("127.0.0.1", 26379)
        writer.write(b"PING\r\n")
        await writer.drain()

        response = await reader.read(1024)
        assert b"-ERR authentication required" in response
        writer.close()
        await writer.wait_closed()

        # Allow async event bus loop to process
        await asyncio.sleep(0.05)

        assert len(received_events) == 1
        event = received_events[0]
        assert event.source == "deception"
        assert event.sensor == "fake_redis_honeypot"
        assert event.event_type == "fake_port_probe"
        assert event.confidence >= 0.95
        assert event.evidence["payload"] == "PING"

    finally:
        await mgr.stop_services()
