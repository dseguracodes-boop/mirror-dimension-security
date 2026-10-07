import pytest
from adapters.opencanary.adapter import OpenCanaryAdapter
from core.bus import EventBus
from core.models import MirrorEvent


@pytest.mark.asyncio
async def test_opencanary_adapter_ingestion():
    bus = EventBus()
    received = []

    @bus.subscribe("fake_port_probe")
    async def on_probe(event: MirrorEvent):
        received.append(event)

    adapter = OpenCanaryAdapter(bus=bus)
    sample_log = '''{
        "dst_host": "10.0.0.1",
        "dst_port": 16379,
        "logdata": {"msg": {"command": "PING"}},
        "logtype": "portscan",
        "node_id": "test-canary",
        "src_host": "192.168.1.50",
        "src_port": 54221,
        "utc_time": "2026-09-23 22:00:00"
    }'''

    event = await adapter.handle_opencanary_log_line(sample_log)
    assert event is not None
    assert event.source == "opencanary"
    assert event.event_type == "fake_port_probe"
    assert event.source_ip == "192.168.1.50"
    assert len(received) == 1
