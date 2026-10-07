import asyncio
import pytest
from core.bus import EventBus
from core.models import MirrorEvent


@pytest.mark.asyncio
async def test_event_bus_publish_subscribe():
    bus = EventBus()
    received = []

    @bus.subscribe("canary_trigger")
    async def handle_canary(event: MirrorEvent):
        received.append(event)

    event = MirrorEvent(
        source="canary",
        sensor="decoy_file",
        event_type="canary_trigger",
        asset_id="secrets",
    )

    await bus.publish(event)
    assert len(received) == 1
    assert received[0].id == event.id
    assert len(bus.history) == 1


@pytest.mark.asyncio
async def test_event_bus_global_wildcard():
    bus = EventBus()
    received = []

    @bus.subscribe("*")
    async def handle_any(event: MirrorEvent):
        received.append(event)

    e1 = MirrorEvent(source="s1", sensor="sens", event_type="type_a")
    e2 = MirrorEvent(source="s2", sensor="sens", event_type="type_b")

    await bus.publish(e1)
    await bus.publish(e2)

    assert len(received) == 2
