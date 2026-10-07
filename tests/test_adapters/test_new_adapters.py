import asyncio
import time
import pytest
from core.bus import EventBus
from adapters.filesystem.watcher import FilesystemWatcher
from adapters.network.traffic_sensor import NetworkPortSensor
from adapters.osquery.client import OsqueryAdapter


@pytest.mark.asyncio
async def test_filesystem_watcher_modification_and_deletion(tmp_path):
    bus = EventBus()
    received_events = []

    @bus.subscribe("canary_trigger")
    async def handler(event):
        received_events.append(event)

    watcher = FilesystemWatcher(bus)
    test_file = tmp_path / "secret.env"
    test_file.write_text("API_KEY=test")

    watcher.watch_path(test_file)

    # 1. No changes -> No events
    evs = await watcher.scan_modifications()
    assert len(evs) == 0

    # 2. Modify file -> Emits event
    time.sleep(0.01)
    test_file.write_text("API_KEY=modified")
    evs = await watcher.scan_modifications()
    assert len(evs) == 1
    assert evs[0].event_type == "canary_trigger"
    assert evs[0].evidence["action"] == "modified"

    # 3. Delete file -> Emits deletion event
    test_file.unlink()
    evs = await watcher.scan_modifications()
    assert len(evs) == 1
    assert evs[0].evidence["action"] == "deleted"


@pytest.mark.asyncio
async def test_network_port_sensor():
    bus = EventBus()
    received_events = []

    @bus.subscribe("fake_port_probe")
    async def handler(event):
        received_events.append(event)

    sensor = NetworkPortSensor(bus, asset_id="db_decoy")
    server = await sensor.start_decoy_listener("127.0.0.1", 19875, service_name="fake_mysql")

    try:
        r, w = await asyncio.open_connection("127.0.0.1", 19875)
        w.write(b"ATTACKER_PROBE\n")
        await w.drain()
        await asyncio.sleep(0.05)
        w.close()

        assert len(received_events) == 1
        assert received_events[0].event_type == "fake_port_probe"
        assert received_events[0].evidence["service"] == "fake_mysql"
        assert received_events[0].asset_id == "db_decoy"
    finally:
        await sensor.close_all()


def test_osquery_adapter_graceful_unavailable():
    bus = EventBus()
    adapter = OsqueryAdapter(bus, osqueryi_bin="non_existent_osquery_binary_xyz")
    assert adapter.is_available() is False
    res = adapter.query("SELECT 1;")
    assert res == []
