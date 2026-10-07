from unittest.mock import MagicMock
from adapters.docker.listener import DockerEventListener
from core.assets import AssetRegistry
from core.bus import EventBus
from core.models import Asset, AssetContainerConfig, AssetType, Criticality


def test_docker_event_normalization_exec():
    bus = EventBus()
    assets = AssetRegistry()
    assets.register(
        Asset(
            id="api",
            type=AssetType.CONTAINER,
            criticality=Criticality.HIGH,
            container=AssetContainerConfig(name="dev-api"),
        )
    )

    listener = DockerEventListener(bus=bus, assets=assets, client=MagicMock())
    raw_event = {
        "Type": "container",
        "Action": "exec_create: /bin/bash",
        "Actor": {
            "ID": "1234567890abcdef",
            "Attributes": {
                "name": "dev-api",
                "image": "my-api:latest",
                "execID": "exec_999",
            },
        },
        "time": 1700000000,
    }

    event = listener.normalize_event(raw_event)
    assert event is not None
    assert event.source == "docker"
    assert event.event_type == "process_anomaly"
    assert event.asset_id == "api"
    assert event.severity == "high"
    assert event.confidence == 0.85
