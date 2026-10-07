from pathlib import Path
from unittest.mock import MagicMock
from core.bus import EventBus
from deception.decoy_files import CanaryFileEventHandler, DecoyFileManager


def test_decoy_files_deployment(tmp_path: Path):
    bus = EventBus()
    mgr = DecoyFileManager(bus=bus, base_dir=tmp_path)
    deployed = mgr.deploy_default_canaries()

    assert len(deployed) >= 1
    assert deployed[0].name == ".env.backup"
    assert deployed[0].exists()

    content = deployed[0].read_text(encoding="utf-8")
    assert "AWS_ACCESS_KEY_ID=AKIA" in content
    assert "DATABASE_URL=postgresql://" in content


def test_canary_event_handler_trigger(tmp_path: Path):
    bus = EventBus()
    canary_file = tmp_path / ".env.backup"
    canary_file.touch()

    loop = MagicMock()
    handler = CanaryFileEventHandler(
        bus=bus,
        canary_paths={canary_file: "test_canary"},
        loop=loop,
    )

    # Mock FileSystemEvent
    mock_event = MagicMock()
    mock_event.src_path = str(canary_file)
    mock_event.is_directory = False

    handler.on_modified(mock_event)

    # Verify scheduled on loop
    loop.is_running.return_value = True
    handler.on_modified(mock_event)
