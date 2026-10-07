from pathlib import Path
from unittest.mock import MagicMock
from evidence.forensics_collector import ForensicsCollector


def test_forensics_collector_snapshot_and_sha256(tmp_path: Path):
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.diff.return_value = [
        {"Path": "/etc/passwd", "Kind": 0},
        {"Path": "/tmp/evil.sh", "Kind": 1},
    ]
    mock_container.attrs = {
        "Id": "abc123456",
        "Name": "/test-target",
        "Created": "2026-09-23T20:00:00Z",
        "Config": {
            "Image": "ubuntu:latest",
            "Cmd": ["/bin/bash"],
            "Env": ["API_KEY=supersecret123", "PATH=/usr/bin"],
        },
        "State": {"Status": "paused"},
    }
    mock_client.containers.get.return_value = mock_container

    collector = ForensicsCollector(vault_dir=tmp_path, client=mock_client)
    snapshot = collector.collect_snapshot(
        incident_id="INC-2026-9999",
        container_identifier="test-target",
        trigger_reason="canary_compromise",
    )

    assert snapshot is not None
    assert snapshot["incident_id"] == "INC-2026-9999"
    assert len(snapshot["filesystem_diff"]) == 2
    assert snapshot["filesystem_diff"][0]["action"] == "MODIFIED"
    assert snapshot["filesystem_diff"][1]["action"] == "ADDED"
    assert "sha256_integrity_seal" in snapshot
    assert len(snapshot["sha256_integrity_seal"]) == 64

    # Verify manifest written to disk
    manifest_file = tmp_path / "INC-2026-9999" / "forensics_manifest.json"
    assert manifest_file.exists()
