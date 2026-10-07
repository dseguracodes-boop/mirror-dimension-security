import concurrent.futures
from pathlib import Path
import pytest
from core.storage import StorageEngine


def test_storage_engine_initialization_and_wal(tmp_path):
    db_file = tmp_path / "test_shield.db"
    storage = StorageEngine(db_path=db_file)
    assert db_file.exists()

    with storage._connection() as conn:
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert mode.lower() == "wal"


def test_storage_engine_incident_crud(tmp_path):
    db_file = tmp_path / "test_shield.db"
    storage = StorageEngine(db_path=db_file)

    inc = {
        "id": "INC-2026-0001",
        "threat_level": "critical",
        "status": "open",
        "started_at": "2026-10-06T00:00:00Z",
        "asset_ids": ["api", "db"],
        "summary": "Test incident",
    }
    storage.save_incident(inc)

    retrieved = storage.get_incident("INC-2026-0001")
    assert retrieved is not None
    assert retrieved["id"] == "INC-2026-0001"
    assert retrieved["threat_level"] == "critical"
    assert "db" in retrieved["asset_ids"]

    # Update incident status
    inc["status"] = "resolved"
    storage.save_incident(inc)
    updated = storage.get_incident("INC-2026-0001")
    assert updated["status"] == "resolved"

    all_incs = storage.list_all_incidents()
    assert len(all_incs) == 1


def test_storage_engine_routes_and_baselines(tmp_path):
    db_file = tmp_path / "test_shield.db"
    storage = StorageEngine(db_path=db_file)

    route = {
        "asset_id": "postgres",
        "primary": "developer-postgres:5432",
        "mirror": "mirror-postgres:5432",
        "active": "developer-postgres:5432",
        "is_diverted": False,
        "total_requests": 15,
        "diverted_requests": 0,
    }
    storage.save_route(route)
    r = storage.get_route("postgres")
    assert r is not None
    assert r["primary"] == "developer-postgres:5432"

    baseline = {
        "asset_id": "postgres",
        "known_good_image": "postgres:16-alpine",
        "config_hash": "abc123hash",
        "sha256_seal": "deadbeef9999",
        "created_at": "2026-10-06T00:00:00Z",
    }
    storage.save_baseline(baseline)
    b = storage.get_baseline("postgres")
    assert b is not None
    assert b["sha256_seal"] == "deadbeef9999"


def test_storage_engine_concurrent_writes(tmp_path):
    """Test that SQLite in WAL mode handles concurrent worker threads writing without database lock errors."""
    db_file = tmp_path / "test_shield.db"
    storage = StorageEngine(db_path=db_file)

    def write_worker(worker_id: int):
        for i in range(25):
            inc_id = f"INC-WORKER-{worker_id}-{i}"
            storage.save_incident({
                "id": inc_id,
                "threat_level": "medium",
                "status": "open",
                "worker": worker_id,
                "seq": i,
            })
            storage.record_audit("test_write", "api", {"worker": worker_id, "i": i})

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(write_worker, w) for w in range(8)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    all_incs = storage.list_all_incidents()
    assert len(all_incs) == 8 * 25
