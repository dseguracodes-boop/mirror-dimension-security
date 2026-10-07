"""Production Transactional Storage Engine for Dimensión Espejo.

Provides ACID persistence, concurrent reads/writes without lock contention,
crash safety via SQLite WAL (Write-Ahead Logging), and zero-loss schema management.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger("mirror.storage")


class StorageEngine:
    """ACID-compliant storage engine managing incidents, routing tables, and cryptographic baselines."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or (
            Path(__file__).resolve().parent.parent / "evidence_vault" / "mirror_shield.db"
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing thread-safe connections with WAL mode and busy timeouts."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create database tables and performance indexes if not existing."""
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
                CREATE INDEX IF NOT EXISTS idx_incidents_threat ON incidents(threat_level);

                CREATE TABLE IF NOT EXISTS routes (
                    asset_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    is_diverted INTEGER NOT NULL,
                    active_target TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS baselines (
                    asset_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    sha256_seal TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    asset_id TEXT,
                    details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(timestamp);
                """
            )
        logger.debug("StorageEngine initialized with WAL at %s", self.db_path)

    # -------------------------------------------------------------------------
    # Incident Storage Methods
    # -------------------------------------------------------------------------

    def save_incident(self, incident_dict: Dict[str, Any]) -> None:
        """Save or update an incident transactionally."""
        inc_id = incident_dict["id"]
        threat = incident_dict.get("threat_level", "low")
        status = incident_dict.get("status", "open")
        started_at = incident_dict.get("started_at", datetime.now(timezone.utc).isoformat())
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(incident_dict, default=str)

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO incidents (id, data, threat_level, status, started_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    data = excluded.data,
                    threat_level = excluded.threat_level,
                    status = excluded.status,
                    updated_at = excluded.updated_at;
                """,
                (inc_id, payload, threat, status, str(started_at), now),
            )

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an incident by ID."""
        with self._connection() as conn:
            row = conn.execute("SELECT data FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row:
                return json.loads(row["data"])
            return None

    def list_all_incidents(self) -> List[Dict[str, Any]]:
        """List all incidents ordered by start time descending."""
        with self._connection() as conn:
            rows = conn.execute("SELECT data FROM incidents ORDER BY started_at DESC").fetchall()
            return [json.loads(r["data"]) for r in rows]

    # -------------------------------------------------------------------------
    # Route Storage Methods
    # -------------------------------------------------------------------------

    def save_route(self, route_dict: Dict[str, Any]) -> None:
        """Save or update upstream traffic route."""
        asset_id = route_dict["asset_id"]
        is_diverted = 1 if route_dict.get("is_diverted") else 0
        active_target = route_dict.get("active", route_dict.get("primary", ""))
        payload = json.dumps(route_dict)
        now = datetime.now(timezone.utc).isoformat()

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO routes (asset_id, data, is_diverted, active_target, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    data = excluded.data,
                    is_diverted = excluded.is_diverted,
                    active_target = excluded.active_target,
                    updated_at = excluded.updated_at;
                """,
                (asset_id, payload, is_diverted, active_target, now),
            )

    def get_route(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve route dictionary for asset."""
        with self._connection() as conn:
            row = conn.execute("SELECT data FROM routes WHERE asset_id = ?", (asset_id,)).fetchone()
            if row:
                return json.loads(row["data"])
            return None

    def list_all_routes(self) -> Dict[str, Dict[str, Any]]:
        """Retrieve all registered routes as a dictionary."""
        with self._connection() as conn:
            rows = conn.execute("SELECT asset_id, data FROM routes").fetchall()
            return {r["asset_id"]: json.loads(r["data"]) for r in rows}

    # -------------------------------------------------------------------------
    # Baseline Storage Methods
    # -------------------------------------------------------------------------

    def save_baseline(self, baseline_dict: Dict[str, Any]) -> None:
        """Save a cryptographically sealed baseline record."""
        asset_id = baseline_dict["asset_id"]
        seal = baseline_dict["sha256_seal"]
        created_at = baseline_dict.get("created_at", datetime.now(timezone.utc).isoformat())
        payload = json.dumps(baseline_dict)

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO baselines (asset_id, data, sha256_seal, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    data = excluded.data,
                    sha256_seal = excluded.sha256_seal,
                    created_at = excluded.created_at;
                """,
                (asset_id, payload, seal, created_at),
            )

    def get_baseline(self, asset_id: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            row = conn.execute("SELECT data FROM baselines WHERE asset_id = ?", (asset_id,)).fetchone()
            if row:
                return json.loads(row["data"])
            return None

    def list_all_baselines(self) -> Dict[str, Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT asset_id, data FROM baselines").fetchall()
            return {r["asset_id"]: json.loads(r["data"]) for r in rows}

    # -------------------------------------------------------------------------
    # Audit Log
    # -------------------------------------------------------------------------

    def record_audit(self, event_type: str, asset_id: Optional[str], details: Dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, event_type, asset_id, details) VALUES (?, ?, ?, ?)",
                (now, event_type, asset_id, json.dumps(details, default=str)),
            )
