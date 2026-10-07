from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from uuid import UUID
from core.models import (
    ActionType,
    Incident,
    IncidentStatus,
    MirrorEvent,
    PolicyDecision,
    ThreatLevel,
)

from core.storage import StorageEngine

logger = logging.getLogger("mirror.incidents")


class IncidentManager:
    """Manages the lifecycle of security incidents correlating multiple events with ACID persistence."""

    def __init__(
        self,
        persistence_file: Optional[Path] = None,
        storage: Optional[StorageEngine] = None,
    ) -> None:
        self.persistence_file = persistence_file or (Path(__file__).resolve().parent.parent / "evidence_vault" / "incidents.json")
        if storage is not None:
            self.storage = storage
        elif persistence_file is not None:
            self.storage = StorageEngine(db_path=self.persistence_file.parent / "mirror_shield.db")
        else:
            self.storage = StorageEngine()
        self._incidents: Dict[str, Incident] = {}
        self._asset_to_incident: Dict[str, str] = {}
        self._counter: int = 1
        self._load()

    def _save(self) -> None:
        try:
            # 1. Primary ACID save to SQLite WAL database
            for inc in self._incidents.values():
                self.storage.save_incident(inc.model_dump(mode="json"))

            # 2. Sync to JSON mirror for export/backwards compatibility
            self.persistence_file.parent.mkdir(parents=True, exist_ok=True)
            data = {k: v.model_dump(mode="json") for k, v in self._incidents.items()}
            with open(self.persistence_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error("Failed to persist incidents: %s", e)

    def _load(self) -> None:
        # 1. Try loading from SQLite database first
        try:
            db_incidents = self.storage.list_all_incidents()
            if db_incidents:
                for inc_data in db_incidents:
                    inc = Incident.model_validate(inc_data)
                    self._incidents[inc.id] = inc
                    if inc.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING):
                        for a_id in inc.asset_ids:
                            self._asset_to_incident[a_id] = inc.id
                if self._incidents:
                    self._counter = max(int(k.split("-")[-1]) for k in self._incidents.keys() if k.split("-")[-1].isdigit()) + 1
                return
        except Exception as e:
            logger.warning("Error loading incidents from SQLite storage: %s", e)

        # 2. Fallback to existing JSON if SQLite empty
        if not self.persistence_file.exists():
            return
        try:
            with open(self.persistence_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, inc_data in data.items():
                inc = Incident.model_validate(inc_data)
                self._incidents[k] = inc
                self.storage.save_incident(inc.model_dump(mode="json"))
                if inc.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING):
                    for a_id in inc.asset_ids:
                        self._asset_to_incident[a_id] = inc.id
            if self._incidents:
                self._counter = max(int(k.split("-")[-1]) for k in self._incidents.keys() if k.split("-")[-1].isdigit()) + 1
        except Exception as e:
            logger.error("Failed to load persisted incidents from JSON: %s", e)

    def _next_incident_id(self) -> str:
        current_year = datetime.now(timezone.utc).year
        incident_id = f"INC-{current_year}-{self._counter:04d}"
        self._counter += 1
        return incident_id

    def process_event(self, event: MirrorEvent, decision: PolicyDecision) -> Incident:
        """Correlate event into an existing open incident or spawn a new one."""
        incident = None

        # Look up existing open incident for this asset
        if event.asset_id and event.asset_id in self._asset_to_incident:
            active_id = self._asset_to_incident[event.asset_id]
            candidate = self._incidents.get(active_id)
            if candidate and candidate.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING):
                incident = candidate

        # Spawn a new incident if threat warrants it or no active incident exists
        if not incident:
            incident_id = self._next_incident_id()
            incident = Incident(
                id=incident_id,
                started_at=event.timestamp,
                asset_ids=[event.asset_id] if event.asset_id else [],
                threat_level=decision.threat,
                event_ids=[event.id],
                status=IncidentStatus.OPEN,
                actions=[decision.action],
                summary=f"Incident initiated by {event.event_type} on asset {event.asset_id or 'unknown'}",
            )
            self._incidents[incident_id] = incident
            if event.asset_id:
                self._asset_to_incident[event.asset_id] = incident_id
        else:
            # Append event to existing incident
            incident.event_ids.append(event.id)
            if event.asset_id and event.asset_id not in incident.asset_ids:
                incident.asset_ids.append(event.asset_id)

            # Escalate threat level if higher
            threat_ranks = {
                ThreatLevel.LOW: 1,
                ThreatLevel.MEDIUM: 2,
                ThreatLevel.HIGH: 3,
                ThreatLevel.CRITICAL: 4,
            }
            if threat_ranks[decision.threat] > threat_ranks[incident.threat_level]:
                incident.threat_level = decision.threat

            if decision.action not in incident.actions:
                incident.actions.append(decision.action)

        self._save()
        return incident

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def list_all(self) -> List[Incident]:
        return list(self._incidents.values())

    def update_status(self, incident_id: str, status: IncidentStatus) -> Optional[Incident]:
        incident = self._incidents.get(incident_id)
        if incident:
            incident.status = status
            if status == IncidentStatus.RESOLVED:
                incident.ended_at = datetime.now(timezone.utc)
                # Free asset mapping
                for asset_id in incident.asset_ids:
                    if self._asset_to_incident.get(asset_id) == incident_id:
                        del self._asset_to_incident[asset_id]
            self._save()
        return incident
