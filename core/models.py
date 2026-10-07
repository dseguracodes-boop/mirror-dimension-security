from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class AssetType(str, Enum):
    CONTAINER = "container"
    DATABASE = "database"
    SERVICE = "service"
    SECRETS = "secrets"
    FILESYSTEM = "filesystem"


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    ALLOW = "allow"
    MONITOR = "monitor"
    DECOY = "decoy"
    ISOLATE = "isolate"
    QUARANTINE = "quarantine"
    EMERGENCY_FREEZE = "emergency_freeze"


class IncidentStatus(str, Enum):
    OPEN = "open"
    CONTAINED = "contained"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class AssetProtections(BaseModel):
    filesystem: bool = False
    network: bool = False
    process: bool = False
    canary: bool = False
    integrity: bool = False


class AssetContainerConfig(BaseModel):
    name: Optional[str] = None
    image: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    volumes: List[str] = Field(default_factory=list)


class Asset(BaseModel):
    id: str
    type: AssetType
    criticality: Criticality
    description: Optional[str] = None
    container: Optional[AssetContainerConfig] = None
    protections: AssetProtections = Field(default_factory=AssetProtections)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MirrorEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    source: str  # e.g., "docker", "filesystem", "canary", "osquery"
    sensor: str  # e.g., "docker_events", "fsevents", "decoy_file", "fake_port"
    event_type: str  # e.g., "canary_trigger", "process_anomaly", "credential_access"
    attack_stage: Optional[str] = None  # e.g., "initial_access", "credential_access", "lateral_movement"

    asset_id: Optional[str] = None

    severity: str = "medium"  # "info", "low", "medium", "high", "critical"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    actor: Optional[str] = None
    process: Optional[str] = None
    container_id: Optional[str] = None

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    path: Optional[str] = None
    command: Optional[str] = None

    evidence: Dict[str, Any] = Field(default_factory=dict)
    correlation_id: Optional[UUID] = None

    # Cryptographic Sensor Provenance
    sensor_id: Optional[str] = None
    signature: Optional[str] = None
    verified_sensor: bool = True


class PolicyDecision(BaseModel):
    threat: ThreatLevel
    action: ActionType
    reason: str
    confidence: float = 1.0


class PolicyRule(BaseModel):
    name: str
    description: Optional[str] = None
    event_type: Optional[str] = None
    sensor: Optional[str] = None
    attack_stage: Optional[str] = None
    asset_criticality: Optional[Criticality] = None
    asset_type: Optional[AssetType] = None
    confidence_min: float = 0.0

    threat: ThreatLevel
    action: ActionType


class Incident(BaseModel):
    id: str  # e.g. "INC-2026-0001"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: Optional[datetime] = None

    asset_ids: List[str] = Field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.LOW
    event_ids: List[UUID] = Field(default_factory=list)

    status: IncidentStatus = IncidentStatus.OPEN
    actions: List[ActionType] = Field(default_factory=list)

    mirror_id: Optional[str] = None
    evidence_id: Optional[str] = None
    summary: Optional[str] = None
