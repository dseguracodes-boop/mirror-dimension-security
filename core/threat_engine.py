"""Dynamic Cumulative Threat Engine with Sliding-Window Scoring.

Prevents 'Low-and-Slow' / Salami-slicing evasion by accumulating risk points
across time windows for assets and source IPs.
"""

from collections import defaultdict
from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from core.models import ActionType, MirrorEvent, PolicyDecision, ThreatLevel

logger = logging.getLogger("mirror.threat_engine")


class ThreatRecord:
    def __init__(self, timestamp: float, points: int, event_id: UUID) -> None:
        self.timestamp = timestamp
        self.points = points
        self.event_id = event_id


class CumulativeThreatScorer:
    """Calculates temporal risk scores across rolling sliding-windows."""

    SEVERITY_POINTS = {
        "info": 5,
        "low": 15,
        "medium": 35,
        "high": 70,
        "critical": 120,
    }

    # Cumulative escalation thresholds
    CRITICAL_SCORE_THRESHOLD = 140
    HIGH_SCORE_THRESHOLD = 75
    MEDIUM_SCORE_THRESHOLD = 40

    def __init__(self, window_seconds: float = 60.0, burst_window_seconds: float = 5.0) -> None:
        self.window_seconds = window_seconds
        self.burst_window_seconds = burst_window_seconds
        self._asset_records: Dict[str, List[ThreatRecord]] = defaultdict(list)
        self._ip_records: Dict[str, List[ThreatRecord]] = defaultdict(list)

    def _prune(self, records: List[ThreatRecord], now: float) -> List[ThreatRecord]:
        cutoff = now - self.window_seconds
        return [r for r in records if r.timestamp >= cutoff]

    def record_and_evaluate(
        self,
        event: MirrorEvent,
        candidate_decision: PolicyDecision,
    ) -> PolicyDecision:
        """Record the event risk telemetry and escalate decision if cumulative score warrants it."""
        now = datetime.now(timezone.utc).timestamp()
        asset_id = event.asset_id or "unspecified"
        source_ip = event.source_ip

        # Calculate base points for this event
        base_points = self.SEVERITY_POINTS.get(event.severity.lower(), 25)
        # Factor in confidence
        points = int(base_points * max(event.confidence, 0.5))

        # Record for asset
        self._asset_records[asset_id] = self._prune(self._asset_records[asset_id], now)
        self._asset_records[asset_id].append(ThreatRecord(now, points, event.id))

        # Check burst velocity on asset (burst factor)
        recent_burst_count = sum(
            1 for r in self._asset_records[asset_id] if (now - r.timestamp) <= self.burst_window_seconds
        )
        burst_multiplier = 1.4 if recent_burst_count >= 3 else 1.0

        total_asset_score = int(sum(r.points for r in self._asset_records[asset_id]) * burst_multiplier)

        # Record for source IP if present
        total_ip_score = 0
        if source_ip:
            self._ip_records[source_ip] = self._prune(self._ip_records[source_ip], now)
            self._ip_records[source_ip].append(ThreatRecord(now, points, event.id))
            total_ip_score = sum(r.points for r in self._ip_records[source_ip])

        max_risk_score = max(total_asset_score, total_ip_score)

        # Check for cumulative escalation
        if max_risk_score >= self.CRITICAL_SCORE_THRESHOLD:
            if candidate_decision.action != ActionType.EMERGENCY_FREEZE:
                logger.warning(
                    "Cumulative threat score %d for '%s' triggered CRITICAL escalation.",
                    max_risk_score,
                    asset_id,
                )
                return PolicyDecision(
                    threat=ThreatLevel.CRITICAL,
                    action=ActionType.EMERGENCY_FREEZE,
                    reason=f"Cumulative Threat Escalation (Score: {max_risk_score} >= {self.CRITICAL_SCORE_THRESHOLD})",
                    confidence=min(1.0, candidate_decision.confidence + 0.2),
                )
        elif max_risk_score >= self.HIGH_SCORE_THRESHOLD:
            if candidate_decision.action in (ActionType.ALLOW, ActionType.MONITOR):
                logger.warning(
                    "Cumulative threat score %d for '%s' triggered HIGH escalation.",
                    max_risk_score,
                    asset_id,
                )
                return PolicyDecision(
                    threat=ThreatLevel.HIGH,
                    action=ActionType.ISOLATE,
                    reason=f"Cumulative Threat Escalation (Score: {max_risk_score} >= {self.HIGH_SCORE_THRESHOLD})",
                    confidence=min(1.0, candidate_decision.confidence + 0.15),
                )

        return candidate_decision

    def get_asset_score(self, asset_id: str) -> int:
        now = datetime.now(timezone.utc).timestamp()
        valid = self._prune(self._asset_records.get(asset_id, []), now)
        return sum(r.points for r in valid)

    def reset(self) -> None:
        self._asset_records.clear()
        self._ip_records.clear()
