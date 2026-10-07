import asyncio
import logging
from typing import Any, Callable, Dict, Optional
from core.decision import ThreatDecisionEngine
from core.incidents import IncidentManager
from core.models import ActionType, Incident, MirrorEvent, PolicyDecision, ThreatLevel

logger = logging.getLogger("mirror.orchestrator")


class MirrorOrchestrator:
    """Coordinates containment, deception, mirror instantiation, and evidence gathering."""

    def __init__(
        self,
        decision_engine: ThreatDecisionEngine,
        incident_manager: IncidentManager,
        isolation_handler: Optional[Callable[[str, ActionType], Any]] = None,
        mirror_handler: Optional[Callable[[str], Any]] = None,
        forensic_handler: Optional[Callable[[MirrorEvent, Incident], Any]] = None,
        traffic_switch_handler: Optional[Callable[[str, Optional[str]], Any]] = None,
    ) -> None:
        self.decision_engine = decision_engine
        self.incident_manager = incident_manager
        self.isolation_handler = isolation_handler
        self.mirror_handler = mirror_handler
        self.forensic_handler = forensic_handler
        self.traffic_switch_handler = traffic_switch_handler

    async def handle_event(self, event: MirrorEvent) -> PolicyDecision:
        """Process an incoming event through decision, incident correlation, and action dispatch."""
        decision = self.decision_engine.decide(event)
        incident = self.incident_manager.process_event(event, decision)

        # Trigger forensic preservation for suspicious/critical events
        if self.forensic_handler and decision.threat in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            try:
                res = self.forensic_handler(event, incident)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as e:
                logger.error("Forensic handler failed: %s", e)

        # Dispatch action
        await self._dispatch_action(event, decision, incident)

        return decision

    async def _dispatch_action(
        self,
        event: MirrorEvent,
        decision: PolicyDecision,
        incident: Incident,
    ) -> None:
        action = decision.action
        asset_id = event.asset_id or "unspecified"

        if action == ActionType.ALLOW:
            logger.debug("Action ALLOW: event permitted without intervention.")

        elif action == ActionType.MONITOR:
            logger.info("Action MONITOR: heightened surveillance on asset '%s'.", asset_id)

        elif action == ActionType.DECOY:
            logger.warning("Action DECOY: deploying deception artifacts for asset '%s'.", asset_id)

        elif action in (ActionType.ISOLATE, ActionType.QUARANTINE, ActionType.EMERGENCY_FREEZE):
            logger.critical(
                "Action %s triggered for asset '%s' [Incident: %s]!",
                action.value.upper(),
                asset_id,
                incident.id,
            )

            # 1. Isolate the real asset
            if self.isolation_handler and event.asset_id:
                try:
                    res = self.isolation_handler(event.asset_id, action)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception as e:
                    logger.error("Isolation handler error: %s", e)

            # 2. Instantiate Clean Mirror
            if self.mirror_handler and event.asset_id:
                try:
                    res = self.mirror_handler(event.asset_id)
                    if asyncio.iscoroutine(res):
                        mirror_id = await res
                        incident.mirror_id = str(mirror_id) if mirror_id else None
                except Exception as e:
                    logger.error("Mirror handler error: %s", e)

            # 3. Divert incoming traffic upstream to the Mirror instance (Zero dropped connections)
            if self.traffic_switch_handler and event.asset_id:
                try:
                    res = self.traffic_switch_handler(event.asset_id, None)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception as e:
                    logger.error("Traffic switch handler error: %s", e)
