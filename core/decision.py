import logging
from typing import Optional
from core.assets import AssetRegistry
from core.models import MirrorEvent, PolicyDecision
from core.policies import PolicyEngine
from core.threat_engine import CumulativeThreatScorer

logger = logging.getLogger("mirror.decision")


class ThreatDecisionEngine:
    """Combines telemetry events, asset knowledge, and policies into decisive actions."""

    def __init__(
        self,
        asset_registry: AssetRegistry,
        policy_engine: PolicyEngine,
        threat_scorer: Optional[CumulativeThreatScorer] = None,
    ) -> None:
        self.asset_registry = asset_registry
        self.policy_engine = policy_engine
        self.threat_scorer = threat_scorer or CumulativeThreatScorer()

    def decide(self, event: MirrorEvent) -> PolicyDecision:
        """Resolve the target asset, evaluate policies, and decide on action."""
        asset = None
        if event.asset_id:
            asset = self.asset_registry.get(event.asset_id)
        elif event.container_id:
            asset = self.asset_registry.find_by_container_name(event.container_id)

        initial_decision = self.policy_engine.evaluate(event, asset)
        decision = self.threat_scorer.record_and_evaluate(event, initial_decision)

        logger.info(
            "Event %s [%s] -> Asset: %s | Threat: %s | Action: %s (%s)",
            event.id,
            event.event_type,
            asset.id if asset else "unknown",
            decision.threat.value.upper(),
            decision.action.value.upper(),
            decision.reason,
        )

        return decision
