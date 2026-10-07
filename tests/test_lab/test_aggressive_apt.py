import pytest
from core.engine import MirrorEngine
from lab.scenarios.aggressive_apt import AggressiveAPTScenario


@pytest.mark.asyncio
async def test_aggressive_apt_scenario_execution(tmp_path):
    engine = MirrorEngine()
    scenario = AggressiveAPTScenario(engine)
    
    events = scenario.build_kill_chain_events()
    assert len(events) == 5
    
    # Execute full attack burst
    results = await scenario.execute()
    assert len(results) == 5
    
    # Check that high/critical threat decisions and actions were taken
    for title, ev, decision in results:
        assert decision.action is not None
        assert decision.threat is not None
    
    # Check that incidents were created and tracked
    incidents = engine.incidents.list_all()
    assert len(incidents) >= 1
    
    # Check that evidence vault was populated for critical events
    assert engine.forensics.vault_dir.exists()
