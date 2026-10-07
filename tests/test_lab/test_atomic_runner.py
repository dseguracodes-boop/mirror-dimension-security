from lab.runners.atomic_runner import AtomicRedTeamRunner


def test_atomic_red_team_runner_loads_cloned_repo():
    runner = AtomicRedTeamRunner()
    techniques = runner.list_techniques()
    
    # Techniques must be present
    assert len(techniques) >= 1
    assert "T1552.001" in techniques

    # Load T1552.001
    tech_data = runner.load_technique("T1552.001")
    assert tech_data is not None
    assert tech_data["attack_technique"] == "T1552.001"
    assert "Credentials In Files" in tech_data["display_name"]

    # Transform into MirrorEvent
    event = runner.create_event_from_technique("T1552.001", test_index=0, asset_id="secrets")
    assert event is not None
    assert event.event_type == "canary_trigger"
    assert event.attack_stage == "credential_access"
    assert event.confidence >= 0.90
    assert event.evidence["technique_id"] == "T1552.001"
