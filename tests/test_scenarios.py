"""The attack simulator and what the rules make of its scenarios."""

import json
import os
import subprocess
import sys

from detlab import scenarios
from detlab.fields import FIELD_MAP


def test_the_simulator_gives_the_same_events_for_the_same_seed():
    first = scenarios.run_simulator()
    assert first == scenarios.run_simulator()
    assert first != scenarios.run_simulator(seed=scenarios.SEED + 1)
    assert {event["scenario"] for event in first} == set(scenarios.ORDER)


def test_fast_mode_keeps_the_pacing_in_the_timestamps():
    events = [event for event in scenarios.run_simulator() if event["scenario"] == "brute_force"]
    assert events[0]["timestamp"] == scenarios.START + ".000Z"
    stamps = [event["timestamp"] for event in events]
    assert stamps == sorted(stamps) and len(set(stamps)) > len(stamps) // 2


def test_the_simulator_writes_json_lines_to_the_log_folder(tmp_path):
    env = dict(os.environ, LOG_DIR=str(tmp_path), SIMULATOR_SEED="1", SIMULATOR_FAST="1")
    done = subprocess.run([sys.executable, str(scenarios.SIMULATOR), "persistence"], env=env, capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    files = list((tmp_path / "windows").glob("attack_persistence_*.json"))
    assert len(files) == 1
    events = [json.loads(line) for line in files[0].read_text(encoding="utf-8").splitlines()]
    assert events and all(event["scenario"] == "persistence" and event["EventID"] for event in events)


def test_attacker_addresses_and_names_are_reserved_for_documentation():
    for event in scenarios.run_simulator():
        for field in ("IpAddress", "DestinationIp"):
            address = event.get(field, "")
            assert not address or address.startswith(("192.168.", "203.0.113.", "198.51.100.", "192.0.2.")), address
        for field in ("DestinationHostname", "QueryName"):
            name = event.get(field, "")
            assert not name or name.endswith((".example.com", ".example.net", ".example.org")), name


def test_events_become_the_documents_the_rules_query():
    raw = {"timestamp": "2026-11-10T10:00:00.000Z", "scenario": "persistence", "mitre_tactics": [],
           "event_type": "sysmon", "event_id": "x", "EventID": 13, "EventName": "Registry Value Set",
           "Image": "C:\\Windows\\System32\\reg.exe", "TargetObject": "HKLM\\Run\\X", "Details": "C:\\a.exe",
           "Computer": "WS045", "EventType": "SetValue"}
    document = scenarios.to_ecs(raw, 3)
    assert document["event"] == {"id": "persistence-003", "code": "13", "kind": "event",
                                 "provider": "Microsoft-Windows-Sysmon", "category": "registry",
                                 "action": "Registry Value Set", "dataset": "detection-lab.attack-simulator"}
    assert document["process"]["executable"] == raw["Image"]
    assert document["registry"] == {"path": "HKLM\\Run\\X", "data": {"strings": "C:\\a.exe"}}
    assert document["winlog"] == {"channel": "Microsoft-Windows-Sysmon/Operational",
                                  "event_data": {"EventType": "SetValue"}}
    assert document["host"]["name"] == "WS045"


def test_security_and_system_events_keep_their_log():
    base = {"timestamp": "2026-11-10T10:00:00.000Z", "scenario": "lateral_movement", "mitre_tactics": [],
            "event_type": "windows_security", "event_id": "x", "EventName": "x", "Computer": "SRV001"}
    installed = scenarios.to_ecs(dict(base, EventID=7045, ServiceName="PSEXESVC"), 1)
    assert installed["winlog"]["channel"] == "System"
    assert installed["event"]["provider"] == "Service Control Manager"
    assert installed["winlog"]["event_data"]["ServiceName"] == "PSEXESVC"
    privileges = scenarios.to_ecs(dict(base, EventID=4672, PrivilegeList=["SeDebugPrivilege", "SeBackupPrivilege"]), 2)
    assert privileges["winlog"]["channel"] == "Security"
    assert privileges["winlog"]["event_data"]["PrivilegeList"] == "SeDebugPrivilege, SeBackupPrivilege"


def test_every_simulator_field_a_rule_uses_is_mapped():
    used = {name for event in scenarios.run_simulator() for name in event} - scenarios.ENVELOPE
    assert {"Image", "CommandLine", "TargetObject", "QueryName", "DestinationIp"} <= used & set(FIELD_MAP)


def test_the_rules_fire_on_the_scenarios_as_recorded(rules):
    documents = scenarios.build()
    assert scenarios.problems(rules, documents) == []
    found = scenarios.fired(rules, documents)
    assert all(found[name] for name in scenarios.ORDER), "every scenario is detected by at least one rule"


def test_a_rule_that_stops_firing_in_a_scenario_is_reported(rules):
    documents = scenarios.build()
    without = [rule for rule in rules if rule.key != "win_wmi_event_subscription"]
    assert scenarios.problems(without, documents) == [
        "missed: win_wmi_event_subscription no longer fires in the persistence scenario"]


def test_the_report_lists_undetected_steps_too(rules):
    text = scenarios.report(rules, scenarios.build())
    assert "not detected" in text
    assert "## Brute force" in text and "`win_failed_logon_burst`" in text
    assert "and 99 more like it" in text
