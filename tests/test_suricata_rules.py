"""The Suricata rules parse, carry their ATT&CK mapping and fire on their captures."""

import json
import os

import pytest

from detlab import build, pcaps
from detlab.__main__ import suricata_problems
from detlab.suricata import read_eve, replay, sids_by_capture, suricata_available

CAPTURES = {name: sorted(sids) for name, (_packets, sids) in pcaps.build().items()}

needs_suricata = pytest.mark.skipif(
    not suricata_available() and os.environ.get("DETLAB_REQUIRE_SURICATA") != "1",
    reason="the suricata program is not installed")


def test_rules_carry_the_lab_conventions(network_rules):
    assert len(network_rules) >= 10
    for rule in network_rules:
        assert 1000001 <= rule.sid <= 1000099, rule.sid
        assert rule.msg.startswith("DETECTION-LAB "), rule.sid
        assert rule.classtype, rule.sid
        assert rule.technique.startswith("T"), rule.sid


def test_every_rule_has_a_capture_and_every_capture_a_rule(network_rules):
    covered = {sid for sids in CAPTURES.values() for sid in sids}
    assert covered == {rule.sid for rule in network_rules}
    assert CAPTURES["benign_traffic"] == []
    assert all(sids for name, sids in CAPTURES.items() if name != "benign_traffic")


def test_captures_use_only_lab_and_documentation_addresses():
    from scapy.layers.inet import IP

    allowed = ("10.10.20.", "203.0.113.", "198.51.100.")
    for name, (packets, _sids) in pcaps.build().items():
        for packet in packets:
            assert packet[IP].src.startswith(allowed) and packet[IP].dst.startswith(allowed), name


@needs_suricata
@pytest.mark.parametrize("name", sorted(CAPTURES))
def test_capture_raises_exactly_its_rules(name):
    assert suricata_available(), "DETLAB_REQUIRE_SURICATA=1 but suricata is not installed"
    assert replay(build.PCAP_DIR / f"{name}.pcap") == CAPTURES[name]


@needs_suricata
def test_the_whole_rule_file_passes():
    assert suricata_problems() == []


def test_reading_alerts_from_an_eve_file(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text("\n".join(json.dumps(event) for event in [
        {"event_type": "alert", "lab_capture": "one", "alert": {"signature_id": 1000021}},
        {"event_type": "alert", "lab_capture": "one", "alert": {"signature_id": 1000020}},
        {"event_type": "alert", "lab_capture": "one", "alert": {"signature_id": 1000020}},
        {"event_type": "flow", "lab_capture": "one"},
        {"event_type": "alert", "lab_capture": "two", "alert": {"signature_id": 1000085}},
    ]) + "\n\n", encoding="utf-8")
    alerts = read_eve(eve)
    assert len(alerts) == 4
    assert sids_by_capture(alerts) == {"one": [1000020, 1000021], "two": [1000085]}
