"""Rule tags are checked against MITRE ATT&CK data stored in the repository."""

from detlab import attack
from detlab.__main__ import tag_problems


def test_reference_data_is_complete():
    data = attack.reference()
    assert data["version"]
    assert list(data["tactics"]) == attack.TACTIC_ORDER
    for tactic in data["tactics"].values():
        assert tactic["id"].startswith("TA") and tactic["name"]
    for technique, entry in data["techniques"].items():
        assert entry["name"], technique
        assert set(entry["tactics"]) <= set(data["tactics"]), technique


def test_every_rule_tag_is_valid(rules, network_rules):
    assert rules and network_rules
    assert tag_problems() == []


def test_every_sigma_rule_names_a_tactic_and_a_technique(rules):
    for rule in rules:
        assert rule.tactics, rule.key
        assert rule.techniques, rule.key
        assert rule.unknown_attack_tags == [], rule.key


def test_a_technique_under_the_wrong_tactic_is_reported():
    problems = attack.problems("demo", ["discovery"], ["T1105"])
    assert any("T1105 belongs to" in problem for problem in problems)


def test_an_unknown_technique_is_reported():
    problems = attack.problems("demo", ["execution"], ["T9999"])
    assert any("T9999 is not an active technique" in problem for problem in problems)


def test_a_tactic_without_a_technique_is_reported():
    problems = attack.problems("demo", ["execution", "impact"], ["T1059.001"])
    assert problems == ["demo: tactic impact has no technique of that tactic in the rule"]


def test_missing_tags_are_reported():
    assert attack.problems("demo", [], []) == ["demo: no tactic", "demo: no technique"]


def test_tactic_lookup_by_id():
    assert attack.tactic_by_id("TA0011") == "command-and-control"
