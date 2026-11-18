"""The command line, without Elasticsearch."""

import json

from detlab import attack
from detlab.__main__ import main


def test_test_command_passes(capsys):
    assert main(["test"]) == 0
    out = capsys.readouterr().out
    assert "Sigma rules: 37 rules" in out or "Sigma rules:" in out
    assert "problem" not in out


def test_check_command_passes(capsys):
    assert main(["check"]) == 0
    out = capsys.readouterr().out
    assert "Generated files: all current" in out
    assert "ATT&CK tags: all valid" in out


def test_convert_prints_one_query(capsys):
    assert main(["convert", "win_certutil_download"]) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("any where ") and "process.command_line" in out
    assert len(out.splitlines()) == 1


def test_convert_all_labels_each_query(capsys, rules):
    assert main(["convert"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len([line for line in lines if line.startswith("// ")]) == len(rules)


def test_convert_unknown_rule(capsys):
    assert main(["convert", "no_such_rule"]) == 1
    assert "no rule named no_such_rule" in capsys.readouterr().err


def test_siem_commands_explain_a_missing_env_file(capsys, monkeypatch, tmp_path):
    from detlab import siem

    monkeypatch.setattr(siem, "ENV_FILE", tmp_path / ".env")
    assert main(["siem", "load"]) == 2
    assert "Run stack/init.sh first" in capsys.readouterr().err


def test_replay_check(tmp_path, capsys):
    from detlab import pcaps

    good = tmp_path / "good.ndjson"
    lines = []
    for name, (_packets, sids) in pcaps.build().items():
        lines += [json.dumps({"event_type": "alert", "lab_capture": name, "alert": {"signature_id": sid}})
                  for sid in sids]
    good.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main(["replay-check", str(good)]) == 0
    bad = tmp_path / "bad.ndjson"
    bad.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    assert main(["replay-check", str(bad)]) == 1
    assert "expected SIDs" in capsys.readouterr().out


def test_attack_reference_can_be_rebuilt_from_stix(tmp_path, monkeypatch, capsys):
    """A tiny STIX file with the same shape as MITRE's is enough to exercise the extraction."""
    data = attack.reference()
    objects = [{"type": "x-mitre-collection", "x_mitre_version": "99.0"}]
    for name, tactic in data["tactics"].items():
        objects.append({"type": "x-mitre-tactic", "x_mitre_shortname": name, "name": tactic["name"],
                        "external_references": [{"source_name": "mitre-attack", "external_id": tactic["id"]}]})
    for technique, entry in data["techniques"].items():
        objects.append({"type": "attack-pattern", "name": entry["name"],
                        "kill_chain_phases": [{"phase_name": tactic} for tactic in entry["tactics"]],
                        "external_references": [{"source_name": "mitre-attack", "external_id": technique}]})
    objects.append({"type": "attack-pattern", "name": "Gone", "revoked": True, "kill_chain_phases": [],
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1562.001"}]})
    stix = tmp_path / "enterprise-attack.json"
    stix.write_text(json.dumps({"objects": objects}), encoding="utf-8")
    target = tmp_path / "attack.json"
    monkeypatch.setattr(attack, "DATA", target)
    monkeypatch.setattr("detlab.__main__.ROOT", tmp_path)
    assert main(["attack-reference", "--stix", str(stix)]) == 0
    rebuilt = json.loads(target.read_text(encoding="utf-8"))
    assert rebuilt["version"] == "99.0"
    assert rebuilt["techniques"] == data["techniques"]
    assert "T1562.001" not in rebuilt["techniques"]
