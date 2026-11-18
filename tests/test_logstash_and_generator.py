"""The Logstash pipeline is generated from the field mapping. The log generator behaves."""

import json
import os
import subprocess
import sys

from detlab import logstash, siem
from detlab.fields import AUTH_LOG_FIELDS, FIELD_MAP
from detlab.rules import ROOT

GENERATOR = ROOT / "log-generator" / "generator.py"


def _generate(target, seed=3, rounds=60):
    env = dict(os.environ, LOG_DIR=str(target), LOG_GENERATOR_SEED=str(seed), LOG_GENERATOR_ROUNDS=str(rounds))
    done = subprocess.run([sys.executable, str(GENERATOR)], env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return {name: (target / name).read_text(encoding="utf-8").splitlines()
            for name in ("windows/sysmon.json", "windows/events.json", "linux/auth.log", "network/firewall.log")}


def test_pipeline_renames_every_mapped_field():
    text = logstash.pipeline()
    for sigma, ecs in FIELD_MAP.items():
        target = "".join(f"[{part}]" for part in ecs.split("."))
        if sigma == "EventID":
            assert '"[event][code]" => "%{EventID}"' in text
        elif sigma in AUTH_LOG_FIELDS:
            # grok parses auth log lines straight into the ECS field. Nothing is renamed.
            assert f'"{sigma}" => "[' not in text
            assert target == "[message]" or f":{target}}}" in text, sigma
        else:
            assert f'"{sigma}" => "{target}"' in text, sigma


def test_pipeline_writes_to_the_live_index_with_the_generated_password():
    text = logstash.pipeline()
    assert f'index => "{siem.LIVE_INDEX}"' in text
    assert 'password => "${ELASTIC_PASSWORD}"' in text
    assert 'document_id => "%{[event][id]}"' in text
    assert text.count("{") == text.count("}")


def test_index_template_covers_every_lab_index():
    template = json.loads(logstash.index_template(siem.index_body()))
    assert template["index_patterns"] == ["detlab-*"]
    for index in (siem.EVENTS_INDEX, siem.SCENARIO_INDEX, siem.ALERTS_INDEX, siem.NETWORK_INDEX, siem.LIVE_INDEX,
                  siem.LIVE_ALERTS_INDEX):
        assert index.startswith("detlab-")
    properties = template["template"]["mappings"]["properties"]
    assert properties["process"]["properties"]["command_line"]["type"] == "keyword"
    assert properties["winlog"]["properties"]["channel"]["type"] == "keyword"


def test_a_bounded_run_writes_all_four_logs_and_stops(tmp_path):
    logs = _generate(tmp_path)
    assert all(logs.values())
    sysmon = [json.loads(line) for line in logs["windows/sysmon.json"]]
    assert {"EventID", "UtcTime", "Computer", "Channel", "Provider"} <= set(sysmon[0])
    security = [json.loads(line) for line in logs["windows/events.json"]]
    assert {event["Channel"] for event in security} <= {"Security", "System"}


def test_the_same_seed_gives_the_same_events(tmp_path):
    first = _generate(tmp_path / "one")
    second = _generate(tmp_path / "two")
    other = _generate(tmp_path / "three", seed=4)

    def shape(logs):
        return [(event["EventID"], event.get("Image"), event.get("CommandLine"))
                for event in map(json.loads, logs["windows/sysmon.json"])]

    assert shape(first) == shape(second)
    assert shape(first) != shape(other)


def test_generated_lines_have_the_shape_logstash_expects(tmp_path):
    import re

    logs = _generate(tmp_path)
    auth = re.compile(r"^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ [\w-]+(\[\d+\])?: .+$")
    firewall = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+ (ALLOW|BLOCK) (TCP|UDP) [\d.]+:\d+ -> [\d.]+:\d+$")
    assert all(auth.match(line) for line in logs["linux/auth.log"])
    assert all(firewall.match(line) for line in logs["network/firewall.log"])


def test_outside_addresses_and_names_are_reserved_for_documentation(tmp_path):
    logs = _generate(tmp_path, rounds=200)
    private = ("192.168.", "10.", "172.16.")
    reserved = ("203.0.113.", "198.51.100.", "192.0.2.")
    for line in logs["network/firewall.log"]:
        source = line.split()[3]
        assert source.startswith(private + reserved), line
    for event in map(json.loads, logs["windows/sysmon.json"]):
        name = event.get("QueryName", "")
        if "." in name and not name.endswith((".com", ".local")):
            assert name.endswith((".example.com", ".example.net", ".example.org")), name
        address = event.get("DestinationIp", "")
        assert not address or address.startswith(private + reserved), address
    text = "\n".join("\n".join(lines) for lines in logs.values())
    assert "evil.com" not in text
