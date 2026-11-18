"""Auth log lines: the Python patterns that mirror the pipeline's grok patterns. Also the rules on generator output."""

import os
import signal
import subprocess
import sys
import time
from datetime import datetime

import pytest

from detlab import authlog, logstash, siem
from detlab.__main__ import main
from detlab.rules import ROOT
from tests.test_siem import FakeElasticsearch, FakeResponse

GENERATOR = ROOT / "log-generator" / "generator.py"
NOW = datetime(2026, 11, 18, 12, 0, 0)
# The bounded run CI plays through Logstash (.github/workflows/ci.yml)
CI_SEED, CI_ROUNDS = 3, 200


def _generate(target, seed=CI_SEED, rounds=CI_ROUNDS):
    env = dict(os.environ, LOG_DIR=str(target), LOG_GENERATOR_SEED=str(seed), LOG_GENERATOR_ROUNDS=str(rounds))
    done = subprocess.run([sys.executable, str(GENERATOR)], env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return target / "linux" / "auth.log"


def test_a_failed_password_line():
    line = "Nov 10 09:00:07 web-01 sshd[4242]: Failed password for invalid user admin from 203.0.113.77 port 50022 ssh2"
    assert authlog.parse(line, NOW) == {
        "@timestamp": "2026-11-10T09:00:07.000Z",
        "event": {"kind": "event", "dataset": "system.auth"},
        "host": {"name": "web-01", "os": {"type": "linux"}},
        "process": {"name": "sshd", "pid": "4242"},
        "source": {"ip": "203.0.113.77"},
        "user": {"name": "admin"},
        "message": line,
    }


def test_a_sudo_line_has_no_process_id_and_no_source_address():
    line = "Nov  5 23:59:59 db01 sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
    document = authlog.parse(line, NOW)
    assert document["@timestamp"] == "2026-11-05T23:59:59.000Z"
    assert document["process"] == {"name": "sudo"}
    assert "source" not in document and "user" not in document


@pytest.mark.parametrize(("text", "user"), [
    ("Accepted publickey for deploy from 10.0.0.5 port 50000 ssh2", "deploy"),
    ("Failed password for root from 10.0.0.5 port 50000 ssh2", "root"),
    ("Invalid user test from 10.0.0.5 port 50000", "test"),
    ("pam_unix(sshd:session): session opened for user deploy by (uid=0)", None),
    ("Failed password for invalid user svc_backup from 10.0.0.5 port 50000 ssh2", "svc_backup"),
    # USERNAME, the grok pattern, has no dollar sign. Logstash leaves the name out for such a line.
    ("Failed password for invalid user ad$min from 10.0.0.5 port 50000 ssh2", None),
])
def test_the_user_name_is_read_like_grok_reads_it(text, user):
    document = authlog.parse(f"Nov 10 09:00:00 srv001 sshd[1000]: {text}", NOW)
    assert document.get("user", {}).get("name") == user


def test_an_address_needs_four_valid_octets():
    def source(text):
        return authlog.parse(f"Nov 10 09:00:00 srv001 sshd[1000]: {text}", NOW).get("source", {}).get("ip")

    assert source("Failed password for root from 192.0.2.7 port 50000 ssh2") == "192.0.2.7"
    assert source("Failed password for root from 999.0.2.7 port 50000 ssh2") is None
    assert source("Failed password for root from gateway port 50000 ssh2") is None


def test_the_year_is_guessed_like_logstash_guesses_it():
    december = authlog.parse("Dec 31 23:59:58 srv001 sshd[1000]: x", datetime(2027, 1, 1, 0, 0, 5))
    january = authlog.parse("Jan  1 00:00:02 srv001 sshd[1000]: x", datetime(2026, 12, 31, 23, 59, 59))
    assert december["@timestamp"] == "2026-12-31T23:59:58.000Z"
    assert january["@timestamp"] == "2027-01-01T00:00:02.000Z"


def test_other_text_is_not_an_auth_log_line(tmp_path):
    assert authlog.parse("2026-11-10T09:00:00 BLOCK TCP 10.0.0.1:1 -> 10.0.0.2:2", NOW) is None
    path = tmp_path / "auth.log"
    path.write_text("Nov 10 09:00:00 srv001 sshd[1000]: ok\nnot a log line\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 2 is not an auth log line"):
        authlog.read(path, NOW)


def test_a_repeated_line_is_one_document(tmp_path):
    path = tmp_path / "auth.log"
    line = "Nov 10 09:00:00 srv001 sshd[1000]: Failed password for root from 192.0.2.7 port 50000 ssh2"
    path.write_text(f"{line}\n{line}\n{line.replace('50000', '50001')}\n", encoding="utf-8")
    documents = authlog.read(path, NOW)
    assert [document["event"]["id"] for document in documents] == ["auth-00001", "auth-00002"]


def test_the_pipeline_uses_the_grok_patterns_kept_next_to_the_python_patterns():
    text = logstash.pipeline()
    for pattern in (authlog.GROK_LINE, authlog.GROK_SOURCE, authlog.GROK_USER):
        assert f'"message" => "{pattern}"' in text
    assert f'"[event][dataset]" => "{authlog.DATASET}"' in text


def test_every_generated_auth_line_parses(tmp_path):
    path = _generate(tmp_path)
    documents = authlog.read(path)
    assert len(documents) == len(set(path.read_text(encoding="utf-8").splitlines()))
    assert {document["process"]["name"] for document in documents} == {"sshd", "sudo", "login"}


def test_the_run_ci_plays_holds_what_both_auth_log_rules_look_for(rules, tmp_path):
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert f"LOG_GENERATOR_SEED={CI_SEED} LOG_GENERATOR_ROUNDS={CI_ROUNDS}" in workflow
    hits, groups = siem.auth_log_expectation(rules, _generate(tmp_path))
    assert hits["lnx_sudo_suspicious_command"] >= 1
    assert len(groups["lnx_ssh_failed_login_burst"]) >= 1
    assert set(hits) | set(groups) == {"lnx_sudo_suspicious_command", "lnx_ssh_failed_login_burst"}


def test_a_brute_force_comes_from_one_address(tmp_path):
    import collections
    import json

    path = _generate(tmp_path)
    ssh = collections.Counter(document["source"]["ip"] for document in authlog.read(path)
                              if "Failed password for" in document["message"])
    assert max(ssh.values()) >= 10
    windows = collections.Counter(event["IpAddress"] for event in map(
        json.loads, (tmp_path / "windows" / "events.json").read_text(encoding="utf-8").splitlines())
        if event["EventID"] == 4625)
    assert max(windows.values()) >= 10
    assert max(ssh, key=ssh.get).startswith(("203.0.113.", "198.51.100.", "192.0.2."))


@pytest.mark.parametrize("script", ["log-generator/generator.py", "attack-simulator/simulator.py"])
def test_the_generators_stop_at_once_on_sigterm(script, tmp_path):
    env = dict(os.environ, LOG_DIR=str(tmp_path))
    process = subprocess.Popen([sys.executable, "-u", str(ROOT / script)], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline()     # it has started and installed its handler
        time.sleep(0.5)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
    finally:
        process.kill()
        process.communicate()


class LiveElasticsearch(FakeElasticsearch):
    """The fake with an auth log in the live index, the way Logstash would have stored it."""

    def __init__(self, rules, documents, **kwargs):
        super().__init__(rules, [], **kwargs)
        self.events[siem.LIVE_INDEX] = documents

    def call(self, method, path, expect=(200, 201), **kwargs):
        if path == f"/{siem.LIVE_INDEX}/_search":
            total = len(self.events[siem.LIVE_INDEX])
            return FakeResponse(body={"hits": {"total": {"value": total}}, "aggregations": {
                "datasets": {"buckets": [{"key": authlog.DATASET, "doc_count": total}]},
                "failures": {"doc_count": 0}}})
        return super().call(method, path, expect, **kwargs)


def _hunt(rules, path, monkeypatch, capsys, **kwargs):
    fake = LiveElasticsearch(rules, authlog.read(path), **kwargs)
    monkeypatch.setattr(siem, "read_env", dict)
    monkeypatch.setattr(siem, "elasticsearch", lambda env=None: fake)
    code = main(["siem", "hunt", "--expect-auth-log", str(path)])
    return code, capsys.readouterr()


def test_hunt_accepts_an_auth_log_whose_hits_match(rules, tmp_path, monkeypatch, capsys):
    code, output = _hunt(rules, _generate(tmp_path), monkeypatch, capsys)
    assert code == 0, output.out + output.err
    assert "Auth log through Logstash: the same" in output.out
    assert "alert  lnx_ssh_failed_login_burst for " in output.out


def test_hunt_reports_an_auth_log_rule_that_stays_quiet(rules, tmp_path, monkeypatch, capsys):
    code, output = _hunt(rules, _generate(tmp_path), monkeypatch, capsys, drop="lnx_sudo_suspicious_command")
    assert code == 1
    assert "lnx_sudo_suspicious_command: 0 hit(s) on the live events, 1 in the test engine" in output.out + output.err


def test_hunt_reports_a_burst_alert_elasticsearch_did_not_raise(rules, tmp_path, monkeypatch, capsys):
    code, output = _hunt(rules, _generate(tmp_path), monkeypatch, capsys, drop="lnx_ssh_failed_login_burst")
    assert code == 1
    assert "missed: lnx_ssh_failed_login_burst raised no alert for" in output.out + output.err
