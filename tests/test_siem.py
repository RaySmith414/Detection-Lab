"""The Elasticsearch side, tested without a server: mappings, loading and the comparison of hits."""

import json

import pytest

from detlab import samples, siem
from detlab.engine import SqliteEngine


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class FakeElasticsearch:
    """Answers the calls siem.py makes. EQL searches are answered by the SQLite engine."""

    def __init__(self, rules, events, drop=None, extra=None):
        self.calls = []
        self.bulk = {}
        self.by_query = {siem.to_eql(rule): rule for rule in rules}
        self.engine = SqliteEngine(events)
        self.sources = {event["event"]["id"]: event for event in events}
        self.drop = drop
        self.extra = extra or {}

    def call(self, method, path, expect=(200, 201), **kwargs):
        self.calls.append((method, path))
        if path.startswith("/_bulk"):
            lines = [json.loads(line) for line in kwargs["data"].splitlines()]
            for action, document in zip(lines[0::2], lines[1::2], strict=True):
                self.bulk.setdefault(action["index"]["_index"], []).append((action["index"].get("_id"), document))
            return FakeResponse(body={"errors": False, "items": []})
        if path.endswith("/_eql/search"):
            rule = self.by_query[kwargs["json"]["query"]]
            ids = [] if rule.key == self.drop else self.engine.matches(rule)
            ids += self.extra.get(rule.key, [])
            return FakeResponse(body={"hits": {"events": [{"_id": i, "_source": self.sources[i]} for i in ids]}})
        if path.endswith("/_count"):
            return FakeResponse(body={"count": len(self.bulk.get(path.split("/")[1], []))})
        return FakeResponse()


def test_every_field_a_rule_can_query_is_mapped():
    properties = siem._properties()
    assert properties["@timestamp"] == {"type": "date"}
    assert properties["process"]["properties"]["command_line"]["type"] == "keyword"
    assert properties["process"]["properties"]["parent"]["properties"]["executable"]["type"] == "keyword"
    assert properties["winlog"]["properties"]["event_data"]["properties"]["GrantedAccess"]["type"] == "keyword"
    assert properties["host"]["properties"]["os"]["properties"]["type"]["type"] == "keyword"
    assert properties["event"]["properties"]["code"]["type"] == "keyword"


def test_timestamps_are_moved_and_converted():
    from datetime import timedelta

    assert siem._shift("2026-11-10T09:00:37.000Z", timedelta(days=1, seconds=3)) == "2026-11-11T09:00:40.000Z"
    assert siem._suricata_time("2026-11-10T11:40:00.010000+0300") == "2026-11-10T08:40:00.010Z"


def test_load_stores_every_sample_under_its_event_id(rules, events, tmp_path):
    everything = events[0] + events[1]
    es = FakeElasticsearch(rules, everything)
    alerts = tmp_path / "network-alerts.ndjson"
    alerts.write_text(json.dumps({"event_type": "alert", "lab_capture": "dns_tunnel",
                                  "timestamp": "2026-11-10T08:40:00.010000+0000",
                                  "alert": {"signature_id": 9000002}}) + "\n", encoding="utf-8")
    counts = siem.load(es, keep_timestamps=True, network_alerts=alerts)
    assert counts == {siem.EVENTS_INDEX: len(everything), siem.NETWORK_INDEX: 1}
    stored = es.bulk[siem.EVENTS_INDEX]
    assert [doc_id for doc_id, _ in stored] == [event["event"]["id"] for event in everything]
    assert stored[0][1]["@timestamp"] == everything[0]["@timestamp"]
    assert es.bulk[siem.NETWORK_INDEX][0][1]["@timestamp"] == "2026-11-10T08:40:00.010Z"
    for index in (siem.EVENTS_INDEX, siem.ALERTS_INDEX, siem.NETWORK_INDEX):
        assert ("PUT", f"/{index}") in es.calls


def test_load_moves_the_samples_to_the_present_by_default(rules, events, tmp_path):
    from datetime import datetime, timezone

    everything = events[0] + events[1]
    es = FakeElasticsearch(rules, everything)
    siem.load(es, network_alerts=tmp_path / "none.ndjson")
    stamps = sorted(document["@timestamp"] for _, document in es.bulk[siem.EVENTS_INDEX])
    newest = datetime.strptime(stamps[-1], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - newest).total_seconds()
    assert 240 <= age <= 420
    assert siem.NETWORK_INDEX not in es.bulk


def test_detect_reports_nothing_when_every_rule_behaves(rules, events):
    everything = events[0] + events[1]
    es = FakeElasticsearch(rules, everything)
    assert siem.detect(es, rules) == []
    alerts = [document for _, document in es.bulk[siem.ALERTS_INDEX]]
    assert len(alerts) == len(events[0])
    assert siem.count(es, siem.ALERTS_INDEX) == len(events[0])
    first = alerts[0]
    assert first["event"]["kind"] == "alert"
    assert first["rule"]["ruleset"] == "detection-lab"
    assert first["threat"]["technique"]["id"] and first["threat"]["tactic"]["name"]
    assert first["labels"]["lab_case"] == "attack"


def test_detect_reports_a_rule_that_stays_quiet_and_one_that_fires_too_often(rules, events):
    everything = events[0] + events[1]
    es = FakeElasticsearch(rules, everything, drop="win_certutil_download",
                           extra={"win_certutil_decode": ["background-1"]})
    problems = siem.detect(es, rules)
    assert "missed: win_certutil_download did not fire on win_certutil_download-attack-1" in problems
    assert "false positive: win_certutil_decode fired on background-1" in problems
    assert len(problems) == 2


def test_client_reports_an_unexpected_status(monkeypatch):
    client = siem.Client("http://127.0.0.1:9200", "secret")
    monkeypatch.setattr(client.session, "request",
                        lambda method, url, timeout, **kwargs: FakeResponse(401, {"error": "nope"}))
    with pytest.raises(siem.SiemError, match="GET /_cluster/health answered HTTP 401"):
        client.call("GET", "/_cluster/health")


def test_a_failed_bulk_load_is_reported():
    class Refusing(FakeElasticsearch):
        def call(self, method, path, expect=(200, 201), **kwargs):
            if path.startswith("/_bulk"):
                return FakeResponse(body={"errors": True, "items": [{"index": {"error": {"type": "mapper"}}}]})
            return super().call(method, path, expect, **kwargs)

    with pytest.raises(siem.SiemError, match="bulk load into detlab-events failed"):
        siem._bulk(Refusing([], []), siem.EVENTS_INDEX, [{"a": 1}])


def test_missing_env_file_is_explained(tmp_path):
    with pytest.raises(siem.SiemError, match="Run stack/init.sh first"):
        siem.read_env(tmp_path / ".env")


def test_env_file_is_parsed(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# comment\nELASTIC_PASSWORD=abc\n\nKIBANA_PASSWORD = def\n", encoding="utf-8")
    assert siem.read_env(env) == {"ELASTIC_PASSWORD": "abc", "KIBANA_PASSWORD": "def"}


def test_kibana_data_views_cover_every_index():
    assert set(siem.DATA_VIEWS) == {siem.EVENTS_INDEX, siem.ALERTS_INDEX, siem.NETWORK_INDEX}


def test_expected_hits_come_from_the_labels(events):
    wanted = samples.expected(events[0] + events[1])
    assert wanted["win_certutil_download-attack-1"] == ["win_certutil_download"]
    assert wanted["win_certutil_download-benign-1"] == []
    assert wanted["background-1"] == []
