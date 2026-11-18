"""Run the lab's detections in Elasticsearch.

`load` creates the indices and stores the sample events (and the Suricata
alerts, when stack/replay-pcaps.sh has produced them). `detect` runs every
Sigma rule as an EQL query, compares the hits with what the samples expect and
stores one alert document per hit. `setup_kibana` creates the data views.

The connection settings come from stack/.env, which stack/init.sh writes.
"""

import json
import time
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from detlab import attack, authlog, exercises, samples, scenarios
from detlab.convert import TIEBREAKER, to_eql
from detlab.engine import match_matrix, threshold_alerts
from detlab.fields import queried_fields
from detlab.logstash import LIVE_INDEX as LIVE_EVENTS_INDEX
from detlab.rules import ROOT, LabRule
from detlab.suricata import read_eve

STACK = ROOT / "stack"
ENV_FILE = STACK / ".env"
NETWORK_ALERTS_FILE = STACK / "output" / "network-alerts.ndjson"
DASHBOARD = STACK / "kibana" / "detection-lab-dashboard.ndjson"
EVENTS_INDEX = "detlab-events"
ALERTS_INDEX = "detlab-alerts"
NETWORK_INDEX = "detlab-network-alerts"
SCENARIO_INDEX = "detlab-scenario-events"
LIVE_INDEX = LIVE_EVENTS_INDEX
LIVE_ALERTS_INDEX = "detlab-live-alerts"
DATA_VIEWS = {
    EVENTS_INDEX: "Detection Lab: sample events",
    SCENARIO_INDEX: "Detection Lab: attack simulator scenarios",
    LIVE_INDEX: "Detection Lab: live events from Logstash",
    LIVE_ALERTS_INDEX: "Detection Lab: alerts on live events",
    ALERTS_INDEX: "Detection Lab: alerts from the Sigma rules",
    NETWORK_INDEX: "Detection Lab: Suricata alerts",
}
TIMEOUT = 60


class SiemError(RuntimeError):
    pass


def read_env(path: Path | None = None) -> dict[str, str]:
    path = path or ENV_FILE
    if not path.exists():
        raise SiemError(f"{path} not found. Run stack/init.sh first.")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


class Client:
    """A small HTTP client for one service that uses the elastic user."""

    def __init__(self, url: str, password: str, user: str = "elastic"):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (user, password)

    def call(self, method: str, path: str, expect: Iterable[int] = (200, 201), **kwargs: Any) -> requests.Response:
        response = self.session.request(method, self.url + path, timeout=TIMEOUT, **kwargs)
        if response.status_code not in expect:
            body = " ".join(response.text.split())[:400]
            raise SiemError(f"{method} {path} answered HTTP {response.status_code}: {body}")
        return response

    def wait(self, path: str, seconds: int = 300) -> None:
        deadline = time.time() + seconds
        while True:
            try:
                if self.session.get(self.url + path, timeout=10).status_code == 200:
                    return
            except requests.RequestException:
                pass
            if time.time() > deadline:
                raise SiemError(f"{self.url}{path} did not answer within {seconds} seconds")
            time.sleep(5)


def elasticsearch(env: dict[str, str] | None = None) -> Client:
    env = env or read_env()
    return Client(env.get("ELASTICSEARCH_URL", "http://127.0.0.1:9200"), env["ELASTIC_PASSWORD"])


def kibana(env: dict[str, str] | None = None) -> Client:
    env = env or read_env()
    return Client(env.get("KIBANA_URL", "http://127.0.0.1:5601"), env["ELASTIC_PASSWORD"])


def _properties() -> dict[str, Any]:
    """Keyword mappings for every field a rule can query, so a query never meets an unknown field."""
    names = queried_fields() | {"event.id", "event.category", "labels.lab_case", "labels.lab_rule",
                                "labels.lab_scenario"}
    tree: dict[str, Any] = {"@timestamp": {"type": "date"}}
    for name in sorted(names):
        node = tree
        parts = name.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {"properties": {}})["properties"]
        node[parts[-1]] = {"type": "keyword", "ignore_above": 8191}
    return tree


def index_body() -> dict[str, Any]:
    """Settings and mappings of every lab index: one shard, text as keywords, every queried field present."""
    mappings: dict[str, Any] = {
        "dynamic_templates": [{"strings_as_keywords": {
            "match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 8191}}}],
        "properties": _properties()}
    return {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": mappings}


def _recreate(es: Client, index: str, body: dict[str, Any]) -> None:
    es.call("DELETE", f"/{index}", expect=(200, 404))
    es.call("PUT", f"/{index}", json=body)


def _bulk(es: Client, index: str, documents: list[dict[str, Any]], id_of=None) -> None:
    if not documents:
        return
    lines = []
    for document in documents:
        action: dict[str, Any] = {"index": {"_index": index}}
        if id_of:
            action["index"]["_id"] = id_of(document)
        lines.append(json.dumps(action))
        lines.append(json.dumps(document))
    response = es.call("POST", "/_bulk?refresh=true", data="\n".join(lines) + "\n",
                       headers={"Content-Type": "application/x-ndjson"})
    answer = response.json()
    if answer.get("errors"):
        first = next(item for item in answer["items"] if "error" in next(iter(item.values())))
        raise SiemError(f"bulk load into {index} failed: {json.dumps(first)[:400]}")


def _shift(stamp: str, delta: timedelta) -> str:
    moved = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc) + delta
    return moved.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moved.microsecond // 1000:03d}Z"


def _suricata_time(stamp: str) -> str:
    """2026-11-10T08:00:00.010000+0000 -> 2026-11-10T08:00:00.010Z"""
    moment = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def load(es: Client, keep_timestamps: bool = False, network_alerts: Path = NETWORK_ALERTS_FILE) -> dict[str, int]:
    """Create the indices and store the samples. Returns the document count per index."""
    attack_events, benign_events = samples.build()
    events = attack_events + benign_events
    alerts = []
    if network_alerts.exists():
        for alert in read_eve(network_alerts):
            alert["@timestamp"] = _suricata_time(alert["timestamp"])
            alerts.append(alert)

    scenario_events = scenarios.build()
    if not keep_timestamps:
        # Move everything so the newest document is five minutes old and shows up in Kibana's default view.
        everything = events + alerts + scenario_events
        newest = max(document["@timestamp"] for document in everything)
        target = datetime.now(timezone.utc) - timedelta(minutes=5)
        delta = target - datetime.strptime(newest, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        for document in everything:
            document["@timestamp"] = _shift(document["@timestamp"], delta)

    _recreate(es, EVENTS_INDEX, index_body())
    _recreate(es, SCENARIO_INDEX, index_body())
    _bulk(es, SCENARIO_INDEX, scenario_events, id_of=lambda event: event["event"]["id"])
    _recreate(es, ALERTS_INDEX, index_body())
    _recreate(es, NETWORK_INDEX, index_body())
    _bulk(es, EVENTS_INDEX, events, id_of=lambda event: event["event"]["id"])
    _bulk(es, NETWORK_INDEX, alerts)
    return {EVENTS_INDEX: len(events), SCENARIO_INDEX: len(scenario_events), NETWORK_INDEX: len(alerts)}


def run_rule(es: Client, rule: LabRule, index: str = EVENTS_INDEX) -> list[dict[str, Any]]:
    """The events in Elasticsearch that a single-event rule's EQL query matches."""
    response = es.call("POST", f"/{index}/_eql/search", json={"query": to_eql(rule), "size": 1000})
    return response.json()["hits"].get("events") or []


def run_threshold(es: Client, rule: LabRule, index: str = EVENTS_INDEX) -> list[dict[str, Any]]:
    """The sequences a threshold rule's EQL query finds. Each has the group values and the events counted."""
    response = es.call("POST", f"/{index}/_eql/search",
                       json={"query": to_eql(rule), "size": 1000, "tiebreaker_field": TIEBREAKER})
    return response.json()["hits"].get("sequences") or []


def _groups(sequences: list[dict[str, Any]]) -> list[tuple[str, ...]]:
    return sorted({tuple(str(key).lower() for key in sequence["join_keys"]) for sequence in sequences})


def _alert(rule: LabRule, source: dict[str, Any]) -> dict[str, Any]:
    """The alert document for one rule hit. `source` is the event. For a threshold rule it is the last one counted."""
    data = attack.reference()
    alert = {
        "@timestamp": source["@timestamp"],
        "event": {"kind": "alert", "id": source["event"]["id"], "dataset": "detection-lab.sigma"},
        "rule": {"name": rule.title, "uuid": str(rule.rule.id), "id": rule.key, "ruleset": "detection-lab",
                 "reference": rule.relative_path},
        "labels": {"severity": rule.level, "lab_case": source.get("labels", {}).get("lab_case", "")},
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": [data["tactics"][name]["id"] for name in rule.tactics],
                       "name": [data["tactics"][name]["name"] for name in rule.tactics]},
            "technique": {"id": rule.techniques,
                          "name": [data["techniques"][technique]["name"] for technique in rule.techniques]},
        },
        "host": source.get("host", {}),
    }
    for field in ("user", "process", "file", "registry", "dns", "destination"):
        if field in source:
            alert[field] = source[field]
    return alert


def detect(es: Client, rules: list[LabRule]) -> list[str]:
    """Run every rule on the samples, store the alerts and return the differences from the expected hits."""
    attack_events, benign_events = samples.build()
    wanted = samples.expected(attack_events + benign_events)
    actual: dict[str, list[str]] = {event_id: [] for event_id in wanted}
    groups: dict[str, list[tuple[str, ...]]] = {}
    alerts = []
    for rule in rules:
        if rule.is_threshold:
            sequences = run_threshold(es, rule)
            groups[rule.key] = _groups(sequences)
            for sequence in sequences:
                alert = _alert(rule, sequence["events"][-1]["_source"])
                alert["labels"]["group"] = ", ".join(str(key) for key in sequence["join_keys"])
                alert["labels"]["events_counted"] = str(len(sequence["events"]))
                alerts.append(alert)
            continue
        for hit in run_rule(es, rule):
            actual.setdefault(hit["_id"], []).append(rule.key)
            alerts.append(_alert(rule, hit["_source"]))
    _recreate(es, ALERTS_INDEX, index_body())
    _bulk(es, ALERTS_INDEX, alerts)
    problems = samples.differences(wanted, {event_id: sorted(keys) for event_id, keys in actual.items()})
    return problems + samples.alert_differences(samples.expected_alerts(), groups)


def detect_scenarios(es: Client, rules: list[LabRule]) -> list[str]:
    """Run every rule on the scenario events in Elasticsearch and compare with the test engine's result."""
    documents = scenarios.build()
    wanted = scenarios.detections(rules, documents)
    actual: dict[str, list[str]] = {event_id: [] for event_id in wanted}
    groups: dict[str, list[tuple[str, ...]]] = {}
    for rule in rules:
        if rule.is_threshold:
            groups[rule.key] = _groups(run_threshold(es, rule, SCENARIO_INDEX))
            continue
        for hit in run_rule(es, rule, SCENARIO_INDEX):
            actual.setdefault(hit["_id"], []).append(rule.key)
    problems = samples.differences(wanted, {event_id: sorted(keys) for event_id, keys in actual.items()})
    return problems + samples.alert_differences(threshold_alerts(rules, documents), groups)


def wait_for_documents(es: Client, index: str, wanted: int, seconds: int = 240) -> int:
    """Wait until an index holds at least `wanted` documents. Returns the count it reached."""
    deadline = time.time() + seconds
    while True:
        response = es.call("GET", f"/{index}/_count", expect=(200, 404))
        found = response.json().get("count", 0) if response.status_code == 200 else 0
        if found >= wanted or time.time() > deadline:
            return found
        time.sleep(3)


def live_overview(es: Client) -> dict[str, Any]:
    """What Logstash has stored: documents per data set and the number Logstash could not parse."""
    es.call("POST", f"/{LIVE_INDEX}/_refresh", expect=(200, 404))
    response = es.call("POST", f"/{LIVE_INDEX}/_search", expect=(200, 404), json={
        "size": 0, "track_total_hits": True,
        "aggs": {"datasets": {"terms": {"field": "event.dataset", "size": 20}},
                 "failures": {"filter": {"wildcard": {"tags": "_*failure"}}}}})
    if response.status_code == 404:
        return {"total": 0, "datasets": {}, "failures": 0}
    answer = response.json()
    return {"total": answer["hits"]["total"]["value"],
            "datasets": {bucket["key"]: bucket["doc_count"]
                         for bucket in answer["aggregations"]["datasets"]["buckets"]},
            "failures": answer["aggregations"]["failures"]["doc_count"]}


def hunt(es: Client, rules: list[LabRule]) -> tuple[dict[str, int], dict[str, list[tuple[str, ...]]]]:
    """Run every rule on the live events and store the alerts. Returns hits per rule and threshold groups."""
    hits: dict[str, int] = {}
    groups: dict[str, list[tuple[str, ...]]] = {}
    alerts = []
    for rule in rules:
        if rule.is_threshold:
            sequences = run_threshold(es, rule, LIVE_INDEX)
            groups[rule.key] = _groups(sequences)
            alerts += [_alert(rule, sequence["events"][-1]["_source"]) for sequence in sequences]
            continue
        found = run_rule(es, rule, LIVE_INDEX)
        hits[rule.key] = len(found)
        alerts += [_alert(rule, hit["_source"]) for hit in found]
    _recreate(es, LIVE_ALERTS_INDEX, index_body())
    _bulk(es, LIVE_ALERTS_INDEX, alerts)
    return hits, groups


def scenario_expectation(rules: list[LabRule]) -> tuple[dict[str, int], dict[str, list[tuple[str, ...]]]]:
    """What `hunt` must return when the live index holds one seeded run of the simulator and nothing else."""
    documents = scenarios.build()
    hits = {rule.key: 0 for rule in rules if not rule.is_threshold}
    for keys in scenarios.detections(rules, documents).values():
        for key in keys:
            hits[key] += 1
    return hits, threshold_alerts(rules, documents)


def auth_log_rules(rules: list[LabRule]) -> list[LabRule]:
    return [rule for rule in rules if (rule.product, rule.category) == ("linux", "auth")]


def auth_log_expectation(rules: list[LabRule], path: Path) -> tuple[dict[str, int], dict[str, list[tuple[str, ...]]]]:
    """What `hunt` must return for the auth log rules when Logstash has read this auth log.

    The lines are parsed by the Python patterns that mirror the pipeline's grok patterns and then
    go through the test engine, so the result does not depend on Logstash or Elasticsearch.
    """
    wanted = auth_log_rules(rules)
    documents = authlog.read(path)
    hits = {rule.key: 0 for rule in wanted if not rule.is_threshold}
    for keys in match_matrix(wanted, documents).values():
        for key in keys:
            hits[key] += 1
    return hits, threshold_alerts(wanted, documents)


def run_exercises(es: Client) -> list[tuple[str, str, int]]:
    """(exercise, query, number of scenario events found) for every solution query of the exercises."""
    results = []
    for name, query in exercises.queries():
        response = es.call("POST", f"/{SCENARIO_INDEX}/_eql/search", json={"query": query, "size": 1000})
        results.append((name, query, len(response.json()["hits"].get("events") or [])))
    return results


def count(es: Client, index: str) -> int:
    return es.call("GET", f"/{index}/_count").json()["count"]


def setup_kibana(kb: Client) -> list[str]:
    """Create one data view per lab index and import the dashboard. Returns the names that now exist."""
    kb.wait("/api/status")
    created = []
    for index, name in DATA_VIEWS.items():
        kb.call("POST", "/api/data_views/data_view", headers={"kbn-xsrf": "detection-lab"}, json={
            "override": True,
            "data_view": {"id": index, "title": index, "name": name, "timeFieldName": "@timestamp"}})
        created.append(name)
    response = kb.call("POST", "/api/saved_objects/_import?overwrite=true", headers={"kbn-xsrf": "detection-lab"},
                       files={"file": (DASHBOARD.name, DASHBOARD.read_bytes(), "application/ndjson")})
    answer = response.json()
    if not answer.get("success"):
        raise SiemError(f"Kibana did not import the dashboard: {json.dumps(answer)[:400]}")
    created.append(json.loads(DASHBOARD.read_text(encoding="utf-8"))["attributes"]["title"])
    return created


def dashboard_fields() -> dict[str, set[str]]:
    """Data view -> the fields the dashboard's panels chart."""
    dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    used: dict[str, set[str]] = {}
    for panel in json.loads(dashboard["attributes"]["panelsJSON"]):
        attributes = panel["embeddableConfig"]["attributes"]
        view = attributes["references"][0]["id"]
        for layer in attributes["state"]["datasourceStates"]["formBased"]["layers"].values():
            for column in layer["columns"].values():
                if column.get("sourceField") and column["sourceField"] != "___records___":
                    used.setdefault(view, set()).add(column["sourceField"])
    return used


def missing_dashboard_fields(es: Client) -> list[str]:
    """Fields the dashboard charts that the indices do not have. Empty when every panel has its data."""
    missing = []
    for view, fields in sorted(dashboard_fields().items()):
        response = es.call("GET", f"/{view}/_field_caps", expect=(200, 404),
                           params={"fields": ",".join(sorted(fields))})
        known = response.json().get("fields", {}) if response.status_code == 200 else {}
        missing += [f"{view}: the dashboard charts {field}, which the index does not have"
                    for field in sorted(fields) if field not in known]
    return missing
