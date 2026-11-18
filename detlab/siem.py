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

from detlab import attack, samples
from detlab.convert import to_eql
from detlab.fields import FIELD_MAP, LOGSOURCES
from detlab.rules import ROOT, LabRule
from detlab.suricata import read_eve

STACK = ROOT / "stack"
ENV_FILE = STACK / ".env"
NETWORK_ALERTS_FILE = STACK / "output" / "network-alerts.ndjson"
EVENTS_INDEX = "detlab-events"
ALERTS_INDEX = "detlab-alerts"
NETWORK_INDEX = "detlab-network-alerts"
DATA_VIEWS = {
    EVENTS_INDEX: "Detection Lab: sample events",
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
    names = set(FIELD_MAP.values()) | {field for conditions in LOGSOURCES.values() for field in conditions}
    names |= {"event.id", "event.category", "labels.lab_case", "labels.lab_rule"}
    tree: dict[str, Any] = {"@timestamp": {"type": "date"}}
    for name in sorted(names):
        node = tree
        parts = name.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {"properties": {}})["properties"]
        node[parts[-1]] = {"type": "keyword", "ignore_above": 8191}
    return tree


def _index_body(properties: dict[str, Any] | None = None) -> dict[str, Any]:
    mappings: dict[str, Any] = {"dynamic_templates": [
        {"strings_as_keywords": {"match_mapping_type": "string",
                                 "mapping": {"type": "keyword", "ignore_above": 8191}}}]}
    if properties:
        mappings["properties"] = properties
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

    if not keep_timestamps:
        # Move everything so the newest document is five minutes old and shows up in Kibana's default view.
        newest = max(document["@timestamp"] for document in events + alerts)
        target = datetime.now(timezone.utc) - timedelta(minutes=5)
        delta = target - datetime.strptime(newest, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        for document in events + alerts:
            document["@timestamp"] = _shift(document["@timestamp"], delta)

    _recreate(es, EVENTS_INDEX, _index_body(_properties()))
    _recreate(es, ALERTS_INDEX, _index_body({"@timestamp": {"type": "date"}}))
    _recreate(es, NETWORK_INDEX, _index_body({"@timestamp": {"type": "date"}}))
    _bulk(es, EVENTS_INDEX, events, id_of=lambda event: event["event"]["id"])
    _bulk(es, NETWORK_INDEX, alerts)
    return {EVENTS_INDEX: len(events), NETWORK_INDEX: len(alerts)}


def run_rule(es: Client, rule: LabRule) -> list[dict[str, Any]]:
    """The events in Elasticsearch that the rule's EQL query matches."""
    response = es.call("POST", f"/{EVENTS_INDEX}/_eql/search", json={"query": to_eql(rule), "size": 1000})
    return response.json()["hits"].get("events") or []


def _alert(rule: LabRule, hit: dict[str, Any]) -> dict[str, Any]:
    data = attack.reference()
    source = hit["_source"]
    alert = {
        "@timestamp": source["@timestamp"],
        "event": {"kind": "alert", "id": source["event"]["id"], "dataset": "detection-lab.sigma"},
        "rule": {"name": rule.title, "uuid": str(rule.rule.id), "id": rule.key, "ruleset": "detection-lab",
                 "reference": rule.relative_path},
        "labels": {"severity": rule.level, "lab_case": source["labels"]["lab_case"]},
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": [data["tactics"][name]["id"] for name in rule.tactics],
                       "name": [data["tactics"][name]["name"] for name in rule.tactics]},
            "technique": {"id": rule.techniques,
                          "name": [data["techniques"][technique]["name"] for technique in rule.techniques]},
        },
        "host": source.get("host", {}),
    }
    for field in ("user", "process", "file", "registry", "dns"):
        if field in source:
            alert[field] = source[field]
    return alert


def detect(es: Client, rules: list[LabRule]) -> list[str]:
    """Run every rule, store the alerts and return the differences from the expected hits."""
    attack_events, benign_events = samples.build()
    wanted = samples.expected(attack_events + benign_events)
    actual: dict[str, list[str]] = {event_id: [] for event_id in wanted}
    alerts = []
    for rule in rules:
        for hit in run_rule(es, rule):
            actual.setdefault(hit["_id"], []).append(rule.key)
            alerts.append(_alert(rule, hit))
    _recreate(es, ALERTS_INDEX, _index_body({"@timestamp": {"type": "date"}}))
    _bulk(es, ALERTS_INDEX, alerts)
    return samples.differences(wanted, {event_id: sorted(keys) for event_id, keys in actual.items()})


def count(es: Client, index: str) -> int:
    return es.call("GET", f"/{index}/_count").json()["count"]


def setup_kibana(kb: Client) -> list[str]:
    """Create one data view per lab index. Returns the names that now exist."""
    kb.wait("/api/status")
    created = []
    for index, name in DATA_VIEWS.items():
        kb.call("POST", "/api/data_views/data_view", headers={"kbn-xsrf": "detection-lab"}, json={
            "override": True,
            "data_view": {"id": index, "title": index, "name": name, "timeFieldName": "@timestamp"}})
        created.append(name)
    return created
