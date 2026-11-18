"""Run Sigma rules against sample events in an in-memory SQLite database.

This is the engine behind the unit tests. It uses the pySigma SQLite backend,
so the matching logic is pySigma's, not a reimplementation.
"""

import json
import re
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from detlab.convert import to_sql
from detlab.fields import flat, queried_fields
from detlab.rules import LabRule


def flatten(document: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """{"process": {"name": "x"}} -> {"process.name": "x"}"""
    out: dict[str, Any] = {}
    for key, value in document.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, name + "."))
        else:
            out[name] = value
    return out


def read_events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class SqliteEngine:
    def __init__(self, events: Iterable[dict[str, Any]]):
        rows = [flatten(event) for event in events]
        # Every field a rule can query gets a column, so a rule never meets an unknown column
        # when no sample carries the field. The Elasticsearch mapping does the same.
        columns = sorted({flat(name) for row in rows for name in row} | {flat(name) for name in queried_fields()}
                         | {"event_id"})
        self.connection = sqlite3.connect(":memory:")
        # Elasticsearch regular expressions must match the whole value and the lab runs them
        # without regard to case. The test engine follows the same two rules.
        self.connection.create_function(
            "regexp", 2, lambda pattern, value: value is not None and
            re.fullmatch(pattern, str(value), re.IGNORECASE) is not None, deterministic=True)
        # NOCASE: Sigma compares strings without regard to case. So does the EQL the lab runs.
        quoted = ", ".join(f'"{column}" TEXT COLLATE NOCASE' for column in columns)
        self.connection.execute(f"CREATE TABLE logs ({quoted})")  # noqa: S608 - column names come from our own samples
        for row in rows:
            names = [flat(name) for name in row]
            values = [json.dumps(value) if isinstance(value, (list, dict)) else value for value in row.values()]
            marks = ", ".join("?" for _ in names)
            column_list = ", ".join(f'"{name}"' for name in names)
            self.connection.execute(f"INSERT INTO logs ({column_list}) VALUES ({marks})", values)  # noqa: S608
        self.columns = set(columns)

    def groups(self, rule: LabRule) -> list[tuple[str, ...]]:
        """For a threshold rule: the group-by values of every group that reached the threshold, sorted."""
        try:
            cursor = self.connection.execute(to_sql(rule))
        except sqlite3.OperationalError as exc:
            raise ValueError(f"{rule.key}: {exc}") from exc
        column = [item[0] for item in cursor.description].index("group_keys")
        found = set()
        for row in cursor:
            found.add(tuple(str(value) for value in json.loads(row[column]).values()))
        return sorted(found)

    def matches(self, rule: LabRule) -> list[str]:
        """IDs (event.id) of the events the rule matches, sorted."""
        sql = to_sql(rule).replace("SELECT * FROM logs", "SELECT event_id FROM logs", 1)
        try:
            return sorted(row[0] for row in self.connection.execute(sql))
        except sqlite3.OperationalError as exc:
            raise ValueError(f"{rule.key}: {exc}. Query: {sql}") from exc


def match_matrix(rules: Iterable[LabRule], events: list[dict[str, Any]]) -> dict[str, list[str]]:
    """event.id -> sorted keys of the rules that match it. Every event has an entry."""
    engine = SqliteEngine(events)
    matrix: dict[str, list[str]] = {event["event"]["id"]: [] for event in events}
    for rule in rules:
        if rule.is_threshold:
            continue
        for event_id in engine.matches(rule):
            matrix[event_id].append(rule.key)
    return {event_id: sorted(keys) for event_id, keys in matrix.items()}


def threshold_alerts(rules: Iterable[LabRule], events: list[dict[str, Any]]) -> dict[str, list[tuple[str, ...]]]:
    """Threshold rule key -> the groups it raises an alert for. Every threshold rule has an entry."""
    engine = SqliteEngine(events)
    return {rule.key: engine.groups(rule) for rule in rules if rule.is_threshold}
