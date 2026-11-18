"""Run the attack simulator and the lab's Sigma rules against what it produces.

attack-simulator/simulator.py plays six attack scenarios and writes the events
in the field names Sysmon and the Windows event log use. This module runs it
with a fixed seed, turns each event into the ECS document the lab stores and
shows which rules fire on which step.

The sample events in detlab.samples were written next to the rules. The
scenarios were written separately, so they are a second opinion on the rules.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from detlab.engine import match_matrix, threshold_alerts
from detlab.fields import FIELD_MAP
from detlab.rules import ROOT, LabRule

SIMULATOR = ROOT / "attack-simulator" / "simulator.py"
SEED = 7
START = "2026-11-10T10:00:00"
ORDER = ["brute_force", "malware_execution", "lateral_movement", "data_exfiltration", "persistence",
         "defense_evasion"]

SYSMON = "Microsoft-Windows-Sysmon"
# The simulator labels every non-Sysmon event "windows_security". These two come from other providers.
PROVIDERS = {7045: "Service Control Manager", 1102: "Microsoft-Windows-Eventlog"}
SECURITY = "Microsoft-Windows-Security-Auditing"
CHANNELS = {7045: "System"}
CATEGORIES = {1: "process", 2: "file", 3: "network", 8: "process", 10: "process", 11: "file", 13: "registry",
              19: "configuration", 20: "configuration", 22: "network", 1102: "iam", 4624: "authentication",
              4625: "authentication", 4672: "iam", 4698: "configuration", 7045: "configuration"}
# Fields of the simulator's envelope, as opposed to fields of the Windows event itself.
ENVELOPE = {"timestamp", "scenario", "mitre_tactics", "event_type", "event_id", "EventID", "EventName", "Computer"}


def run_simulator(seed: int = SEED, start: str = START) -> list[dict[str, Any]]:
    """Play every scenario once in fast mode and return the raw events in order."""
    with tempfile.TemporaryDirectory() as scratch:
        env = dict(os.environ, LOG_DIR=scratch, SIMULATOR_SEED=str(seed), SIMULATOR_FAST="1",
                   SIMULATOR_START_TIME=start)
        done = subprocess.run([sys.executable, str(SIMULATOR), "all"], env=env, capture_output=True, text=True,
                              timeout=120)
        if done.returncode != 0:
            raise RuntimeError(f"the attack simulator failed: {done.stderr.strip()[-400:]}")
        events = []
        for path in sorted(Path(scratch, "windows").glob("attack_*.json")):
            events += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    position = {name: index for index, name in enumerate(ORDER)}
    return sorted(events, key=lambda event: (position[event["scenario"]], event["timestamp"]))


def _put(document: dict[str, Any], dotted: str, value: Any) -> None:
    node = document
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def to_ecs(raw: dict[str, Any], number: int) -> dict[str, Any]:
    """One simulator event as the ECS document the lab's rules query."""
    code = raw["EventID"]
    host = raw.get("Computer") or raw.get("WorkstationName") or "unknown"
    document: dict[str, Any] = {
        "@timestamp": raw["timestamp"],
        "event": {"id": f"{raw['scenario']}-{number:03d}", "code": str(code), "kind": "event",
                  "provider": SYSMON if raw["event_type"] == "sysmon" else PROVIDERS.get(code, SECURITY),
                  "category": CATEGORIES.get(code, "host"), "action": raw["EventName"],
                  "dataset": "detection-lab.attack-simulator"},
        "host": {"name": host, "os": {"type": "windows"}},
        "winlog": {"channel": CHANNELS.get(code, "Security") if raw["event_type"] != "sysmon"
                   else "Microsoft-Windows-Sysmon/Operational"},
        "labels": {"lab_scenario": raw["scenario"]},
    }
    for name, value in raw.items():
        if name in ENVELOPE:
            continue
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        elif not isinstance(value, str):
            value = str(value)
        _put(document, FIELD_MAP.get(name, f"winlog.event_data.{name}"), value)
    return document


def build() -> list[dict[str, Any]]:
    """Every scenario event as an ECS document, numbered within its scenario."""
    counters: dict[str, int] = {}
    documents = []
    for raw in run_simulator():
        counters[raw["scenario"]] = counters.get(raw["scenario"], 0) + 1
        documents.append(to_ecs(raw, counters[raw["scenario"]]))
    return documents


# The rules that must fire in each scenario. A test compares this with what the rules do.
EXPECTED: dict[str, set[str]] = {
    "brute_force": {"win_failed_logon_burst"},
    "malware_execution": {
        "win_office_spawns_script_host", "win_powershell_encoded_command", "win_script_host_drops_executable",
        "win_masquerading_system_binary_wrong_path", "win_suspicious_process_outbound_connection"},
    "lateral_movement": {
        "win_lsass_process_access", "win_sedebug_privilege_assigned", "win_remote_admin_port_from_shell",
        "win_service_installed_psexec", "win_psexec_service_child_process", "win_wmic_remote_process_create"},
    "data_exfiltration": {
        "win_archive_password_protected", "win_dns_query_long_encoded_label", "win_dns_tunnel_burst",
        "win_suspicious_process_outbound_connection", "win_powershell_http_upload"},
    "persistence": {
        "win_registry_run_key_suspicious_value", "win_reg_add_run_key",
        "win_scheduled_task_created_suspicious_command", "win_schtasks_create_suspicious_action",
        "win_service_installed_suspicious_path", "win_service_create_user_writable_path",
        "win_wmi_event_subscription"},
    "defense_evasion": {
        "win_remote_thread_from_user_folder", "win_powershell_amsi_bypass", "win_file_creation_time_changed",
        "win_security_log_cleared", "win_event_log_clearing", "win_defender_tampering",
        "win_defender_disabled_registry"},
}
TITLES = {"brute_force": "Brute force", "malware_execution": "Malware execution",
          "lateral_movement": "Lateral movement", "data_exfiltration": "Data exfiltration",
          "persistence": "Persistence", "defense_evasion": "Defense evasion"}


def of(documents: list[dict[str, Any]], scenario: str) -> list[dict[str, Any]]:
    return [document for document in documents if document["labels"]["lab_scenario"] == scenario]


def detections(rules: list[LabRule], documents: list[dict[str, Any]]) -> dict[str, list[str]]:
    """event.id -> keys of the single-event rules that fire on the event."""
    return match_matrix(rules, documents)


def alerts(rules: list[LabRule], documents: list[dict[str, Any]]) -> dict[str, list[str]]:
    """scenario -> keys of the threshold rules that raise an alert on that scenario's events."""
    found = {}
    for scenario in ORDER:
        raised = threshold_alerts(rules, of(documents, scenario))
        found[scenario] = sorted(key for key, groups in raised.items() if groups)
    return found


def fired(rules: list[LabRule], documents: list[dict[str, Any]]) -> dict[str, set[str]]:
    """scenario -> every rule that fired at least once in it, single-event and threshold rules alike."""
    hits = detections(rules, documents)
    found: dict[str, set[str]] = {scenario: set(keys) for scenario, keys in alerts(rules, documents).items()}
    for document in documents:
        found[document["labels"]["lab_scenario"]].update(hits[document["event"]["id"]])
    return found


def problems(rules: list[LabRule], documents: list[dict[str, Any]]) -> list[str]:
    """Differences between the rules that fire in each scenario and the rules that must."""
    found = fired(rules, documents)
    lines = []
    for scenario in ORDER:
        lines += [f"missed: {key} no longer fires in the {scenario} scenario"
                  for key in sorted(EXPECTED[scenario] - found[scenario])]
        lines += [f"new: {key} now fires in the {scenario} scenario. Add it to EXPECTED in detlab/scenarios.py"
                  for key in sorted(found[scenario] - EXPECTED[scenario])]
    return lines


def _detail(document: dict[str, Any]) -> str:
    """The most telling field of an event, for the report."""
    data = document.get("winlog", {}).get("event_data", {})
    destination = document.get("destination", {})
    candidates = [
        document.get("process", {}).get("command_line"),
        document.get("registry", {}).get("path"),
        document.get("dns", {}).get("question", {}).get("name"),
        f"{document.get('process', {}).get('executable', '').rsplit(chr(92), 1)[-1]} to "
        f"{destination.get('ip')}:{destination.get('port')}" if destination else None,
        document.get("file", {}).get("path"),
        data.get("TaskName"), data.get("ServiceName"),
        f"{data.get('TargetUserName')} from {data.get('IpAddress')}" if data.get("IpAddress") else None,
        f"{document.get('process', {}).get('executable', '')} into {data.get('TargetImage')}"
        if data.get("TargetImage") else None,
        data.get("Name"), data.get("SubjectUserName"),
    ]
    text = next((candidate for candidate in candidates if candidate), "")
    return text if len(text) <= 90 else text[:87] + "..."


def report(rules: list[LabRule], documents: list[dict[str, Any]]) -> str:
    """docs/SCENARIOS.md: every scenario step and the rules that fire on it."""
    hits = detections(rules, documents)
    raised = alerts(rules, documents)
    total = len(documents)
    seen = sum(1 for document in documents if hits[document["event"]["id"]])
    lines = [
        "# Attack scenarios",
        "",
        "Generated by `python -m detlab build`. Do not edit it by hand.",
        "",
        "`attack-simulator/simulator.py` plays six attack scenarios and writes the events a Windows host would "
        "log. This page shows what the lab's Sigma rules make of them. The simulator runs with a fixed seed "
        f"({SEED}), so the events below are the same on every run.",
        "",
        "The scenarios are older than the rules. Run against them, the first 37 rules fired on 7 kinds of "
        "step and missed whole scenarios. The rules written to close those gaps are part of the lab now, "
        "each with its own samples in `simulations/events`.",
        "",
        f"A single-event rule fires on {seen} of the {total} events. The other events are steps that look "
        "ordinary one at a time (a failed logon, a DNS lookup) or that no rule covers yet. "
        "They are listed as not detected instead of being left out.",
        "",
        "| Scenario | Events | Rules that fire | Steps no single rule fires on |",
        "| --- | --- | --- | --- |",
    ]
    found = fired(rules, documents)
    for scenario in ORDER:
        events = of(documents, scenario)
        quiet = sum(1 for document in events if not hits[document["event"]["id"]])
        lines.append(f"| [{TITLES[scenario]}](#{TITLES[scenario].lower().replace(' ', '-')}) | {len(events)} | "
                     f"{len(found[scenario])} | {quiet} |")
    for scenario in ORDER:
        events = of(documents, scenario)
        lines += ["", f"## {TITLES[scenario]}", ""]
        if raised[scenario]:
            lines += ["Threshold rules that raise an alert on this scenario: "
                      + ", ".join(f"`{key}`" for key in raised[scenario]) + ".", ""]
        lines += ["| Step | Event | Detail | Rules that fire |", "| --- | --- | --- | --- |"]
        rows: list[list[Any]] = []
        for document in events:
            keys = hits[document["event"]["id"]]
            row = [document["event"]["id"].rsplit("-", 1)[1],
                   f"{document['event']['code']} {document['event']['action']}", _detail(document), keys, 1]
            # Repeated steps (a hundred failed logons, a run of beacons) become one row.
            if rows and rows[-1][1] == row[1] and rows[-1][3] == keys and len(events) > 20:
                rows[-1][4] += 1
            else:
                rows.append(row)
        for number, event, detail, keys, count in rows:
            step = number if count == 1 else f"{number} to {int(number) + count - 1:03d}"
            detail = detail.replace("|", "\\|")
            shown = f"`{detail}`" if detail else ""
            if count > 1:
                shown += f" and {count - 1} more like it"
            lines.append(f"| {step} | {event} | {shown} | "
                         f"{'<br>'.join(f'`{key}`' for key in keys) or 'not detected'} |")
    return "\n".join(lines) + "\n"
