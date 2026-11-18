"""The slice of MITRE ATT&CK the lab's rules refer to.

detlab/data/attack.json holds the tactics of ATT&CK Enterprise and the
techniques the rules use, taken from MITRE's published STIX data. Keeping it in
the repository lets the tests check every rule tag without network access.
Refresh it with: python -m detlab attack-reference --stix enterprise-attack.json
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA = Path(__file__).resolve().parent / "data" / "attack.json"

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation",
    "stealth", "defense-impairment", "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]


@lru_cache(maxsize=1)
def reference() -> dict[str, Any]:
    return json.loads(DATA.read_text(encoding="utf-8"))


def tactic_by_id(tactic_id: str) -> str:
    """Short name of a tactic from its ID, for example TA0011 -> command-and-control."""
    for name, entry in reference()["tactics"].items():
        if entry["id"] == tactic_id:
            return name
    raise KeyError(tactic_id)


def problems(key: str, tactics: list[str], techniques: list[str]) -> list[str]:
    """What is wrong with a rule's ATT&CK tags. An empty list means they are consistent."""
    data = reference()
    found: list[str] = []
    if not tactics:
        found.append(f"{key}: no tactic")
    if not techniques:
        found.append(f"{key}: no technique")
    for tactic in tactics:
        if tactic not in data["tactics"]:
            found.append(f"{key}: unknown tactic {tactic}")
    for technique in techniques:
        entry = data["techniques"].get(technique)
        if entry is None:
            found.append(f"{key}: {technique} is not an active technique in ATT&CK {data['version']}")
        elif not set(tactics) & set(entry["tactics"]):
            found.append(f"{key}: {technique} belongs to {entry['tactics']}, the rule names {tactics}")
    for tactic in tactics:
        if tactic in data["tactics"] and not any(
                tactic in data["techniques"].get(technique, {}).get("tactics", []) for technique in techniques):
            found.append(f"{key}: tactic {tactic} has no technique of that tactic in the rule")
    return found


def build_reference(stix_path: Path, techniques: list[str]) -> dict[str, Any]:
    """Extract the reference data from MITRE's enterprise-attack.json."""
    objects = json.loads(stix_path.read_text(encoding="utf-8"))["objects"]

    def external_id(item: dict[str, Any]) -> str:
        return next(ref["external_id"] for ref in item["external_references"] if ref["source_name"] == "mitre-attack")

    version = next(item["x_mitre_version"] for item in objects if item.get("type") == "x-mitre-collection")
    tactics = {item["x_mitre_shortname"]: {"id": external_id(item), "name": item["name"]}
               for item in objects if item.get("type") == "x-mitre-tactic" and not item.get("x_mitre_deprecated")}
    active = {external_id(item): {"name": item["name"],
                                  "tactics": sorted(phase["phase_name"] for phase in item.get("kill_chain_phases", []))}
              for item in objects if item.get("type") == "attack-pattern"
              and not item.get("revoked") and not item.get("x_mitre_deprecated")}
    wanted = set(techniques) | {technique.split(".")[0] for technique in techniques}
    missing = sorted(technique for technique in wanted if technique not in active)
    if missing:
        raise ValueError(f"not active in ATT&CK {version}: {', '.join(missing)}")
    unknown = sorted(set(tactics) ^ set(TACTIC_ORDER))
    if unknown:
        raise ValueError(f"the tactic list changed, update TACTIC_ORDER: {unknown}")
    return {"source": "MITRE ATT&CK Enterprise, attack-stix-data", "version": version,
            "tactics": {name: tactics[name] for name in TACTIC_ORDER},
            "techniques": {technique: active[technique] for technique in sorted(wanted)}}
