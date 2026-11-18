"""Read the lab's Suricata rules and replay captures through Suricata."""

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from detlab.attack import tactic_by_id
from detlab.rules import SURICATA_RULES

HOME_NET = "[10.10.20.0/24]"


@dataclass(frozen=True)
class SuricataRule:
    sid: int
    msg: str
    protocol: str
    classtype: str
    tactic: str          # ATT&CK tactic short name
    technique: str       # ATT&CK technique ID

    @property
    def key(self) -> str:
        return f"suricata-{self.sid}"


def load_suricata_rules(path: Path = SURICATA_RULES) -> list[SuricataRule]:
    rules = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        def option(pattern: str, what: str, text: str = line, at: int = number) -> str:
            match = re.search(pattern, text)
            if not match:
                raise ValueError(f"{path.name}:{at}: no {what}")
            return match.group(1)

        rules.append(SuricataRule(
            sid=int(option(r"\bsid:(\d+);", "sid")),
            msg=option(r'msg:"([^"]+)";', "msg"),
            protocol=option(r"^alert (\S+) ", "protocol"),
            classtype=option(r"classtype:([\w-]+);", "classtype"),
            tactic=tactic_by_id(option(r"mitre_tactic_id (TA\d{4})", "mitre_tactic_id")),
            technique=option(r"mitre_technique_id (T\d{4}(?:\.\d{3})?)", "mitre_technique_id"),
        ))
    sids = [rule.sid for rule in rules]
    if len(sids) != len(set(sids)):
        raise ValueError("two Suricata rules share a SID")
    return rules


def suricata_available() -> bool:
    return shutil.which("suricata") is not None


def replay(pcap: Path, rules: Path = SURICATA_RULES) -> list[int]:
    """SIDs of the alerts Suricata raises on a capture, sorted and without repeats."""
    with tempfile.TemporaryDirectory() as logs:
        done = subprocess.run(
            ["suricata", "-r", str(pcap), "-S", str(rules), "-l", logs, "-k", "none",
             "--set", f"vars.address-groups.HOME_NET={HOME_NET}",
             "--set", "vars.address-groups.EXTERNAL_NET=!$HOME_NET"],
            capture_output=True, text=True, timeout=300)
        if done.returncode != 0:
            raise RuntimeError(f"suricata failed on {pcap.name}: {done.stderr.strip()[-400:]}")
        return sorted({alert["alert"]["signature_id"] for alert in read_eve(Path(logs) / "eve.json")})


def read_eve(path: Path) -> list[dict[str, Any]]:
    """The alert events of an eve.json file (or of the combined file the replay script writes)."""
    alerts = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            event = json.loads(line)
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


def sids_by_capture(alerts: list[dict[str, Any]]) -> dict[str, list[int]]:
    """lab_capture -> sorted SIDs, from alerts that carry the capture name."""
    found: dict[str, set] = {}
    for alert in alerts:
        found.setdefault(alert.get("lab_capture", ""), set()).add(alert["alert"]["signature_id"])
    return {capture: sorted(sids) for capture, sids in found.items()}
