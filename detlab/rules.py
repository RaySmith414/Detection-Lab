"""Load the Sigma rules of the lab and read their metadata."""

import re
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from detlab.attack import reference

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "rules" / "sigma"
SURICATA_RULES = ROOT / "rules" / "suricata" / "detection-lab.rules"

TECHNIQUE = re.compile(r"^t\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class LabRule:
    key: str                # file name without extension, used in expectations and reports
    path: Path
    rule: SigmaRule

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def level(self) -> str:
        return str(self.rule.level.name).lower() if self.rule.level else "unknown"

    @property
    def product(self) -> str:
        return self.rule.logsource.product or ""

    @property
    def category(self) -> str:
        return self.rule.logsource.category or ""

    @property
    def tactics(self) -> list[str]:
        known = reference()["tactics"]
        return [tag.name for tag in self.rule.tags if tag.namespace == "attack" and tag.name in known]

    @property
    def techniques(self) -> list[str]:
        return [tag.name.upper() for tag in self.rule.tags if tag.namespace == "attack" and TECHNIQUE.match(tag.name)]

    @property
    def unknown_attack_tags(self) -> list[str]:
        """attack.* tags that are neither a tactic of the reference data nor shaped like a technique ID."""
        known = reference()["tactics"]
        return [tag.name for tag in self.rule.tags
                if tag.namespace == "attack" and tag.name not in known and not TECHNIQUE.match(tag.name)]

    @property
    def relative_path(self) -> str:
        return self.path.relative_to(ROOT).as_posix()


def load_rules() -> list[LabRule]:
    rules = []
    for path in sorted(SIGMA_DIR.rglob("*.yml")):
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        if len(collection.rules) != 1:
            raise ValueError(f"{path}: expected one rule per file")
        rules.append(LabRule(path.stem, path, collection.rules[0]))
    keys = [rule.key for rule in rules]
    if len(keys) != len(set(keys)):
        raise ValueError("two Sigma rule files share a name")
    return rules
