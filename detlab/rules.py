"""Load the Sigma rules of the lab and read their metadata."""

import re
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from detlab.attack import reference

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "rules" / "sigma"
SURICATA_RULES = ROOT / "rules" / "suricata" / "detection-lab.rules"

TECHNIQUE = re.compile(r"^t\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class LabRule:
    """One rule file. Most hold a single rule. A threshold rule file holds the rule it counts and the count."""

    key: str                    # file name without extension, used in expectations and reports
    path: Path
    collection: SigmaCollection

    @property
    def rule(self):
        """The rule that raises the alert: the correlation rule of a threshold file, else the only rule."""
        return self.collection.rules[-1]

    @property
    def base(self) -> SigmaRule:
        """The rule that selects events. For a single rule that is the rule itself."""
        return self.collection.rules[0]

    @property
    def is_threshold(self) -> bool:
        return isinstance(self.rule, SigmaCorrelationRule)

    @property
    def group_by(self) -> list[str]:
        return list(self.rule.group_by or []) if self.is_threshold else []

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def level(self) -> str:
        return str(self.rule.level.name).lower() if self.rule.level else "unknown"

    @property
    def product(self) -> str:
        return self.base.logsource.product or ""

    @property
    def category(self) -> str:
        """The log source within the product: a Sigma category or a service such as the Security log."""
        return self.base.logsource.category or self.base.logsource.service or ""

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
        thresholds = [rule for rule in collection.rules if isinstance(rule, SigmaCorrelationRule)]
        if len(collection.rules) != 1 and not (len(collection.rules) == 2 and thresholds == [collection.rules[-1]]):
            raise ValueError(f"{path}: expected one rule or one rule followed by the threshold rule that counts it")
        rules.append(LabRule(path.stem, path, collection))
    keys = [rule.key for rule in rules]
    if len(keys) != len(set(keys)):
        raise ValueError("two Sigma rule files share a name")
    return rules
