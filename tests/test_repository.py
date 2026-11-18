"""The repository as a whole: the stack definition, the CI workflow and what the docs claim."""

import re
from pathlib import Path

import pytest
import yaml

from detlab import pcaps, samples
from detlab.rules import ROOT, load_rules
from detlab.suricata import load_suricata_rules

COMPOSE = yaml.safe_load((ROOT / "stack" / "docker-compose.yml").read_text(encoding="utf-8"))
WORKFLOW_TEXT = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
MARKDOWN = sorted(path for path in ROOT.rglob("*.md")
                  if not any(part.startswith(".") for part in path.relative_to(ROOT).parts))


def test_every_image_is_pinned_to_a_version():
    for name, service in COMPOSE["services"].items():
        image = service["image"]
        assert re.search(r":\d+\.\d+\.\d+$", image), f"{name}: {image} is not pinned to a full version"


def test_every_published_port_is_bound_to_localhost():
    for name, service in COMPOSE["services"].items():
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name}: {port}"


def test_the_compose_file_holds_no_secret():
    text = (ROOT / "stack" / "docker-compose.yml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if re.search(r"(PASSWORD|ENCRYPTIONKEY)\s*:", line):
            assert "${" in line and ":?" in line, f"secret is not taken from .env: {line.strip()}"


def test_the_suricata_container_has_no_network_and_reads_only():
    service = COMPOSE["services"]["suricata"]
    assert service["network_mode"] == "none"
    assert all(volume.endswith(":ro") for volume in service["volumes"])
    assert service["profiles"] == ["replay"]


def test_env_file_and_output_are_ignored_by_git():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "stack/.env" in ignored and "stack/output/" in ignored


def test_init_script_writes_every_variable_the_compose_file_needs(tmp_path):
    wanted = set(re.findall(r"\$\{(\w+):\?", (ROOT / "stack" / "docker-compose.yml").read_text(encoding="utf-8")))
    written = set(re.findall(r"^(\w+)=", (ROOT / "stack" / "init.sh").read_text(encoding="utf-8"), re.MULTILINE))
    assert wanted and wanted <= written, f"init.sh does not write {sorted(wanted - written)}"


def test_workflow_actions_are_pinned_and_permissions_are_read_only():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW_TEXT)
    assert uses
    for action in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action), f"{action} is not pinned to a commit"
    workflow = yaml.safe_load(WORKFLOW_TEXT)
    assert workflow["permissions"] == {"contents": "read"}
    assert "persist-credentials: false" in WORKFLOW_TEXT


def test_ci_requires_suricata_instead_of_skipping_it():
    assert "DETLAB_REQUIRE_SURICATA" in WORKFLOW_TEXT


def test_readme_numbers_match_the_repository():
    rules = load_rules()
    network_rules = load_suricata_rules()
    attack_events, benign_events = samples.build()
    captures = pcaps.build()
    windows = sum(1 for rule in rules if rule.product == "windows")
    linux = len(rules) - windows
    for claim in (
        f"{len(rules)} Sigma rules",
        f"{len(network_rules)} Suricata rules",
        f"{windows} for Windows",
        f"{linux} for Linux",
        f"{len(attack_events)} attack events",
        f"{len(benign_events)} benign events",
        f"{len(captures) - 1} attack captures",
        f"all {len(rules)} Sigma rules",
        f"Sigma rules: {len(rules)} rules, {len(attack_events)} attack events all detected, "
        f"{len(benign_events)} benign events all quiet",
        f"Suricata rules: {len(network_rules)} rules, {len(captures) - 1} attack captures all detected",
    ):
        assert claim in README, f"README no longer says: {claim}"


def test_readme_versions_match_the_stack():
    for name in ("elasticsearch", "kibana"):
        version = COMPOSE["services"][name]["image"].split(":")[1]
        assert f"{name.capitalize()} {version}" in README


def test_readme_has_no_placeholders_or_unmeasured_claims():
    lowered = README.lower()
    for phrase in ("placeholder", "screenshot", "coming soon", "todo", "95%", "splunk", "sentinel"):
        assert phrase not in lowered, phrase


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_relative_links_in_markdown_resolve(path):
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        resolved = (path.parent / target.split("#")[0]).resolve()
        assert resolved.exists(), f"{path.name}: broken link {target}"


def test_project_layout_in_readme_names_real_paths():
    block = README.split("## Project layout", 1)[1].split("```text", 1)[1].split("```", 1)[0]
    stack = []
    for line in block.splitlines():
        depth = (len(line) - len(line.lstrip())) // 2
        if not line.strip() or depth == 0:      # blank lines and the root folder
            continue
        name = line.split("#")[0].strip()
        stack = stack[:depth - 1] + [name]
        assert (ROOT / Path(*[part.rstrip("/") for part in stack])).exists(), f"README lists {'/'.join(stack)}"


def test_guide_examples_follow_the_conventions_they_describe():
    guide = (ROOT / "docs" / "ADDING_DETECTIONS.md").read_text(encoding="utf-8")
    rule = yaml.safe_load(guide.split("```yaml", 1)[1].split("```", 1)[0])
    assert rule["description"].startswith("Detects ")
    assert rule["logsource"] == {"category": "process_creation", "product": "windows"}
    used = {rule.sid for rule in load_suricata_rules()}
    example_sid = int(re.search(r"sid:(\d+);", guide).group(1))
    assert 9000001 <= example_sid <= 9000099 and example_sid not in used
