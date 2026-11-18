import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detlab import samples  # noqa: E402
from detlab.rules import load_rules  # noqa: E402
from detlab.suricata import load_suricata_rules  # noqa: E402


@pytest.fixture(scope="session")
def rules():
    return load_rules()


@pytest.fixture(scope="session")
def network_rules():
    return load_suricata_rules()


@pytest.fixture(scope="session")
def events():
    attack_events, benign_events = samples.build()
    return attack_events, benign_events
