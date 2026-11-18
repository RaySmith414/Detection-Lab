# Detection Lab

[![CI](https://github.com/RaySmith414/Detection-Lab/actions/workflows/ci.yml/badge.svg)](https://github.com/RaySmith414/Detection-Lab/actions/workflows/ci.yml)

Detection rules that are tested like code. The lab holds 37 Sigma rules for Windows and Linux endpoints and 13 Suricata rules for network traffic. Each rule is mapped to MITRE ATT&CK and proven against sample telemetry: events and packet captures that must raise it and near misses that must stay quiet. A small Elasticsearch and Kibana stack runs the same rules as EQL queries.

## What is in the lab

| Part | Where | Contents |
| --- | --- | --- |
| Sigma rules | [`rules/sigma`](rules/sigma) | 26 for Windows (Sysmon) and 11 for Linux (process auditing) |
| Suricata rules | [`rules/suricata`](rules/suricata/detection-lab.rules) | 13 rules for DNS, HTTP, TLS, TCP and ICMP traffic |
| Sample events | [`simulations/events`](simulations/events) | 55 attack events and 66 benign events as ECS documents |
| Packet captures | [`simulations/pcaps`](simulations/pcaps) | 12 attack captures and 1 capture of ordinary traffic |
| Converted queries | [`converted/eql`](converted/eql) | Every Sigma rule as an Elasticsearch EQL query |
| Coverage | [`docs/COVERAGE.md`](docs/COVERAGE.md) | Rules by ATT&CK tactic and technique, generated from the rules |
| SIEM stack | [`stack`](stack/docker-compose.yml) | Elasticsearch 8.19.23, Kibana 8.19.23 and a Suricata 7 container |
| Toolkit | [`detlab`](detlab) | `python -m detlab`: test, build, convert and load |

## How a detection is tested

1. **One field mapping.** [`detlab/fields.py`](detlab/fields.py) maps Sigma fields to ECS fields. pySigma uses it to turn each rule into SQL for the unit tests and into EQL for Elasticsearch, so a rule is tested against the field names it will query in the SIEM.
2. **Attack samples and near misses.** [`detlab/samples.py`](detlab/samples.py) holds, for every rule, events that must fire it (one for each branch of its logic) and benign events that sit close to it. The test demands an exact result: an attack event fires its own rule and no other, a benign event fires nothing.
3. **Captures for the network rules.** [`detlab/pcaps.py`](detlab/pcaps.py) builds one capture per Suricata rule with scapy. Suricata replays each capture offline and must raise exactly the expected signature IDs. The capture of ordinary traffic must raise none.
4. **ATT&CK tags are checked.** The tags of every rule are validated against data taken from MITRE's published STIX files: the technique has to be active and has to belong to the tactic the rule names.
5. **The same result in the SIEM.** CI loads the events into Elasticsearch, runs every rule there as EQL and compares the hits with the expected ones.

The samples, captures, converted queries and the coverage document are generated files. A test fails when one of them no longer matches the rules.

## What is tested

Every push runs two jobs in GitHub Actions.

**Unit tests** on Python 3.10 through 3.13 with the Suricata package of Ubuntu 24.04: rule format, conversion, every sample event, every capture, the ATT&CK tags and the generated files.

**The stack job** starts from a clean runner and:

1. generates passwords with `stack/init.sh`
2. starts Elasticsearch and Kibana and waits for their health checks
3. replays every capture through Suricata in a container and checks the alerts
4. loads the sample events and the Suricata alerts into Elasticsearch
5. runs all 37 Sigma rules as EQL queries and compares every hit with the expected result
6. creates the Kibana data views through the Kibana API
7. stops the stack and checks that nothing is left behind

**What this does not show.** The telemetry is synthetic. The events are shaped like the documents Elastic Agent produces for Sysmon and for Linux process auditing. The captures are built packet by packet. Nothing was recorded on a real host or network and no attack tool is run. A rule that passes here detects the technique as the samples show it. It has not been tuned against the noise of a production environment.

## Quick start

```bash
git clone https://github.com/RaySmith414/Detection-Lab.git
cd Detection-Lab

python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

.venv/bin/python -m detlab test      # every rule against every sample
.venv/bin/python -m pytest           # the full test suite
```

Python 3.10 or newer is required. The Suricata tests run when the `suricata` program is installed (`sudo apt-get install suricata` on Ubuntu) and are skipped otherwise.

```text
$ python -m detlab test
Sigma rules: 37 rules, 55 attack events all detected, 66 benign events all quiet
Suricata rules: 13 rules, 12 attack captures all detected, benign capture quiet
```

## Running the rules in Elasticsearch

The stack needs Docker with the Compose plugin. In CI, Elasticsearch and Kibana together used about 3 GB of RAM.

```bash
stack/init.sh                                    # writes stack/.env with random passwords
(cd stack && docker compose up -d --wait)        # Elasticsearch and Kibana
stack/replay-pcaps.sh                            # Suricata alerts from the captures

.venv/bin/python -m detlab siem load             # sample events and Suricata alerts
.venv/bin/python -m detlab siem detect           # run every rule as EQL, store the alerts
.venv/bin/python -m detlab siem kibana           # data views for Discover
```

Open http://127.0.0.1:5601 and log in as `elastic` with the `ELASTIC_PASSWORD` from `stack/.env`. Discover then offers three data views: the sample events, the alerts from the Sigma rules and the Suricata alerts. `siem load` moves the sample timestamps so the newest document is five minutes old.

To stop the stack, run `(cd stack && docker compose down)`. Add `-v` to delete the data as well.

## ATT&CK version

The tags follow ATT&CK Enterprise 20.1. That release replaced the Defense Evasion tactic with Stealth (TA0005) and Defense Impairment (TA0112) and renumbered several techniques. Disable or Modify Tools, for example, is now T1685. Older rule sets that still say `attack.defense-evasion` or `attack.t1562.001` use tags the lab's check would reject.

[`detlab/data/attack.json`](detlab/data/attack.json) holds the tactics and the techniques the rules use. `python -m detlab attack-reference --stix enterprise-attack.json` rebuilds it from a newer release of MITRE's [attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

## Adding a detection

[`docs/ADDING_DETECTIONS.md`](docs/ADDING_DETECTIONS.md) walks through a new Sigma rule and a new Suricata rule: the rule, its samples, the commands that prove it and the files to regenerate.

## Security notes

- **Nothing here is malicious.** The sample events are text. The captures hold harmless payloads: the downloaded "executable" is the first bytes of a PE header and nothing else. Addresses come from the lab range 10.10.20.0/24 and from the documentation ranges 203.0.113.0/24 and 198.51.100.0/24.
- **Ports.** Elasticsearch and Kibana are published on `127.0.0.1` only.
- **Passwords.** `stack/init.sh` creates a random value for each secret and stores it in `stack/.env` with file mode 600. The file is ignored by git.
- **No TLS.** Traffic between the containers and to the published ports is plain HTTP. Keep the stack on a machine you control.

## Project layout

```text
Detection-Lab/
  rules/
    sigma/windows/            # 26 rules
    sigma/linux/              # 11 rules
    suricata/detection-lab.rules
  simulations/
    events/                   # attack.ndjson and benign.ndjson (generated)
    pcaps/                    # one capture per Suricata rule (generated)
  converted/eql/              # EQL query of every Sigma rule (generated)
  detlab/
    fields.py                 # Sigma field to ECS field mapping
    samples.py                # the sample events of every rule
    pcaps.py                  # the packet captures
    engine.py                 # SQLite engine for the unit tests
    siem.py                   # Elasticsearch and Kibana
    attack.py                 # ATT&CK reference data and tag checks
    data/attack.json
  stack/
    docker-compose.yml        # Elasticsearch, Kibana and the Suricata container
    init.sh                   # generates passwords
    replay-pcaps.sh           # replays the captures in the Suricata container
  docs/
    COVERAGE.md               # generated
    ADDING_DETECTIONS.md
  tests/
```

## Author

Rayshaun Smith ([GitHub](https://github.com/RaySmith414))
