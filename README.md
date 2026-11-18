# Detection Lab

[![CI](https://github.com/RaySmith414/Detection-Lab/actions/workflows/ci.yml/badge.svg)](https://github.com/RaySmith414/Detection-Lab/actions/workflows/ci.yml)

A detection engineering lab in Docker. An ELK stack with Suricata takes in telemetry from a log generator and an attack simulator. 93 detection rules run against it: 60 Sigma rules for Windows and Linux endpoints and 33 Suricata rules for network traffic. Every rule is mapped to MITRE ATT&CK and tested like code, against events and packet captures that must raise it and near misses that must stay quiet.

## What is in the lab

| Part | Where | Contents |
| --- | --- | --- |
| Sigma rules | [`rules/sigma`](rules/sigma) | 47 for Windows (Sysmon, Security and System logs) and 13 for Linux (process events and the auth log). 3 of them are threshold rules that count events. |
| Suricata rules | [`rules/suricata`](rules/suricata/detection-lab.rules) | 33 rules for scans, brute force, command and control, lateral movement, exfiltration and web attacks |
| Attack simulator | [`attack-simulator`](attack-simulator/simulator.py) | Six scenarios that write the events a Windows host would log: brute force, malware execution, lateral movement, data exfiltration, persistence and defense evasion |
| Log generator | [`log-generator`](log-generator/generator.py) | Background telemetry: Windows Security, Sysmon, Linux auth and firewall logs |
| Sample events | [`simulations/events`](simulations/events) | 136 attack events and 151 benign events as ECS documents, the unit tests of the Sigma rules |
| Packet captures | [`simulations/pcaps`](simulations/pcaps) | 32 attack captures and 1 capture of ordinary traffic, the unit tests of the Suricata rules |
| SIEM stack | [`stack`](stack/docker-compose.yml) | Elasticsearch 8.19.23, Logstash 8.19.23, Kibana 8.19.23 and a Suricata 7 container |
| Dashboard | [`stack/kibana`](stack/kibana) | Security Overview with eight panels, imported through the Kibana API |
| Sysmon configuration | [`configs/sysmon-config.xml`](configs/sysmon-config.xml) | Logs every event type the Sigma rules read |
| Reports | [`docs`](docs) | [Coverage by ATT&CK technique](docs/COVERAGE.md), [what the rules catch in each scenario](docs/SCENARIOS.md) and [hunting exercises](docs/EXERCISES.md) |
| Toolkit | [`detlab`](detlab) | `python -m detlab`: test, build, convert, load, detect and hunt |

## How a detection is tested

1. **One field mapping.** [`detlab/fields.py`](detlab/fields.py) maps Sigma fields to ECS fields. pySigma uses it to turn each rule into SQL for the unit tests and into EQL for Elasticsearch. The Logstash pipeline and the Elasticsearch index template are generated from the same table, so a rule is tested against the field names it queries in the SIEM.
2. **Attack samples and near misses.** [`detlab/samples.py`](detlab/samples.py) holds, for every rule, events that must fire it (one for each branch of its logic) and benign events that sit close to it. The test demands an exact result: an attack event fires its own rule and no other, a benign event fires nothing. Threshold rules get groups of events instead: a burst that must raise the alert and groups that stay below the count. In Elasticsearch a threshold rule is an EQL sequence, which has to be searched with a tiebreaker field or it misses events that share a timestamp ([details](docs/ADDING_DETECTIONS.md#a-threshold-rule)).
3. **Captures for the network rules.** [`detlab/pcaps.py`](detlab/pcaps.py) builds one capture per Suricata rule with scapy. Suricata replays each capture offline and must raise exactly the expected signature IDs. The capture of ordinary traffic must raise none.
4. **Scenarios as a second opinion.** The attack simulator plays its six scenarios with a fixed seed and the rules run against the result. [`docs/SCENARIOS.md`](docs/SCENARIOS.md) lists every step with the rules that fire on it. Steps that no rule catches are listed too.
5. **ATT&CK tags are checked.** The tags of every rule are validated against data taken from MITRE's published STIX files: the technique has to be active and has to belong to the tactic the rule names.
6. **The same result in the SIEM.** CI runs every rule as EQL in Elasticsearch against the samples and the scenarios and compares the hits. It also sends the simulator's events and the log generator's auth log through Logstash and checks that the rules find the same in what Logstash stored.

The samples, captures, converted queries, the Logstash pipeline and the reports are generated files. A test fails when one of them no longer matches the rules.

## What is tested

Every push runs two jobs in GitHub Actions.

**Unit tests** on Python 3.10 through 3.13 with the Suricata package of Ubuntu 24.04: rule format, conversion, every sample event, every capture, the scenarios, the ATT&CK tags, the simulator, the log generator and the generated files.

**The stack job** starts from a clean runner and:

1. generates passwords with `stack/init.sh`
2. starts Elasticsearch, Logstash and Kibana and waits for their health checks
3. replays every capture through Suricata in a container and checks the alerts
4. loads the sample events, the scenario events and the Suricata alerts into Elasticsearch
5. runs all 60 Sigma rules as EQL queries and compares every hit with the expected result
6. runs the solution queries of the hunting exercises and checks that each one finds events
7. plays the six scenarios through Logstash and checks that every rule fires as often as in the unit tests
8. runs the log generator on the host and as a container, checks that Logstash parses every line and that the auth log rules find what the unit test engine finds in the same file
9. creates the Kibana data views, imports the dashboard and checks that every field it charts exists
10. stops the stack and checks that nothing is left behind

**What this does not show.** The telemetry is synthetic. The simulator and the log generator write events in the shape of Windows and Linux logs. The captures are built packet by packet. Nothing was recorded on a real host or network and no attack tool is run. A rule that passes here detects the technique as the samples show it. It has not been tuned against the noise of a production environment. The dashboard is checked for import and for its fields, not for how it looks.

## Quick start

```bash
git clone https://github.com/RaySmith414/Detection-Lab.git
cd Detection-Lab

python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

.venv/bin/python -m detlab test         # every rule against every sample, capture and scenario
.venv/bin/python -m detlab scenarios    # which rules fire in each attack scenario
.venv/bin/python -m pytest              # the full test suite
```

Python 3.10 or newer is required. The Suricata tests run when the `suricata` program is installed (`sudo apt-get install suricata` on Ubuntu) and are skipped otherwise.

```text
$ python -m detlab test
Sigma rules: 60 rules (3 of them threshold rules), 136 attack events all detected, 151 benign events all quiet
Attack scenarios: 6 scenarios with 185 events, 30 rules fire as expected
Suricata rules: 33 rules, 32 attack captures all detected, benign capture quiet
```

## Running the stack

The stack needs Docker with the Compose plugin. In CI the three ELK containers use about 4 GB of RAM together and the images take about 4.5 GB of disk.

```bash
stack/init.sh                                    # writes stack/.env with random passwords
(cd stack && docker compose up -d --wait)        # Elasticsearch, Logstash and Kibana
stack/replay-pcaps.sh                            # Suricata alerts from the captures

.venv/bin/python -m detlab siem load             # samples, scenario events and Suricata alerts
.venv/bin/python -m detlab siem detect           # run every rule as EQL, store the alerts
```

Live telemetry goes through Logstash. Anything written under `stack/logs` is parsed and stored as ECS documents:

```bash
LOG_DIR=stack/logs .venv/bin/python attack-simulator/simulator.py all     # the six scenarios, once
LOG_DIR=stack/logs LOG_GENERATOR_ROUNDS=500 .venv/bin/python log-generator/generator.py

.venv/bin/python -m detlab siem hunt             # run every rule on what Logstash stored
.venv/bin/python -m detlab siem kibana           # data views and the dashboard
```

`(cd stack && docker compose --profile live up -d)` runs both generators as containers instead, until you stop them.

Open http://127.0.0.1:5601 and log in as `elastic` with the `ELASTIC_PASSWORD` from `stack/.env`. Discover offers a data view for each index. *Detection Lab - Security Overview* is under Dashboards. `siem load` moves the sample timestamps so the newest document is five minutes old.

To stop the stack, run `(cd stack && docker compose --profile live down)`. Add `-v` to delete the data as well.

## ATT&CK version

The tags follow ATT&CK Enterprise 20.1. That release replaced the Defense Evasion tactic with Stealth (TA0005) and Defense Impairment (TA0112) and renumbered several techniques. Disable or Modify Tools, for example, is now T1685. Older rule sets that still say `attack.defense-evasion` or `attack.t1562.001` use tags the lab's check would reject.

[`detlab/data/attack.json`](detlab/data/attack.json) holds the tactics and the techniques the rules use. `python -m detlab attack-reference --stix enterprise-attack.json` rebuilds it from a newer release of MITRE's [attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

## What the lab does not detect yet

- **A successful logon right after a burst of failed ones.** That is a sequence of a count and a single event. The toolkit only converts rules that count one kind of event.
- **Command and control beaconing by its regular interval.** The pattern sits in the spacing between connections, which a rule that looks at one event at a time cannot measure.
- **Kerberoasting, pass the hash and remote execution over WMI or WinRM on the network.** A Suricata rule for these has to tell an attack from daily use of the same protocol. The lab has no captures of real traffic to tune one against.

## Adding a detection

[`docs/ADDING_DETECTIONS.md`](docs/ADDING_DETECTIONS.md) walks through a new Sigma rule, a threshold rule, a rule for the Linux auth log and a new Suricata rule: the rule, its samples, the commands that prove it and the files to regenerate.

## Security notes

- **Nothing here is malicious.** The events are text. The captures hold harmless payloads: the downloaded "executable" is the first bytes of a PE header and nothing else. Attacker addresses come from the documentation ranges 203.0.113.0/24, 198.51.100.0/24 and 192.0.2.0/24 and attacker host names from example.com, example.net and example.org.
- **Ports.** Elasticsearch and Kibana are published on `127.0.0.1` only. Logstash publishes no port.
- **Passwords.** `stack/init.sh` creates a random value for each secret and stores it in `stack/.env` with file mode 600. The file is ignored by git. Logstash writes to Elasticsearch as the `elastic` user, which is fine for a lab and too much for anything else.
- **No TLS.** Traffic between the containers and to the published ports is plain HTTP. Keep the stack on a machine you control.
- **Generators.** The log generator and the attack simulator containers run without a network and as your own user. They only write files under `stack/logs`.

## Project layout

```text
Detection-Lab/
  rules/
    sigma/windows/            # 47 rules
    sigma/linux/              # 13 rules
    suricata/detection-lab.rules
  attack-simulator/
    simulator.py              # six attack scenarios
    scenarios/scenarios.yaml  # attack chains and hunting exercises
  log-generator/
    generator.py              # background telemetry
  simulations/
    events/                   # attack.ndjson and benign.ndjson (generated)
    scenarios/                # the simulator's events as ECS documents (generated)
    pcaps/                    # one capture per Suricata rule (generated)
  converted/eql/              # EQL query of every Sigma rule (generated)
  configs/
    sysmon-config.xml
  detlab/
    fields.py                 # Sigma field to ECS field mapping
    samples.py                # the sample events of every rule
    pcaps.py                  # the packet captures
    scenarios.py              # the simulator's scenarios and the rules expected in each
    engine.py                 # SQLite engine for the unit tests
    siem.py                   # Elasticsearch and Kibana
    logstash.py               # writes the Logstash pipeline and the index template
    authlog.py                # auth log lines, parsed the way the pipeline parses them
    attack.py                 # ATT&CK reference data and tag checks
    data/attack.json
  stack/
    docker-compose.yml        # Elasticsearch, Logstash, Kibana, Suricata and the generators
    init.sh                   # generates passwords
    replay-pcaps.sh           # replays the captures in the Suricata container
    logstash/pipeline/        # generated from detlab/fields.py
    elasticsearch/            # index template (generated)
    kibana/                   # the dashboard
  docs/
    COVERAGE.md               # generated
    SCENARIOS.md              # generated
    EXERCISES.md              # generated
    ADDING_DETECTIONS.md
  tests/
```

## Author

Rayshaun Smith ([GitHub](https://github.com/RaySmith414))
