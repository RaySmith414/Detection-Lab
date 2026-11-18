"""Command line for the lab: python -m detlab <command>

    test                 run every Sigma rule against the sample events and, when
                         Suricata is installed, every Suricata rule against the captures
    build                write the generated files (samples, captures, queries, coverage)
    check                fail when a generated file is stale or an ATT&CK tag is wrong
    convert [RULE]       print the Elasticsearch EQL query of one rule or of all rules
    scenarios            show which rules fire on each step of the attack simulator's scenarios
    siem load            store the samples and the scenario events in Elasticsearch (stack/ must be running)
    siem detect          run every rule in Elasticsearch and compare with the expected hits
    siem hunt            run every rule on the live events that Logstash stored
    siem exercises       run the solution queries of the hunting exercises on the scenario events
    siem kibana          create the Kibana data views and import the dashboard
    replay-check FILE    check the alerts that stack/replay-pcaps.sh wrote
    attack-reference     rebuild detlab/data/attack.json from MITRE's STIX file
"""

import argparse
import json
import sys
from pathlib import Path

from detlab import attack, build, pcaps, samples, scenarios, siem
from detlab.convert import to_eql
from detlab.engine import match_matrix, threshold_alerts
from detlab.rules import ROOT, load_rules
from detlab.suricata import load_suricata_rules, read_eve, replay, sids_by_capture, suricata_available


def _report(title: str, problems: list[str], passed: str) -> bool:
    if problems:
        print(f"{title}: {len(problems)} problem(s)")
        for problem in problems:
            print(f"  {problem}")
        return False
    print(f"{title}: {passed}")
    return True


def tag_problems() -> list[str]:
    problems: list[str] = []
    for rule in load_rules():
        problems += attack.problems(rule.key, rule.tactics, rule.techniques)
        problems += [f"{rule.key}: unknown tag attack.{tag}" for tag in rule.unknown_attack_tags]
    for rule in load_suricata_rules():
        problems += attack.problems(rule.key, [rule.tactic], [rule.technique])
    return problems


def sigma_problems() -> list[str]:
    rules = load_rules()
    attack_events, benign_events = samples.build()
    events = attack_events + benign_events
    problems = samples.differences(samples.expected(events), match_matrix(rules, events))
    problems += samples.alert_differences(samples.expected_alerts(), threshold_alerts(rules, events))
    thresholds = {rule.key for rule in rules if rule.is_threshold}
    problems += [f"{key}: no sample groups in BURSTS" for key in sorted(thresholds - set(samples.BURSTS))]
    problems += [f"{key}: BURSTS names a rule that is not a threshold rule"
                 for key in sorted(set(samples.BURSTS) - thresholds)]
    keys = {rule.key for rule in rules}
    for case, group in (("attack", attack_events), ("benign", benign_events)):
        covered = {event["labels"]["lab_rule"] for event in group}
        problems += [f"{key}: no {case} sample" for key in sorted(keys - covered)]
    known = keys | {"background"}
    problems += sorted({f"sample for unknown rule {event['labels']['lab_rule']}"
                        for event in events if event["labels"]["lab_rule"] not in known})
    return problems


def suricata_problems(pcap_dir: Path = build.PCAP_DIR) -> list[str]:
    problems = []
    expected = {name: sorted(sids) for name, (_packets, sids) in pcaps.build().items()}
    for name, sids in expected.items():
        got = replay(pcap_dir / f"{name}.pcap")
        if got != sids:
            problems.append(f"{name}.pcap: expected SIDs {sids}, Suricata raised {got}")
    covered = {sid for sids in expected.values() for sid in sids}
    problems += [f"sid {rule.sid}: no capture raises it" for rule in load_suricata_rules() if rule.sid not in covered]
    return problems


def cmd_test(_args) -> int:
    rules = load_rules()
    attack_events, benign_events = samples.build()
    thresholds = sum(1 for rule in rules if rule.is_threshold)
    ok = _report("Sigma rules", sigma_problems(),
                 f"{len(rules)} rules ({thresholds} of them threshold rules), {len(attack_events)} attack events "
                 f"all detected, {len(benign_events)} benign events all quiet")
    documents = scenarios.build()
    found = scenarios.fired(rules, documents)
    ok &= _report("Attack scenarios", scenarios.problems(rules, documents),
                  f"{len(scenarios.ORDER)} scenarios with {len(documents)} events, "
                  f"{len(set().union(*found.values()))} rules fire as expected")
    if suricata_available():
        captures = pcaps.build()
        ok &= _report("Suricata rules", suricata_problems(),
                      f"{len(load_suricata_rules())} rules, {len(captures) - 1} attack captures all detected, "
                      f"benign capture quiet")
    else:
        print("Suricata rules: skipped, the suricata program is not installed")
    return 0 if ok else 1


def cmd_scenarios(_args) -> int:
    rules = load_rules()
    documents = scenarios.build()
    hits = scenarios.detections(rules, documents)
    raised = scenarios.alerts(rules, documents)
    for scenario in scenarios.ORDER:
        events = scenarios.of(documents, scenario)
        detected = sum(1 for document in events if hits[document["event"]["id"]])
        print(f"{scenarios.TITLES[scenario]}: a rule fires on {detected} of {len(events)} events")
        for key in sorted({key for document in events for key in hits[document["event"]["id"]]}):
            print(f"  {key}")
        for key in raised[scenario]:
            print(f"  {key} (threshold)")
    return 0 if _report("Attack scenarios", scenarios.problems(rules, documents), "as expected") else 1


def cmd_build(_args) -> int:
    changed = build.write(build.generated_files())
    for path in changed:
        print(f"{'wrote' if path.exists() else 'removed'} {path.relative_to(ROOT).as_posix()}")
    print(f"{len(changed)} file(s) changed")
    return 0


def cmd_check(_args) -> int:
    ok = _report("Generated files", build.stale(build.generated_files()), "all current")
    ok &= _report("ATT&CK tags", tag_problems(),
                  f"all valid for ATT&CK Enterprise {attack.reference()['version']}")
    if not ok:
        print("Run `python -m detlab build` after changing a rule, a sample or a capture.")
    return 0 if ok else 1


def cmd_convert(args) -> int:
    rules = [rule for rule in load_rules() if args.rule in (None, rule.key)]
    if not rules:
        print(f"no rule named {args.rule}", file=sys.stderr)
        return 1
    for rule in rules:
        if len(rules) > 1:
            print(f"// {rule.key}")
        print(to_eql(rule))
    return 0


def cmd_siem(args) -> int:
    try:
        env = siem.read_env()
        es = siem.elasticsearch(env)
        if args.action == "load":
            es.wait("/_cluster/health?wait_for_status=yellow&timeout=5s")
            counts = siem.load(es, keep_timestamps=args.keep_timestamps)
            for index, number in counts.items():
                print(f"{index}: {number} document(s)")
            if not counts[siem.NETWORK_INDEX]:
                print("No Suricata alerts loaded. Run stack/replay-pcaps.sh first to include them.")
            return 0
        if args.action == "detect":
            rules = load_rules()
            ok = _report("Sigma rules in Elasticsearch", siem.detect(es, rules),
                         f"{len(rules)} rules ran as EQL, every hit as expected, "
                         f"{siem.count(es, siem.ALERTS_INDEX)} alert(s) stored in {siem.ALERTS_INDEX}")
            ok &= _report("Attack scenarios in Elasticsearch", siem.detect_scenarios(es, rules),
                          "the same hits as the test engine")
            return 0 if ok else 1
        if args.action == "hunt":
            return _hunt(es, args)
        if args.action == "exercises":
            results = siem.run_exercises(es)
            for name, query, found in results:
                print(f"{found:4d}  {name}: {query}")
            empty = [f"{name}: the query finds nothing: {query}" for name, query, found in results if not found]
            return 0 if _report("Exercises", empty, f"{len(results)} solution queries all find events") else 1
        for name in siem.setup_kibana(siem.kibana(env)):
            print(f"Kibana: {name}")
        return 0 if _report("Dashboard fields", siem.missing_dashboard_fields(es), "every charted field exists") else 1
    except siem.SiemError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _hunt(es, args) -> int:
    rules = load_rules()
    if args.wait:
        reached = siem.wait_for_documents(es, siem.LIVE_INDEX, args.wait)
        if reached < args.wait:
            print(f"error: {siem.LIVE_INDEX} holds {reached} document(s), expected {args.wait}", file=sys.stderr)
            return 2
    overview = siem.live_overview(es)
    print(f"{siem.LIVE_INDEX}: {overview['total']} document(s)")
    for dataset, number in sorted(overview["datasets"].items()):
        print(f"  {dataset}: {number}")
    hits, groups = siem.hunt(es, rules)
    for key, number in sorted(hits.items()):
        if number:
            print(f"{number:5d}  {key}")
    for key, found in sorted(groups.items()):
        for group in found:
            print(f"alert  {key} for {', '.join(group)}")
    ok = _report("Logstash", [f"{overview['failures']} document(s) that Logstash could not parse"]
                 if overview["failures"] else [], "every line parsed")
    if args.expect_scenarios:
        wanted_hits, wanted_groups = siem.scenario_expectation(rules)
        problems = [f"{key}: {hits.get(key, 0)} hit(s) on the live events, {number} in the test engine"
                    for key, number in sorted(wanted_hits.items()) if hits.get(key, 0) != number]
        problems += samples.alert_differences(wanted_groups, groups)
        ok &= _report("Scenarios through Logstash", problems, "the same hits per rule as the test engine")
    if args.expect_auth_log:
        wanted_hits, wanted_groups = siem.auth_log_expectation(rules, Path(args.expect_auth_log))
        problems = [f"{key}: {hits.get(key, 0)} hit(s) on the live events, {number} in the test engine"
                    for key, number in sorted(wanted_hits.items()) if hits.get(key, 0) != number]
        problems += samples.alert_differences(wanted_groups, {key: groups.get(key, []) for key in wanted_groups})
        total = sum(wanted_hits.values()) + sum(len(alerting) for alerting in wanted_groups.values())
        ok &= _report("Auth log through Logstash", problems,
                      f"the same {total} hit(s) and alert(s) for the auth log rules as the test engine")
    return 0 if ok else 1


def cmd_replay_check(args) -> int:
    found = sids_by_capture(read_eve(Path(args.file)))
    problems = []
    for name, (_packets, sids) in pcaps.build().items():
        got = found.get(name, [])
        if got != sorted(sids):
            problems.append(f"{name}.pcap: expected SIDs {sorted(sids)}, the file has {got}")
    ok = _report("Suricata replay", problems, f"{sum(len(sids) for sids in found.values())} alert SID(s) as expected")
    return 0 if ok else 1


def cmd_attack_reference(args) -> int:
    used = sorted({technique for rule in load_rules() for technique in rule.techniques}
                  | {rule.technique for rule in load_suricata_rules()})
    data = attack.build_reference(Path(args.stix), used)
    attack.DATA.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {attack.DATA.relative_to(ROOT).as_posix()}: ATT&CK {data['version']}, "
          f"{len(data['techniques'])} techniques")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m detlab", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("test").set_defaults(run=cmd_test)
    commands.add_parser("scenarios").set_defaults(run=cmd_scenarios)
    commands.add_parser("build").set_defaults(run=cmd_build)
    commands.add_parser("check").set_defaults(run=cmd_check)
    convert = commands.add_parser("convert")
    convert.add_argument("rule", nargs="?", help="rule key, for example win_certutil_download")
    convert.set_defaults(run=cmd_convert)
    siem_parser = commands.add_parser("siem")
    siem_parser.add_argument("action", choices=["load", "detect", "hunt", "exercises", "kibana"])
    siem_parser.add_argument("--wait", type=int, default=0, metavar="N",
                             help="hunt: first wait until Logstash has stored N documents")
    siem_parser.add_argument("--expect-scenarios", action="store_true",
                             help="hunt: fail unless the hits equal those of one seeded simulator run")
    siem_parser.add_argument("--expect-auth-log", metavar="FILE",
                             help="hunt: fail unless the auth log rules find in Elasticsearch what the test engine "
                                  "finds in this auth log, the one Logstash has read")
    siem_parser.add_argument("--keep-timestamps", action="store_true",
                             help="store the samples with their original times instead of moving them to now")
    siem_parser.set_defaults(run=cmd_siem)
    replay_check = commands.add_parser("replay-check")
    replay_check.add_argument("file", help="the file stack/replay-pcaps.sh wrote")
    replay_check.set_defaults(run=cmd_replay_check)
    reference = commands.add_parser("attack-reference")
    reference.add_argument("--stix", required=True,
                           help="path of enterprise-attack.json from mitre-attack/attack-stix-data")
    reference.set_defaults(run=cmd_attack_reference)
    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
