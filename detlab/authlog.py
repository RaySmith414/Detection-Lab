"""Lines of a Linux auth log, parsed the way the stack's Logstash pipeline parses them.

Each grok pattern Logstash uses sits here next to the Python pattern that
mirrors it. detlab/logstash.py writes the grok patterns into the pipeline, the
samples of the auth log rules are built with the Python patterns, and
`siem hunt --expect-auth-log` uses the Python patterns to work out what the
rules must find in the lines Logstash has stored. Change both sides together.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATASET = "system.auth"

# "Nov 10 09:00:00 web-01 sshd[4242]: Failed password for root from 203.0.113.77 port 50022 ssh2"
GROK_LINE = ("^%{SYSLOGTIMESTAMP:[@metadata][stamp]} %{NOTSPACE:[host][name]} "
             "%{DATA:[process][name]}(?:\\[%{POSINT:[process][pid]}\\])?: %{GREEDYDATA:[@metadata][text]}$")
LINE = re.compile(r"^(?P<stamp>[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d) (?P<host>\S+) "
                  r"(?P<program>.*?)(?:\[(?P<pid>[1-9]\d*)\])?: (?P<text>.*)$")

GROK_SOURCE = "from %{IP:[source][ip]}"
_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
SOURCE = re.compile(rf"from (?<![0-9])(?P<ip>(?:{_OCTET}\.){{3}}{_OCTET})(?![0-9])")

GROK_USER = "(?:for|user) (?:invalid user )?%{USERNAME:[user][name]} from"
USER = re.compile(r"(?:for|user) (?:invalid user )?(?P<user>[a-zA-Z0-9._-]+) from")


def _moment(stamp: str, now: datetime) -> datetime:
    """A syslog stamp has no year. Like Logstash, take the current one and mind the turn of the year."""
    moment = datetime.strptime(f"{now.year} {stamp}", "%Y %b %d %H:%M:%S")
    if moment.month == 12 and now.month == 1:
        return moment.replace(year=now.year - 1)
    if moment.month == 1 and now.month == 12:
        return moment.replace(year=now.year + 1)
    return moment


def parse(line: str, now: datetime | None = None) -> dict[str, Any] | None:
    """The ECS document Logstash stores for one line. None for a line the first pattern rejects."""
    found = LINE.match(line)
    if not found:
        return None
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    document: dict[str, Any] = {
        "@timestamp": _moment(found["stamp"], now).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "event": {"kind": "event", "dataset": DATASET},
        "host": {"name": found["host"], "os": {"type": "linux"}},
        "process": {"name": found["program"]},
        "message": line,
    }
    if found["pid"]:
        document["process"]["pid"] = found["pid"]
    source = SOURCE.search(line)
    if source:
        document["source"] = {"ip": source["ip"]}
    user = USER.search(line)
    if user:
        document["user"] = {"name": user["user"]}
    return document


def read(path: Path, now: datetime | None = None) -> list[dict[str, Any]]:
    """One document per distinct line of the file. Logstash stores a repeated line once as well."""
    documents = []
    for number, line in enumerate(dict.fromkeys(path.read_text(encoding="utf-8").splitlines()), start=1):
        document = parse(line, now)
        if document is None:
            raise ValueError(f"{path}: line {number} is not an auth log line: {line[:120]}")
        document["event"]["id"] = f"auth-{number:05d}"
        documents.append(document)
    return documents
