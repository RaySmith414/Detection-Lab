"""How Sigma fields and log sources map onto the ECS documents the lab stores.

This module is the single source for the mapping. The SQLite test engine and
the Elasticsearch converter are both built from it, so a rule is tested against
the same field names it will query in Elasticsearch.
"""


# Sigma field name -> ECS field name
FIELD_MAP: dict[str, str] = {
    # Process events (Sysmon 1, auditd execve)
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "OriginalFileName": "process.pe.original_file_name",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "CurrentDirectory": "process.working_directory",
    "User": "user.name",
    "IntegrityLevel": "winlog.event_data.IntegrityLevel",
    # Process access (Sysmon 10)
    "SourceImage": "process.executable",
    "TargetImage": "winlog.event_data.TargetImage",
    "GrantedAccess": "winlog.event_data.GrantedAccess",
    # Registry (Sysmon 13)
    "TargetObject": "registry.path",
    "Details": "registry.data.strings",
    # Files (Sysmon 11)
    "TargetFilename": "file.path",
    # Network (Sysmon 3) and DNS (Sysmon 22)
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
    "DestinationHostname": "destination.domain",
    "QueryName": "dns.question.name",
    # Any Windows event
    "EventID": "event.code",
    "Computer": "host.name",
    # Windows Security and System logs, Sysmon 2, 8, 19 and 20: the event's own fields
    "TargetUserName": "winlog.event_data.TargetUserName",
    "SubjectUserName": "winlog.event_data.SubjectUserName",
    "IpAddress": "winlog.event_data.IpAddress",
    "LogonType": "winlog.event_data.LogonType",
    "PrivilegeList": "winlog.event_data.PrivilegeList",
    "TaskName": "winlog.event_data.TaskName",
    "TaskContent": "winlog.event_data.TaskContent",
    "ServiceName": "winlog.event_data.ServiceName",
    "ImagePath": "winlog.event_data.ImagePath",
    "Operation": "winlog.event_data.Operation",
    "Destination": "winlog.event_data.Destination",
    "CreationUtcTime": "winlog.event_data.CreationUtcTime",
    "StartModule": "winlog.event_data.StartModule",
    # Lines of the Linux auth log (see AUTH_LOG_FIELDS below)
    "program": "process.name",
    "message": "message",
    "src_ip": "source.ip",
}

# Logstash parses auth log lines with grok straight into the ECS fields (detlab/authlog.py has the
# patterns), so these three never need renaming there.
AUTH_LOG_FIELDS = ("program", "message", "src_ip")

# (product, category) -> conditions that select that kind of event
LOGSOURCES: dict[tuple[str, str], dict[str, str]] = {
    ("windows", "process_creation"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "1"},
    ("windows", "network_connection"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "3"},
    ("windows", "process_access"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "10"},
    ("windows", "file_event"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "11"},
    ("windows", "registry_set"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "13"},
    ("windows", "dns_query"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "22"},
    ("windows", "file_change"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "2"},
    ("windows", "create_remote_thread"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "8"},
    ("windows", "wmi_event"): {"winlog.channel": "Microsoft-Windows-Sysmon/Operational"},
    ("linux", "process_creation"): {"host.os.type": "linux", "event.category": "process", "event.type": "start"},
}

# (product, service) -> conditions that select that log. Rules for these name the event ID themselves.
SERVICES: dict[tuple[str, str], dict[str, str]] = {
    ("windows", "security"): {"winlog.channel": "Security"},
    ("windows", "system"): {"winlog.channel": "System"},
    ("linux", "auth"): {"event.dataset": "system.auth"},
}


def flat(name: str) -> str:
    """Column name used by the SQLite engine for an ECS field."""
    return name.replace(".", "_").replace("@", "")


def queried_fields() -> set:
    """Every ECS field a converted rule can refer to."""
    names = set(FIELD_MAP.values())
    for table in (LOGSOURCES, SERVICES):
        names |= {field for conditions in table.values() for field in conditions}
    return names
