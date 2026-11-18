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
}

# (product, category) -> conditions that select that kind of event
LOGSOURCES: dict[tuple[str, str], dict[str, str]] = {
    ("windows", "process_creation"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "1"},
    ("windows", "network_connection"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "3"},
    ("windows", "process_access"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "10"},
    ("windows", "file_event"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "11"},
    ("windows", "registry_set"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "13"},
    ("windows", "dns_query"): {"event.provider": "Microsoft-Windows-Sysmon", "event.code": "22"},
    ("linux", "process_creation"): {"host.os.type": "linux", "event.category": "process", "event.type": "start"},
}


def flat(name: str) -> str:
    """Column name used by the SQLite engine for an ECS field."""
    return name.replace(".", "_").replace("@", "")
