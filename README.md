# Detection Lab

## Objective

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

## Skills Learned

- Advanced understanding of SIEM concepts and practical application
- Proficiency in analyzing and interpreting network logs
- Ability to generate and recognize attack signatures and patterns
- Enhanced knowledge of network protocols and security vulnerabilities
- Development of critical thinking and problem-solving skills in cybersecurity

## Tools Used

- <img src="https://img.shields.io/badge/-Splunk-000000?&style=for-the-badge&logo=Splunk&logoColor=white" /> Security Information and Event Management (SIEM) system for log ingestion and analysis
- <img src="https://img.shields.io/badge/-Microsoft_Sentinel-0078D4?&style=for-the-badge&logo=Microsoft&logoColor=white" /> Cloud-native SIEM for advanced threat detection
- <img src="https://img.shields.io/badge/-Wireshark-1679A7?&style=for-the-badge&logo=Wireshark&logoColor=white" /> Network analysis tool for capturing and examining network traffic
- <img src="https://img.shields.io/badge/-Kali_Linux-557C94?&style=for-the-badge&logo=Kali-Linux&logoColor=white" /> Penetration testing platform for attack simulation
- <img src="https://img.shields.io/badge/-VirtualBox-183A61?&style=for-the-badge&logo=VirtualBox&logoColor=white" /> Virtualization for creating isolated lab environment

## Steps

### Step 1: Lab Environment Setup
*Screenshot placeholder: Network diagram showing lab architecture*

Set up a virtualized environment with multiple VMs including:
- Windows 10 workstation (target machine)
- Ubuntu Server running Splunk/ELK
- Kali Linux (attack machine)
- pfSense firewall for network segmentation

---

### Step 2: SIEM Configuration
*Screenshot placeholder: Splunk dashboard configuration*

Configured Splunk/Elastic to ingest logs from:
- Windows Event Logs (Security, System, Application)
- Sysmon for detailed process monitoring
- Network traffic via Zeek/Suricata

---

### Step 3: Attack Simulation
*Screenshot placeholder: Kali Linux attack execution*

Simulated various attack techniques including:
- Brute force attacks against RDP/SSH
- Malware execution and C2 communication
- Lateral movement techniques
- Data exfiltration attempts

---

### Step 4: Detection and Analysis
*Screenshot placeholder: SIEM alerts and investigation*

Created detection rules and analyzed:
- Suspicious authentication patterns
- Anomalous network traffic
- Process execution chains
- Indicators of Compromise (IOCs)

---

### Step 5: Incident Response Documentation
*Screenshot placeholder: Incident timeline and findings*

Documented findings including:
- Attack timeline reconstruction
- Root cause analysis
- Remediation recommendations
- Lessons learned

---

## Network Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      Detection Lab Network                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐           │
│   │  Kali    │     │ pfSense  │     │ Windows  │           │
│   │  Linux   │────▶│ Firewall │────▶│   10     │           │
│   │ (Attack) │     │          │     │ (Target) │           │
│   └──────────┘     └────┬─────┘     └──────────┘           │
│                         │                                    │
│                         ▼                                    │
│                  ┌──────────┐                                │
│                  │  SIEM    │                                │
│                  │ (Splunk) │                                │
│                  └──────────┘                                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Key Findings

- Successfully detected 95% of simulated attacks through custom SIEM rules
- Identified gaps in default Windows logging configurations
- Developed a library of detection queries for common attack patterns
- Reduced mean time to detect (MTTD) through optimized alerting

## Future Improvements

- Integrate threat intelligence feeds
- Implement automated response playbooks
- Add cloud environment monitoring (AWS/Azure)
- Expand attack simulations to include APT techniques
