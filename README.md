# Enterprise DFIR Investigation

## Executive Summary

This project documents a multi-host digital forensics and incident response investigation conducted in a simulated enterprise environment. The investigation began with the compromise of an internet-facing WordPress server and followed the attacker’s activity across multiple Linux and Windows systems.

Evidence from web logs, Linux audit records, Windows forensic artifacts, PowerShell transcripts, and volatile memory was correlated to reconstruct the intrusion from initial access through privilege escalation, credential access, persistence, and lateral movement.

Key findings included WordPress administrative compromise, webshell deployment, reverse-shell activity, Linux persistence, abuse of stolen domain credentials, scheduled-task manipulation, executable masquerading, LSASS credential dumping, PsExec-based movement, suspicious DLL execution, process injection, and subsequent RDP activity.

The purpose of this project is to demonstrate evidence-driven intrusion reconstruction across multiple hosts while clearly separating directly observed artifacts from conclusions that could not be fully established with the available telemetry.

## Investigation Scope

The investigation focused on four systems representing successive stages of the intrusion:

| System | Investigation Focus |
| --- | --- |
| DeceptiPot | Internet-facing WordPress compromise, Linux execution, privilege escalation, reconnaissance, and persistence |
| SRV-IT-QA | RDP access, scheduled-task abuse, executable masquerading, credential dumping, and lateral movement |
| SRV-DMZ-GW | Process-chain reconstruction, suspicious DLL execution, process injection, memory forensics, and outbound lateral movement |
| SRV-CRM-01 | RDP access and CRM-related data artifacts |

The investigation was performed as a simulated DFIR exercise. Findings are presented as an analyst case study rather than as a walkthrough of the original training material.

Only activity supported by the preserved evidence is treated as confirmed. Where the scenario suggested additional attacker behavior that could not be independently verified from the available artifacts, that limitation is documented explicitly.

## Environment and Evidence Sources

The investigation required analysis across both Linux and Windows systems using multiple forensic data sources.

### Linux Evidence

Evidence from the initial Linux compromise included:

- Apache access logs
- Linux Audit Framework (`auditd`) records
- shell and command-history artifacts
- filesystem artifacts
- systemd service configuration
- WordPress-related files and application activity

These sources were used to correlate attacker-controlled web requests with host-level command execution, reverse-shell activity, privilege escalation, internal reconnaissance, and persistence.

### Windows Evidence

Subsequent Windows investigations used artifacts including:

- Windows event data
- PowerShell transcripts
- Prefetch artifacts
- filesystem metadata
- executable metadata
- process and command-line evidence
- volatile memory captures

These sources were used to investigate remote access, credential access, masqueraded executables, lateral movement, suspicious process ancestry, and memory-resident activity.

### Memory Forensics

Volatile memory analysis was performed with Volatility to examine:

- running processes
- parent-child process relationships
- command-line arguments
- network connections
- suspicious executable memory regions
- injected shellcode

Memory analysis was particularly important when investigating activity on `SRV-DMZ-GW`, where process injection and memory-resident payload behavior were identified.

### Investigation Approach

The investigation followed an evidence-first workflow:

1. Identify suspicious activity within the available artifact set.
2. Correlate related events across logs, processes, files, and network evidence.
3. Reconstruct the sequence of attacker actions.
4. Validate findings using independent artifacts where possible.
5. Record limitations when the evidence did not support a definitive conclusion.

This approach was used throughout the investigation to avoid treating scenario context or assumptions as independently verified forensic findings.

## Environment and Evidence Sources

## Attack Overview

## Stage 1 — Initial Access and Linux Compromise

### WordPress Brute Force
### Webshell Deployment
### Reverse Shell
### Privilege Escalation
### Internal Reconnaissance
### Linux Persistence

## Stage 2 — Credential Access and Windows Lateral Movement

### RDP Access with Stolen Credentials
### Scheduled Task Abuse
### Executable Masquerading
### Execution Validation
### LSASS Credential Dumping
### PsExec Lateral Movement

## Stage 3 — Memory Forensics and Continued Lateral Movement

### Process Tree Reconstruction
### Suspicious DLL Execution
### Masqueraded Update Payloads
### Process Injection
### Meterpreter Identification
### RDP Connection Analysis

## Stage 4 — CRM Server Compromise

### RDP Access
### CRM Data Artifacts
### Evidence Limitations

## Cross-Host Attack Timeline

## Key Findings

## Indicators of Compromise

## MITRE ATT&CK Mapping

## Detection Opportunities

## Remediation Recommendations

## Evidence Limitations

## Skills Demonstrated