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

The intrusion began against `DeceptiPot`, an internet-facing Linux system hosting a WordPress application. Web-server logs, Linux audit records, shell artifacts, and filesystem evidence were correlated to reconstruct the attack from initial access through root-level persistence.

### WordPress Brute Force

Review of the Apache access logs identified repeated authentication activity directed at the WordPress login interface.

The request pattern was consistent with automated password guessing and showed repeated attempts against the administrative login endpoint. The activity was associated with external infrastructure later tied to the intrusion.

This established the likely initial-access path:

```text
External attacker
      ↓
WordPress login attempts
      ↓
Successful administrative access
```

The authentication activity alone did not prove host compromise. Subsequent WordPress and operating-system evidence was required to establish that the attacker progressed beyond account access.

> **Evidence:** Apache access-log activity showing repeated WordPress authentication attempts.

### Webshell Deployment

Following the WordPress compromise, activity shifted from authentication attempts to administrative functions capable of modifying application files.

Web-server evidence showed interaction with WordPress functionality associated with modifying PHP content. A PHP-based webshell was subsequently identified within the application environment.

This represented the transition from compromised application credentials to arbitrary command execution on the underlying host.

The resulting attack path was:

```text
Compromised WordPress administrator
        ↓
Application file modification
        ↓
PHP webshell
        ↓
Operating-system command execution
```

Web-request evidence was correlated with Linux audit records to validate that attacker-controlled requests resulted in processes being launched on the server.

> **Evidence:** WordPress administrative activity and the corresponding PHP/webshell artifact.

### Web-to-Host Execution Correlation

One of the strongest findings in the Linux investigation was the ability to correlate application-layer activity with host-level execution.

Suspicious HTTP requests contained attacker-controlled command input. Corresponding `auditd` records showed execution of the associated operating-system commands.

This provided independent evidence that the malicious web activity was not limited to requests reaching the application; the commands were executed by the host.

The correlation can be summarized as:

```text
Malicious HTTP request
        ↓
WordPress / PHP processing
        ↓
auditd EXECVE event
        ↓
Host command execution
```

This distinction was important because a malicious request alone does not establish successful command execution.

> **Evidence:** Matching web request and `auditd` execution records.

### Reverse Shell Establishment

Host telemetry later showed use of `socat`, a networking utility capable of establishing bidirectional connections and interactive shells.

The observed execution was consistent with the attacker upgrading webshell-style access into an interactive reverse shell.

This provided a more flexible foothold on the server and enabled additional host discovery and privilege-escalation activity.

```text
Webshell access
      ↓
socat execution
      ↓
Interactive reverse shell
```

Because `socat` is a legitimate administration and networking utility, its presence alone was not treated as malicious. Its significance came from the surrounding compromise context and execution sequence.

> **Evidence:** `auditd` / process evidence showing `socat` execution associated with the intrusion.

### Privilege Escalation

The investigation identified an exposed SSH private key that could be used to obtain higher-privileged access.

Subsequent shell artifacts indicated that the attacker transitioned into a root-level context. This expanded the compromise from application-level and user-level execution to full administrative control of the Linux host.

The evidence supported the following progression:

```text
Initial shell
      ↓
Credential / key discovery
      ↓
SSH private-key access
      ↓
Root-level session
```

The investigation treated the exposed key as credential material rather than a software-exploitation vulnerability. No evidence was identified showing that the attacker required exploitation of a kernel or application vulnerability to obtain root privileges.

> **Evidence:** SSH key artifact and root-level shell/history activity.

### Internal Reconnaissance

After obtaining elevated privileges, the attacker performed reconnaissance against the surrounding environment.

Observed activity included host and network discovery intended to identify additional reachable systems and services.

This marked the transition from compromise of the internet-facing host toward lateral movement deeper into the environment.

```text
Compromised DeceptiPot
        ↓
Network reconnaissance
        ↓
Identification of internal targets
```

The reconnaissance was significant because the following stages of the investigation involved Windows systems that were not directly internet-facing.

> **Evidence:** Root shell or command-history artifacts showing internal reconnaissance activity.

### Payload Retrieval

The attacker retrieved additional tooling after establishing elevated access.

Artifacts indicated that external content was downloaded to the compromised system for use in later stages of the intrusion.

Rather than treating the download alone as proof of execution, the investigation separated:

- payload retrieval
- payload placement
- subsequent execution evidence

where those stages could be independently established.

> **Evidence:** Shell or filesystem artifacts showing retrieval of attacker tooling.

### Linux Persistence

Persistent access was established through a malicious systemd service designed to resemble a legitimate Linux kernel worker.

The service referenced an attacker-controlled executable and was configured so the malicious program could launch automatically with the system.

The persistence mechanism used naming intended to blend into normal Linux activity:

```text
systemd
   ↓
trusted-looking service name
   ↓
attacker-controlled executable
   ↓
automatic execution
```

This represented a durable foothold independent of the original WordPress access path.

Persistence through systemd is especially significant because service execution may occur with elevated privileges and survive user logoff or system restart.

> **Evidence:** Malicious systemd service configuration and associated executable artifact.

### Stage 1 Findings

The Linux investigation established the following sequence with supporting evidence:

1. Repeated authentication activity targeted the exposed WordPress application.
2. Administrative WordPress access enabled modification of application content.
3. A PHP webshell provided operating-system command execution.
4. Web requests were correlated with `auditd` records to confirm host execution.
5. `socat` was used to establish interactive remote access.
6. Exposed credential material enabled escalation to a root-level context.
7. The compromised server was used to perform internal reconnaissance.
8. Additional attacker tooling was retrieved.
9. A malicious systemd service established persistent access.

By the end of this stage, the attacker had progressed from an internet-facing web application to persistent root-level access on the Linux host and had begun identifying targets inside the enterprise network.

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