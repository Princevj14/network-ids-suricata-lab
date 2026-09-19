# Analyst Report: SYN Port Scan Detection

## Alert Details

| Field | Detail |
|---|---|
| Alert | CUSTOM Possible SYN port scan detected (sid:1000001) |
| Source | 192.168.204.1 (host laptop / attacker) |
| Destination | 192.168.204.20 (ids-target VM) |
| Tool used | Nmap SYN scan (-sS -p-) |
| MITRE ATT&CK | T1595.001 — Active Scanning |
| Severity | Medium |
| Detection Method | Offline PCAP replay analysis |

## What Was Observed
A single source IP (192.168.204.1) sent SYN packets to all 65,535 TCP ports on the target host within a short time window. This is consistent with automated port scanning behaviour. Only port 22 (SSH) was confirmed open.

## Triage Steps
1. Confirm source IP — is it an authorised internal scanner or an unknown host?
2. Check if any ports beyond 22 responded — those open ports are potential attack surface
3. Review subsequent traffic from that source IP for follow-up exploitation attempts
4. Cross-reference source IP against threat intelligence feeds

## Analyst Verdict
Reconnaissance activity consistent with pre-exploitation scanning. If source is not an authorised scanner, treat as hostile and escalate. Recommend: block source IP at perimeter if external; isolate and investigate if internal.
