# Analyst Report: Reverse Shell Detection

## Alert Details

| Field | Detail |
|---|---|
| Alert | CUSTOM Possible reverse shell outbound to known shell port (sid:1000002) |
| Source | 192.168.204.20 (ids-target VM / compromised host) |
| Destination | 192.168.204.1 port 4444 (attacker listener) |
| Tool used | Netcat (nc -e /bin/bash) |
| MITRE ATT&CK | T1059.004 — Unix Shell |
| Severity | Critical |
| Detection Method | Offline PCAP replay analysis |

## What Was Observed
An internal host (192.168.204.20) initiated an outbound TCP connection to port 4444 on an attacker-controlled IP. Port 4444 is a well-known reverse shell port used by Metasploit default listeners and manual netcat shells. The connection pattern (outbound from victim to attacker) is consistent with post-exploitation callback following successful compromise.

## Triage Steps
1. Immediately isolate the source host (192.168.204.20) from the network
2. Confirm whether the connection was established (SYN only, or SYN-ACK returned)
3. Review process list and running services on the source host for the shell process
4. Check for persistence mechanisms (cron jobs, new users, modified .bashrc)
5. Identify how the host was initially compromised — review auth.log for prior access

## Analyst Verdict
Critical — active post-exploitation activity. Host should be considered fully compromised. Initiate incident response: isolate host, preserve memory/disk image for forensics, reset all credentials that may have been accessible from that host.
