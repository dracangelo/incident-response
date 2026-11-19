# Network Security Incident Response Playbooks

Lateral Movement (RDP/SMB/PsExec) · Data Exfiltration (large uploads, DNS tunneling) · Port Scanning & Reconnaissance · Rogue Device / ARP Spoofing · DDoS · Compromised Edge Device / VPN Appliance · DNS Hijacking & Rogue DHCP/DNS · Rogue Wi-Fi / Evil Twin

Version 1.0 · Owner: Security / IR Lead + Network Engineering · Review every 6 months and after every SEV1/SEV2. Replace every `<PLACEHOLDER>` before use.

The first five playbooks were requested; **Playbooks 6–8 (edge device compromise, DNS hijacking/rogue DHCP, rogue Wi-Fi)** are added because they are common network incidents with their own evidence and containment steps. Command beaconing, phishing, brute force and ransomware are covered in the core IR playbooks; this document hands off to them where an incident crosses over. Examples use Splunk (SPL), Microsoft Defender KQL, Zeek/tcpdump/tshark and Cisco-style switch commands; map them to your stack.

## 0. Shared Foundation

### 0.1 Severity for network incidents

| Sev | Definition | Examples | Ack SLA | Update cadence |
| --- | --- | --- | --- | --- |
| SEV1 | Active spread to servers/DCs, confirmed large exfil of sensitive data, customer-facing outage under attack, compromised perimeter device with internal access | Lateral movement toward DC, DDoS taking production down, exploited VPN appliance | 15 min | 30 min |
| SEV2 | Confirmed malicious network activity with limited scope | Single-host exfil, confirmed ARP-spoof MITM on one VLAN, DDoS partly mitigated | 30 min | 1 h |
| SEV3 | Suspicious, likely malicious, unconfirmed | Internal scan from a user host, unexplained large upload | 4 h | 8 h |
| SEV4 | Noise, blocked, or authorized | Internet background scanning, scheduled vuln scan | 1 business day | On closure |

Rule: **start high, downgrade with evidence.**

### 0.2 Universal rules for network incidents

1. **Network state is volatile.** ARP/CAM tables, DHCP leases, NAT and firewall session tables, and live connections change or expire. Capture them **before** you shut ports or change rules.
2. **Prefer targeted containment** (isolate a host or port) over broad blocks (segment-wide or perimeter changes) unless spread is active. Know the business blast radius before you act; ask the Business Owner for anything customer-facing.
3. **Every firewall/ACL/DNS change gets a ticket ID, an owner, an expiry and a rollback.** Time-box blocks (attackers rotate; stale blocks break business).
4. **Out-of-band management.** Use a management network or console access for network devices. Do not manage a possibly-compromised device over the path under attack.
5. **Time sync.** Record clock offset of every log source; correlate in UTC. Unsynced logs wreck timelines.
6. **Authorized activity first.** Check the **authorized-testing register** (Appendix E) and change calendar before declaring scans, odd traffic or new devices malicious.
7. **Captures can contain personal data and credentials.** Capture the minimum needed, restrict access, and get Legal sign-off before capturing content outside your own infrastructure or of encrypted/consumer traffic.
8. **No hack-back.** Do not scan, probe or attack attacker infrastructure. Block, report and preserve.
9. **Assume credentials crossing a compromised path are exposed** (MITM, rogue DHCP/DNS, rogue AP, compromised edge device). Scope resets by who authenticated through it during the window.
10. **Escalate on crossing:** lateral movement + exfil + C2 usually means a ransomware precursor. Treat it as SEV1 and open the Ransomware playbook in parallel.

### 0.3 Containment options, smallest blast radius first

| Action | Scope | Reversible | Caution |
| --- | --- | --- | --- |
| EDR network isolation of a host | One host | Yes, instantly | Keeps analyst access and memory; preferred first move |
| Disable the account used | One identity | Yes | Revoke sessions/tickets too (see Identity playbooks) |
| Host firewall rule (GPO or local) | One/few hosts | Yes | Good for blocking SMB/RDP/WinRM east-west |
| Quarantine VLAN via NAC | One device | Yes | Needs NAC; keeps device powered and observable |
| Shut switch port | One port | Yes | Capture CAM/ARP/DHCP bindings first |
| DNS sinkhole / RPZ entry | Domain | Yes | Logs who resolves it; useful for scoping |
| Proxy/firewall block to IP/domain | Destination | Yes | Expiry + ticket; block after isolating the source for C2/exfil |
| East-west ACL / segment firewall rule | Segment | Yes | Test impact; announce |
| Rate limit / challenge (WAF, CDN, ISP) | Service | Yes | First choice for L7 floods |
| Remote-triggered blackhole (RTBH) / null route | Destination IP | Yes | **Completes the DoS** for that IP; last resort |
| Disconnect site / WAN link / take system offline | Site/system | Yes | Business Owner approval; ransomware or active destruction only |

### 0.4 Telemetry map: where to look

| Question | Source |
| --- | --- |
| Who talked to whom, how much, when | NetFlow/IPFIX, firewall session logs, VPC flow logs, Zeek `conn.log` |
| What was in the session (protocol, files, names) | Zeek (`dns`, `smb_files`, `dce_rpc`, `http`, `ssl`), Suricata, pcap |
| DNS behavior | Resolver logs, DNS RPZ logs, Zeek `dns.log`, passive DNS |
| Web/egress | Proxy logs (with bytes), CASB, DLP |
| Which process made the connection | EDR network events, Sysmon EID 3 |
| Logon and remote execution | Windows Security 4624/4625/4648/4672/4688/4697/4698/5140/5145, System 7045, TerminalServices logs, Sysmon 1/3/13 |
| Who is plugged in where | Switch CAM/MAC tables, ARP tables, DHCP leases and snooping bindings, NAC logs, 802.1X/RADIUS |
| Wireless | WLC/AP logs, WIPS alerts, RADIUS logs |
| Remote access | VPN/ZTNA logs, RD Gateway logs, edge device admin logs |
| Config/change history | Network config backup diffs, TACACS+/AAA command logs, change tickets |

---

## 1. Playbook: Lateral Movement over RDP, SMB or PsExec

**Scope:** An attacker (or malware) moving between internal hosts using Remote Desktop (3389), SMB/admin shares (445), PsExec and clones (Impacket psexec/smbexec), WMI, WinRM (5985/5986), scheduled tasks/services, SSH, with stolen credentials, hashes or Kerberos tickets.

**Default severity:** SEV3 unconfirmed odd remote logons → SEV2 confirmed malicious movement between workstations → SEV1 movement to servers, DCs, backup or hypervisor infrastructure, or multiple hops/fan-out.

### 1.1 Detection sources

- Windows Security **4624** with LogonType **10** (RemoteInteractive/RDP) or **3** (network) from workstation to workstation or from unusual sources; **4648** explicit-credential logons; **4672** special privileges assigned to a new session; **4768/4769** Kerberos anomalies.
- System **7045** / Security **4697** service installs: `PSEXESVC`, or random-named services/executables dropped via `ADMIN$` (Impacket style). **5140/5145** share access to `ADMIN$`, `C$`, `IPC$` with named pipes such as `psexesvc`, `svcctl`, `atsvc`.
- **4698** scheduled task creation remotely; WMI activity (`WmiPrvSE.exe` spawning shells); WinRM (`wsmprovhost.exe` spawning shells).
- TerminalServices-RemoteConnectionManager **1149** and LocalSessionManager **21/22/24/25** for RDP source and session activity.
- One host connecting to many hosts on 445/3389/5985 (fan-out) in NetFlow, EDR network events or Zeek; Suricata/EDR alerts for SMB exploit or pass-the-hash behavior.

### 1.2 Triage (first 15–30 minutes)

1. Identify **source host, destination host(s), account, protocol, time** for each hop. Build a hop graph (who → whom → whom).
2. Is it **legitimate admin activity?** Jump hosts, RMM/management tools (SCCM, PDQ, Ansible), patching, backup agents, vuln scanners. Check the change calendar and ask the owner. Admin tools do it in predictable patterns; attackers do it from the wrong host, at odd times, with the wrong account.
3. **Determine the patient zero / pivot:** which source host is itself compromised? Look for the first abnormal logon in the chain and the first host that initiated it.
4. Identify **credentials in use:** local admin shared across hosts (no LAPS), a domain admin, a service account, NTLM hash reuse, Kerberos tickets.
5. Look for the **tooling and payload:** services created, files in `ADMIN$`/Temp, scheduled tasks, new persistence, credential dumping (LSASS access), recon commands (`net group`, `nltest`, AdFind, BloodHound/SharpHound LDAP volume).

### 1.3 Decision tree

```
[Alert: suspicious remote logon / remote service / SMB or RDP fan-out]
   |
   v
Explained by an authorized admin tool, jump host and change ticket (owner confirms)?
   |-- YES --> Document, baseline, close (SEV4). Tune the rule.
   |-- NO / UNSURE
        v
   Is the SOURCE host managed and healthy? (EDR telemetry, process tree on source)
        |-- Source shows malicious process/credential access --> source host is compromised: isolate it (SEV2+)
        |-- Source clean but credential is stolen --> treat ACCOUNT as compromised; isolate destination(s) as needed
        v
   CONTAIN NOW (do in parallel):
     1. EDR-isolate source host(s) and any destination host with a malicious payload
     2. Disable the account used; revoke sessions/tickets
     3. Block east-west SMB/RDP/WinRM into the affected segment except from approved jump hosts
        v
   How far did it go? Hop graph complete?
        |-- Reached server / DC / backup / hypervisor --> SEV1: IC bridge; assume credential theft; Ransomware playbook in parallel
        |-- Workstations only --> SEV2: continue scoping
        v
   Credential exposure: every account that logged on to a compromised host must be treated as exposed
        |--> reset them (privileged first); krbtgt if DC compromised (Ransomware playbook 3.6)
        v
   Initial access? --> Phishing / VPN / exploited service / beaconing (core IR playbooks)
        v
   Eradicate (reimage compromised hosts), harden, monitor 30 days, close
```

### 1.4 Containment actions

- **Isolate** source and compromised destination hosts with EDR. Do not reboot (memory evidence).
- **Block east-west management protocols** except from jump hosts, using segment ACLs or a host-firewall GPO. Example (Windows host firewall, run via EDR live response or GPO):

```
New-NetFirewallRule -DisplayName "IR-<ID> block inbound SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block
New-NetFirewallRule -DisplayName "IR-<ID> block inbound RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block
New-NetFirewallRule -DisplayName "IR-<ID> block inbound WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -Action Block
```

- **Accounts:** disable the compromised account; reset privileged and service accounts that touched affected hosts; rotate local administrator passwords (deploy LAPS); revoke Kerberos tickets/sessions.
- **Do not** clean with AV and move on. A host with lateral-movement tooling is reimaged.

### 1.5 Evidence checklist

- [ ] Hop graph with timestamps (source → destination → account → protocol)
- [ ] Windows Security, System, PowerShell, TerminalServices, Sysmon logs from each hop host, exported and hashed
- [ ] Memory image of the pivot/patient-zero host and at least one destination host (before reboot)
- [ ] EDR process trees and file events for payloads, services and scheduled tasks
- [ ] NetFlow/Zeek/firewall records for east-west 445/3389/5985/22 for the full window (±7 days around first hop)
- [ ] DC logs: 4768/4769/4624/4672/4776 for the accounts involved; AD group and GPO changes
- [ ] Dropped tools: names, hashes, paths (PsExec, Impacket artifacts, Mimikatz, AdFind, SharpHound output)
- [ ] List of every account that logged on to affected hosts (for reset scoping)

### 1.6 Queries

Splunk, fan-out of remote logons from one source (field names vary by add-on):

```
index=wineventlog EventCode=4624 Logon_Type IN (3,10) earliest=-4h
| stats dc(dest) as dest_hosts values(dest) as hosts min(_time) as first max(_time) as last by Account_Name Source_Network_Address
| where dest_hosts > 5
| convert ctime(first) ctime(last)
| sort - dest_hosts
```

Splunk, PsExec-style service installs (named or random 8-letter service binary):

```
index=wineventlog source="WinEventLog:System" EventCode=7045 earliest=-24h
| regex Service_File_Name="(?i)(psexesvc|%SystemRoot%\\[a-z]{8}\.exe)"
| table _time host Service_Name Service_File_Name Service_Account
```

KQL (Defender), one host connecting to many hosts on lateral-movement ports:

```
DeviceNetworkEvents
| where Timestamp > ago(6h) and RemotePort in (445, 3389, 5985, 5986) and ActionType == "ConnectionSuccess"
| summarize targets = dcount(RemoteIP), list = make_set(RemoteIP, 20) by DeviceName, InitiatingProcessFileName
| where targets > 5
| sort by targets desc
```

RDP source history on a host (PowerShell):

```
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" |
  ? Id -eq 1149 | select TimeCreated,@{n='Msg';e={$_.Message}} -First 50
```

### 1.7 Eradication, recovery & hardening

- Reimage compromised hosts; verify no persistence on neighbors; rotate all exposed credentials; confirm DC integrity.
- **Harden:** LAPS for local admin passwords; block workstation-to-workstation SMB/RDP/WinRM (host firewall via GPO); admin access only via **jump hosts / RD Gateway with MFA**; tiered admin model and Protected Users group; Credential Guard; disable SMBv1; require SMB signing; restrict NTLM; deny network logon for local accounts; remove standing local admin; EDR on every endpoint and server; alert on the detections above.
- Segment: user VLANs cannot reach server management ports; servers limited to required flows.

### 1.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Confirmed malicious hop | IC + IT Lead | Immediately |
| Server, DC, backup, hypervisor reached; or 3+ hosts | CISO; SEV1; Ransomware playbook in parallel | 15 min |
| Credential dumping on a privileged host | IC; privileged credential reset plan | 15 min |
| Data staged or exfil seen | Playbook 2; Legal/DPO | 1 h |

### 1.9 Closure criteria

All hops identified and cleaned or rebuilt, exposed credentials rotated, entry vector closed, east-west controls tightened, detections added, 30 days of clean monitoring.

---

## 2. Playbook: Data Exfiltration (Large Uploads, DNS Tunneling)

**Scope:** Unauthorized transfer of data out of the network: large uploads to cloud storage or attacker servers (HTTPS, FTP/SFTP, SSH, rclone, MEGA), **DNS tunneling** (data in query names/TXT responses), ICMP tunneling, DoH to bypass DNS controls, and staged archives awaiting transfer.

**Default severity:** SEV3 anomalous outbound with no sensitive data confirmed → SEV2 confirmed unauthorized transfer from one host/account → SEV1 sensitive/regulated data, large volume, or double-extortion indicators.

### 2.1 Detection sources

- **Volume:** NetFlow/firewall/proxy bytes-out per host or per destination far above baseline; sustained uploads at off-hours; first-seen destination with large transfer.
- **Destinations:** consumer cloud storage and file-drop services (MEGA, Dropbox/Drive personal, transfer.sh-style services), unusual FTP/SFTP/SSH or high-port TLS to rare IPs; user agents like `rclone`.
- **DNS tunneling:** very high query counts to one parent domain, **many unique long subdomains** (labels commonly 40+ chars), high-entropy names, heavy TXT/NULL/CNAME usage, one client generating abnormal query rates, DNS to external resolvers bypassing internal ones; tools like iodine, dnscat2, dns2tcp.
- **ICMP tunneling:** large or high-frequency echo payloads to one external host.
- **Staging:** archive creation (`7z`, `rar`, `tar`, `makecab`), large new files in Temp/ProgramData, mass file reads on file servers or database dumps; DLP and CASB alerts.

### 2.2 Triage (first 30 minutes)

1. Confirm the facts: **source host/user, destination (IP/domain), protocol/port, bytes, start/end, process (EDR)**.
2. **Legitimate?** Backups, cloud sync, software distribution, large business transfers, CI/CD, video upload by marketing. Check owner and change calendar. Destination reputation, domain age, hosting, certificate.
3. **What data?** Identify the files/tables behind it: staged archive listing, file server access logs (5145/4663), DB query logs, DLP match, SaaS audit logs. Classify (personal data, credentials, IP, financial).
4. **How did the attacker get there?** Compromised account, malware on host, insider, misconfigured storage. Check for lateral movement (Playbook 1) and C2 (core beaconing playbook).
5. For **DNS tunneling:** list the parent domain, client IPs, query count and size, record types; confirm the domain is not a legitimate service (CDN, AV cloud lookup, mail-security vendor) that legitimately uses long names.

### 2.3 Decision tree

```
[Alert: anomalous outbound volume / suspicious DNS pattern / DLP hit]
   |
   v
Explained by an approved process and owner confirms?
   |-- YES --> Document, baseline, close (SEV4).
   |-- NO / UNSURE
        v
   Destination unapproved or domain unknown/rare?
        |-- NO (approved destination, odd volume) --> SEV3: ask owner, review user/account, DLP check
        |-- YES
             v
        CONTAIN:
          1. EDR-isolate the source host (or disable the account/API key doing the upload)
          2. Block destination at proxy/firewall; DNS sinkhole the tunneling domain
          3. Preserve evidence (flows, proxy, DNS, pcap, staged files) BEFORE cleanup
             v
        What data left? (access logs, staged archive, DLP, DB logs)
             |-- Sensitive/regulated data OR unknown --> SEV1/2: Legal/DPO notified; breach assessment clock starts
             |-- Non-sensitive confirmed --> SEV2/3
             v
        Source of access: external attacker --> Playbook 1 and core beaconing/ransomware playbooks
                          insider / policy violation --> HR + Legal before any employee contact
             v
        Eradicate, close the exfil path (egress controls), monitor, close
```

### 2.4 Containment actions

- **Isolate** the source host; **block** the destination IP/domain/URL (after isolation, so the operator is not tipped before the host is contained).
- **DNS tunneling:** sinkhole/RPZ the parent domain; **force clients to use only internal resolvers** (block outbound 53/853 from clients; block known public DoH endpoints or inspect DoH); rate-limit or alert on high query volume per client.
- **Accounts/keys:** disable the compromised account; rotate API keys, cloud access keys, database credentials the host could reach; revoke OAuth tokens (see Identity playbooks).
- **Staged data:** preserve the archive and its metadata (path, size, creation time, hash) before deletion.
- Where the exfil path is a SaaS/cloud service, restrict via CASB or tenant restrictions and remove external sharing links.

### 2.5 Evidence checklist

- [ ] NetFlow/firewall/proxy records for the source and destination across the full period (bytes, packets, timestamps)
- [ ] DNS logs for the parent domain (query names, types, client IPs, volume); pcap of a short sample of the tunneled DNS
- [ ] EDR process tree for the uploading/tunneling process, command line, parent
- [ ] Staged archive(s): path, size, timestamps, hash, listing of contents (not opened on a production share)
- [ ] File server/DB/SaaS audit logs showing which data was read
- [ ] DLP/CASB alerts and matched content classification
- [ ] Memory image of the source host before reboot
- [ ] Tool artifacts: rclone config, MEGAsync, WinSCP, curl scripts, tunneling binaries (names, hashes)
- [ ] Volume estimate and data inventory for the notification decision

### 2.6 Queries

Splunk, large outbound volume per source/destination pair (7 days):

```
index=firewall action=allowed direction=outbound earliest=-7d
| stats sum(bytes_out) as bytes dc(dest_port) as ports min(_time) as first max(_time) as last by src_ip dest_ip
| where bytes > 2000000000
| eval GB=round(bytes/1073741824,2)
| convert ctime(first) ctime(last)
| sort - bytes
```

Splunk, DNS tunneling shape (many unique, long queries to one parent domain; the `rex` below is a rough parent-domain extractor and mishandles multi-part TLDs such as co.ke, so refine it with a public-suffix lookup):

```
index=dns earliest=-4h
| eval qlen=len(query)
| rex field=query "(?<parent>[^.]+\.[^.]+)$"
| stats count dc(query) as uniq_q avg(qlen) as avg_len max(qlen) as max_len values(record_type) as types by src_ip parent
| where uniq_q > 500 AND avg_len > 40
| sort - uniq_q
```

Zeek, longest DNS queries by client:

```
cat dns.log | zeek-cut id.orig_h query qtype_name | awk '{print length($2), $0}' | sort -nr | head -50
```

KQL (Defender), high outbound volume by process:

```
DeviceNetworkEvents
| where Timestamp > ago(24h) and ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| summarize conns = count(), dests = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName
| where conns > 5000
| sort by conns desc
```

### 2.7 Eradication, recovery & hardening

- Reimage the source host if compromised; rotate exposed credentials/keys; close access paths.
- **Egress control:** default-deny outbound from servers; proxy-only web egress; clients may reach **only internal DNS resolvers** with DNS logging and RPZ; block DoH/DoT to unapproved resolvers; block FTP/SSH/odd high ports out except from approved hosts.
- **Detection:** per-host egress baselines and alerts, DNS tunneling analytics, blocklist for file-drop and MEGA/rclone traffic where not business-needed, DLP/CASB on sanctioned cloud, canary files on file servers.
- Restrict who can create archives or run sync tools on servers; enforce least-privilege file/DB access.

### 2.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Confirmed unauthorized outbound transfer | IC + IT Lead | Immediately |
| Personal/regulated/sensitive data | Legal/DPO (notification clock) | 1 h |
| Lateral movement or C2 present | Playbook 1; core beaconing/ransomware playbooks | Immediately |
| Insider indicators | HR + Legal (no employee contact before coordination) | Same day |
| Extortion message received | Legal; law enforcement; ransomware playbook; do not engage | Immediately |

### 2.9 Closure criteria

Exfil path closed and blocked, data scope determined and documented, notifications decided and made, credentials rotated, egress controls and detections added, monitoring 30 days.

---

## 3. Playbook: Port Scanning & Reconnaissance

**Scope:** Probing to discover hosts, open ports, services, users and shares: external internet scans against your perimeter, and internal scanning/enumeration (Nmap, masscan, SMB/LDAP/RPC enumeration, BloodHound/SharpHound, ping/ARP sweeps).

**The context decides everything.** External scanning is constant background noise: do not open an incident for it alone. **Internal scanning from a user host or server is high signal** (compromised host, or unauthorized testing) and often precedes lateral movement.

**Default severity:** SEV4 external background scanning, nothing responsive → SEV3 external scan followed by exploitation attempts, or authorized-looking internal scan not on the register → SEV2 confirmed unauthorized internal scanning → SEV1 scanning from a host that is also showing lateral movement/exfil, or from a server/DC.

### 3.1 Detection sources

- **Vertical scan:** one source hitting many ports on one host. **Horizontal sweep:** one source hitting one port on many hosts. Firewall deny counts, Zeek `conn.log` states `S0`/`REJ`/`RSTO`, NetFlow with tiny flows to many destinations.
- IDS/IPS signatures (Suricata/Snort scan rules), honeypot/canary-host and canary-port hits, ARP/ICMP sweeps from non-network hosts.
- **Enumeration:** bursts of SMB session/share enumeration, many LDAP queries from one workstation (SharpHound-style), SAMR/NetSessionEnum RPC to the DC, Kerberos SPN scanning (many 4769 for service accounts), DNS zone-transfer attempts (AXFR).
- EDR alerts for Nmap/masscan/Advanced IP Scanner/netscan binaries or scripted scanning.
- Vulnerability scanner outputs and WAF logs for external probes.

### 3.2 Triage (first 15–30 minutes)

1. **Check the authorized-testing register and change calendar** (internal vuln scanner schedule, pentest windows, monitoring tools, asset-discovery agents). Authorized scans come from known source IPs at known times.
2. **Classify:** external or internal; horizontal, vertical or targeted enumeration.
3. **External:** source IP/ASN reputation, targets and ports probed, whether anything **responded**, any follow-on activity (exploit attempts, credential attacks, successful connections after the scan) from the same source.
4. **Internal:** which host, which user, which **process** (EDR), what scope (subnets, ports, protocols), what time, and what did that host do before and after (inbound logon? new process? beaconing?).
5. Verify **exposure:** which scanned services are reachable from the internet, and should they be?

### 3.3 Decision tree

```
[Scan / recon alert]
   |
   v
Is it from a registered scanner / pentest / monitoring tool within its window?
   |-- YES --> Document, close (SEV4).
   |-- NO
        v
   Source external or internal?
        |
        |-- EXTERNAL
        |     v
        |   Did anything respond, or did follow-on attacks come from the same source (exploit/brute force/successful session)?
        |     |-- NO  --> SEV4: rate-limit/block source (time-boxed), confirm no unnecessary exposure, close.
        |     |-- YES --> SEV3/2: block source, treat follow-on per relevant playbook (edge device, brute force, web exploitation), review exposed service for compromise.
        |
        |-- INTERNAL
              v
          Is the scanning host managed and the process legitimate (IT tool, approved by owner)?
              |-- YES but unregistered --> process finding; register or stop it; SEV3
              |-- NO / unknown process / user denies --> SEV2: host or account compromised
                    1. EDR-isolate the host; disable the account
                    2. Treat as lateral-movement precursor: Playbook 1 on this host and every host it touched
                    3. Check for beaconing/C2 and credential theft on the host
                    4. Server/DC as source? --> SEV1
        v
   Close the exposure gaps found, add detections, monitor
```

### 3.4 Containment actions

- **External:** block the source IP/ASN at the edge (time-boxed, ticketed), rate limit new connections per source, ensure only intended services are exposed; do not chase every scanner.
- **Internal:** EDR-isolate the scanning host; disable the user; capture memory; block east-west management ports to the affected segment (Playbook 1.4).
- Check whether the scan identified weak targets (open SMB/RDP/databases, default creds) and **close those first**, because the attacker will return to them.

### 3.5 Evidence checklist

- [ ] Firewall/flow/Zeek records for the scan (source, targets, ports, timing, responses)
- [ ] IDS/IPS alerts and canary hits
- [ ] EDR process tree and command line of the scanner on the internal host (hash of the binary)
- [ ] Logs of what was **responsive** and what the scanner may have learned (open ports/services list)
- [ ] Authorized-testing register entry (or its absence) with owner confirmation
- [ ] Follow-on activity from the same source or host (logons, exploit attempts, new connections)
- [ ] External source reputation/WHOIS/ASN notes

### 3.6 Queries

Splunk, scan-like sources (many ports or many hosts), last hour:

```
index=firewall earliest=-1h
| stats dc(dest_port) as ports dc(dest_ip) as hosts count by src_ip
| where ports > 100 OR hosts > 100
| sort - count
```

Splunk, internal source touching many hosts on a small set of ports with mostly failed/denied connections:

```
index=firewall src_ip=10.0.0.0/8 earliest=-1h
| stats count(eval(action="blocked")) as denied count(eval(action="allowed")) as allowed dc(dest_ip) as hosts by src_ip dest_port
| where hosts > 50 AND denied > allowed
```

KQL (Defender), scanning behavior on a device (many distinct targets, short window):

```
DeviceNetworkEvents
| where Timestamp > ago(1h)
| summarize targets = dcount(RemoteIP), ports = dcount(RemotePort) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where targets > 100 or ports > 100
```

Zeek, scan summary (rejected/unanswered connections per source):

```
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state | awk '$4=="S0" || $4=="REJ"{c[$1]++} END{for(i in c) print c[i], i}' | sort -nr | head
```

### 3.7 Eradication & hardening

- Remove unneeded internet exposure; put admin interfaces behind VPN/ZTNA; patch exposed services.
- Segmentation: user networks cannot enumerate servers; restrict LDAP/SMB enumeration paths where feasible.
- Deploy **canary hosts/ports and honey tokens** (internal) so any touch alerts with near-zero false positives.
- Keep the authorized-testing register current and tied to the alert logic (allowlist by source and window).
- Alert on first-seen scanning tools and on enumeration bursts from non-admin hosts.

### 3.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Unauthorized internal scanning | IC + IT Lead | 30 min |
| Scan from a server/DC or alongside lateral movement/exfil | CISO; SEV1 | 15 min |
| External scan followed by exploitation of an exposed service | Owner of the service; edge/vuln response | 30 min |
| Persistent targeted recon by one actor | Threat intel; ISP abuse/law enforcement as appropriate | Next business day |

### 3.9 Closure criteria

Source attributed (authorized, external noise, or compromise handled), exposure reduced, detections tuned, register updated, follow-on activity ruled out.

---

## 4. Playbook: Rogue Device / ARP Spoofing

**Scope:** (a) a **rogue device** (unknown laptop, Raspberry Pi/implant, rogue switch or hub, unmanaged IoT, unauthorized AP) connected to the wired network; and (b) **ARP spoofing/poisoning**, where a host claims another's IP (typically the gateway) to man-in-the-middle traffic; also MAC flooding and DHCP spoofing against switches.

**Default severity:** SEV3 unknown device, no malicious traffic seen → SEV2 confirmed ARP spoofing/MITM or malicious rogue device → SEV1 MITM on a server/management VLAN, or admin credentials exposed.

### 4.1 Detection sources

- **NAC/asset inventory:** unknown MAC, unknown vendor OUI (microcontroller, single-board computer, hacking-hardware vendors), device with no hostname/EDR, 802.1X bypass (MAB) of an unexpected device.
- **Switch telemetry:** port-security violations, **MAC flapping** (same MAC on multiple ports), **Dynamic ARP Inspection (DAI) drops**, DHCP snooping violations, unexpected new MACs on a port that normally has one.
- **Network tools:** arpwatch (new station, flip-flop, changed ethernet address), IDS ARP alerts, Zeek `arp` anomalies, Wireshark "duplicate IP address detected" expert info.
- **Symptoms:** gateway MAC in a client's ARP table does not match the router's; intermittent connectivity; TLS certificate warnings; slow network; users report redirects.
- Unknown device appearing in DHCP leases; unexpected hostnames; new device on a management VLAN.

### 4.2 Triage (first 15–30 minutes)

1. **Identify the device:** MAC → IP (ARP/DHCP) → switch port (CAM table) → physical location. Vendor lookup of the OUI.
2. **Known or unknown?** CMDB, NAC, procurement records, DHCP reservation; ask the VLAN owner. Authorized lab devices and visitors' laptops exist, so verify before acting.
3. **Is it spoofing?** On an affected host: gateway MAC vs the real gateway MAC; one MAC claiming several IPs; duplicate-address events; unsolicited/gratuitous ARP replies at high rate. Capture ARP on the segment.
4. **Impact window:** when did it start, which hosts/VLAN, which traffic crossed the attacker (cleartext, NTLM, SMB, HTTP, session cookies)?
5. **Managed host as the attacker?** If the spoofing source is a corporate endpoint with EDR, that host is compromised (treat under Playbooks 1 and the core beaconing playbook).

### 4.3 Decision tree

```
[Alert: unknown device / MAC flap / ARP anomaly / DAI drop]
   |
   v
CAPTURE STATE FIRST: CAM + ARP + DHCP snooping entries for the MAC/IP, short ARP pcap on the VLAN
   v
Is the device known and authorized (inventory, owner confirms)?
   |-- YES --> If misbehaving (spoofing) treat as compromised host; else document and close (SEV4).
   |-- NO / UNKNOWN
        v
   Quarantine: NAC block or shut the switch port (after capture). Locate physically (security/facilities).
        v
   Evidence of ARP spoofing / MITM (gateway MAC mismatch, duplicate IP, gratuitous ARP flood)?
        |-- YES --> SEV2: MITM confirmed
        |     1. Remove attacker from the path (port shut / NAC)
        |     2. Flush ARP caches on affected hosts/gateway; verify correct MACs
        |     3. Determine credentials/sessions exposed in the window; reset them, revoke sessions
        |     4. Management VLAN or servers affected? --> SEV1
        |-- NO (device present, no malicious traffic seen) --> SEV3: keep quarantined, recover device, investigate how it got on (open port, no NAC)
        v
   Physical device recovered? --> photograph in place, bag, label, chain of custody; do not plug in or power on
        v
   Harden (port security, DAI, DHCP snooping, 802.1X), monitor, close
```

### 4.4 State-capture and containment commands (Cisco IOS-style; adapt to your vendor)

```
show mac address-table address aaaa.bbbb.cccc
show ip arp | include 10.1.2.3
show ip dhcp snooping binding
show ip arp inspection statistics
show port-security interface Gi1/0/12
show logging | include MACFLAP|PORT_SECURITY|ARP_INSPECTION

! after capture:
interface Gi1/0/12
 description IR-<ID> QUARANTINED rogue device
 shutdown
```

Endpoint and sniffing checks:

```
# Linux
ip neigh show; arp -an; tcpdump -nn -e -i eth0 arp
# Windows
arp -a; Get-NetNeighbor | sort IPAddress
# Wireshark/tshark: duplicate IP / ARP anomalies
tshark -r cap.pcap -Y "arp.duplicate-address-detected || arp.isgratuitous"
```

### 4.5 Evidence checklist

- [ ] Switch CAM/ARP/DHCP snooping/port-security output for the MAC and port **before** shutdown
- [ ] ARP pcap from the affected VLAN (short capture is enough), plus any captured traffic showing MITM
- [ ] DHCP lease/server logs for the device (hostname, requested options)
- [ ] NAC/802.1X/RADIUS logs; the port's history (previous MACs)
- [ ] Switch logs: MACFLAP, port-security, DAI, DHCP snooping violations
- [ ] Physical device: photos in place (with cable path), device labeled, hashed images of storage if applicable, chain of custody
- [ ] List of users/systems on the VLAN during the window (for credential/session scoping)
- [ ] Access/CCTV/badge records for the physical location (if available and permitted)

### 4.6 Eradication, recovery & hardening

- Remove/seize the device; flush ARP caches; verify gateway MACs; restore normal path.
- **Reset credentials and revoke sessions** for users who authenticated over the segment during the window (NTLM relay and cleartext protocols especially).
- **Hardening:** 802.1X/NAC on all access ports; **port security** (max MACs per port, sticky, violation=shutdown or restrict); **DHCP snooping**; **Dynamic ARP Inspection**; IP source guard; disable unused ports and put them in a dead VLAN; private VLANs for server/IoT segments; storm control; protect trunks (no DTP, native VLAN hygiene); require **encryption** (TLS everywhere, SMB signing, LDAP signing/channel binding); physical port covers and locked closets for exposed ports.
- Add detections: new MAC on server/management VLAN, MAC flap, DAI drops, gateway MAC change.

### 4.7 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Unknown device on any VLAN | Network Eng + IC | 30 min |
| Confirmed ARP spoofing/MITM | IC + IT Lead; credential reset plan | Immediately |
| Management VLAN or server VLAN affected | CISO; SEV1 | 15 min |
| Physical intrusion suspected | Physical security + Legal/HR | 1 h |
| Credentials exposed | Identity playbooks (reset, revoke) | Immediately |

### 4.8 Closure criteria

Device identified and removed or authorized, MITM ruled out or contained, exposed credentials reset, port/NAC protections in place, physical entry path closed, detections added.

---

## 5. Playbook: DDoS (Distributed Denial of Service)

**Scope:** Attacks that exhaust bandwidth, state or application capacity to deny service: **volumetric** (UDP floods, reflection/amplification via DNS, NTP, memcached, SSDP, CLDAP), **protocol** (SYN/ACK floods, fragmentation), **application-layer** (HTTP/S floods, slow-rate attacks like Slowloris, HTTP/2 rapid-reset style abuse, expensive-endpoint abuse). Includes **ransom DDoS** (extortion threats) and DDoS used as a **smokescreen** for intrusion.

**Default severity:** SEV3 automatically mitigated, no customer impact → SEV2 degraded service / partial mitigation → SEV1 customer-facing outage or critical business service down.

### 5.1 Detection sources

Bandwidth/packet-rate spikes (SNMP/NetFlow), upstream/ISP or CDN/scrubbing provider alerts, latency and 5xx error spikes, load balancer/WAF metrics, connection-table exhaustion (many `SYN_RECV`), CPU/memory saturation on edge devices, synthetic monitoring failures, customer complaints, extortion email/message.

### 5.2 Triage (first 10–15 minutes)

1. **Confirm it is an attack.** Rule out: flash crowd (campaign, press, product launch), our own bad deploy or retry storm, upstream outage, certificate/DNS failure, backend failure. Ask: did marketing or a partner change anything?
2. **Identify the layer** from flows: **L3/L4** (bandwidth or PPS saturation, SYN flood, UDP/amplification) vs **L7** (normal-looking HTTP requests exhausting app or DB).
3. **Characterize:** target IP(s)/services, protocols/ports, packet sizes, top source ASNs/geos, reflection signatures (source port 53/123/11211/1900/389), request paths and user agents, request rate per client.
4. **Where is the bottleneck?** If the **internet link is saturated, only upstream mitigation helps** (ISP, CDN, scrubbing); local filtering cannot fix traffic that never fits through your pipe.
5. **Check for a second attack:** DDoS as a smokescreen. Review auth logs, WAF alerts and EDR during the window.
6. Check whether **your own hosts are participating** (outbound floods: compromised servers/IoT).

### 5.3 Decision tree

```
[Service degradation / alert]
   |
   v
Attack confirmed (not flash crowd, deploy, or upstream failure)?
   |-- NO --> Handle as a service incident with the owning team; keep monitoring.
   |-- YES --> Open incident; notify IC, Network, SRE, Comms
        v
   Is the link/ingress saturated (volumetric)?
        |-- YES --> ACTIVATE UPSTREAM MITIGATION NOW: ISP DDoS service / CDN / scrubbing (BGP diversion or always-on).
        |           Call the provider's emergency line; give targets, start time, traffic profile.
        |-- NO  --> continue
        v
   Layer 7 (HTTP/S, app)?
        |-- YES --> WAF/CDN: rate limits per client/path, bot challenge, geo/ASN rules, cache static + expensive responses,
        |           block bad user agents/paths, enable "under attack" mode, protect login/search/checkout endpoints, scale out within budget
        |-- NO (protocol/state) --> SYN cookies/proxy, ACLs for reflection ports, connection limits, drop fragments, upstream filtering
        v
   Still down?
        |-- Targeted single IP, rest of the network must survive --> RTBH/blackhole of that IP as last resort (it completes the DoS for that IP;
        |   move the service to a protected IP/CDN)
        v
   Lock the origin: accept traffic only from CDN/scrubbing ranges; change origin IPs if they leaked
        v
   Extortion demand? --> do NOT pay or engage; preserve the message; Legal + law enforcement
        v
   Communicate (status page, customers); review for smokescreen intrusion; after-action and capacity/protection fixes
```

### 5.4 Containment & mitigation checklist

- Contact **ISP/CDN/scrubbing provider** (numbers in Appendix C) and request mitigation immediately; confirm clean-traffic return path works.
- **WAF/CDN rules:** rate limit by IP/ASN/path, challenge suspicious clients, block abusive user agents, enforce geo/ASN restrictions if business allows; serve cached or static fallback pages.
- **Network:** ACL/filter reflection source ports (53, 123, 11211, 1900, 389) at the edge if you do not run those services publicly; SYN cookies/SYN proxy; limit half-open connections; drop fragments and malformed packets; disable unneeded public UDP services.
- **Origin protection:** restrict origin to CDN/scrubbing IP ranges; rotate exposed origin IPs.
- **Capacity:** scale out (autoscale caps, extra capacity), shed non-essential load, put non-critical features behind feature flags.
- **Our hosts as sources:** if internal hosts are flooding outward, EDR-isolate them and treat as compromised (core beaconing playbook).
- **RTBH** only with Network Eng + Business Owner approval.

### 5.5 Evidence checklist

- [ ] Traffic graphs (bps/pps/connections), start/end times (UTC), peak values
- [ ] NetFlow/sFlow samples; top talkers, protocols, ports, ASNs, packet sizes
- [ ] Short pcap samples at the edge (30–60 s) showing attack traffic; WAF/CDN logs with top paths, UAs, client counts
- [ ] Server/edge-device metrics (CPU, memory, connection tables), error logs, load balancer logs
- [ ] ISP/CDN/scrubbing provider tickets and their traffic reports
- [ ] Extortion messages (headers, wallet/contact details) if any
- [ ] Review of auth/WAF/EDR logs during the window for intrusion
- [ ] Business impact record (downtime, affected customers, revenue estimate)

### 5.6 Commands and queries

Splunk, top targets and talkers over the last 15 minutes:

```
index=netflow earliest=-15m
| stats sum(bytes) as bytes sum(packets) as pkts dc(src_ip) as sources by dest_ip dest_port protocol
| sort - pkts
| head 20
```

Splunk, HTTP request rate per client and path (L7 flood):

```
index=web earliest=-10m
| stats count dc(uri_path) as paths by clientip useragent
| where count > 1000
| sort - count
```

On a Linux server under SYN pressure:

```
ss -s
netstat -ant | awk '{print $6}' | sort | uniq -c | sort -nr
sysctl net.ipv4.tcp_syncookies           # 1 = enabled
tcpdump -nn -i eth0 -s 96 -c 20000 -w /evidence/ddos_sample.pcap 'tcp[tcpflags] & tcp-syn != 0'
```

Reflection source signature check:

```
tshark -r ddos_sample.pcap -Y "udp.srcport in {53 123 389 1900 11211}" -T fields -e ip.src -e udp.srcport | sort | uniq -c | sort -nr | head
```

### 5.7 Recovery & hardening

- Restore normal routing after mitigation; keep protection active for at least the typical campaign duration (attackers return); remove temporary blocks on a schedule.
- **Always-on DDoS protection** (ISP/CDN/scrubbing) with tested BGP/DNS failover; hide origin IPs; keep an emergency contact and runbook current.
- Close amplification vectors you operate: no open DNS resolvers, no NTP monlist, no public memcached/SSDP/CLDAP; **BCP38/uRPF** egress filtering so your network cannot be used for spoofed floods.
- Rate limiting, caching and expensive-endpoint protection (login/search/API); capacity planning with headroom; load tests and DDoS tabletop at least annually.
- Alerting on PPS/bps and application metrics with human paging.

### 5.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Customer-facing degradation | IC, Network Eng, SRE, Business Owner | Immediately |
| Link saturation | ISP/CDN/scrubbing emergency line | Immediately |
| Extortion threat | Legal, executive sponsor, law enforcement | 1 h |
| Signs of parallel intrusion | Security IR; relevant playbook | Immediately |
| Customer/regulator/contract notifications | Comms + Legal | Per SLA/contract |

### 5.9 Closure criteria

Service restored and stable under protection, attack characterized and documented, provider tickets closed, no concurrent intrusion found, protection/capacity gaps with owners and dates, customers informed as required.

---

## 6. Playbook: Compromised Edge Device / VPN Appliance

**Scope:** Exploitation or unauthorized access of internet-facing network devices: VPN/SSL-VPN gateways, firewalls, load balancers/ADCs, routers, remote-access and secure-gateway appliances, and their management interfaces. Also unauthorized VPN access with stolen credentials. Edge devices are high-value because they sit on the boundary, hold credentials/keys, often lack EDR, and are targeted by mass-exploitation campaigns within hours or days of a vulnerability becoming known.

**Default severity:** SEV2 suspected exploitation or unauthorized admin access, no internal pivot seen → **SEV1** confirmed compromise, or any pivot into the internal network.

### 6.1 Detection sources

- **Threat intel/advisories:** vendor PSIRT notices, CISA Known Exploited Vulnerabilities (KEV) matches against your inventory; vendor integrity-checker or IOC tool results.
- **On the device:** admin logins from unexpected IPs, new local admin or VPN users, config changes outside change windows, new scheduled tasks/cron-like entries, unexpected files (web shells, modified web/login pages), logging disabled or cleared, abnormal CPU, unexpected outbound connections **from the appliance itself**.
- **Network:** exploit signatures at the IPS, requests to known vulnerable paths in logs, the device initiating outbound connections to rare IPs, VPN sessions from hosting/VPS ASNs or multiple geos with valid credentials, internal scanning or authentication attempts originating from the VPN address pool or the device's internal IP.
- **Credential signals:** VPN account logins followed immediately by SMB/RDP/LDAP enumeration; accounts used simultaneously from different countries.

### 6.2 Triage (first 30 minutes)

1. **Is this device affected by a known-exploited or recent critical vulnerability** (version/firmware vs. advisory; was it patched before or after exploitation began)? Is its **management interface exposed to the internet**?
2. **Collect before changing:** running and startup config, local user list, VPN user/session list, logs (admin, system, VPN, event), firmware version and hash, running processes if the platform allows, output of the vendor integrity/IOC tool.
3. **Compare config to the last known-good backup** (diff). Look for added users, changed AAA/LDAP/RADIUS settings, new routes/NAT/ACL rules, new tunnels/GRE/IPsec peers, modified syslog targets, changed certificates.
4. **Outbound check:** connections from the device to external hosts (firewall logs for the device's IP), DNS queries it made.
5. **Internal pivot check:** activity sourced from the device's internal IP or the VPN pool; logons by VPN users to internal systems during the window; Playbooks 1 and 3 on any hit.
6. **Credential exposure:** which credentials/secrets does the device hold or process (VPN user passwords in transit, LDAP bind account, certificates and private keys, pre-shared keys, API tokens, SAML/OIDC secrets)?

### 6.3 Decision tree

```
[Alert / advisory match / anomaly on an edge device]
   |
   v
Is the device vulnerable to a known-exploited issue, or showing anomalies (config diff, new users, outbound, integrity check)?
   |-- NO (patched earlier, integrity clean, config matches baseline) --> SEV4: document, verify logs, close
   |-- YES / UNSURE --> treat as compromised (SEV2 -> SEV1 on any pivot)
        v
   PRESERVE: export config, logs, session list, integrity output; request vendor forensic collection procedure
        v
   RESTRICT (do not power off): management interface to internal/out-of-band only; block device outbound to unnecessary destinations;
   consider failover to a standby device
        v
   Internal pivot or VPN-sourced malicious activity seen?
        |-- YES --> SEV1: IC bridge; Playbook 1 on every touched host; Ransomware playbook readiness; disable VPN pool access
        |-- NO  --> continue
        v
   ROTATE (assume exposed): admin and local accounts, LDAP/RADIUS service accounts, certificates and private keys, IPsec PSKs, API tokens;
   force password reset and session revocation for VPN users who were active in the window; enforce MFA
        v
   REBUILD: factory reset and reinstall known-good firmware, then reconfigure from reviewed config
   (do not blindly restore a backup config; the attacker may have modified it)
        v
   Patch/mitigate per vendor advisory, restore service, heightened monitoring 30 days; engage vendor PSIRT / IR retainer
```

### 6.4 Containment actions

- **Evidence before patch:** patching or rebooting can erase artifacts, and some devices change state after upgrade. Collect first (or snapshot a VM-based appliance).
- Lock management access to an out-of-band/internal admin network and named admin IPs; disable unused services (SSL-VPN admin portals, SNMP, Telnet, HTTP).
- Fail over to a clean standby/replacement where possible; if no standby, accept a controlled outage over operating a compromised gateway.
- Rotate secrets as in 6.3; revoke VPN sessions; require MFA; block attacker IPs but do not rely on IP blocks alone.
- Hunt inside: every system reachable from the device's internal interface or VPN pool during the exposure window.

### 6.5 Evidence checklist

- [ ] Running and startup configs (hashed), config diff against baseline
- [ ] Local user/admin list, AAA settings, VPN user list, active and historic VPN sessions (IP, user, time)
- [ ] Device logs (admin/CLI/web, system, VPN, event, audit), exported off-box before reboot
- [ ] Firmware version/build and hash; patch history; advisory references
- [ ] Vendor integrity-checker/IOC tool output; filesystem/memory image via vendor-supported procedure
- [ ] Firewall/NetFlow records of the device's own outbound traffic; packet capture of management and VPN interfaces if feasible
- [ ] Internal logs showing activity from the VPN pool/device IP (logons, scans, SMB/RDP, LDAP)
- [ ] List of secrets/credentials/certificates the device held, with rotation status
- [ ] Timeline: vulnerability publication → exploitation → patch → first anomalous event

### 6.6 Queries

Splunk, VPN logins from unusual countries/ASNs or concurrent sessions in different geos:

```
index=vpn action=success earliest=-7d
| iplocation src_ip
| stats dc(Country) as countries values(Country) as geos values(src_ip) as ips count by user
| where countries > 1
| sort - countries
```

Splunk, internal activity from the VPN address pool (adjust the CIDR):

```
index=firewall src_ip=10.250.0.0/16 earliest=-7d
| stats dc(dest_ip) as hosts dc(dest_port) as ports values(dest_port) as top_ports by src_ip
| where hosts > 25
| sort - hosts
```

Splunk, outbound connections initiated by the device itself (adjust IP):

```
index=firewall src_ip=198.51.100.1 direction=outbound earliest=-30d
| stats count sum(bytes_out) as bytes by dest_ip dest_port
| sort - bytes
```

### 6.7 Eradication, recovery & hardening

- Rebuilt from known-good firmware; reviewed config; all secrets rotated; MFA enforced; VPN users re-verified.
- **Patch SLAs for edge devices in days, not weeks**, driven by KEV/vendor advisories; emergency change path pre-approved.
- **Never expose management interfaces to the internet;** restrict to out-of-band admin networks or ZTNA; MFA on VPN and admin; geo/ASN restrictions where feasible.
- **Off-box logging** to SIEM (tamper-resistant) and alerts for config change, new admin, logging stop, and outbound from the device. Config backups with hash and diff alerts.
- Limit what VPN users can reach (least-privilege access, segmented VPN pool), and monitor the pool as an untrusted segment.
- Replace end-of-life devices; keep inventory with firmware versions and exposure status.

### 6.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Suspected exploitation | IC, Network Eng, CISO | 30 min |
| Confirmed compromise or internal pivot | CISO; SEV1; IR retainer; vendor PSIRT | 15 min |
| Credentials/keys exposed | Identity team (resets), PKI owner (certificate rotation) | Immediately |
| Data access/exfil via pivot | Legal/DPO | 1 h |
| Multi-organization campaign | National CERT/ISAC sharing via Legal approval | Same day |

### 6.9 Closure criteria

Device rebuilt and verified, all secrets rotated, internal hunt complete and clean, vulnerability closed, management exposure removed, detections and patch-SLA process in place, 30 days of clean monitoring.

---

## 7. Playbook: DNS Hijacking, Poisoning & Rogue DHCP/DNS

**Scope:** Attacker control or manipulation of name resolution, at four layers: (1) **registrar / authoritative DNS** (account takeover, NS or record changes, subdomain takeover), (2) **recursive resolvers** (cache poisoning, malicious forwarders), (3) **local network** (rogue DHCP server handing out attacker DNS/gateway, LLMNR/NBT-NS/mDNS and WPAD poisoning, rogue router DNS settings), (4) **endpoints** (hosts-file changes, malicious DNS/proxy settings, malicious PAC files).

**Default severity:** SEV3 anomaly unconfirmed → SEV2 confirmed manipulation affecting some users or one VLAN → SEV1 your public zone/registrar compromised, mail/web traffic redirected, or fraudulent certificates issued.

### 7.1 Detection sources

- **Public zone:** registrar/DNS-provider change notifications, unexpected NS/A/AAAA/MX/TXT/CNAME changes, DNSSEC validation failures, new certificates for your domains in **Certificate Transparency** logs that you did not request, dangling CNAME/subdomain-takeover alerts, user reports of wrong sites or certificate warnings.
- **Resolvers:** answers that differ from authoritative; sudden spikes of NXDOMAIN/SERVFAIL; resolver software alerts; forwarders changed; clients sending DNS to external resolvers.
- **LAN:** DHCP snooping violations, **more than one DHCP Offer** on a segment, clients with DNS servers or gateways not on the approved list, LLMNR/NBT-NS responses from non-server hosts (Responder-style), unexpected WPAD resolution.
- **Endpoints:** modified hosts file, changed adapter DNS, proxy auto-config pointing to unknown hosts, EDR alerts on DNS settings changes.

### 7.2 Triage (first 30 minutes)

1. **Which layer?** Compare answers for the same name: authoritative vs. your resolver vs. a public resolver vs. an affected client.

```
dig +norec @ns1.example.com www.example.com A     # authoritative (use each NS)
dig @10.0.0.53 www.example.com A                  # internal resolver
dig @1.1.1.1 www.example.com A                    # external reference
dig +short NS example.com @a.gtld-servers.net     # delegation at the parent (adjust for the TLD)
dig +dnssec www.example.com                        # DNSSEC status
# on an affected client
ipconfig /all    |  Get-DnsClientServerAddress    |  resolvectl status
```

2. **Authoritative layer:** check registrar and DNS-provider audit logs, who logged in, from where, NS delegation, record history, contact/transfer-lock changes; check CT logs for new certificates; run CAA lookups.
3. **Resolver layer:** check for poisoned cache entries (`rndc dumpdb`, resolver logs), forwarders, software version/patch state, whether the resolver is reachable from the internet (open resolver).
4. **LAN layer:** identify DHCP servers answering (test below); find the offending MAC/port; check clients' DNS and gateway; look for LLMNR/NBT-NS poisoning (Responder) and WPAD abuse.
5. **Endpoint layer:** hosts file, DNS/proxy settings, PAC URLs, malware.
6. **Impact window and exposure:** which users/systems resolved wrong answers, what credentials/sessions/mail may have been captured (including MX hijack for mail interception and certificate validation failures that users clicked through).

```
# Detect rogue DHCP (authorized test host; sends a DHCP discover and lists all offers)
nmap --script broadcast-dhcp-discover
# Wireshark/tshark filter for DHCP offers
tshark -i eth0 -Y "dhcp.option.dhcp == 2" -T fields -e ip.src -e eth.src -e dhcp.option.router -e dhcp.option.domain_name_server
```

### 7.3 Decision tree

```
[Alert: wrong DNS answers / cert errors / rogue DHCP / zone change]
   |
   v
Which layer shows the discrepancy?
   |
   |-- AUTHORITATIVE / REGISTRAR (public zone changed)   --> SEV1 until proven otherwise
   |     1. Lock the registrar/DNS account: reset password, MFA, revoke sessions/API keys, remove unknown contacts/users, enable registrar/registry lock
   |     2. Restore correct NS and records from known-good copy; lower TTLs during recovery; verify from multiple resolvers
   |     3. Check CT logs/CAA for rogue certificates; request revocation; consider key rotation for affected services
   |     4. Assess interception: web/API logins, MX (mail) redirected, API clients; notify affected users/partners; Identity playbooks for resets
   |
   |-- RESOLVER (poisoned cache / malicious forwarder)
   |     1. Flush cache; correct forwarders; patch resolver; restrict recursion to internal clients; enable DNSSEC validation
   |     2. Find the poisoning source (logs/pcap), block; review which clients got bad answers
   |
   |-- LOCAL NETWORK (rogue DHCP / LLMNR-NBT-NS / WPAD)
   |     1. Capture offers; find MAC -> port (CAM); shut/NAC-block the port after capture
   |     2. Renew leases/flush DNS on affected clients; verify gateway/DNS values
   |     3. Assume credentials/NTLM hashes captured: reset affected users, revoke sessions
   |     4. Host is managed and malicious? --> compromised host: Playbook 1 + core beaconing playbook
   |
   |-- ENDPOINT (hosts file / DNS / proxy settings changed)
         1. EDR-isolate; capture; treat as malware infection
         2. Restore settings; reimage if persistence found
   v
Eradicate, harden (7.7), monitor, close
```

### 7.4 Containment actions

- **Registrar/DNS provider:** contact the provider's security/abuse team (emergency contact in Appendix C); request audit logs and an account freeze.
- **Resolvers:** `Clear-DnsServerCache` (Windows DNS), `rndc flush` (BIND), `unbound-control flush_zone` or restart; clients: `ipconfig /flushdns`.
- **Rogue DHCP:** shut port, enable DHCP snooping with trusted ports only; push corrected leases.
- **Block** known-bad resolver IPs and hijack destination IPs at the firewall; sinkhole attacker domains.
- **User comms** if certificate warnings were possible: do not click through warnings; report.

### 7.5 Evidence checklist

- [ ] Zone files/record history before and after; registrar/DNS provider audit logs and login records
- [ ] Authoritative vs. resolver vs. public answers with timestamps (saved `dig` output)
- [ ] CT log entries (e.g., crt.sh export) for your domains; CAA records
- [ ] Resolver logs, cache dump, version/patch state; NXDOMAIN/SERVFAIL stats
- [ ] DHCP offers pcap, DHCP server logs, switch CAM/DHCP snooping output, offending MAC/port
- [ ] Client network configs (`ipconfig /all`), hosts file, proxy/PAC settings of affected systems
- [ ] List of affected users/systems and the exposure window
- [ ] Responder/LLMNR/NBT-NS evidence (pcap) if LAN poisoning

### 7.6 Queries

Splunk, DNS clients querying resolvers other than the approved internal ones:

```
index=firewall (dest_port=53 OR dest_port=853) earliest=-24h
| search NOT dest_ip IN (10.0.0.53, 10.0.1.53)
| stats count dc(src_ip) as clients by dest_ip
| sort - count
```

Splunk, internal name resolving to an unexpected IP (maintain a lookup of expected answers):

```
index=dns earliest=-4h query="www.example.com"
| lookup expected_dns query OUTPUT expected_ip
| where answer!=expected_ip
| stats count values(answer) by src_ip query expected_ip
```

Windows, find systems with changed DNS servers and hosts-file entries (run via EDR/Intune):

```
Get-DnsClientServerAddress -AddressFamily IPv4 | ? { $_.ServerAddresses -and ($_.ServerAddresses -notcontains "10.0.0.53") }
Get-Content "$env:SystemRoot\\System32\\drivers\\etc\\hosts" | ? { $_ -notmatch "^\\s*#" -and $_.Trim() }
```

### 7.7 Eradication, recovery & hardening

- **Registrar and DNS provider:** MFA (phishing-resistant if available), **registrar/registry lock**, least-privilege accounts, alerts on every zone/NS/contact change, API key hygiene.
- **DNSSEC** signing and validation; **CAA** records restricting certificate issuance; **CT monitoring** with alerts; remove dangling CNAMEs and unused cloud-hosted subdomains.
- **Resolvers:** patched, recursion limited to internal clients, no open resolvers, DNSSEC validation, query logging, response policy zones (RPZ).
- **LAN:** DHCP snooping, DAI, port security, 802.1X; **disable LLMNR, NBT-NS, mDNS and WPAD auto-discovery** via GPO; require SMB/LDAP signing; clients may use only approved resolvers (block external 53/853 and unapproved DoH).
- Endpoint controls: alert on DNS/proxy/hosts-file changes.

### 7.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Public zone or registrar changed | CISO, IC, Network/DNS owner; SEV1 | Immediately |
| MX/mail or login endpoints redirected | Identity team, Legal/DPO, Comms | 30 min |
| Rogue certificates issued | PKI/security; CA revocation requests | 1 h |
| Rogue DHCP/LLMNR on LAN | Network Eng, IC; credential reset plan | 30 min |
| Credentials/NTLM hashes captured | Identity playbooks | Immediately |

### 7.9 Closure criteria

Correct resolution verified from multiple vantage points, registrar/DNS accounts secured and locked, rogue certificates revoked or ruled out, rogue DHCP/poisoning source removed, exposed credentials reset, hardening applied, monitoring in place.

---

## 8. Playbook: Rogue Wi-Fi / Evil Twin

**Scope:** (a) **rogue access point** connected to the wired network (unauthorized employee AP, consumer router, implant); (b) **evil twin / honeypot AP** cloning your SSID to capture credentials or intercept traffic (including WPA2/WPA3-Enterprise lookalikes that harvest MSCHAPv2 credentials); (c) **deauthentication/disassociation attacks** forcing clients onto the rogue AP; (d) unauthorized mobile hotspots and bridged clients.

**Default severity:** SEV4 explained unauthorized AP (no abuse) → SEV3 rogue AP on the wired network or unexplained SSID clone → SEV2 evidence that clients associated with an evil twin or credentials were exposed → SEV1 privileged or many users exposed, or rogue AP bridging to sensitive VLANs.

### 8.1 Detection sources

WIPS/WLC rogue and **SSID-spoof** alerts, unknown **BSSID** advertising your SSID, deauthentication-frame floods, channel/band anomalies, users reporting repeated password/captive-portal prompts or certificate warnings on known Wi-Fi, RADIUS logs with authentication attempts to a RADIUS server you do not operate, wired-side detection (AP-vendor OUI on an access port, unknown DHCP clients), signal found in unexpected locations (parking lot, floor with no AP).

### 8.2 Triage (first 30 minutes)

1. Record **SSID, BSSID, channel, band, security type (open/WPA2/WPA3/Enterprise), RSSI, vendor OUI, first seen**, from WIPS/WLC or a monitor-mode capture.
2. **Wired or not?** Search switch CAM tables for a MAC adjacent to the BSSID (APs often use the wired MAC +/- a small offset) and for unknown DHCP clients. Wired = rogue AP on your LAN; not wired = evil twin or neighbor/hotspot.
3. **Locate it:** triangulate with your APs' RSSI, a directional antenna or handheld survey tool; involve physical security.
4. **Who connected?** WLC association logs, DHCP leases on the rogue's subnet if wired, RADIUS logs. For an Enterprise evil twin, any client that does not validate the server certificate may have leaked an MSCHAPv2 exchange (crackable) and should be treated as credential exposure.
5. **Intent:** employee convenience (benign but policy violation) vs. malicious (cloned SSID, deauth activity, hostile location, hardware implant).

### 8.3 Decision tree

```
[WIPS/WLC rogue or SSID-clone alert / user report]
   |
   v
Capture details (SSID, BSSID, channel, RSSI, security type); start monitor-mode capture if possible
   v
Is the AP connected to the wired network?
   |-- YES (rogue AP on LAN)
   |     1. Find the switch port from the CAM table; capture state; shut/NAC-block the port
   |     2. Locate and recover the device (photograph in place, chain of custody; do not power on)
   |     3. Employee device? --> policy handling via HR/manager; malicious/implant? --> SEV2, physical-security and Legal
   |-- NO (evil twin / external)
         v
   Any of your clients associated with it, or credentials exposed?
         |-- YES / UNKNOWN --> SEV2: identify users via WLC/RADIUS logs; reset credentials, revoke sessions;
         |                    check for follow-on logins from outside; Identity playbooks
         |-- NO --> SEV3: monitor, notify users, strengthen client validation
         v
   Containment of an external AP: locate, involve physical security and landlord/property management; report to the regulator or law enforcement.
   Active wireless containment (deauth/jamming) can be unlawful when it affects other people's networks: only on your own authorized
   premises/spectrum and only with Legal sign-off
   v
   Harden (8.6), monitor, close
```

### 8.4 Containment actions

- **Wired rogue AP:** capture CAM/ARP/DHCP first (Playbook 4.4 commands), then shut the port or NAC-block; remove the device.
- **Evil twin:** notify users (do not connect to unexpected networks, report certificate prompts); reset credentials for users who associated or authenticated via it; enforce certificate validation for Enterprise Wi-Fi (below).
- **Controller-based containment** (WIPS "contain" feature) only after Legal confirms it is limited to your own premises and rogue devices on your wired network.
- **Guest/open networks:** ensure they cannot reach internal VLANs; rate limit and isolate clients.

### 8.5 Evidence checklist

- [ ] WIPS/WLC alerts and timeline; BSSID/SSID/channel/RSSI/security details
- [ ] Monitor-mode pcap (beacons, deauth frames, association and EAP exchanges) from a compatible capture adapter
- [ ] WLC association logs, RADIUS/802.1X logs for affected users (and any RADIUS servers you do not own)
- [ ] Switch CAM/ARP/DHCP outputs if wired; port history
- [ ] Physical device: photos, location, labels, chain of custody, hashed storage image if recovered
- [ ] Location survey notes (RSSI map, direction), CCTV/badge records if permitted
- [ ] List of users/devices that associated; credential-reset record

### 8.6 Eradication, recovery & hardening

- Remove rogue devices; reset exposed credentials; verify no persistence from a hardware implant.
- **WPA3-Enterprise or WPA2-Enterprise with EAP-TLS** (certificate-based client auth, no passwords to harvest); push **server-certificate validation** (pin the RADIUS CA and server name) through MDM/GPO so clients refuse lookalike servers.
- Enable **Protected Management Frames (802.11w)** to blunt deauth attacks; WIPS with rogue detection and SSID-spoof alerts; periodic wireless site surveys.
- Wired side: **802.1X/NAC and port security** so a plugged-in AP cannot bridge; disable unused ports; locked closets.
- Separate guest SSID with client isolation and no internal reach; avoid captive portals that train users to type credentials.
- Policy: no personal APs/hotspots bridged to corporate LAN; user guidance on unexpected Wi-Fi prompts.

### 8.7 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Rogue AP on wired LAN | Network Eng + IC; physical security | 30 min |
| Evil twin with client associations | Identity team (resets), CISO | 30 min |
| Hardware implant suspected | Legal, physical security, law enforcement; Playbook 4 | 1 h |
| Executives/privileged users exposed | CISO; SEV1 | 15 min |

### 8.8 Closure criteria

Rogue/evil-twin source removed or neutralized lawfully, exposed credentials reset, wired access controls in place, client certificate validation enforced, WIPS tuned, users informed.

---

## 9. Appendices

### Appendix A: Network containment command cheat sheet

**Windows host firewall (via EDR/GPO)**

```
New-NetFirewallRule -DisplayName "IR-<ID> block outbound to C2" -Direction Outbound -RemoteAddress 203.0.113.10 -Action Block
New-NetFirewallRule -DisplayName "IR-<ID> block inbound SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block
Get-NetFirewallRule -DisplayName "IR-*" | Remove-NetFirewallRule    # rollback
```

**Linux**

```
iptables -I INPUT -s 203.0.113.50 -j DROP        # or: nft add rule inet filter input ip saddr 203.0.113.50 drop
iptables -I OUTPUT -d 203.0.113.10 -j DROP
ip link set eth0 down                            # last resort; loses remote access
```

**Cisco IOS-style switch**

```
interface Gi1/0/12
 description IR-<ID> QUARANTINED
 shutdown
ip access-list extended IR-QUARANTINE
 permit ip host 10.1.2.3 host 10.0.0.53
 deny ip host 10.1.2.3 any log
```

**DNS sinkhole / RPZ (BIND RPZ example records)**

```
evil.example CNAME .          ; returns NXDOMAIN for the domain
*.evil.example CNAME .
```

Every rule: ticket ID in the name, owner, expiry date, rollback command recorded in the incident log.

### Appendix B: Capture and evidence procedures

- **Where to capture:** SPAN/mirror port, network TAP, or on the host. A host capture sees only its own traffic. Mirror ports can drop packets under load; TAPs are lossless.
- **Rolling capture to disk (keep evidence storage separate from production):**

```
tcpdump -i eth0 -nn -s 0 -w /evidence/cap.pcap -C 100 -W 20 'host 10.1.2.3'
tcpdump -i eth0 -nn -s 96 -c 20000 -w /evidence/sample.pcap     # header-only sample (DDoS)
sha256sum /evidence/*.pcap > /evidence/hashes.txt
```

- **Zeek over a pcap:** `zeek -r cap.pcap` produces conn/dns/http/ssl/smb logs for fast triage.
- **Wireless:** monitor-mode capture needs a compatible adapter; capture the channel(s) of interest and record channel and location.
- **Content capture rules:** capture the minimum needed (headers or targeted hosts), restrict storage access, encrypt evidence at rest, get Legal approval before capturing user content or encrypted/consumer traffic outside company infrastructure, and note the retention period.
- **Network device state:** export `show` output (CAM/ARP/DHCP snooping/ACL counters/config) **before** changes; save with timestamps and hashes.
- **Chain of custody:** who/what/when/where/tool/hash for every file and every physical device.

### Appendix C: Escalation matrix

| Role | Primary | Backup | Phone | Out-of-band |
| --- | --- | --- | --- | --- |
| Incident Commander | `<NAME>` | `<NAME>` | `<PHONE>` | `<SIGNAL/BRIDGE>` |
| Network Engineering lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| SRE / platform on-call | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| CISO | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Identity / IAM lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Legal / DPO | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Comms lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Physical security | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| ISP / DDoS scrubbing emergency line | `<VENDOR>` |  | `<PHONE>` | Account/circuit IDs: `<IDS>` |
| CDN / WAF provider | `<VENDOR>` |  | `<PHONE>` |  |
| Registrar / DNS provider security contact | `<VENDOR>` |  | `<PHONE>` |  |
| Edge-device vendor PSIRT / support | `<VENDOR>` |  | `<PHONE>` | Contract #: `<NUMBER>` |
| IR retainer / cyber insurer | `<VENDOR>` |  | `<PHONE>` | Policy #: `<NUMBER>` |
| Law enforcement / national CERT | `<AGENCY>` |  | `<PHONE>` |  |

Keep a printed and offline copy and test the ISP/scrubbing contact at least twice a year.

### Appendix D: Communication templates

**Internal initial notice (SEV1/SEV2)**

> Subject: \[SECURITY INCIDENT IR-YYYY-NNN\] Network incident, action required. We are responding to `<TYPE>` affecting `<SCOPE>`. Effective immediately: `<ACTION>`. Do not discuss on affected channels; use `<CHANNEL>`. Next update at `<TIME UTC>`.

**Customer status page (DDoS/outage)**

> We are experiencing degraded availability of `<SERVICE>` since `<TIME UTC>` due to abnormal traffic. Mitigation is in progress. Data is not known to be affected. Next update by `<TIME UTC>`.

**Users (rogue Wi-Fi / DNS / certificate warnings)**

> Between `<TIME>` and `<TIME>` some people may have seen unexpected Wi-Fi sign-in prompts or certificate warnings. Do not click through certificate warnings; if you entered your password after such a prompt, contact Security at `<CONTACT>` so we can secure your account. You are not in trouble; quick reporting helps.

**Executive update (every cycle)**

> Status: `<contained/not>` · Scope: `<hosts/segments/services>` · Data or service impact: `<...>` · Actions in progress: `<...>` · Decisions needed: `<...>` · Next update: `<TIME UTC>`.

### Appendix E: Authorized-testing and scanning register

Maintain a register that SOC analysts can check in under a minute. Allowlist scanners in detections by **source IP and time window**, not by IP alone.

| Field | Example |
| --- | --- |
| Activity ID / ticket | `PT-2026-014` |
| Type | Internal vuln scan / pentest / red team / asset discovery |
| Source IPs / hosts | `10.20.5.10`, `203.0.113.77` |
| Targets / scope | `10.30.0.0/16` |
| Window (UTC) | `2026-12-02 08:00 – 18:00` |
| Owner and contact (phone) | `<NAME>` `<PHONE>` |
| Approval / authorization reference | `<LINK>` |
| Deconfliction notes | Notify SOC before start and after end; stop word: `<WORD>` |

### Appendix F: Notification clock checklist (Legal/DPO)

- [ ] Time of awareness of likely personal-data exposure (UTC): `____`
- [ ] Data/systems reached by lateral movement or exfil; categories and volume: `____`
- [ ] Applicable regimes (GDPR, Kenya Data Protection Act, sector rules, customer contracts, insurer): `____`
- [ ] Regulator deadline (commonly 72 h from awareness; confirm with counsel): `____`
- [ ] Individuals/customers to notify and deadline: `____`
- [ ] Law enforcement/CERT report reference: `____`
- [ ] Contractual availability SLAs breached by DDoS or outage (credits/notices): `____`

### Appendix G: Readiness checklist (do before the incident)

- [ ] **Baselines:** normal traffic volume per host/segment, normal DNS volume, normal east-west admin paths, expected DHCP/DNS servers
- [ ] **Telemetry:** NetFlow/IPFIX from edge and core, firewall logs, DNS and proxy logs with bytes, DHCP logs, Zeek/Suricata at key chokepoints, switch logs, VPN/edge logs, EDR network events; all in SIEM with 90+ days retention and NTP sync
- [ ] **Segmentation:** user VLANs cannot reach server management ports; servers default-deny outbound; separate management, guest, IoT and VPN segments
- [ ] **Egress control:** DNS only to internal resolvers, DoH/DoT controlled, proxy-only web, outbound allowlists for servers
- [ ] **Access-layer security:** 802.1X/NAC, port security, DHCP snooping, DAI, disabled unused ports
- [ ] **East-west hardening:** LAPS, SMB signing, SMBv1 off, jump hosts for RDP/WinRM/SSH with MFA, LLMNR/NBT-NS/mDNS/WPAD off
- [ ] **Edge devices:** inventory with firmware versions, patch SLA in days for KEV/critical, no internet-exposed management, off-box logging, config backups with diff alerts
- [ ] **DDoS:** always-on protection or tested on-demand mitigation, origin hidden, runbook and contacts tested, BCP38/uRPF, no open amplifiers
- [ ] **DNS:** registrar lock + MFA, DNSSEC, CAA, CT monitoring, dangling-record cleanup
- [ ] **Wireless:** WIPS, EAP-TLS or WPA3-Enterprise with certificate validation enforced, PMF enabled, guest isolation
- [ ] **Capture capability:** TAPs/SPAN ports at chokepoints, capture host with storage, procedures and Legal pre-approval for capture
- [ ] **Registers:** authorized-testing register, asset inventory/CMDB linked to NAC
- [ ] Tabletop exercises per playbook at least annually (DDoS and edge-device compromise with executives and the ISP)

### Appendix H: Quick reference

| Situation | First action |
| --- | --- |
| Suspicious remote logons / PsExec | Hop graph, EDR-isolate source, disable account, block east-west SMB/RDP/WinRM |
| Large unexplained upload | Isolate host, block destination after isolation, preserve flows/proxy/staged files, find what data |
| DNS tunneling suspected | Sinkhole parent domain, force internal resolvers only, isolate the client, pcap sample |
| Internal scan from a user host | Check the register; if unregistered, isolate host and treat as lateral-movement precursor |
| External scan | Usually noise: block time-boxed, check exposure, watch for follow-on |
| Unknown device / MAC flap | Capture CAM/ARP/DHCP first, then shut port or NAC block; locate and recover device |
| ARP spoofing confirmed | Remove source from path, flush ARP caches, reset credentials and sessions for the VLAN window |
| DDoS | Confirm attack, call ISP/CDN/scrubber, WAF rate limits, origin lockdown, RTBH last resort |
| Edge device suspect | Preserve config/logs, restrict management, rotate secrets, rebuild; patch after evidence |
| Public DNS changed | Lock registrar/DNS account, restore records, check CT and certificates, assess interception |
| Rogue DHCP or LLMNR poisoning | Capture, find MAC/port, shut port, reset exposed credentials, disable LLMNR/NBT-NS/WPAD |
| Rogue Wi-Fi / evil twin | Capture details, locate, wired port shutdown if wired, reset exposed credentials, enforce certificate validation |
| Unsure about severity | Treat one level higher; downgrade with evidence |
