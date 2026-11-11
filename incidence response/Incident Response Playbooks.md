# Incident Response Playbooks

Phishing · Brute Force / Password Spray · Ransomware · Malware Beaconing (C2)

Version 2.0 · Owner: Security / IR Lead · Review cadence: every 6 months, after every SEV1/SEV2, and after material changes to identity, email, endpoint, network, or backup controls.

**Operational status:** This is a response framework, not a substitute for environment-specific runbooks or legal advice. Before approval, assign named responders, verify permissions and tool paths, test every query against your actual schema, define business-critical systems, and replace every `<PLACEHOLDER>`. Do not run destructive actions from this document without confirming the target and recording approval.

## 0. Shared Foundation (applies to all four playbooks)

### 0.1 Severity matrix

| Sev | Definition | Examples | Ack SLA* | Update cadence |
| --- | --- | --- | --- | --- |
| SEV1 Critical | Confirmed business-impacting compromise, active spread, or data loss | Ransomware executing, domain admin compromise, confirmed exfil | 15 min | Every 30 min |
| SEV2 High | Confirmed compromise of one or a few assets/accounts, no spread yet | Account takeover with mailbox rules, confirmed C2 on one host | 30 min | Every 1 h |
| SEV3 Medium | Suspicious activity, likely malicious, impact unconfirmed | Phish clicked, no creds entered; spray blocked by MFA | 4 h | Every 8 h |
| SEV4 Low | Policy violation, blocked attempt, no foothold | Phish delivered and reported, nobody interacted | 1 business day | On closure |

\* Ack SLA means the responder acknowledges the alert and an incident owner is assigned; it is not a promise that containment or recovery will be complete in that time. These are proposed internal targets and must be staffed and tested.

Rule: **start high, downgrade with evidence.** Reassess severity when scope or impact changes. The IC records the rationale, approver, and time for every severity change. Raise severity immediately when spread, privileged access, sensitive data exposure, or material business disruption is discovered.

### 0.2 Roles (name a primary and a backup for each)

| Role | Responsibility |
| --- | --- |
| Incident Commander (IC) | Owns the incident, makes containment calls, runs the bridge, keeps the timeline |
| Triage / Analyst | Hands-on investigation, evidence collection |
| Forensics Lead | Disk/memory acquisition, chain of custody |
| IT / Sysadmin Lead | Executes isolation, resets, rebuilds, backups |
| Comms Lead | Internal, customer, regulator and press messaging |
| Legal / DPO | Legal advice, notification obligations, privilege, law enforcement, insurer |
| Business Owner | Approves business-impacting actions (taking a system offline) |
| Scribe | Timestamped log of every decision and action (UTC) |
| Service / System Owner | Explains dependencies, recovery order, acceptable outage, and validation tests |
| Privacy / DPO representative (if separate) | Supports personal-data impact assessment and notification analysis |

### 0.3 Universal rules

1. **Timestamps in UTC.** Log who, what, when, and why for every action.
2. **Preserve before you destroy.** Volatile evidence (memory, connections, running processes) first. Do not reboot, reimage or "clean" until Forensics says go, unless spread is active and containment outranks evidence.
3. **Contain proportionally.** Disable the account or isolate the host. Do not delete anything.
4. **Use out-of-band comms** if you suspect mail or chat is compromised (phone bridge, Signal group, or a pre-built alternate channel).
5. **Assume the attacker is watching** the same channels you are. Keep incident details off the compromised system.
6. **One source of truth:** a single incident ticket/doc ID, `IR-YYYY-NNN`.
7. **Need-to-know.** Share details only with the response team until scope is known.
8. **Authority to act:** document in advance who can isolate endpoints, disable identities, block network paths, and suspend services. At SEV1, the IC may invoke pre-approved emergency authority; notify the Business Owner as soon as practicable. Actions with material safety, production, clinical, or critical-service consequences require the designated emergency decision path.
9. **No unilateral external messaging:** only the Comms Lead, with Legal approval, issues customer, regulator, media, or public statements.
10. **Safety and continuity first:** protect people and essential services. If containment could create a safety risk or a larger outage, the IC and System Owner choose the least harmful effective control and document the trade-off.
11. **Record confidence:** label findings as confirmed, likely, possible, or not observed. Absence of logs is not proof that activity did not occur.

### 0.4 Evidence handling (all playbooks)

- Hash every artifact on collection: `sha256sum <file>` (Linux) or `Get-FileHash -Algorithm SHA256 <file>` (Windows). Record in the evidence log.
- Store in write-restricted evidence storage, not on the affected host or a user share.
- Chain of custody: who collected, from where, when (UTC), tool and version, hash, who has accessed it.
- Collection order is situation-dependent. A useful default is memory and volatile process/network state, then relevant live logs/configuration, then disk images and backups. Do not delay urgent containment to complete collection.
- Record clock source and any known time skew. Preserve original timestamps and document any conversion to UTC.
- For cloud/SaaS evidence, export audit records promptly because retention and availability may be limited. Record tenant, query, time range, export time, and actor.
- Do not upload confidential files, memory images, or customer data to public analysis services. Use approved private analysis or submit hashes only.
- Work on copies. Never analyze the original.

**Evidence log template**

| ID | UTC time | Artifact | Source host/system | Collected by | Tool/method | SHA-256 | Stored at | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E-001 |  |  |  |  |  |  |  |  |

### 0.5 First-response control checklist

Before executing a playbook, the IC or delegate confirms:

1. [ ] Incident ID created; severity, detection time, declaration time, and incident owner recorded.
2. [ ] Response channel is trusted; use out-of-band communications if identity, email, or collaboration tools may be compromised.
3. [ ] Affected users, devices, services, business owner, and known dependencies identified.
4. [ ] Immediate risk assessed: active spread, privileged access, sensitive/personal data, financial fraud, safety, and service availability.
5. [ ] Evidence preservation owner assigned; collection must not delay urgent containment.
6. [ ] Containment action, target, expected effect, rollback/recovery path, approver, and execution time recorded.
7. [ ] Next update time and action owners communicated to the response team.

### 0.6 Standard phases used in every playbook

Detect → Triage → Contain → Investigate/Scope → Eradicate → Recover → Lessons Learned. Playbooks list the specific actions at each phase.

### 0.7 Assumed tooling (map to yours)

SIEM (Splunk examples below; KQL examples for Microsoft where noted), EDR, email security/admin console, identity provider, firewall/proxy/DNS, NDR/IDS, backup console, approved sandbox, and threat-intelligence platform. Record the exact product, tenant, permissions, retention, and tested operator account in the local implementation sheet.

**Query warning:** examples are starting points, not copy/paste production detections. Indexes, field names, event coverage, timestamp semantics, and product schemas vary. Validate syntax and results in a test window; preserve the raw events behind every alert. A query returning zero rows does not prove the activity did not occur.

---

## 1. Playbook: Phishing

**Scope:** Reported or detected malicious email (credential harvesting, malware attachment, malicious link, BEC/invoice fraud, QR phishing).

**Default severity:** SEV4 delivered/no interaction → SEV3 clicked → SEV2 credentials entered or attachment executed → SEV1 privileged/finance account compromised or wire fraud in motion.

### 1.1 Detection sources

User report button/mailbox (`phish@<DOMAIN>`), email gateway alert, EDR alert on Office/browser child process, proxy/DNS hit on known-bad domain, IdP risky sign-in, finance/vendor call about unusual payment request.

### 1.2 Triage (first 15 minutes)

1. Preserve the **original message as .eml/.msg with full headers** (never rely on a screenshot or forward-as-body). Record the mailbox and collection method. If immediate purge is necessary, preserve a copy and message trace first where practicable.
2. Extract: sender (display name, envelope-from, Reply-To, Return-Path), `Received` chain, SPF/DKIM/DMARC results, subject, URLs (defang when logging: `hxxps://evil[.]com`), attachment names and hashes, message-ID.
3. Check reputation of URLs, domains, IPs, hashes. Detonate attachments/links **only in a sandbox**.
4. **Scope the blast radius:** who else received it, who opened it, who clicked.
5. Determine user interaction: ask the user (do not blame; ask neutrally), and verify with logs.

### 1.3 Decision tree

```
[Reported email]
   |
   v
Is it malicious? (headers + URL/attachment analysis)
   |-- NO (legit/marketing/spam) --> Reply to reporter, close as benign/spam. Tune rule if needed.
   |-- YES
        v
   Preserve message, trace, and key audit evidence; search mail logs for all recipients
        |
        v
   Did any recipient INTERACT?
        |
        v
   Contain: purge confirmed malicious copies and apply scoped blocks (coordinate owners)
        |-- NO interaction ----------------------------> SEV4. Document, add IOCs to blocklist, close.
        |-- Clicked link only
        |       v
        |   Did the landing page request credentials / drop a file?
        |       |-- Credential page, user entered creds --> go to CREDS ENTERED
        |       |-- Credential page, user did NOT enter --> SEV3. Monitor 7 days; user awareness note.
        |       |-- File downloaded -----------------------> go to ATTACHMENT/FILE EXECUTED
        |-- Opened attachment
                v
          Was it executed / macro enabled / file saved?
                |-- NO --> SEV3. Delete file; scan host; monitor.
                |-- YES/UNKNOWN --> ATTACHMENT/FILE EXECUTED

CREDS ENTERED (SEV2):
   1. Disable account sign-in OR force password reset + revoke all sessions/tokens
   2. Check for MFA method changes, new devices, OAuth app consents
   3. Check mailbox for new inbox rules, forwarding, delegates
   4. Check sign-ins from attacker IP; sent mail from the account
   5. Privileged or finance account? --> escalate to SEV1
   6. Any outbound phishing or fraud sent? --> notify affected recipients/vendors

ATTACHMENT/FILE EXECUTED (SEV2):
   1. EDR-isolate the host
   2. Collect triage package / memory
   3. Hand off to MALWARE BEACONING playbook (Section 4); consider RANSOMWARE playbook if encryption observed
```

### 1.4 Containment actions (do in parallel)

- Purge: Microsoft 365 Compliance/Defender search & purge (soft delete first; hard delete once evidence is preserved), or Google Workspace Email Log Search + Security Investigation Tool to delete.
- Block: sender address/domain, malicious URLs/domains, and file hashes using controls that match the observed indicators. Avoid broad IP/domain blocks that could disrupt shared hosting or legitimate services; set an expiry/review time for temporary blocks.
- If credentials are exposed: use the identity provider's compromised-account procedure to block sign-in or reset credentials, revoke sessions/refresh tokens, review authentication methods, and re-register MFA where needed. Confirm token revocation has taken effect.
- Remove malicious OAuth grants/consents only after recording the app ID, publisher, permissions, consenting identity, and audit evidence. Check for service principals and other users who granted the same app.

### 1.5 Evidence checklist

- [ ] Original .eml/.msg with full headers
- [ ] Message trace results (all recipients, delivery status, actions)
- [ ] URL list + redirect chain + sandbox-captured landing-page evidence (do not browse from a production workstation)
- [ ] Attachment copies + hashes + sandbox report
- [ ] Proxy/DNS logs for each clicker (±48 h)
- [ ] IdP sign-in logs for each credential-exposed account (30 days back)
- [ ] Mailbox audit log: rule creation, forwarding, delegate, sent items
- [ ] OAuth/app consent audit
- [ ] EDR process tree if any attachment opened
- [ ] Interview notes from the user (what they did, when)

### 1.6 Useful queries

The examples below use illustrative field names and placeholders. Replace them with your tenant's schema, validate against known test events, and tune thresholds to normal traffic before alerting or automation.

Splunk, who clicked/visited the phishing domain:

```
index=proxy (url_domain="evil.example" OR dest="evil.example")
| stats count min(_time) as first max(_time) as last values(url) by user src_ip
| convert ctime(first) ctime(last)
```

KQL (Defender), delivered recipients of a sender:

```
EmailEvents
| where SenderFromAddress == "attacker@evil.example"
| project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, NetworkMessageId
```

KQL, suspicious inbox rules created recently:

```
CloudAppEvents
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| project Timestamp, AccountDisplayName, RawEventData
```

### 1.7 Eradication & recovery

- Confirm all copies purged (re-run message trace after 1 hour).
- Remove attacker persistence: inbox rules, forwarding, delegates, OAuth grants, added MFA methods.
- Re-enable the account only after reset + MFA re-enrollment verified.
- Monitor affected accounts closely for 14 days (risky-sign-in alerts at high priority).

### 1.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Credentials entered on a phishing page | IC + IT Lead | Immediately |
| Finance/exec/admin account affected | CISO + Legal | 30 min |
| Wire transfer or payment instruction acted on | CFO, bank fraud desk, Legal; start payment recall | Immediately (hours matter) |
| Customer/personal data accessed via mailbox | DPO/Legal (notification clock) | 1 h |
| Executed attachment | Section 4 playbook | Immediately |

Wire fraud: call the bank immediately and ask for a recall/hold; report to national cybercrime unit or law enforcement.

### 1.9 Closure criteria

All copies purged, IOCs blocked, affected accounts reset and clean, no attacker persistence, users informed, rule/detection tuned, ticket documented.

---

## 2. Playbook: Brute Force / Password Spray / Credential Stuffing

**Scope:** Repeated authentication attempts against VPN, SSH/RDP, web apps, email/IdP, or admin panels.

**Distinguish the attack type first, because the response differs:**

| Type | Pattern | Typical signal |
| --- | --- | --- |
| Brute force | Many passwords against one account | Many failures, one user, one or few IPs |
| Password spray | One/few passwords against many accounts | Few failures per user, many users, same source/ASN |
| Credential stuffing | Leaked username:password pairs | Many users, mostly one attempt each, distributed IPs, valid-looking usernames |

**Default severity:** SEV4 all attempts failed/blocked → SEV3 high volume, lockouts impacting users → SEV2 any successful login from attacker → SEV1 successful login to privileged account or evidence of lateral movement/data access.

### 2.1 Detection sources

IdP risky sign-in/impossible travel, SIEM threshold rules, account lockout spikes, WAF/fail2ban, VPN concentrator logs, Windows Event IDs 4625 (failed logon) / 4624 (success) / 4740 (lockout), SSH `auth.log`/`secure`.

### 2.2 Triage (first 15 minutes)

1. Identify the **target service**, **source IPs/ASNs**, **time window**, **usernames targeted**, **user-agent/protocol** (legacy auth such as IMAP/SMTP/EWS is a common bypass of MFA).
2. Classify: brute force, spray, or stuffing (table above).
3. **Find any successes.** This is the most important question. Correlate failures followed by success from the same source/user.
4. Check whether MFA was required and satisfied. Investigate legacy authentication, MFA fatigue, token/session theft, conditional-access exclusions, and unusual device or location context; do not assume a successful login was MFA-protected.

### 2.3 Decision tree

```
[Alert: auth attack pattern]
   |
   v
Any SUCCESSFUL authentication from the attacking source(s)
or from an unfamiliar geo/ASN for the targeted accounts?
   |
   |-- NO
   |     v
   |   Are legit users being locked out / is service degraded?
   |     |-- YES --> SEV3. Apply targeted, time-limited source controls; assess user lockouts and service impact; enable rate limiting / CAPTCHA where appropriate.
   |     |-- NO  --> SEV4. Record sources, apply proportionate controls, tune thresholds, log IOCs, close.
   |
   |-- YES (SEV2)
         v
   Was MFA enforced and satisfied?
         |-- Success WITHOUT MFA (legacy auth / no MFA enrolled) --> account compromised
         |-- Success WITH MFA --> suspect MFA fatigue, SIM swap, session/token theft, or insider; treat as compromised
         v
   CONTAIN account: disable sign-in, revoke sessions/tokens, reset password
         v
   Account privileged / service account / admin?
         |-- YES --> SEV1: IC bridge, hunt for lateral movement and persistence (new admins, keys, tokens)
         |-- NO  --> continue
         v
   Post-login activity: data access, mail rules/forwarding, MFA changes, new devices,
   OAuth consents, VPN sessions, internal logins from that identity
         v
   Evidence of lateral movement, malware, data access?
         |-- YES --> escalate: Malware Beaconing (Section 4) / Data breach assessment
         |-- NO  --> eradicate, monitor 14 days, close
```

### 2.4 Containment actions

- **Edge block:** attacker IPs at WAF/firewall where confidence is high; time-box and review blocks because attackers rotate and shared IPs/ASNs can host legitimate users.
- **Targeted accounts:** force MFA, reset passwords for confirmed-compromised accounts only (a mass reset can break services and alert the attacker).
- **Disable legacy authentication** (Basic Auth for IMAP/POP/SMTP/EWS); require modern auth + MFA.
- **Conditional access:** apply risk-based location/device policies only after checking legitimate travel, VPN egress, partners, and service dependencies. Prefer targeted policies over broad country/ASN blocks.
- **Exposed services:** take RDP/SSH off the public internet (VPN/bastion/ZTNA); enable fail2ban or equivalent; key-only SSH.
- Check **credential reuse**: if the password was in a leak, check the same identity on other systems.

### 2.5 Evidence checklist

- [ ] Raw auth logs (IdP, VPN, server, WAF) for the full attack window ±24 h, exported and hashed
- [ ] List of source IPs, ASNs, geo, user-agents, protocols
- [ ] List of targeted usernames (spray lists often reveal the attacker's source: staff directory, leaked data)
- [ ] All successful auth events with MFA result and device info
- [ ] Post-login activity for each compromised identity (30 days back if possible)
- [ ] Account change log: password, MFA method, recovery email/phone, devices, app consents
- [ ] Mailbox rules/forwarding/delegates for compromised accounts
- [ ] Breach-intel check for the targeted identities

### 2.6 Useful queries

The examples below assume normalized authentication fields. Confirm whether your source records one event per attempt, how it represents MFA, and how NAT/VPN/proxy addresses are handled.

Splunk, password spray (many users, few attempts each, one source):

```
index=auth action=failure earliest=-4h
| stats dc(user) as users count as attempts by src_ip
| where users > 15
| sort - users
```

Splunk, brute force then success:

```
index=auth (action=failure OR action=success) earliest=-4h
| sort 0 _time
| streamstats current=f count(eval(action="failure")) as fails by user, src_ip
| where action="success" AND fails > 10
```

Windows: failed logons by source (PowerShell):

```
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddHours(-4)} |
  ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data |
    Where-Object Name -eq 'IpAddress' | Select -Expand '#text' } |
  Group-Object | Sort Count -Desc | Select -First 20
```

Linux SSH:

```
grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head
grep 'Accepted' /var/log/auth.log | tail -50
```

### 2.7 Eradication & recovery

- Remove attacker persistence (new MFA methods, app passwords, OAuth grants, SSH keys, forwarding rules, new local/domain users).
- Re-enable accounts after verified clean reset + MFA re-enrollment.
- Harden: MFA everywhere, number-matching/phishing-resistant MFA for admins, disable legacy auth, smart lockout, breached-password protection, remove stale accounts.
- Add detections: spray threshold, impossible travel, successful login after N failures.

### 2.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Any confirmed successful attacker login | IC + IT Lead | Immediately |
| Privileged/service/admin account | CISO; IC bridge; treat as SEV1 | 15 min |
| Evidence of data access/exfil | Legal/DPO | 1 h |
| Credential stuffing against customer-facing auth | Product owner, Comms, Legal | 1 h; force customer resets as needed |
| Persistent attack from one actor | Threat intel/ISP abuse/law enforcement as appropriate | Next business day |

### 2.9 Closure criteria

Source blocked, all successes investigated and resolved, compromised identities reset and clean, legacy paths closed, detections added, lessons recorded.

---

## 3. Playbook: Ransomware

**Scope:** Encryption of files, ransom notes, mass file renames, or pre-ransomware indicators (backup deletion, mass AV disablement, domain-wide tooling deployment).

**Default severity: SEV1 from the moment encryption is suspected.** Do not wait for certainty.

**Time matters most.** Operators often hold access for days and encrypt in hours (commonly overnight or on weekends). The first 30 minutes decide how much is lost.

### 3.1 Detection sources

EDR ransomware/behavior alerts, user reports of renamed/unopenable files and a ransom note, file server alerts (mass modification), `vssadmin delete shadows` / `wbadmin delete` / `bcdedit` recovery-disabling commands, canary file alerts, backup system alerts, mass AV/EDR tamper events, high-volume SMB writes.

### 3.2 First 30 minutes: stop the bleeding

The order below is a priority guide, not a rigid sequence. Assign separate responders to containment, backup protection, evidence, and business continuity where staffing permits.

1. **Declare SEV1**, open the incident bridge and an out-of-band comms channel. Assume email and AD may be compromised.
2. **Isolate affected hosts and affected network paths** using EDR containment or network controls. Confirm isolation from the console; do not assume a command succeeded. Keep power on where feasible to preserve volatile evidence.
3. **Do not reboot or power off by default.** Memory may contain keys and forensic evidence. If encryption continues and no effective isolation is available, the IC may authorize a power-off to limit damage; record who decided, why, when, and the evidence lost or preserved.
4. **Protect backups now:** restrict backup-console access, disable suspected compromised backup identities, isolate backup management paths, and protect immutable/offline copies. Do not indiscriminately disconnect storage or interrupt a backup/restore job without checking dependencies; preserve backup audit logs.
5. **Cut likely lateral paths:** apply targeted segmentation controls for SMB, RDP, WinRM, remote management, and attacker-controlled VPN/remote-access identities. Broad port blocks can disrupt operations; coordinate with the System Owner and record exceptions.
6. **Stop encryption reaching shares:** disconnect or lock file shares and NAS from compromised clients.
7. **Preserve VM state** using an approved hypervisor snapshot or forensic acquisition when safe and supported. A snapshot is not a substitute for a forensic disk image and may alter storage state; document the method and consult the Forensics Lead.
8. Notify IC, CISO, Legal, Business Owner, IT Lead. Engage your **cyber insurer and IR retainer** (check policy: many require notification and pre-approved vendors before you spend or negotiate).

### 3.3 Decision tree

```
[Suspected ransomware]
   |
   v
Is encryption actively happening or ransom note present?
   |-- NO (pre-ransomware indicators only: shadow copy deletion, mass tooling, AV tamper, domain admin abuse)
   |       v
   |   Treat as SEV1-imminent: isolate suspect hosts, rotate privileged credentials,
   |   disable attacker accounts, hunt (3.5).
   |-- YES
        v
   ISOLATE affected hosts + segments (3.2). Protect backups.
        v
   Is the domain controller / hypervisor / backup infra affected?
        |-- YES --> Critical: assume full domain compromise. IC bridge, retainer on the call,
        |           plan staged rebuild (3.6).
        |-- NO  --> Scope with EDR/SIEM; keep containment tight.
        v
   Identify: family (note text, extension, ID-Ransomware, sample hash), patient zero,
   initial access, exfil evidence.
        v
   Was data EXFILTRATED (double extortion)?
        |-- YES/UNKNOWN --> Legal/DPO: breach notification analysis starts now. Preserve flow/proxy/cloud logs.
        |-- NO --> still preserve evidence; continue.
        v
   Clean, intact, offline/immutable backups available and verified?
        |-- YES --> restore into a clean environment (3.6). NEVER restore onto infected hosts.
        |-- NO  --> executive/legal decision on options (3.7). Check public decryptors (nomoreransom.org).
        v
   Remove attacker access BEFORE restoring, or you will be re-encrypted.
```

### 3.4 Evidence checklist

- [ ] Ransom note(s) (copy + screenshot), several encrypted file samples, extension
- [ ] Malware sample(s)/dropper hashes, scheduled tasks/services/startup items
- [ ] Memory image of at least one affected host (before reboot) and of suspected patient zero
- [ ] Disk image / EDR triage package of patient zero and key hosts
- [ ] EDR process trees and timeline for all affected hosts
- [ ] Windows event logs (Security, System, PowerShell Operational, Sysmon, TaskScheduler, TerminalServices), exported
- [ ] AD logs: DC security logs, new accounts/group changes, GPO changes, Kerberos anomalies (4768/4769/4672/4720/4728/4732)
- [ ] VPN, firewall, proxy, DNS, NetFlow logs (30 days or more if available) for initial access and exfil
- [ ] Cloud/SaaS audit logs (M365, Google, AWS/Azure/GCP) for key abuse and exfil
- [ ] Backup system logs (deletion events, who logged in, when)
- [ ] Attacker tooling (Cobalt Strike, AnyDesk/ScreenConnect, Rclone, Mimikatz, PsExec, AdFind, Advanced IP Scanner): names, hashes, paths
- [ ] Timeline: initial access → privilege escalation → lateral movement → exfil → encryption

### 3.5 Investigation / scoping questions

1. **Initial access:** phishing, exposed RDP/VPN without MFA, exploited edge device (VPN/firewall/Exchange), compromised vendor/MSP, malicious download?
2. **Dwell time:** earliest attacker activity. Hunt back 30–90 days.
3. **Privilege:** which privileged accounts were used? Domain admin? Which servers touched?
4. **Persistence:** new users, scheduled tasks, services, RMM tools, GPOs, remote access tools, web shells.
5. **Exfil:** large outbound transfers, cloud storage (Mega, Rclone), FTP, unusual DNS volume.
6. **Blast radius:** which systems, shares, VMs, databases and SaaS tenants are encrypted or exposed.

Splunk hunts:

```
// Recovery-inhibiting commands
(index=wineventlog OR index=sysmon) (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wbadmin*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*wmic*shadowcopy*delete*")
| table _time host user ParentImage Image CommandLine

// Mass file creation/modification on a host (Sysmon EventCode 11; tune the threshold)
index=sysmon EventCode=11 earliest=-1h
| bin _time span=1m
| stats count by _time host
| where count > 1000

// Large outbound volume per internal host (exfil candidate)
index=firewall action=allowed direction=outbound earliest=-7d
| stats sum(bytes_out) as bytes by src_ip dest_ip
| where bytes > 5000000000
| sort - bytes
```

### 3.6 Eradication & recovery

**Do not rush restoration.** Restoring before removing attacker access means re-infection.

1. **Remove access:** disable attacker accounts, close the initial access vector (patch, enforce MFA, remove exposed RDP), remove persistence and RMM tools.
2. **Credential reset (if AD is compromised):** plan a coordinated rotation with the identity/domain recovery lead. Prioritize privileged identities, service accounts, local administrator credentials, and user accounts according to exposure. If KRBTGT rotation is required, follow current Microsoft guidance, verify AD replication health, and observe the required interval between resets; do not run a generic reset sequence blindly. Revoke cloud sessions/tokens and rotate exposed secrets, certificates, API keys, and SSH keys as applicable.
3. **Rebuild, don't clean:** reimage affected endpoints and rebuild servers from known-good media. If identity infrastructure or domain controllers are compromised, use a documented forest/domain recovery plan and clean administrative workstations; do not simply restore a DC snapshot or promote an untrusted backup.
4. **Restore data** only from backups whose integrity and recovery point have been assessed. Test restores in an isolated environment, scan and validate data, confirm the backup is not contaminated by attacker persistence, and have the System Owner verify application-level integrity.
5. **Staged reconnection:** reconnect in a documented dependency order approved by the Business Owner and technical recovery leads. Validate identity, endpoint protection, logging, network controls, backups, and business transactions before expanding access.
6. **Heightened monitoring** for 30 days or more: re-entry attempts are common.

### 3.7 Extortion/payment decision (executives and Legal only)

Analysts do **not** negotiate or pay. Decision owner: executive leadership with Legal, insurer and IR retainer.

- Sanctions exposure: paying designated groups can be illegal (e.g., OFAC in the US); Legal runs the check.
- Payment does not guarantee decryption or deletion of stolen data.
- Contact law enforcement regardless (they may hold decryptor keys or intelligence).
- Check public decryptors first (nomoreransom.org).
- Document the decision and rationale.

### 3.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Any suspected encryption | IC, CISO, IT Lead, Business Owner | Immediately |
| Insurer / IR retainer | Via Legal/CISO per policy terms | 1 h |
| DC, hypervisor or backups affected | Executive leadership | Immediately |
| Possible data exfil / personal data | Legal/DPO, Comms | 1 h |
| Regulators | Legal/DPO | Applicable statutory deadline; confirm trigger and jurisdiction with counsel |
| Law enforcement | Legal | Same day (national CERT/cybercrime unit, FBI/IC3 in the US, etc.) |
| Customers/partners/press | Comms Lead + Legal approval | As decided |

### 3.9 Closure criteria

Attacker access removed and verified, all systems rebuilt/restored and validated, credentials rotated, 30 days of enhanced monitoring with no recurrence, regulatory obligations met, root cause fixed, post-incident review held.

---

## 4. Playbook: Malware Beaconing (C2)

**Scope:** A host (or hosts) making periodic outbound connections to attacker infrastructure, indicating an implant (RAT, loader, Cobalt Strike/Sliver/Havoc beacon, info stealer).

**Default severity:** SEV3 unconfirmed beacon-like traffic → SEV2 confirmed malicious C2 on a host → SEV1 beaconing from a server/privileged host/multiple hosts, or evidence of lateral movement/exfil.

### 4.1 Detection sources

EDR alerts, DNS logs (DGA, long TXT queries, high-entropy domains, newly registered domains), proxy/firewall logs, NDR/IDS (Suricata/Zeek), threat intel match, beacon analytics (fixed-interval connections with jitter), TLS fingerprints (JA3/JA4), unusual user-agent strings, rare-destination analysis.

### 4.2 Triage (first 30 minutes)

1. Identify the **host, user, process, destination (IP/domain/URL), port, protocol, interval, bytes in/out**.
2. **Validate:** is it really malicious? Check for legitimate periodic software (updaters, telemetry, RMM, monitoring agents, NTP, VPN keepalives). Check destination reputation, domain age, hosting, certificate, ASN.
3. Pull the **process behind the connection** (EDR or `netstat`/`ss` + PID → process → parent → path → signature → hash). Unsigned binary, odd path (`%AppData%`, `/tmp`, `/dev/shm`), or a legitimate process with injected code are red flags.
4. **Scope:** same destination or pattern from other hosts? Same hash elsewhere?

### 4.3 Decision tree

```
[Beacon-like traffic / alert]
   |
   v
Explained by a known legitimate application/service?
   |-- YES --> Document, baseline/allowlist, close (SEV4).
   |-- NO / UNSURE
        v
   Destination reputation / process analysis / sandbox result malicious?
        |-- Clearly benign --> close, tune.
        |-- Malicious OR still suspicious
              v
        ACT NOW: EDR network-isolate host (or block destination at firewall/DNS if isolation not possible)
              v
        Which asset is it?
              |-- Standard workstation ---------------------------------> SEV2
              |-- Server / admin workstation / DC / jump host / many hosts --> SEV1, IC bridge
              v
        Collect evidence, memory first (4.5)
              v
        Scope: same IOC on other hosts? Lateral movement? Credential theft? Exfil?
              |-- YES --> expand containment to all affected hosts; reset exposed credentials;
              |           treat as ransomware precursor (Section 3 pre-ransomware branch)
              |-- NO  --> single-host response
              v
        Identify initial access (phish, drive-by, exposed service, USB, supply chain)
              v
        Eradicate: reimage (preferred over cleaning), reset user + local credentials, block IOCs
              v
        Monitor, then close
```

### 4.4 Containment actions

- **Preferred:** EDR network containment, after confirming the host and business impact. Verify that the EDR control actually isolated the endpoint and understand whether its management channel remains available.
- **Network layer:** after host isolation where possible, block confirmed C2 indicators at DNS/firewall/proxy. If isolation is unavailable and active harm is occurring, block the destination immediately and document the trade-off. Avoid assuming every connection to a shared IP/domain is malicious.
- **Do not** reboot, log out, or run AV cleanup yet. Preserve first.
- **Credentials:** assess credentials and secrets used, stored, or accessed on the host (user/admin/service accounts, browser sessions, API keys, SSH keys, certificates). Rotate confirmed or reasonably suspected exposed secrets after containment, in coordination with service owners to avoid avoidable outages.
- **Server/high-value:** consider failover before isolation to limit business impact (Business Owner sign-off).

### 4.5 Evidence checklist

- [ ] Memory capture (WinPmem/DumpIt/Magnet RAM Capture on Windows; AVML/LiME on Linux) with hash
- [ ] Running processes with parent/child tree, loaded modules, command lines, network connections
- [ ] Malicious binary/script copies + hashes (look up by hash on VirusTotal; do not upload sensitive files)
- [ ] Persistence: Run keys, services, scheduled tasks, WMI subscriptions, startup folder, cron/systemd/launch agents, DLL hijack candidates, SSH `authorized_keys`
- [ ] Disk image or EDR triage collection (KAPE on Windows, UAC/tarball on Linux)
- [ ] Windows logs: Security (4624/4688/4698/7045), Sysmon (1, 3, 7, 8, 11, 13, 22), PowerShell 4104, DNS client
- [ ] DNS/proxy/firewall/NDR logs for the host: full beacon history to find the **first connection**
- [ ] PCAP of beacon traffic if capturable
- [ ] User interview: what happened before first beacon (download, email, USB)
- [ ] Browser history/downloads and email history around first-seen time

Volatile collection, Windows (admin shell, saving to external evidence media):

```
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath | Export-Csv procs.csv
Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv conns.csv
Get-ScheduledTask | Where State -ne 'Disabled' | Export-Csv tasks.csv
Get-CimInstance Win32_Service | Select Name,PathName,StartMode,State | Export-Csv services.csv
ipconfig /displaydns > dnscache.txt
```

Linux:

```
ps auxfww > ps.txt; ss -tupan > conns.txt; lsof -nP -i > lsof.txt
crontab -l; ls -la /etc/cron.* /var/spool/cron; systemctl list-unit-files --state=enabled
find / -xdev -mtime -7 -type f 2>/dev/null | head -500 > recent_files.txt
```

### 4.6 Beacon-hunting queries

Beacon analytics are heuristic: legitimate update agents and monitoring tools can be periodic, while real C2 may use jitter, domain rotation, or low-frequency callbacks. Correlate timing with process lineage, destination reputation, endpoint telemetry, and business context.

Splunk, regular-interval connections (low variance in inter-connection time):

```
(index=proxy OR index=firewall) earliest=-24h
| sort 0 src_ip dest _time
| streamstats current=f last(_time) as prev by src_ip dest
| eval delta=_time-prev
| stats count avg(delta) as avg stdev(delta) as sd by src_ip dest
| where count>50 AND sd < (avg*0.2)
| sort - count
```

Splunk, newly seen domains from a host:

```
index=dns earliest=-7d
| stats earliest(_time) as first count by query src_ip
| where first > relative_time(now(), "-1d") AND count > 20
| convert ctime(first)
```

KQL (Defender), connections to a suspect destination:

```
DeviceNetworkEvents
| where RemoteUrl has "evil.example" or RemoteIP == "203.0.113.10"
| summarize count(), min(Timestamp), max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### 4.7 Eradication & recovery

1. Confirm full scope (all hosts with the IOC) before touching anything.
2. **Reimage** compromised endpoints from the gold image; do not rely on AV cleanup for a confirmed implant.
3. Reset credentials (user, local admin, service accounts, tokens, keys) that touched the host.
4. Patch the entry vector (vulnerable app, exposed service, missing MFA); fix email/web controls if phishing or drive-by.
5. Push IOCs (hashes, domains, IPs, JA3, mutex names, YARA) to EDR, DNS, proxy, firewall, SIEM.
6. Monitor the host and neighbors for 14–30 days.

### 4.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Confirmed C2 on any asset | IC + IT Lead | Immediately |
| Server, DC, admin workstation, or more than one host | CISO; treat as SEV1 | 15 min |
| Lateral movement, credential dumping, or ransomware precursors | Activate Ransomware playbook (Section 3) | Immediately |
| Exfil of sensitive/personal data | Legal/DPO | 1 h |
| Targeted/APT indicators | Threat intel, external IR retainer, CERT/law enforcement | Same day |

### 4.9 Closure criteria

All affected hosts reimaged and verified, IOCs blocked and detections deployed, credentials rotated, entry vector closed, 14–30 days of clean monitoring, root cause documented.

---

## 5. Appendices

### Appendix A: Master escalation matrix

| Role | Primary | Backup | Phone | Out-of-band contact |
| --- | --- | --- | --- | --- |
| Incident Commander | `<NAME>` | `<NAME>` | `<PHONE>` | `<SIGNAL/PHONE BRIDGE>` |
| CISO / Security Head | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| IT / Sysadmin Lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Legal / DPO | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Comms Lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Executive sponsor | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Cyber insurer hotline | `<VENDOR>` |  | `<PHONE>` | Policy #: `<NUMBER>` |
| IR retainer | `<VENDOR>` |  | `<PHONE>` |  |
| Law enforcement / national CERT | `<AGENCY>` |  | `<PHONE>` |  |
| Bank fraud desk | `<BANK>` |  | `<PHONE>` |  |

Keep a printed and offline copy. If the network or email is down, this page must still be reachable.

### Appendix B: Incident ticket template

```
Incident ID: IR-YYYY-NNN     Severity: SEV_    Status: Open / Contained / Eradicated / Closed
Detected (UTC):              Declared (UTC):   Contained (UTC):
IC:                          Scribe:           Bridge/Channel:
Category: Phishing / Brute force / Ransomware / Malware beaconing / Other
Detection source:
Affected: users / hosts / systems / data
Initial access (known/suspected):
Business impact:
Actions taken (timestamped):
Evidence collected (IDs from evidence log):
IOCs (defanged):
Open questions / next actions (owner, due):
Notifications made (who, when, how):
```

### Appendix C: Communication templates

**Internal initial notice (SEV1/SEV2)**

> Subject: \[SECURITY INCIDENT IR-YYYY-NNN\] Action required. We are responding to a security incident affecting `<SCOPE>`. Effective immediately: `<ACTION, e.g., do not open/restart/disconnect X>`. Do not discuss on email or chat; use `<CHANNEL>`. Next update at `<TIME UTC>`. Questions to `<CONTACT>`.

**User phishing advisory**

> A phishing email with subject `<SUBJECT>` from `<SENDER>` was delivered to some staff. If you opened the link/attachment or entered credentials, contact Security immediately at `<CONTACT>`. You will not be penalized for reporting. If you did not interact, ignore it; we have already removed it from mailboxes.

**Executive brief (every update)**

> Status: `<contained/not>` · Impact: `<systems/data/customers>` · Cause (known/suspected): `<...>` · Actions in progress: `<...>` · Decisions needed from you: `<...>` · Next update: `<TIME UTC>`.

### Appendix D: Notification clock checklist (Legal/DPO)

- [ ] Time the organization became *aware* of a likely personal-data breach (UTC): `____`
- [ ] Personal data involved? Categories and volume: `____`
- [ ] Applicable regimes (GDPR, Kenya Data Protection Act, sector rules, contracts/customer SLAs, insurer): `____`
- [ ] Applicable statutory notification deadline and trigger confirmed by Legal/DPO for each relevant jurisdiction: `____`
- [ ] If Kenya applies, assess the Data Protection Act and applicable regulations with the ODPC/DPO; do not assume one deadline applies to every incident, controller, processor, or data-subject notice.
- [ ] Individual notification required? `Y/N`, deadline: `____`
- [ ] Law enforcement / national CERT report considered and, if appropriate, filed: `____`
- [ ] Privilege: IR vendor engaged through counsel where advisable: `Y/N`

### Appendix E: Post-incident review (within 5 business days of closure)

Blameless format. Attendees: IR team, IT, Business Owner, Legal, Comms.

1. Timeline (detection → containment → closure) with MTTD/MTTC/MTTR.
2. What worked and what failed (detection, tooling, access, comms, decisions).
3. Root cause and contributing factors.
4. Were playbook steps followed? Which were wrong, missing or unclear? Update this document.
5. Action items: owner, due date, tracked to closure (e.g., enforce MFA, remove exposed RDP, fix backup isolation, new detection).
6. Lessons for user awareness training.

### Appendix F: Readiness checklist (do this before the incident)

- [ ] Named IC/backup for every role; contact list printed offline
- [ ] EDR on all endpoints/servers with remote network isolation
- [ ] Centralized logs retained 90 days or more (auth, DNS, proxy, firewall, EDR, email, cloud audit); NTP-synced
- [ ] Immutable/offline backups, restore tested in the last 90 days, backup admin separate from domain admin
- [ ] MFA on all remote access, email, admin and cloud consoles; legacy auth disabled
- [ ] Privileged access: tiered admin accounts, LAPS, no daily-use admin accounts
- [ ] Phishing report button and purge capability tested
- [ ] Forensics kit ready: memory capture tools, write-blocker, external evidence drives, KAPE/UAC, blank hash log
- [ ] Cyber insurance policy reviewed, IR retainer signed, legal counsel identified
- [ ] Tabletop exercise per playbook at least twice a year (ransomware at least annually, with execs)
- [ ] Out-of-band comms channel pre-created and tested

### Appendix G: Quick reference

| Situation | First action |
| --- | --- |
| Phish reported | Get the .eml, check recipients, purge, block |
| Creds entered | Disable sign-in, revoke sessions, check mailbox rules and MFA changes |
| Successful login after spray | Disable account, revoke tokens, hunt post-login activity |
| Encryption in progress | EDR-isolate, protect backups, do not reboot, declare SEV1 |
| Beacon confirmed | Isolate first, then block C2, memory capture, scope other hosts |
| Unsure about severity | Treat one level higher; downgrade later |


### Appendix H: Decision and action log

| UTC time | Decision / action | Target / scope | Reason and evidence | Risk / expected impact | Approver | Executed by | Result / verification |
| --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |  |

### Appendix I: Recovery validation and hand-back

Do not close an incident solely because alerts stopped. For each affected service or asset, record:

- [ ] Asset/service owner accepts the recovery and confirms business functionality.
- [ ] Initial access vector is closed and the fix is verified (not merely planned).
- [ ] Persistence checks completed; identity, endpoint, network, and cloud telemetry show no unexplained recurrence.
- [ ] Credentials, tokens, keys, certificates, and secrets assessed and rotated where exposed.
- [ ] EDR/AV, firewall, DNS, logging, backup, and alerting controls are active and reporting.
- [ ] Restored data and critical transactions are validated by the business owner.
- [ ] Temporary blocks, emergency accounts, firewall exceptions, and containment controls have an owner and expiry/review date.
- [ ] Outstanding risks, compensating controls, and accepted residual risks are documented.
- [ ] Monitoring owner, duration, alert thresholds, and escalation contact are named.
- [ ] Lessons-learned actions have owners, due dates, and tracking references.

**Closure approval:** Incident Commander: `____` · System Owner: `____` · Business Owner: `____` · Closure UTC: `____`

### Appendix J: Local implementation register

Complete and test this register before declaring the playbook operational.

| Capability | Local tool / console | Named operator / backup | Required permission | Tested on (UTC) | Evidence / runbook link |
| --- | --- | --- | --- | --- | --- |
| SIEM search/export |  |  |  |  |  |
| EDR isolate / collect |  |  |  |  |  |
| Email search / purge |  |  |  |  |  |
| Identity disable / revoke |  |  |  |  |  |
| Firewall / DNS block |  |  |  |  |  |
| Backup isolation / restore |  |  |  |  |  |
| Forensic acquisition |  |  |  |  |  |
| Out-of-band communications |  |  |  |  |  |
| Legal / DPO escalation |  |  |  |  |  |

### Appendix K: Query validation notes

For every SIEM/EDR query in this document, maintain a local tested version with:

1. Product and version / tenant.
2. Actual index, table, and field names.
3. Time range and timezone assumptions.
4. Test event or known-positive validation case.
5. Known false positives and blind spots.
6. Query owner and last-tested date.

Never treat a generic example query as a complete detection rule. Use a controlled test dataset where possible, then validate against known benign activity and a documented positive test before enabling alerting or automated response.
