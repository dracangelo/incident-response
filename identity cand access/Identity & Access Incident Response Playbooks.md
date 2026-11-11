# Identity & Access Incident Response Playbooks

Compromised Account / Credential Stuffing · MFA Fatigue · AiTM Phishing & Token Theft · BEC & Inbox Rules · Malicious OAuth Consent · New Admin / Privilege Escalation · Impossible Travel / Anomalous Login

Version 1.0 · Owner: Security / IR Lead · Review every 6 months and after every SEV1/SEV2. Replace every `<PLACEHOLDER>` before use.

Primary examples target **Microsoft Entra ID / Microsoft 365** (Graph PowerShell, Exchange Online, KQL), with **Okta** and **Google Workspace** notes and **Splunk** where useful. Severity levels, roles, UTC logging and evidence handling are the same as in the core IR playbooks (phishing, brute force, ransomware, beaconing); the essentials are repeated below so this document stands alone.

## 0. Shared Foundation

### 0.1 Severity for identity incidents

| Sev | Identity definition | Ack SLA | Update cadence |
| --- | --- | --- | --- |
| SEV1 | Privileged identity (Global/Domain/Cloud admin, break-glass, CI/CD or service principal with broad rights) compromised, rogue admin created, or active data exfil/fraud in progress | 15 min | 30 min |
| SEV2 | Confirmed standard-user account takeover, malicious OAuth consent granted, malicious inbox rules in place | 30 min | 1 h |
| SEV3 | Suspicious sign-in or prompts, no confirmed attacker success | 4 h | 8 h |
| SEV4 | Blocked attempt, false positive, no impact | 1 business day | On closure |

Rule: **start high, downgrade with evidence.**

### 0.2 Universal identity rules

1. **A compromised identity equals everything it can reach:** mail, files, SSO apps, VPN, cloud consoles, CI/CD. Scope by what the identity could access, not just what it did.
2. **A password reset is not eviction.** Stolen refresh tokens and session cookies survive it. Always **revoke sessions**.
3. **Export logs first.** Identity log retention is short and your own containment actions add noise. Export sign-in, audit and mailbox logs for the user (30 days back) before changing anything.
4. **Attacker persistence lives in identity metadata:** added MFA methods, registered devices, OAuth grants, app credentials, inbox rules, forwarding, delegates, role assignments, federation settings, Conditional Access exclusions. Every account-compromise response runs the persistence sweep (Appendix A).
5. **Verify the user out-of-band.** Call the number in the HR directory, never one from the account's profile or recovery fields (the attacker may have changed them).
6. **Never lock yourself out.** Keep at least two cloud-only emergency (break-glass) admin accounts, excluded from Conditional Access, with an alert on any use. Know where the credentials are before you start disabling admins.
7. **Assume the attacker reads the same mailbox.** Do not discuss the incident in the affected mailbox or in chat sessions that identity can read.
8. **Authority to act:** at SEV1/SEV2 the IC may disable any account, revoke any session and block any app without prior approval; notify the Business Owner immediately after.

### 0.3 Standard containment for a confirmed compromised user

Use this sequence in every playbook that ends in "account compromised".

1. **Export evidence** (sign-in logs interactive + non-interactive, audit logs, Unified Audit Log, mailbox audit) for the user and hash it.
2. **Block sign-in** (disable the account). If disabling would stop a critical process, do steps 3–5 immediately and keep monitoring.
3. **Revoke all sessions/refresh tokens.**
4. **Reset the password** to a random long value; give the new credential to the user by phone only after steps 5–6 are done.
5. **Remove attacker-added authentication methods and devices;** require MFA re-registration with identity verification.
6. **Run the persistence sweep** (Appendix A): inbox rules, forwarding, delegates, OAuth grants, app passwords, role assignments.
7. **Scope reach:** what did this identity access (mail, SharePoint/OneDrive, Teams, SSO apps, VPN, cloud consoles)?
8. **Re-enable** only after verification, then monitor 14 days with elevated alerting.

Note: already-issued access tokens can remain valid until they expire (commonly 60–90 minutes) unless Continuous Access Evaluation (CAE) applies. For critical cases also block the attacker IP and the user in Conditional Access.

### 0.4 Where the evidence lives (verify retention in your tenant and stream to SIEM)

| Source | Gives you | Typical retention |
| --- | --- | --- |
| Entra sign-in logs (interactive and non-interactive) | IP, location, device, app, MFA result, Conditional Access result, user agent | 7 days (free) / 30 days (P1/P2) |
| Entra audit logs | Role changes, consents, app/credential changes, auth-method registration, policy changes | 7 / 30 days |
| Microsoft Purview Unified Audit Log | Exchange/SharePoint/Teams activity, inbox rules, mail access | \~180 days on current licensing |
| Exchange mailbox audit | Mailbox logons, item access, rule changes | Per audit settings |
| Entra ID Protection | Risky users and risk detections (leaked credentials, anomalous token, atypical travel) | 30 days |
| Okta System Log | Auth, MFA push events, admin actions | 90 days |
| Google Workspace Admin/Login/Token audit | Logins, OAuth token grants, admin changes | Up to \~6 months |
| VPN, proxy, DNS, EDR | Device-side corroboration | Per config |

---

## 1. Playbook: Compromised Account / Credential Stuffing

**Scope:** A user (employee or customer) account accessed by someone other than its owner, via leaked, guessed, reused or phished credentials. Includes credential stuffing against your login endpoints.

**Default severity:** SEV4 attempts blocked → SEV3 attack at volume with no success → SEV2 confirmed takeover of standard account → SEV1 privileged/service account, or exfil/fraud in progress.

### 1.1 Detection sources

Entra ID Protection (leaked credentials, unfamiliar sign-in properties, anonymous/malicious IP), SIEM rules (success after N failures, spray threshold), WAF/bot-management alerts on login endpoints, user report ("I didn't do that"), customer complaints and password-reset volume spikes, breach-intel feed matching your domain, fraud team alerts.

### 1.2 Triage (first 15 minutes)

1. Establish **who, what, when:** account, source IP/ASN/geo, user agent, application, protocol, first and last suspicious event (UTC).
2. Determine **success vs. failure.** Look at successful sign-ins from the attacker's IP/ASN/user agent, not only failures.
3. Was MFA **required, satisfied, or bypassed** (legacy auth, no MFA enrolled, claim in token from earlier AiTM)?
4. Check post-login activity: mail access, rules, downloads, MFA changes, OAuth consent, role changes.
5. Classify the **vector:** stuffing (many accounts, one try each, distributed IPs), spray, phished (see Playbook 3), or malware stealer (check endpoint).

### 1.3 Decision tree

```
[Alert / report of suspicious account activity]
   |
   v
Any SUCCESSFUL sign-in from attacker infrastructure or unfamiliar device/location
that the user does not confirm (out-of-band)?
   |-- NO (all failures / blocked / user confirms legit) --> SEV3/4: block sources, tune, monitor, close.
   |-- YES --> SEV2: account compromised. Run Standard Containment (0.3).
        v
   Is it a privileged, service, or break-glass account?
        |-- YES --> SEV1: IC bridge; hunt role changes, new credentials, tokens, federation, CA changes (Playbook 6).
        |-- NO  --> continue
        v
   What did the attacker do after login?
        |-- Mail rules / forwarding / sent mail to vendors ---> Playbook 4 (BEC)
        |-- OAuth app consent granted ------------------------> Playbook 5
        |-- New MFA method / device registered ---------------> remove; check Playbook 3 (token theft)
        |-- Data download / mass file access ------------------> Legal/DPO; scope exfil
        |-- Lateral: logins to other systems with this identity --> expand scope
        |-- Nothing found ------------------------------------> continue
        v
   How did they get the credential?
        |-- Reused/leaked password --> force reset for any other account sharing it; enable breached-password protection
        |-- Phished -----------------> Phishing playbook + Playbook 3
        |-- Infostealer on endpoint --> EDR triage of user's device; reimage (Beaconing playbook)
        |-- Unknown -----------------> treat endpoint and mailbox as suspect; widen hunt
        v
   Eradicate, harden, monitor 14 days, close
```

### 1.4 Containment for credential stuffing at scale (customer or workforce)

- Block/challenge the sources: rate limit per IP, ASN and username; bot management/CAPTCHA; temporary geo or ASN blocks (time-boxed).
- Force password reset and MFA enrollment **only for accounts with confirmed successful attacker logins** (and any matching leaked-credential lists), not for everyone, unless a full credential dump is confirmed.
- Disable legacy authentication and enable breached/leaked-password checks.
- For customers: notify affected users, review for fraud (orders, payouts, changed email/phone/address), lock withdrawals/payment changes until verified.

### 1.5 Evidence checklist

- [ ] Sign-in logs (interactive + non-interactive) for the user, 30 days, exported and hashed
- [ ] Attacker IPs, ASNs, user agents, apps, protocols, timestamps
- [ ] Audit log events for the user (auth methods, devices, consents, roles)
- [ ] Mailbox audit + inbox rules, forwarding, delegates (see Appendix A)
- [ ] Unified Audit Log: file downloads, mail access, sharing events
- [ ] Breach-intel check on the credential (source of leak, date)
- [ ] Endpoint triage of the user's device if infostealer suspected
- [ ] User interview notes (phishing click, password reuse, unexpected prompts)

### 1.6 Queries

KQL, success after multiple failures from the same IP:

```
let window = 4h;
SigninLogs
| where TimeGenerated > ago(window)
| summarize fails = countif(ResultType != 0), succ = countif(ResultType == 0),
            users = dcount(UserPrincipalName), firstSucc = minif(TimeGenerated, ResultType == 0)
  by IPAddress
| where fails > 10 and succ > 0
| sort by fails desc
```

KQL, all activity of the suspect IP across users:

```
union SigninLogs, AADNonInteractiveUserSignInLogs
| where IPAddress == "203.0.113.50"
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResultType, ClientAppUsed, UserAgent, Location
```

Splunk (Okta), credential stuffing shape (many users, near-one attempt each):

```
index=okta eventType="user.session.start" outcome.result=FAILURE earliest=-4h
| stats dc(actor.alternateId) as users count by client.ipAddress
| where users > 20
| sort - users
```

### 1.7 Eradication & recovery

- Persistence sweep complete and documented (Appendix A).
- Password and sessions reset; MFA methods clean and re-registered with verification.
- Credentials reused elsewhere rotated (privileged and service accounts first).
- Enable or fix: MFA for all, legacy auth blocked, breached-password protection, smart lockout, risk-based Conditional Access (require MFA or block at medium/high user risk and sign-in risk).

### 1.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Any confirmed attacker login | IC + IT Lead | Immediately |
| Privileged/service/break-glass account | CISO; SEV1 bridge | 15 min |
| Mail rules, forwarding, vendor-facing mail sent | Playbook 4; Finance if payments involved | Immediately |
| Personal/customer data accessed or exported | Legal/DPO (notification clock) | 1 h |
| Mass customer account takeover | Product owner, Fraud, Comms, Legal | 1 h |

### 1.9 Closure criteria

All attacker access removed, persistence sweep clean, root cause and cause-of-credential-exposure known, reset/enrollment completed, detections tuned, 14 days of clean monitoring.

---

## 2. Playbook: MFA Fatigue (Push Bombing)

**Scope:** Attacker has a valid password and floods the user with MFA push requests (or calls, SMS) until the user approves, often combined with a helpdesk-impersonation call ("I'm from IT, approve the prompt to stop it") or help-desk social engineering to reset MFA.

**Default severity:** SEV3 prompts denied/ignored, no success → SEV2 prompt approved or MFA method reset by attacker → SEV1 privileged account.

**Key insight:** the attacker **already has the password.** Even if every prompt was denied, the credential is burned and must be reset.

### 2.1 Detection sources

User report ("I keep getting prompts"), Entra sign-in logs with repeated MFA failures/no-response (ResultType 500121 and 50074 family) followed by success, Okta System Log push events (`system.push.send_factor_verify_push`, `user.mfa.okta_verify.deny_push`), ID Protection risk, helpdesk tickets for MFA reset, unusual helpdesk-initiated resets.

### 2.2 Triage (first 15 minutes)

1. **Ask the user (by phone):** Did you approve any prompt? Did anyone call or message you claiming to be IT? When did the prompts start?
2. Pull the sign-in sequence: number of prompts, timing, result of each, **source IP/location of the sign-in attempts** (the prompts appear to come from the attacker's IP), eventual success.
3. If any success: which app/resource was accessed, from which IP, which device, what happened next.
4. Check whether the **MFA method list or device registrations changed** (attacker adding their own authenticator, phone or FIDO key after one approval).
5. Check helpdesk logs: was there a recent MFA reset or password reset request for this user, and how was identity verified?

### 2.3 Decision tree

```
[Multiple unsolicited MFA prompts for a user]
   |
   v
Did ANY prompt get approved (by the user, or a sign-in succeeded from an unfamiliar IP)?
   |-- NO
   |     v
   |   SEV3: password is known to the attacker. Reset password + revoke sessions.
   |   Block attacker IP. Report-as-fraud / block user from MFA if your IdP supports it.
   |   Review how password leaked (stuffing, phish, infostealer). Check other accounts with the same attacker IP.
   |
   |-- YES (SEV2)
         v
   Run Standard Containment (0.3). Then:
         v
   Did the attacker register a new MFA method / device / app password?
         |-- YES --> remove it; list ALL methods; require verified re-enrollment
         v
   Did the attacker access mail/files/apps? --> Playbook 4 (BEC) / 5 (OAuth) as indicated; scope exfil
         v
   Was a helpdesk reset involved?
         |-- YES --> treat as social-engineering incident: audit that ticket, other resets that day, tighten verification (Appendix D)
         v
   Privileged account? --> SEV1, Playbook 6 checks
```

### 2.4 Containment actions

- Reset password and **revoke sessions** at once. If prompts continue, the attacker's source still has the old password only until it is reset.
- Block the attacker IP/ASN (Conditional Access named location, firewall, WAF).
- Temporarily **block MFA for that user** via your IdP's fraud/"report suspicious activity" feature (this blocks sign-in until an admin resets it) or disable the account until verified reset.
- Educate the user at the end of the call (do not blame): deny and report every unexpected prompt.

### 2.5 Evidence checklist

- [ ] Full MFA event timeline (prompt count, timing, results, IPs) exported
- [ ] Sign-in log entries for any success, with device and IP details
- [ ] Authentication-method change events (registered, deleted, default method changed)
- [ ] Device registration events (Entra join/registration)
- [ ] Helpdesk tickets and call recordings for resets related to the user
- [ ] User interview notes (including vishing call details: number, time, claimed identity)

### 2.6 Queries

KQL, many failed/no-response MFA events then success per user:

```
SigninLogs
| where TimeGenerated > ago(24h)
| summarize mfaFail = countif(ResultType in (500121, 50074, 50076, 50158)),
            success = countif(ResultType == 0),
            ips = make_set(IPAddress, 10), first = min(TimeGenerated), last = max(TimeGenerated)
  by UserPrincipalName, bin(TimeGenerated, 1h)
| where mfaFail >= 5 and success > 0
```

KQL, authentication method changes after the burst:

```
AuditLogs
| where OperationName in ("User registered security info", "User deleted security info", "User changed default security info", "Admin registered security info")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

Splunk (Okta), push bombing:

```
index=okta eventType IN ("system.push.send_factor_verify_push","user.mfa.okta_verify.deny_push") earliest=-1h
| stats count by actor.alternateId, client.ipAddress
| where count >= 5
```

### 2.7 Eradication & recovery

- Credentials reset, sessions revoked, authentication methods verified clean.
- Move to **number matching with additional context** (app name and location) for push MFA; for admins and high-risk roles use **phishing-resistant MFA** (FIDO2 security keys or passkeys, certificate-based auth).
- Limit prompt volume (lockout/throttle after N denied prompts) and disable SMS/voice fallback where feasible.
- Harden helpdesk: no MFA resets without strong identity verification (Appendix D).

### 2.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Approved prompt / successful attacker login | IC + IT Lead | Immediately |
| Helpdesk reset abused | Helpdesk lead + CISO | 30 min |
| Privileged account | CISO; SEV1 | 15 min |
| Several users targeted by same actor | Threat intel; broaden to Playbook 1 (stuffing/spray) | 1 h |

### 2.9 Closure criteria

Password reset and sessions revoked, authentication methods clean, user educated, attacker IPs blocked, helpdesk verification gap closed, MFA hardening scheduled with an owner and date.

---

## 3. Playbook: Adversary-in-the-Middle (AiTM) Phishing & Session Token Theft

**Scope:** A reverse-proxy phishing page (Evilginx-style kits, EvilProxy, Tycoon-type phishing-as-a-service) relays the real login page, captures the password **and the post-MFA session cookie**, and the attacker replays the token. Also covers session/token theft by infostealer malware and cookie replay.

**Default severity:** SEV3 user visited the page, no credential entry → SEV2 credentials entered or anomalous token use → SEV1 privileged identity, or follow-on fraud/exfil.

**Key insight:** MFA was **completed by the real user**, so the sign-in looks legitimate. A password reset alone will not evict the attacker. **Revoke sessions, remove attacker-added MFA methods, and check device registrations.**

### 3.1 Detection sources

Entra ID Protection detections (**anomalous token**, **token issuer anomaly**, **attacker in the middle**, unfamiliar sign-in properties), email gateway/user report of a login lure, proxy/DNS hit on a lookalike domain, Defender/EDR alerts, sign-ins where the token is used from a different IP/user agent than where MFA was completed, new MFA method registered within minutes of a sign-in from a new IP, new inbox rule created shortly after a sign-in.

### 3.2 Triage (first 30 minutes)

1. Get the phishing message and URL (see Phishing playbook) and **defang** it. Detonate in a sandbox to identify the proxy kit and the real target (Microsoft, Okta, Google login).
2. Identify everyone who clicked, and **who entered credentials** (proxy logs, DNS logs, EDR, user interviews).
3. For each exposed user, correlate sign-ins: the attacker's sign-in typically shows **MFA satisfied** but from an IP and user agent that differ from the user's usual device, often a data-center/VPN/residential-proxy ASN, shortly after the lure click.
4. Check what happened after the token was obtained: new MFA method, device registration, inbox rules, mail searches (keywords like invoice, wire, payment), OAuth consent, data download.
5. Look for token **replay**: the same session or token used from two IPs, or the sign-in with a `Satisfied by claim in the token` MFA detail from an unmanaged device.

### 3.3 Decision tree

```
[Report/alert: AiTM page, anomalous token, or lookalike login domain]
   |
   v
Did the user submit credentials / complete MFA on the phishing page? (proxy logs, user, sign-ins)
   |-- NO --> SEV3: block domain, purge email, advise user. Monitor 7 days.
   |-- YES / UNKNOWN (treat as YES until disproved)
        v
   Anomalous sign-in or token use after the click? (new IP/UA/ASN, token replay, risk detection)
        |-- NO evidence (checked 24-48 h) --> SEV2 precautionary: revoke sessions, reset password, re-register MFA
        |-- YES --> SEV2 confirmed: Standard Containment (0.3), with these extras:
               1. REVOKE SESSIONS (password reset alone is not enough)
               2. List and remove ALL MFA methods the user did not register; remove unknown registered devices
               3. Block attacker IPs/ASN in Conditional Access
               4. Persistence sweep (Appendix A): inbox rules, forwarding, OAuth, delegates
               5. Privileged? --> SEV1
        v
   Follow-on activity?
        |-- Fraudulent mail / vendor requests --> Playbook 4
        |-- OAuth consent --> Playbook 5
        |-- Data download --> exfil scoping, Legal/DPO
        v
   Block the phishing infrastructure, purge, harden, close
```

### 3.4 Containment actions

- Revoke all sessions for every user who submitted credentials; reset passwords; verify MFA methods and devices.
- **Block the AiTM domain(s) and IPs** at proxy, DNS, email gateway; submit the URL to Microsoft/Google Safe Browsing and to the hosting provider/registrar for takedown.
- Purge all copies of the lure from mailboxes; search for the same sender/infrastructure in other channels (Teams, SMS, QR codes).
- Conditional Access quick wins: require **compliant or hybrid-joined device** for sensitive apps, block sign-ins from unknown ASNs/countries, require re-authentication for risky sessions.

### 3.5 Evidence checklist

- [ ] Phishing email (.eml), URLs, redirect chain, sandbox report and screenshots of the proxied page
- [ ] Proxy/DNS/EDR logs showing who visited the lure URL, and when
- [ ] Sign-in logs (interactive and non-interactive) for each exposed user: IP, ASN, user agent, device, MFA detail, Conditional Access result, session ID
- [ ] Entra ID Protection risk detections for the user
- [ ] Audit logs: authentication method registration, device registration, consents, role changes
- [ ] Mailbox rules, forwarding, delegates, sent items, mail-access audit events
- [ ] Endpoint triage if infostealer-based cookie theft is suspected

### 3.6 Queries

KQL, sign-ins by an exposed user from IPs other than their normal ones, after the click time:

```
union SigninLogs, AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "user@contoso.com" and TimeGenerated > datetime(2026-11-10T00:00:00Z)
| project TimeGenerated, IPAddress, tostring(LocationDetails.countryOrRegion), AppDisplayName, UserAgent,
          AuthenticationRequirement, tostring(DeviceDetail.deviceId), ConditionalAccessStatus, ResultType
| sort by TimeGenerated asc
```

KQL, one session/correlation seen from multiple IPs (token replay candidate):

```
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(48h) and ResultType == 0
| summarize ips = dcount(IPAddress), ipList = make_set(IPAddress, 10) by UserPrincipalName, SessionId
| where ips > 1
```

KQL, MFA method registered soon after a risky sign-in:

```
AuditLogs
| where OperationName has "security info" and TimeGenerated > ago(48h)
| extend actor = tostring(InitiatedBy.user.userPrincipalName), ip = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, actor, ip, Result
```

### 3.7 Eradication & recovery

- Sessions revoked, unknown MFA methods/devices removed, persistence sweep clean.
- Re-enroll MFA with verification; prefer **phishing-resistant MFA (FIDO2/passkeys)**, which cannot be relayed by an AiTM proxy because authentication is bound to the real domain.
- Interim controls if FIDO2 is not yet deployed: device-compliance requirement in Conditional Access, **token protection** (token binding) where supported, CAE, sign-in frequency limits for sensitive apps, block legacy authentication.
- Add detections for the patterns above and for lookalike-domain lures.

### 3.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Credentials entered / token replay confirmed | IC + IT Lead | Immediately |
| Privileged or finance account | CISO; Finance; SEV1 | 15 min |
| Follow-on BEC / payment request sent | Playbook 4; bank | Immediately |
| Several users hit by the same kit | Threat intel; Comms (user advisory); takedown requests | 1 h |
| Personal data accessed | Legal/DPO | 1 h |

### 3.9 Closure criteria

All exposed users re-secured (sessions revoked, methods verified, persistence clean), phishing infrastructure blocked and reported, detections in place, phishing-resistant MFA plan owned and dated, users informed.

---

## 4. Playbook: Business Email Compromise (BEC) & Malicious Inbox Rules

**Scope:** Fraud conducted through email: (a) **account-takeover BEC**, where the attacker operates inside a real mailbox (reading threads, hiding replies with rules, forwarding mail out, sending fraudulent payment or bank-change requests); and (b) **spoofed/lookalike BEC**, where the attacker impersonates an executive or vendor from an external or lookalike domain with no compromise. Malicious inbox rules and forwarding are the signature persistence mechanism.

**Default severity:** SEV3 spoof attempt, nobody acted → SEV2 mailbox compromised or malicious rules found → SEV1 money moved, executive/finance mailbox, or large-scale data exposure.

**Money moves fast.** If a payment was sent, the recall call to the bank is the first action, ahead of forensics.

### 4.1 Detection sources

User/vendor report ("did you really send this?"), Finance reporting changed bank details, Unified Audit Log events `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, `Set-Mailbox` (forwarding), `Add-MailboxPermission`, transport rule changes, Defender/Exchange alerts (suspicious inbox forwarding, suspicious inbox manipulation rule, mass-forwarding), DMARC reports showing lookalike senders, lookalike-domain registration alerts.

### 4.2 Triage (first 15 minutes)

1. **Money first:** was any payment, gift-card purchase, payroll change or vendor bank-detail change made on the strength of these emails? If yes, start the financial response (4.4) in parallel.
2. Decide **compromise or spoof:** inspect headers. Sent from the real mailbox (internal `Received` path, sign-in logs from an unusual IP) = takeover. Sent from an external or lookalike domain (display-name spoof, Reply-To to a different address) = spoof.
3. If takeover: pull **inbox rules (including hidden), forwarding, delegates, mail flow rules,** and sign-in history (Appendix A).
4. Determine **exposure window** (first attacker sign-in to now) and **who received fraudulent mail** (vendors, customers, colleagues).
5. Identify what the attacker read: mail-access audit events, search queries, files opened.

### 4.3 Decision tree

```
[Suspicious payment request / report of odd email / malicious rule alert]
   |
   v
Was money or sensitive data sent?
   |-- YES --> START FINANCIAL RESPONSE NOW (4.4), continue below in parallel. SEV1 if amount/impact material.
   |-- NO  --> continue
   v
Sent from the legitimate mailbox (mail traversed internal path; attacker sign-in found)?
   |-- YES: ACCOUNT TAKEOVER BEC (SEV2)
   |      1. Standard Containment (0.3); revoke sessions
   |      2. Remove malicious inbox rules, forwarding, delegates, OAuth grants, added MFA methods
   |      3. Check mail flow rules, other mailboxes with the same rule pattern
   |      4. Notify every recipient of fraudulent mail (vendors, customers) out-of-band
   |      5. Determine the entry vector: Playbook 1 (credentials) or Playbook 3 (AiTM/token)
   |-- NO: SPOOF / LOOKALIKE BEC
          1. Block sender/domain; purge from all mailboxes
          2. Check SPF/DKIM/DMARC alignment; move DMARC to p=quarantine/reject
          3. Register or monitor defensive lookalike domains; add executive-impersonation protection
          4. Alert staff in the targeted function (Finance, HR, Procurement)
   v
Any sign the attacker accessed other users' data or sent from other accounts?
   |-- YES --> widen scope (Playbook 1 for each account)
   |-- NO  --> eradicate, monitor, close
```

### 4.4 Financial response (do not wait for the investigation)

1. **Call the bank's fraud desk immediately** and request a **recall/hold**; give transaction reference, amount, beneficiary account and bank. Follow with a written request. Hours matter, because funds are often moved out within a day.
2. Report to **law enforcement/national cybercrime unit** immediately (in the US: IC3, which can trigger the Financial Fraud Kill Chain/recovery process for qualifying wires; elsewhere, your national police cybercrime unit and national CERT). Keep the report reference.
3. Notify the **cyber/crime insurer** per policy terms.
4. **Freeze changes:** hold pending payments to the same beneficiary, and require out-of-band callback verification (to a number already on file, never one from the email) for any bank-detail change until closure.
5. Preserve the email chain, invoices and bank confirmations as evidence.

### 4.5 Containment & clean-up (takeover BEC)

For a user with the compromise confirmed, run Standard Containment (0.3), then inspect and remove persistence:

- **Inbox rules:** forward/redirect to external addresses; move to unusual folders (RSS Feeds, Archive, Conversation History, Notes); mark as read; delete; conditions on words such as invoice, payment, wire, bank, statement, "unsubscribe", or on a vendor's domain.
- **Mailbox-level forwarding** (`ForwardingSmtpAddress`, `ForwardingAddress`).
- **Delegates / Full Access / Send-As / Send on Behalf** permissions.
- **Mail flow (transport) rules** and connectors (an admin-level attacker action; escalate if found).
- **OAuth consents** and **additional MFA methods** (Playbook 5, Section 2).
- **Sent Items and Deleted Items**, since attackers delete evidence of fraudulent mail.

Exchange Online inspection and removal (run as a Mail/Exchange admin):

```
Get-InboxRule -Mailbox user@contoso.com -IncludeHidden |
  fl Name,Enabled,Priority,From,SubjectContainsWords,BodyContainsWords,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,MoveToFolder,MarkAsRead
Get-Mailbox user@contoso.com | fl ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
Get-MailboxPermission user@contoso.com | ? { $_.User -notlike "NT AUTHORITY*" -and -not $_.IsInherited }
Get-RecipientPermission user@contoso.com
Get-TransportRule | fl Name,State,Mode,RedirectMessageTo,BlindCopyTo,SentToScope,WhenChanged

# After evidence is exported:
Remove-InboxRule -Mailbox user@contoso.com -Identity "<rule id or name>"
Set-Mailbox user@contoso.com -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false
```

### 4.6 Evidence checklist

- [ ] Original fraudulent emails (.eml with headers) and the full thread
- [ ] Payment records: invoice, bank details, transaction IDs, timestamps, bank communications
- [ ] Export of every inbox rule (including hidden), forwarding settings, delegates, transport rules **before removal**
- [ ] Sign-in logs for the mailbox (30 days), attacker IPs and user agents
- [ ] Unified Audit Log: `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, `Set-Mailbox`, mail-access, send events
- [ ] Message trace of all fraudulent messages sent (recipients)
- [ ] List of third parties notified, with times
- [ ] Law enforcement report number and insurer claim number

### 4.7 Queries

KQL (Defender), rule creation or modification:

```
CloudAppEvents
| where Timestamp > ago(7d) and ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox")
| extend p = tostring(RawEventData.Parameters)
| where p has_any ("ForwardTo","RedirectTo","ForwardAsAttachmentTo","DeleteMessage","SmtpAddress","RSS","Archive")
| project Timestamp, AccountDisplayName, IPAddress, ActionType, p
```

Splunk (Office 365 management activity):

```
index=o365 sourcetype="o365:management:activity" Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox")
| table _time UserId ClientIP Operation Parameters{}.Name Parameters{}.Value
```

Exchange Online PowerShell, external auto-forwards enabled across the tenant:

```
Get-Mailbox -ResultSize Unlimited | ? { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |
  select UserPrincipalName,ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward
```

### 4.8 Eradication, recovery & hardening

- Persistence removed and verified; user re-secured; mailbox monitored 14 days.
- **Block automatic external forwarding** in the outbound spam policy; alert on any inbox rule with external forwarding or deletion.
- Enforce DMARC (quarantine → reject), SPF, DKIM; enable impersonation protection and first-contact safety tips; tag external email.
- **Process controls:** dual approval and callback verification for payments and bank-detail changes; no changes by email alone.
- Notify affected vendors/customers with a short factual statement and verified contact details.

### 4.9 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Payment made or attempted | CFO/Finance, bank fraud desk, Legal, IC | Immediately |
| Executive or finance mailbox | CISO; SEV1 | 15 min |
| Personal/customer data exposed in mailbox | Legal/DPO | 1 h |
| External parties received fraudulent mail | Comms + Legal approved notice | 4 h |
| Law enforcement and insurer | Legal | Same day |

### 4.10 Closure criteria

Financial recovery actions filed and tracked, malicious rules/forwarding/delegates removed, entry vector closed, external parties notified, payment-process gap fixed, detections added.

---

## 5. Playbook: Malicious OAuth App Consent (Illicit Consent Grant)

**Scope:** A user (or admin) grants a malicious or compromised third-party application delegated or application permissions to mailbox, files or directory. Access is **token-based and persists through password resets and MFA**. Includes attackers adding credentials to an existing legitimate service principal for persistence.

**Default severity:** SEV3 risky app seen, no consent → SEV2 consent granted by a standard user → SEV1 admin consent granted for high-risk permissions, tenant-wide application permissions, or app already exfiltrating data.

### 5.1 Detection sources

Entra audit logs: **Consent to application**, **Add service principal**, **Add OAuth2PermissionGrant**/"Add delegated permission grant", **Add app role assignment to service principal**, **Update application – Certificates and secrets management**; Defender for Cloud Apps / App Governance alerts (unusual or overprivileged OAuth app); user report of a "Permissions requested" prompt after a lure; email/Teams lure with a consent link; unfamiliar enterprise application with a mail-read scope; Google Workspace token audit (`authorize` events) for unknown client IDs.

### 5.2 Triage (first 30 minutes)

1. Identify the **application:** display name, application (client) ID, service principal object ID, publisher/verified status, home tenant (external multi-tenant?), creation date, reply URLs, who owns it.
2. Identify **permissions granted** and their type (delegated vs. application). High risk: `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `MailboxSettings.ReadWrite`, `Files.Read.All`, `Files.ReadWrite.All`, `Sites.Read.All`, `Contacts.Read`, `User.Read.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `offline_access` (long-lived refresh token), `full_access_as_app`.
3. Identify **who consented** (users, or admin on behalf of org), when, and from which IP. Link to the lure that prompted it.
4. Determine **what the app did:** API/Graph activity logs, mail-access audit events, file downloads, sign-ins by the service principal (workload identity sign-in logs).
5. Check whether it is truly malicious or a legitimate-but-unreviewed app (check publisher verification, vendor website, other tenants' reputation, business owner).

### 5.3 Decision tree

```
[Alert: new/suspicious OAuth app consent]
   |
   v
Is the app approved/known (business owner confirms, verified publisher, in app catalog)?
   |-- YES --> Document, tighten permissions if excessive, close (SEV4).
   |-- NO / UNKNOWN
        v
   Treat as malicious until disproved. CONTAIN IMMEDIATELY:
     1. Disable the service principal (stop token use)
     2. Revoke the permission grants (delegated + app roles)
     3. Revoke sessions of the consenting user(s) (invalidates refresh tokens)
     4. Block the app tenant-wide (consent policy/app block)
        v
   Was it admin consent / application permissions / high-risk scopes?
        |-- YES --> SEV1: assume tenant-wide data access; widen audit review to all mailboxes/sites the permission covered
        |-- NO  --> SEV2: scope to the consenting users
        v
   Review what the app accessed (mail, files, directory) --> exfil assessment, Legal/DPO
        v
   Why did the user consent? Phish lure --> Phishing playbook; account also compromised? --> Playbook 1/3
        v
   Persistence sweep: other apps with new secrets/certs, new service principals by the same actor
        v
   Remove (delete) app + grants after evidence preserved; harden consent policy; close
```

### 5.4 Containment commands (Microsoft Graph PowerShell)

```
# Identify the app and its grants
Get-MgServicePrincipal -Filter "appId eq '<client-id>'" | fl Id,DisplayName,AppId,PublisherName,VerifiedPublisher,AccountEnabled
Get-MgOauth2PermissionGrant -Filter "clientId eq '<sp-object-id>'" | fl Id,ConsentType,PrincipalId,Scope
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <sp-object-id>

# Contain
Update-MgServicePrincipal -ServicePrincipalId <sp-object-id> -AccountEnabled:$false
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <grant-id>
Revoke-MgUserSignInSession -UserId user@contoso.com

# After evidence export, remove the app
Remove-MgServicePrincipal -ServicePrincipalId <sp-object-id>
```

Google Workspace: Admin console → Security → Access and data control → API controls → App access control: block the client ID; revoke the user's token under the user's Security tab; review the token audit log. Okta: deactivate the OAuth/OIDC app integration and revoke its tokens.

### 5.5 Evidence checklist

- [ ] App details: client ID, SP object ID, publisher, home tenant, reply URLs, creation time, owners
- [ ] Permission grants (scopes, consent type, who granted, when, from which IP)
- [ ] Audit log entries for consent, SP creation, grants, credential additions
- [ ] Workload identity (service principal) sign-in logs and Graph activity logs for the app
- [ ] Mail-access / file-access audit events attributable to the app
- [ ] The lure (email/Teams message/URL) and the list of recipients
- [ ] Export of all enterprise apps with high-risk scopes for comparison
- [ ] Record of every revocation/disablement action and time (UTC)

### 5.6 Queries

KQL, recent consents and service principal creation:

```
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName in ("Consent to application","Add service principal","Add delegated permission grant","Add app role assignment to service principal","Add OAuth2PermissionGrant")
| extend actor = tostring(InitiatedBy.user.userPrincipalName), ip = tostring(InitiatedBy.user.ipAddress),
         app = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, actor, ip, app, Result, AdditionalDetails
```

KQL, credentials added to existing apps (persistence):

```
AuditLogs
| where OperationName in ("Update application – Certificates and secrets management","Add service principal credentials","Update service principal")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

### 5.7 Eradication & recovery

- App disabled, grants revoked, app deleted after evidence preserved; consenting users' sessions revoked.
- Rotate any secrets or certificates for **legitimate** apps if the actor had app-admin rights.
- **Harden consent:** disable user consent or restrict to **verified publishers and low-risk permissions**; enable the **admin consent workflow**; enable app governance/anomaly alerts; review high-risk apps quarterly; restrict who can create app registrations.
- Add detection for consent to apps with mail/file scopes and for new credentials on service principals.

### 5.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Consent granted to unverified app | IC + IT Lead | 30 min |
| Admin consent or application permissions | CISO; SEV1 | 15 min |
| Evidence of mail/file exfil | Legal/DPO | 1 h |
| Same lure hit multiple users | Phishing playbook; Comms | 1 h |
| Multi-tenant malicious app | Report to Microsoft/Google (abuse) and CERT | Next business day |

### 5.9 Closure criteria

App removed and blocked, all consenting users re-secured, access scope understood, consent policy hardened, detection live, lessons documented.

---

## 6. Playbook: New Admin Account or Privilege Escalation

**Scope:** An unauthorized new administrative identity, or an existing identity gaining privileged roles/permissions outside change control: Entra directory roles (Global Admin, Privileged Role Admin, Exchange/SharePoint Admin, Application Admin), PIM bypass, Azure RBAC (Owner/Contributor/User Access Administrator), AD group changes (Domain Admins, Enterprise Admins, Schema Admins, Account Operators), cloud IAM (AWS/GCP) admin policies, service principal permissions, Okta super admin.

**Default severity:** SEV1 for any unauthorized privileged-role change until proven authorized. Admin compromise ends with full control of the tenant.

### 6.1 Detection sources

Entra audit logs: **Add member to role**, **Add eligible member to role** (PIM), **Add user**, **Update user**, **Add app role assignment**, **Update conditional access policy**, **Set federation settings / domain authentication** changes (federation backdoor), **Add service principal credentials**; Azure Activity Log role-assignment writes; Windows Security events 4720 (user created), 4728/4732/4756 (member added to global/local/universal group), 4672 (special privileges), 4738; AdminSDHolder/SDProp changes; AWS CloudTrail `AttachUserPolicy`, `CreateAccessKey`, `CreateUser`; Okta admin role assignment events.

### 6.2 Triage (first 15 minutes)

1. Who made the change (actor), from where (IP, device), when, via which path (portal, API, PowerShell), and **does a change ticket / PIM request exist?**
2. **Verify out-of-band** with the actor's manager and the actor (phone). Do not message via the possibly-compromised identity.
3. Who is the beneficiary identity: new account, existing account, service principal, guest/external user? What roles or permissions were granted?
4. What has the new admin or elevated identity **done since:** sign-ins, mail access, role/app/policy changes, key creation, resource deployment, data access.
5. Look for **secondary persistence**: extra admins, new app registrations or SP credentials, federation or CA policy changes, mail flow rules, access keys, break-glass tampering.

### 6.3 Decision tree

```
[Alert: privileged role assignment / new admin / admin group change]
   |
   v
Authorized? (matching change ticket/PIM approval AND actor confirms out-of-band)
   |-- YES --> Document, close (SEV4). If outside standard process, file a process finding.
   |-- NO / UNVERIFIABLE --> SEV1: IC bridge
        v
   CONTAIN (order matters; do NOT lock yourself out; confirm break-glass access works first):
     1. Remove the unauthorized role/group membership
     2. Disable the new/elevated account; revoke its sessions
     3. Disable or restrict the ACTOR account if it was compromised; revoke its sessions; reset credentials
     4. Review and, if needed, freeze other admin accounts (rotate break-glass credentials after the incident)
        v
   Did the attacker change anything else with elevated rights?
     - Roles/PIM settings, CA policies (exclusions, disabled policies), auth-method policies
     - Federation/domain settings, SSO trust, SAML/OIDC signing certs
     - App registrations, SP credentials, API permissions
     - Mail flow rules, connectors, retention/audit settings (log tampering)
     - Cloud: new IAM users/keys/roles, VMs, storage policies, snapshots shared externally
        |-- YES --> revert each, record in timeline; treat the tenant as compromised: Section 6.4
        |-- NO  --> continue
        v
   How did the actor get elevated access? (compromised admin: Playbook 1/3; consent abuse: Playbook 5; insider; stolen API key)
        v
   Eradicate, rotate privileged secrets, monitor 30 days, close
```

### 6.4 If the tenant itself may be compromised

- Treat **all privileged credentials and secrets as burned**: rotate admin passwords, reissue FIDO keys where lost, rotate service principal secrets/certificates and automation credentials, rotate SAML/token-signing certificates if federation was touched, rotate cloud access keys.
- Review **every** privileged role holder and every enterprise application with privileged permissions; compare with last known-good export.
- On-premises AD: if Domain Admin was affected, follow the AD recovery path of the ransomware playbook (krbtgt double reset, DC review, GPO review).
- Engage the external IR retainer and the vendor's support (Microsoft DART/Okta/AWS) at SEV1.
- Preserve and export all audit logs immediately; check that audit logging was not disabled or shortened.

### 6.5 Evidence checklist

- [ ] Audit events for the role/group change (actor, target, role, time, IP, correlation ID)
- [ ] Change tickets/PIM requests (or confirmation that none exist)
- [ ] Sign-in logs for actor and beneficiary (30 days)
- [ ] All actions by the beneficiary identity since creation/elevation
- [ ] Snapshot of current roles, PIM assignments, CA policies, auth-method policies, federation settings, app permissions (compare with baseline)
- [ ] AD DC security logs (4720, 4728, 4732, 4756, 4672, 4768/4769) and AdminSDHolder state
- [ ] Cloud audit logs (Azure Activity, AWS CloudTrail, GCP Audit) for the same window
- [ ] Out-of-band confirmation notes (who, when, what was said)

### 6.6 Queries

KQL, role assignments and PIM changes, outside approved windows:

```
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role","Add eligible member to role","Add member to role in PIM completed (permanent)","Add app role assignment to service principal")
| extend actor = tostring(InitiatedBy.user.userPrincipalName), ip = tostring(InitiatedBy.user.ipAddress),
         target = tostring(TargetResources[0].userPrincipalName), role = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, OperationName, actor, ip, target, role, Result
```

Splunk, Windows privileged group additions (Domain/Enterprise Admins etc.):

```
index=wineventlog EventCode IN (4728,4732,4756) earliest=-7d
| search Group_Name IN ("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators")
| table _time host Subject_Account_Name Member_Name Group_Name
```

AWS CloudTrail, IAM privilege changes:

```
index=aws sourcetype=aws:cloudtrail eventName IN ("CreateUser","CreateAccessKey","AttachUserPolicy","PutUserPolicy","AttachRolePolicy","UpdateAssumeRolePolicy")
| table _time userIdentity.arn eventName requestParameters.* sourceIPAddress
```

### 6.7 Eradication & recovery

- Unauthorized roles and identities removed; secrets rotated; all secondary persistence reverted and verified against baseline.
- **Harden privileged access:** Privileged Identity Management with just-in-time activation and approval for all admin roles, no standing Global Admin beyond emergency accounts, separate admin accounts (no mailbox/internet use), phishing-resistant MFA for all admins, Conditional Access requiring compliant privileged-access workstations, alerts on **every** privileged role change, regular access reviews, restrict who can create apps/grant consent.
- Keep an immutable baseline export of roles, policies and app permissions for diffing.

### 6.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Unauthorized privileged change | IC, CISO, IT Lead | Immediately |
| Global/Domain/Cloud admin or federation touched | Executive leadership, IR retainer, vendor support | 30 min |
| Evidence of data exfil or resource abuse | Legal/DPO | 1 h |
| Insider suspicion | HR + Legal (coordinate before any employee contact) | Same day |
| Confirmed attacker control of tenant | Regulators/law enforcement per Legal | Per law |

### 6.9 Closure criteria

All privileged roles and secrets match approved baseline, no secondary persistence, root cause identified and fixed, PIM/MFA/alerting controls in place, 30 days of clean monitoring, post-incident review completed.

---

## 7. Playbook: Impossible Travel / Anomalous Login

**Scope:** Alerts that a sign-in is unusual for the user: impossible or atypical travel, unfamiliar sign-in properties, anonymous/malicious IP, new device or ASN, unusual hours, sign-in from a country the business does not operate in.

**Default severity:** SEV4 explained by a benign cause → SEV3 unexplained, no follow-on activity → SEV2 unexplained plus suspicious follow-on (rules, MFA change, consent, downloads) → SEV1 privileged identity.

**This is a triage playbook.** These alerts have a high false-positive rate (VPNs, mobile carriers, cloud proxies, travel, shared egress). The job is to separate noise from compromise **quickly and with evidence**, not to reset everyone's password on reflex. When it is real, it becomes Playbook 1 or 3.

### 7.1 Detection sources

Entra ID Protection risk detections (unfamiliar sign-in properties, atypical travel, anonymous IP, malicious IP, impossible travel from Defender for Cloud Apps, leaked credentials), Okta ThreatInsight/behavior detection, Google Workspace suspicious login alerts, SIEM geovelocity rules, VPN concentrator and proxy logs, CASB alerts.

### 7.2 Triage checklist (first 15 minutes)

1. **Pull the two sign-ins:** time (UTC), IP, ASN/ISP, geo, device ID, OS/browser, user agent, app, MFA result, Conditional Access result, session ID, client protocol.
2. **Benign explanations to test:**
   - Corporate VPN/proxy/ZTNA egress, cloud security gateway (Zscaler, etc.), or mobile carrier CGNAT
   - Known device ID, compliant/managed device, same user agent as history
   - Travel confirmed by the user, HR calendar or a travel booking system
   - Service/automation account with a known IP pattern
   - Time zone/geo-IP database error, IPv6 or IP-reassignment quirks
3. **Malicious indicators:**
   - Unmanaged/unknown device, new user agent (python-requests, curl, outdated browsers), automation signatures
   - Hosting/VPS/Tor/residential-proxy ASN, anonymous IP flag
   - MFA satisfied *by claim in token* or MFA method freshly added
   - Legacy protocols (IMAP, POP, SMTP AUTH, EWS basic)
   - Failures immediately before success, or many accounts from the same IP
   - Follow-on actions: inbox rule, MFA registration, OAuth consent, mass mail access or download
4. **Contact the user out-of-band** (phone number from the HR directory): were you at `<place>` at `<time>`, using `<device>`?
5. Check **post-sign-in activity** for the session regardless of the answer.

### 7.3 Decision tree

```
[Anomalous / impossible travel alert]
   |
   v
Is there a benign explanation proven by evidence (managed device ID + known egress/VPN, or user confirms by phone)?
   |-- YES --> Check post-login activity once. Clean?
   |             |-- YES --> Dismiss risk as safe; document; tune (named location, VPN IP allowlist). SEV4.
   |             |-- NO  --> go to NO branch
   |-- NO / CANNOT REACH USER / USER DENIES
        v
   Does the suspicious sign-in show SUCCESS?
        |-- NO (blocked/failed) --> SEV3: block IP, reset password if user risk is elevated, watch 7 days.
        |-- YES
             v
        Any suspicious follow-on (rules, MFA change, consent, downloads, sent mail)?
             |-- YES --> SEV2: account compromised. Standard Containment (0.3).
             |           Then Playbook 1 / 3 / 4 / 5 as indicated.
             |-- NO  --> SEV3 precautionary: revoke sessions, reset password, verify MFA methods,
             |           block the IP, monitor 7 days. Escalate if new evidence appears.
        v
   Privileged account? --> SEV1, Playbook 6 checks
```

### 7.4 Containment actions (proportionate)

- **Likely benign:** no user impact; dismiss with evidence and tune.
- **Unexplained, success, no follow-on:** revoke sessions, reset password, review auth methods, block IP/ASN, monitor. Do not disable unless the user cannot be verified.
- **Compromise confirmed:** Standard Containment (0.3).
- For repeat noise, fix the cause: register trusted egress IPs as **named locations**, add VPN ranges to allowlists, set sign-in risk policies to **require MFA or block at medium/high** rather than only alerting.

### 7.5 Evidence checklist

- [ ] Both sign-in records (and the full session's sign-in history, interactive and non-interactive)
- [ ] IP/ASN reputation and hosting type (VPN, VPS, Tor, residential proxy, mobile carrier)
- [ ] Device and user-agent comparison against the user's baseline (last 30 days)
- [ ] Risk detection details and risk level/state
- [ ] Post-sign-in activity: mail rules, MFA changes, consents, file/mail access
- [ ] Out-of-band confirmation record (who, when, what the user said)
- [ ] Disposition and justification (benign / compromise), with tuning action

### 7.6 Queries

KQL, a user's sign-in baseline vs. the suspect sign-in:

```
let u = "user@contoso.com";
let baseline = SigninLogs | where TimeGenerated between (ago(30d) .. ago(1d)) and UserPrincipalName == u and ResultType == 0
  | summarize knownCountries = make_set(tostring(LocationDetails.countryOrRegion)), knownDevices = make_set(tostring(DeviceDetail.deviceId)), knownASNs = make_set(AutonomousSystemNumber);
SigninLogs
| where TimeGenerated > ago(1d) and UserPrincipalName == u
| extend country = tostring(LocationDetails.countryOrRegion), device = tostring(DeviceDetail.deviceId)
| project TimeGenerated, IPAddress, country, AutonomousSystemNumber, device, UserAgent, ResultType, AppDisplayName, AuthenticationRequirement
| sort by TimeGenerated asc
```

KQL, simple impossible-travel candidate (successful sign-ins in different countries within two hours):

```
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| extend country = tostring(LocationDetails.countryOrRegion)
| sort by UserPrincipalName asc, TimeGenerated asc
| extend prevCountry = prev(country), prevTime = prev(TimeGenerated), prevUser = prev(UserPrincipalName)
| where UserPrincipalName == prevUser and country != prevCountry and TimeGenerated - prevTime < 2h
| project UserPrincipalName, prevTime, prevCountry, TimeGenerated, country, IPAddress
```

Splunk (Okta), new country for a user in the last day vs. 30-day history:

```
index=okta eventType="user.session.start" outcome.result=SUCCESS earliest=-30d
| eval day=if(_time>relative_time(now(),"-1d"),"recent","history")
| stats values(eval(if(day="history",client.geographicalContext.country,null()))) as known
        values(eval(if(day="recent",client.geographicalContext.country,null()))) as recent
        by actor.alternateId
| where mvcount(mvfilter(NOT match(recent, mvjoin(known,"|")))) > 0
```

### 7.7 Eradication, recovery & tuning

- If benign: record the cause and fix the alert (named locations, VPN egress list, risk policy tuning). Track the false-positive rate per rule.
- If malicious: complete the relevant playbook's eradication and hardening.
- Move from alert-only to **enforcement:** Conditional Access with sign-in/user risk, device compliance, block legacy auth, block countries you never operate in.

### 7.8 Escalation path

| Trigger | Escalate to | Within |
| --- | --- | --- |
| Unexplained successful sign-in with suspicious follow-on | IC + IT Lead; Playbook 1/3 | Immediately |
| Privileged account | CISO; SEV1 | 15 min |
| Several accounts, same infrastructure | Threat intel; Playbook 1 (stuffing/spray) | 1 h |
| Cannot reach user and activity continues | Disable account and escalate to user's manager/IC | 30 min |

### 7.9 Closure criteria

Disposition recorded (benign with evidence, or compromise with containment), user verified, tuning applied or compromise playbook completed, ticket documented.

---

## 8. Appendices

### Appendix A: Persistence sweep (run for every confirmed compromise)

| Check | Where | What to look for |
| --- | --- | --- |
| Authentication methods | Entra user → Authentication methods; `Get-MgUserAuthenticationMethod`; Okta factors; Google 2SV | Phones, authenticators, FIDO keys, app passwords, TAP the user did not add |
| Registered devices | Entra devices (`Get-MgUserRegisteredDevice`); Intune; Okta devices | Unknown devices, newly joined/registered devices, primary refresh token risk |
| Inbox rules (incl. hidden) | `Get-InboxRule -IncludeHidden` | Forward/redirect, delete, move to obscure folders, mark read |
| Mailbox forwarding | `Get-Mailbox` | `ForwardingSmtpAddress`, `ForwardingAddress` |
| Delegates and permissions | `Get-MailboxPermission`, `Get-RecipientPermission` | Full Access, Send-As, Send on Behalf for unknown principals |
| OAuth consents | `Get-MgUserOauth2PermissionGrant`; enterprise apps; Google token audit | Unknown or high-risk apps, new consents in the exposure window |
| Role/group membership | Entra roles, PIM, AD groups, cloud IAM | New or changed privileged membership |
| App credentials | App registrations / service principals | New secrets or certificates, new owners |
| Conditional Access and policies | CA policies, auth-method policies | Exclusions added, policies disabled or weakened |
| Mail flow | Transport rules, connectors | Redirect/BCC rules, new connectors |
| Sharing and file access | SharePoint/OneDrive sharing, anonymous links | Mass-sharing, external links created |
| SSO app sessions | Each SSO-connected app | Active sessions, API keys, personal access tokens created in connected apps (GitHub, Slack, Salesforce, cloud consoles) |

### Appendix B: Identity containment cheat sheet

**Microsoft Entra ID (Microsoft Graph PowerShell)**

```
Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.AccessAsUser.All","UserAuthenticationMethod.ReadWrite.All","Application.ReadWrite.All"
Update-MgUser -UserId user@contoso.com -AccountEnabled:$false          # block sign-in
Revoke-MgUserSignInSession -UserId user@contoso.com                    # revoke refresh tokens / sessions
Get-MgUserAuthenticationMethod -UserId user@contoso.com                # list methods; remove unknown ones
Get-MgUserRegisteredDevice -UserId user@contoso.com                    # list registered devices
Get-MgUserOauth2PermissionGrant -UserId user@contoso.com               # delegated consents
```

Reset the password in the admin center or via `Update-MgUser` with a random value; require password change at next sign-in after verified hand-off. Add the attacker IPs to a **named location** and block via a Conditional Access policy.

**Okta**

- Clear user sessions: Admin → Directory → People → user → Clear User Sessions (API: `DELETE /api/v1/users/{userId}/sessions`)
- Suspend user (`POST /api/v1/users/{userId}/lifecycle/suspend`); reset factors (`POST /api/v1/users/{userId}/lifecycle/reset_factors`); expire password
- Revoke OAuth grants/tokens for the user; review System Log for the actor, IP and session

**Google Workspace**

- Admin console → Users → user → Security: Reset password, **Reset sign-in cookies**, review/revoke third-party app access, review 2-Step Verification and recovery info
- Security investigation tool: search login, Gmail, Drive, token and admin audit logs; delete malicious messages; remove forwarding and filters

**On-premises Active Directory**

- Disable account, reset password twice, remove from privileged groups, review `Get-ADUser -Properties *` for SPN/delegation/`msDS-AllowedToDelegateTo` changes, check Kerberos event IDs, purge Kerberos tickets on hosts (`klist purge`) if a ticket-based attack is suspected

### Appendix C: Escalation matrix

| Role | Primary | Backup | Phone | Out-of-band |
| --- | --- | --- | --- | --- |
| Incident Commander | `<NAME>` | `<NAME>` | `<PHONE>` | `<SIGNAL/BRIDGE>` |
| Identity / IAM Lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| IT / Messaging (Exchange) Lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| CISO | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Finance / Treasury (BEC) | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Legal / DPO | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Comms Lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Helpdesk Lead | `<NAME>` | `<NAME>` | `<PHONE>` |  |
| Cloud/IdP vendor support (e.g., Microsoft DART, Okta) | `<VENDOR>` |  | `<PHONE>` | Contract #: `<NUMBER>` |
| IR retainer / cyber insurer | `<VENDOR>` |  | `<PHONE>` | Policy #: `<NUMBER>` |
| Bank fraud desk | `<BANK>` |  | `<PHONE>` |  |
| Law enforcement / national CERT | `<AGENCY>` |  | `<PHONE>` |  |

Keep a printed and offline copy. Test the break-glass account procedure at least twice a year.

### Appendix D: Helpdesk identity-verification standard (stops MFA reset and password reset social engineering)

1. **No credential or MFA reset on the strength of a call, chat or email alone.**
2. Verify with **two independent factors**, such as: video call with ID check, callback to the number in the HR system (never the number provided by the caller), approval from the user's manager through a separate channel, or in-person verification.
3. For privileged accounts and executives, resets require **a second approver and Security notification**.
4. After any reset: notify the user at the previously registered contact, and for 24 hours alert on sign-ins from new devices/IPs.
5. Refuse and escalate when the caller creates urgency ("CEO is traveling", "I'm locked out of a board meeting"), cannot be verified, or asks to change the recovery phone/email.
6. Log every reset: ticket, requester, verification method, approver.

### Appendix E: Communication templates

**Affected user (account compromise)**

> Your `<SYSTEM>` account showed signs of unauthorized access on `<DATE UTC>`. We have signed you out of all sessions and secured your account. We need to speak with you by phone at `<NUMBER>`. Until we call, do not sign in to `<SYSTEM>` and do not approve any sign-in prompts you did not start. You are not in trouble; quick reporting helps us protect everyone.

**External party (vendor/customer received fraudulent mail)**

> We detected that email sent from `<ADDRESS>` between `<TIME>` and `<TIME>` UTC was not authorized and may have asked you to change payment details or open a link. Please disregard those messages and do not act on them. Verify any payment or bank-detail change with us by phone at `<VERIFIED NUMBER>`. Contact `<CONTACT>` with questions.

**Executive update (every cycle)**

> Status: `<contained/not>` · Identities affected: `<count/privilege level>` · Data/money at risk: `<...>` · Actions in progress: `<...>` · Decisions needed: `<...>` · Next update: `<TIME UTC>`.

### Appendix F: Notification clock checklist (Legal/DPO)

- [ ] Time of awareness of likely personal-data exposure (UTC): `____`
- [ ] Mailboxes/files/apps accessed by the attacker and the personal-data categories in them: `____`
- [ ] Applicable regimes (GDPR, Kenya Data Protection Act, sector rules, customer contracts, insurer): `____`
- [ ] Regulator deadline (commonly 72 h from awareness; confirm with counsel): `____`
- [ ] Individuals/customers to notify and deadline: `____`
- [ ] Law enforcement report (and reference) and financial-fraud report: `____`

### Appendix G: Readiness checklist (do before the incident)

- [ ] Sign-in, audit, mailbox audit and Unified Audit logs streamed to the SIEM with 90+ days retention; mailbox auditing on
- [ ] Alerts live for: inbox rule with external forward/delete, new MFA method, new OAuth consent, privileged role change, CA policy change, federation change, risky sign-in, MFA-denial bursts
- [ ] MFA for everyone, **phishing-resistant MFA (FIDO2/passkeys) for admins and finance**, number matching and context on push
- [ ] Legacy authentication blocked; external auto-forwarding blocked
- [ ] User consent restricted; admin consent workflow enabled
- [ ] PIM/just-in-time admin, separate admin accounts, two tested break-glass accounts with alerting
- [ ] Conditional Access: device compliance for sensitive apps, risk-based policies, named locations, token protection/CAE where supported
- [ ] DMARC at quarantine/reject; impersonation protection; external email tagging
- [ ] Payment controls: dual approval and callback verification for bank-detail changes
- [ ] Helpdesk verification standard (Appendix D) trained and audited
- [ ] Baseline exports of roles, CA policies, enterprise apps and permissions kept immutably for diffing
- [ ] Tabletop for each playbook at least annually; BEC and tenant-admin-compromise exercises with Finance and executives

### Appendix H: Quick reference

| Situation | First action |
| --- | --- |
| Confirmed account takeover | Export logs, revoke sessions, reset password, remove attacker MFA methods, run persistence sweep |
| MFA prompts, none approved | Reset password and revoke sessions (the password is burned); block attacker IP |
| MFA prompt approved | Standard Containment, check new MFA methods/devices and helpdesk resets |
| AiTM suspected | Revoke sessions (reset is not enough), remove unknown methods/devices, block lure domain |
| Fraudulent payment request | Call the bank for recall first, then contain mailbox and remove rules |
| Inbox rule with external forward | Export then remove rule, remove forwarding, check other mailboxes with the same pattern |
| Unknown OAuth app consent | Disable service principal, revoke grants, revoke user sessions, scope what it read |
| Unexpected admin role change | Verify out-of-band, remove role, disable identities, check for secondary persistence, protect break-glass |
| Impossible travel alert | Test benign causes, call user out-of-band, check post-login activity, then dismiss or contain |
| Unsure about severity | Treat one level higher; downgrade with evidence |
