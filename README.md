# How to Use the Incident Response Playbooks

This guide explains how to use **Incident Response Playbooks v2.0** during preparation, an active security incident, and post-incident review.

## 1. What the playbook covers

Use the relevant response section for:

- **Phishing** — malicious email, links, attachments, credential theft, or business email compromise.
- **Brute force / password spray / credential stuffing** — repeated or distributed attempts to access accounts or services.
- **Ransomware** — suspected or confirmed file encryption, ransom notes, or activity that may precede encryption.
- **Malware beaconing (C2)** — suspicious recurring outbound connections that may indicate an infected host.

Section 0 contains rules and procedures that apply to every incident. The appendices contain reusable templates, readiness checks, and operational registers.

## 2. Prepare before an incident

Do not wait for an incident to customise the document. The Security / IR Lead should:

1. Replace every `<PLACEHOLDER>` with the organisation's real contacts, systems, channels, and values.
2. Assign a primary and backup for each response role in **Section 0.2** and **Appendix A**.
3. Complete **Appendix J – Local Implementation Register** with the actual SIEM, EDR, email, identity, network, backup, evidence-storage, and communication tools. Record who has permission to use them.
4. Confirm emergency authority and approval paths for isolating devices, disabling accounts, blocking traffic, and taking services offline.
5. Verify that evidence storage, out-of-band communications, log access, and backup recovery procedures work.
6. Test the example queries against your own data sources and schemas using **Appendix K**. Treat them as starting points, not production-ready detections.
7. Review the readiness checklist in **Appendix F** and run tabletop exercises.

Keep an offline copy of the playbook and contact list in case email, identity services, or the network are unavailable.

## 3. Use it during an incident

Follow this sequence for every incident:

1. **Create and record:** Open an incident ticket using **Appendix B**. Assign an ID such as `IR-2026-001`, record detection time, declare severity, and name the Incident Commander (IC) and Scribe.
2. **Choose the playbook:** Start with the section matching the observed activity. If more than one type applies, use the related playbooks together—for example, phishing followed by malware execution, or C2 activity that may precede ransomware.
3. **Triage:** Follow the detection sources, first-response steps, and decision tree. Establish what happened, which users/assets are affected, whether access succeeded, and whether activity is continuing.
4. **Preserve evidence:** Use the shared evidence-handling procedure in **Section 0.4** and the relevant playbook checklist. Record evidence in the evidence log; preserve originals and analyse working copies.
5. **Contain safely:** Follow the playbook's containment guidance. Confirm the exact target, likely business impact, authority, expected effect, and rollback/recovery path before acting. Record the decision and execution time. Do not delay urgent containment where active harm is continuing.
6. **Investigate and scope:** Determine initial access, affected identities and systems, persistence, lateral movement, data access/exfiltration, and business impact. Mark findings as confirmed, likely, possible, or not observed.
7. **Eradicate and recover:** Follow the relevant recovery section. Validate that attacker access and persistence are removed, systems are clean, and business services work before returning them to normal operation. Use **Appendix I – Recovery Validation and Hand-back**.
8. **Close and learn:** Confirm the playbook's closure criteria are met, complete the incident record, and hold the post-incident review in **Appendix E**. Assign owners and due dates to improvement actions.

## 4. Severity and communications

Use the severity matrix in **Section 0.1**. Start at the higher reasonable severity and downgrade only when evidence supports it. Reassess severity as scope or impact changes, and record the reason, approver, and time.

The acknowledgement targets are proposed internal targets—not guaranteed containment or recovery times. The IC coordinates response and updates; the Scribe maintains the timeline. Use an approved out-of-band channel if email or collaboration accounts may be compromised. Only the authorised Comms Lead, with Legal approval, should issue external statements.

## 5. Using the technical queries

The Splunk, KQL, PowerShell, and Linux examples are investigation aids. Before using them:

- Replace sample domains, IPs, usernames, indexes, and other example values.
- Map field names and event sources to your environment; products and schemas differ.
- Check the time range, timezone, permissions, and expected event coverage.
- Test against known events and inspect raw records behind results.
- Tune thresholds to your normal environment and document limitations.
- Do not treat an empty result as proof that an event did not happen.

Do not upload confidential files, memory captures, or customer data to public analysis services. Follow your organisation's approved evidence and data-handling rules.

## 6. Important safety and governance rules

- This document is an operational framework, not a replacement for organisation-specific procedures, vendor guidance, or legal advice.
- Protect people and essential services; consider safety and continuity before disruptive containment actions.
- Do not reboot, reimage, delete, or clean affected systems before considering volatile evidence, unless urgent containment takes priority.
- Do not run destructive commands or broad blocks without confirming the target and recording the decision.
- Legal / DPO must assess applicable notification duties and deadlines. Do not assume one deadline applies to every incident or jurisdiction.
- Analysts must not independently negotiate or approve ransom payments.

## 7. Review and maintain

The Security / IR Lead should review the playbooks at least every six months, after every SEV1/SEV2 incident, and after material changes to systems or controls. Update contacts, permissions, queries, evidence locations, and recovery dependencies. Track changes and retest procedures during exercises.

**Quick reference:** Reported phish → Section 1 · Authentication attack → Section 2 · Encryption or ransomware precursors → Section 3 · Suspicious C2 traffic → Section 4 · Shared rules and templates → Sections 0 and 5.
