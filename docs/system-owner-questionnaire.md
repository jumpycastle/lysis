# System Owner Questionnaire

> **What this is.** A generic intake questionnaire for a system/application owner to complete before
> a security or threat-model review. Its answers are exactly the context a reviewer — or the Lysis
> threat-model agent — needs to build the system model and answer the control gates. Hand it to the
> owner, collect the answers, and feed them in as review context (`--context`) alongside your
> architecture docs.
>
> **Reference template — replace the placeholders** (`<Organization>`, `<IdP>`, `<PAM>`, `<SIEM>`,
> `<CMDB>`, `<Security Team>`) with your environment's names before you send it. Answer options in
> parentheses are suggested controlled vocabularies; adapt them to your own tiers and schemes.
>
> **Questions marked ⟡ map directly to the agent's control gates** (strong auth, RBAC, security
> logging, incident kill-switch, asset inventory, patch hygiene) — a "No", or a "Yes" without
> evidence, is what produces a gate finding.

## Placeholders to replace

| Placeholder | Replace with |
|---|---|
| `<Organization>` | Your organization or team name |
| `<IdP>` | Your enterprise SSO / identity provider |
| `<PAM>` | Your privileged-access vault / approved secrets manager |
| `<SIEM>` | Your SIEM / log-aggregation platform |
| `<CMDB>` | Your asset inventory / CMDB |
| `<Security Team>` | The team that owns incident response |

If the owner manages more than one system, complete a separate questionnaire per system. For any
item, the owner should work with their technical owner, system administrator, or vendor support as
needed.

---

## 1. Application profile

1. What is the name of this application? *(text)*
2. ⟡ What is the unique `<CMDB>` ID for this application? *(text / Unknown / N/A)*
3. In one sentence, what does the application do and who uses it? *(text)*
4. Who is the **business owner**? *(name / email)*
5. Who is the **technical owner**? *(name / email)*
6. What type of application is this? *(Vendor-managed SaaS · Commercial software self-hosted · Custom-developed · Low-code/no-code · Open-source · Hybrid · Other · Unknown)*
7. Where is the application hosted? *(Multi-select: `<Organization>` AWS · Azure · GCP · On-prem · Vendor-managed SaaS · Vendor-hosted private environment · Other · Unknown)*
8. In which region(s) / data residency zone(s) is data stored or processed? *(text / Unknown)*
9. What is the application's GxP / regulated status? *(Validated or qualified · Validation in progress · Not in scope · Unknown)* — *omit if you don't review regulated systems*
10. Which business unit(s) does this application support? *(Multi-select from your controlled list)*
11. What level of operational support covers it? *(24x7 on-call rotation · Business-hours support · No defined on-call coverage · Unknown)*
12. What would the business impact be if the application were unavailable for 3 days? *(Low · Moderate · High · Critical · Unknown)* — and explain in two sentences or fewer. *(text)*
13. What is the application's service tier? *(Tier 1 · Tier 2 · Tier 3 · Untiered · Unknown)*
14. What is the Disaster Recovery status? *(Documented and tested in the past 12 months · Documented, not tested in 12 months · No documented DR plan · N/A · Unknown)* — if documented, describe the approach in ≤3 sentences (e.g. hot/cold, multi-region). *(text)*
15. Are application data and configuration backed up, and has a restore been tested? *(Backed up and restore tested · Backed up, restore not tested · Not backed up · Vendor-managed · Unknown)*

## 2. Identity & access

16. ⟡ Do all human users authenticate via enterprise SSO (`<IdP>`)? *(Yes · Partial · No · No human users · Unknown)* — if No/Partial, describe the exceptions (local, vendor, customer, or emergency accounts). *(text)*
17. ⟡ Is multi-factor authentication enforced for all human access? *(Yes · Partial · No · Unknown)* — if Partial/No, describe which accounts are exempt. *(text)*
18. Can any users or accounts bypass SSO or MFA? *(Yes · No · Unknown)* — if Yes, describe. *(text)*
19. What is the maximum authenticated session duration before full re-authentication? *(<4h · 4–8h · 8–12h · 12–24h · >24h · No defined maximum · Unknown)*
20. What is the idle-session timeout? *(<15 min · 15–60 min · 1–4h · >4h · None · Unknown)*
21. Can active sessions be revoked immediately when an account is disabled or access is removed? *(Yes · Partial · No · Unknown)*
22. Approximately how many users have administrative or privileged access? *(None · 1–2 · 3–10 · 11–25 · 25+ · Unknown)*
23. Do privileged users use separate, named privileged accounts for administrative actions? *(Yes · Partial · No · N/A · Unknown)*
24. Are those privileged credentials managed in `<PAM>`? *(Yes · Partial · No · N/A · Unknown)*
25. Are break-glass or emergency administrator accounts maintained? *(Yes · No · Unknown)* — if Yes, how are they secured, monitored, and reviewed? *(text)*
26. ⟡ Is role-based access control (RBAC) enforced for sensitive data and actions? *(Yes · Partial · No · Unknown)*
27. Are permissions ever assigned directly to individual users outside defined roles? *(Yes · No · Unknown)*
28. Which non-`<Organization>` user populations can access the application? *(Multi-select: None · Contractors · Vendors/MSP · External partners · Customers · Other · Unknown)* — if not None, describe who they are, how they authenticate, and whether access expires automatically. *(text)*
29. If a vendor or MSP has access, is it named per-individual, MFA-protected, least-privilege, time-limited, and monitored? *(Yes · Partial · No · N/A · Unknown)*
30. Does the application contain any shared, generic, default, or built-in accounts usable interactively? *(Yes · No · Unknown)* — if Yes, describe purpose and protections. *(text)*

## 3. Secrets & machine identities

31. Does the application use service accounts, local emergency accounts, API keys, certificates, client secrets, or other machine identities? *(Yes · No · Unknown)*
32. Where are those credentials/secrets stored? *(Multi-select: `<PAM>` · Approved cloud secrets manager · Vendor-managed secrets manager · Application config or local file · Source-code repository · Shared manually · Other · Unknown)*
33. How are they rotated? *(Automatically · Manually on a defined schedule · Vendor-managed · No defined rotation · Unknown)*
34. Are any credentials or secrets shared with an external organization? *(Yes · No · Unknown)* — if Yes, describe the recipient, purpose, and access level. *(text)*

## 4. Data & exposure

35. What is the highest data classification stored, processed, or transmitted? *(Public · Internal · Confidential · Sensitive · Unknown)*
36. If Sensitive, which regulated data types are handled? *(Multi-select: PII · PHI · Clinical/GxP records · IP or trade secrets · Credentials/secrets · Financial · Other · None)*
37. Is data encrypted **in transit** (e.g. TLS) and **at rest**? *(Both · In transit only · At rest only · Neither · Unknown)*
38. Which application interfaces are reachable from the public internet? *(Multi-select: None · User/login UI · Administrative interfaces · API or webhook · SFTP/file-transfer · Integration endpoint · Other · Unknown — cannot pick both None and Unknown)*
39. Can the application be accessed from unmanaged or personal devices? *(Yes · No · Unknown)*
40. Which additional access restrictions are enforced? *(Multi-select: Managed device required · VPN required · Virtual desktop required · Trusted corporate network required · IP allowlisting · Geographic restriction · Client certificate · Other · None · Unknown)*
41. Approximately how many human users access the application? *(None · <50 · 50–250 · 250–1,000 · 1,000–5,000 · 5,000+ · Unknown)*
42. Does the application exchange data with other internal systems, third parties, or external organizations? *(Yes · No · Unknown)* — if Yes, list them or link a data-flow/integration diagram. *(text / link)*
43. Does the application have API integrations, automations (batch jobs, scheduled updates), or dependencies on other services? *(Yes · No · Unknown)* — if Yes, briefly describe purpose and access level. *(text)*

## 5. Logging & monitoring

44. ⟡ Are security-relevant application logs currently forwarded to `<SIEM>`? *(Yes · Partial · No · Unknown)*
45. If No/Partial/Unknown, how long are security-relevant logs retained in the application? *(<30 days · 30–90 days · 91–365 days · >1 year · Not defined · Unknown)*
46. Which activities are captured in audit logs? *(Multi-select: Successful/failed authentication · Account create/delete/disable · Role or privilege changes · Admin configuration changes · Data exports / bulk downloads · API & service-account activity · Other · None · Unknown)*
47. At what level of activity would behavior be considered abnormal (e.g. mass exports, API spikes, privilege changes, admin actions)? *(text)*

## 6. Incident response & resilience

48. ⟡ During an incident, can active access be promptly disabled and sessions revoked? *(Yes for human and machine access · Partial · No · Vendor assistance required · Need help establishing this · Unknown)*
49. ⟡ Can the `<Security Team>` do so **without** direct support from the app team — e.g. via a protected account, API key, or integration provided for incident use? *(Yes for both · Partial · No · Vendor assistance required · Need help establishing this · Unknown)*

## 7. Change & vulnerability management

50. ⟡ For `<Organization>`-managed components, how quickly are critical security updates typically applied? *(≤30 days · 31–90 days · 91–180 days · 181–365 days · >365 days · No defined process · Unsupported/EOL · N/A · Unknown)*
51. Are there scheduled maintenance windows for patching and upgrades? *(Yes · No · Unknown)* — if Yes, what cadence? *(text)*
52. For custom-developed or low-code applications, are code, dependencies, containers, and infrastructure-as-code scanned with approved security tooling before release? *(Yes · Partial · No · N/A · Unknown)*

## 8. Emerging technology & additional context

53. Does the application use generative AI, AI agents, or MCP servers/connectors? *(Yes · No · Unknown)* — if Yes, briefly describe the use and any data exposed to it. *(text)*

**Free-text:** Describe any known security risks, exceptions, or compensating controls not captured above. *(text)*

**Documentation links** *(optional, provide where available):* architecture diagram · data-flow diagram · disaster-recovery plan · support documentation · security or vendor assessment · other.

---

## Optional: Device / OT / lab-instrument addendum

Complete this block only if the system includes hardware, an on-prem gateway, a lab instrument, or
embedded firmware. These map to the agent's **Device / IoT lens**.

- **D1.** Is there an on-device admin UI/API, and is it reachable from the LAN? Is it cleartext (HTTP, Telnet, unauthenticated)? Which hosts/segments can reach it? *(text)*
- **D2.** Are there shared/universal default credentials, or passwords printed on labels/name plates? Is a change forced at first use? *(Yes · No · Unknown)* + describe.
- **D3.** Do factory reset or firmware updates restore default credentials or settings? *(Yes · No · Unknown)*
- **D4.** Are serial numbers, MACs, or hostnames used for cloud enrollment, pairing, or authentication — and are they network-discoverable or physically visible? *(Yes · No · Unknown)*
- **D5.** Is firmware signed, and is downgrade/rollback prevented? Do USB updates auto-run on insertion? *(text)*
- **D6.** Does the device auto-discover or pair with peers on the same subnet (mDNS/ZeroConf)? Could a rogue peer impersonate it or inject telemetry? *(Yes · No · Unknown)*
- **D7.** What alternate access paths exist? *(Multi-select: Optional Wi-Fi/WLAN module · USB ports · Serial console · Vendor remote-service access · Cellular modem · None · Unknown)*
- **D8.** Can setpoints, thresholds, or operating modes be changed over the network or from the cloud? *(Yes · No · Unknown)*
- **D9.** Are you asked to bypass DPI, proxy, or firewall inspection for this device's traffic? *(Yes · No · Unknown)*
