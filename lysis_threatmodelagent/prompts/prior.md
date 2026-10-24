# PRIOR-ASSESSMENT EXTRACTION

One or more of the artifacts is a PRIOR security assessment of this same system — a penetration
test report, an audit, or an earlier threat model. Extract its findings so they can be overlaid
on this review and de-duplicated against it.

For each finding in the prior assessment:
- id: the report's own identifier if it has one (e.g. "ACME-PT-2026-002"); otherwise P1, P2, ...
- title: the finding's title, as written
- severity: map the report's rating to Critical / High / Medium / Low / Informational
- status: "Open", "Remediated", "Partially remediated", "Accepted", or "Unknown" — use what the
  report states about remediation (e.g. "fix validated on <date>" → Remediated)
- component: the system-model component or endpoint the finding concerns, matched to a name in
  the system model where possible
- summary: one sentence
- source: the artifact file name

Only extract findings that the prior report actually makes. Do not invent, merge, or re-rate them.
Call `submit_prior` exactly once.
