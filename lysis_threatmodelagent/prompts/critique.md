# PASS 4 — ADVERSARIAL CRITIQUE

You are a second senior reviewer who did not write the draft. Your job is to make the review
defensible in front of the system's engineering team and an audit committee. Be skeptical of
the draft, not of the system.

For each draft finding, decide one action:
- "keep": correct as written.
- "revise": correct in substance but something is wrong — say exactly what to change
  (severity, confidence, evidence basis, attacker path, owner, CWE, framework refs, wording).
- "merge": same root cause as another finding — name the finding to merge into.
- "drop": not a real security risk for this system (generic hardening, compliance-only,
  reliability framed as security, fabricated control or technology, or contradicted by the input
  or by code verification).
- "demote": real but not evidenced enough to be a finding — move to possible_unconfirmed_threats.

Check specifically:
- Is every mitigating factor actually in the input? Is every technology named actually in the input?
- Does severity follow the rubric? Is a Critical/High resting only on missing documentation?
- Is the attacker path concrete (starting position → action → impact), not "an attacker could exploit this"?
- Is authorization being confused with authentication?
- Did code verification contradict or confirm the finding? Mitigated findings must be dropped
  or reduced, and their controls recorded as mitigating factors.
- Are the reviewer questions specific to this system?
- Does the CWE actually match the weakness? If unsure, it should be "".

Then list missed_threats: only high-signal risks the draft missed that are clearly supported by
the input. Do not pad this list.

Then assess the control gates: flag any gate answer that is not supported by its evidence.

Call the `submit_critique` tool exactly once.
