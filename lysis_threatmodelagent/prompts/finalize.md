# PASS 5 — FINALIZE

Produce the final review. You have the system model, the draft, code verification results
(if any), and the critique. Apply the critique: keep, revise, merge, drop, and demote as it says,
and add missed threats it identified that are clearly supported. If you disagree with a critique
item, you may keep the draft version, but only if the input clearly supports it.

Output:
1. findings: the final Risk findings (same fields as the draft). Keep ids stable ("R1"...);
   new findings get new ids.
2. gate_assessments: final Yes / No / Unknown per control gate with evidence. For every gate
   that is "No", or "Yes" without evidence, either point finding_ref at an existing finding
   that covers it or leave finding_ref empty (a gate finding will be generated from your
   evidence).
3. decisions: the go-live decision(s). One per scope; use a single decision when the system is
   one coherent unit. For each:
   - scope: scope name
   - decision: "Approved for Go-Live" | "Conditional Approval" | "Not Approved"
   - rationale: 1–2 sentences. Reference findings by id in square brackets, e.g. "[R2]".
   - conditions: for Conditional Approval, the specific conditions for go-live.
   Decision rules:
   - Approved for Go-Live: zero Critical AND zero High findings in that scope.
   - Conditional Approval: Critical/High exist, but complementary controls can bring residual
     risk to an acceptable level. List the conditions.
   - Not Approved: multiple Critical findings, or no complementary controls available. Explain
     what would need to change.
4. For every final finding, set `component` to the system-model component it belongs on (a name
   from the system model), for diagram placement.
5. If prior-assessment findings are provided in <prior_findings>, set `prior_overlap` on each final
   finding to one of: "duplicate" (the prior assessment already reported this same issue),
   "partial" (this extends or adds attack surface to a prior finding), or "none" (not covered by the
   prior assessment). Put the related prior finding ids in `prior_refs`. If no prior findings are
   provided, leave `prior_overlap` empty.
6. attack_chains: identify up to 5 attack chains — ordered sequences of findings where one step
   enables the next, ending in a high-impact outcome (code execution, data exfiltration, account
   takeover, cross-tenant compromise). Each chain has an id ("AC1"...), a short name, a 1–2 sentence
   narrative, an overall end-state severity, and `steps`: the ordered finding ids that form the path
   (earliest first). Steps may reference findings from this review and/or prior-assessment finding
   ids where a prior finding is a genuine step. Only build a chain where each step really enables the
   next in this system — do not chain unrelated findings. If nothing chains, return an empty list.
7. review_context: possible_unconfirmed_threats and assumptions.

Call the `submit_final` tool exactly once.
