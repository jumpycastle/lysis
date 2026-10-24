# PASS 2 — THREAT ENUMERATION (DRAFT)

You have the artifacts and the extracted system model. Enumerate risks.

Method:
1. Walk every data flow that crosses a trust boundary and every entry point. Apply STRIDE
   to each element (Spoofing, Tampering, Repudiation, InformationDisclosure,
   DenialOfService, ElevationOfPrivilege).
2. For each credible threat, ask: what does the input say that makes this real? If the answer
   is "nothing, it's just not documented", it is either a Medium-at-most finding with
   evidence_basis "absence_of_documentation", or it belongs in review_context as a possible
   unconfirmed threat.
3. Check the relevant standards from the standards pack (triggers listed below) and note where
   the design conflicts with them. A standard only matters if you can tie it to an attack path.
4. Answer every mandatory control gate (listed below) with Yes / No / Unknown and the evidence.
5. Keep the list short and sharp. Merge findings that share a root cause.

For each Risk finding:
- id: "R1", "R2", ... (stable within this review)
- scope: which scope from the system model it belongs to
- title: specific ("Tenant ID taken from request body on /api/export enables cross-tenant reads"),
  never generic ("Insufficient access control")
- description: 2–4 sentences, what is wrong and where
- attacker_path: 1–3 sentences, concrete exploitation from a named starting position
- risk: one sentence on likelihood × impact in this system
- worst_case_scenario: 1–2 sentences
- mitigating_factors: controls the INPUT describes that reduce this risk. Empty string if none.
  Never invent one.
- severity, confidence, evidence_basis
- cvss_vector: CVSS:3.1 base vector string (the score is computed for you); "" if you
  genuinely cannot vector it
- cwe: "CWE-NNN" only when you are confident of the mapping; otherwise ""
- remediation: specific to this system
- interim_guidance: what to do before remediation lands (required when remediation is non-trivial)
- category: short domain label (e.g. "Access Control", "Secrets Management", "Logging")
- stride_category, framework_refs
- evidence: prose citing artifacts by name and standards by name
- evidence_quotes: exact verbatim quotes from text artifacts supporting the finding
  ({"artifact": "<file name>", "quote": "<exact text>"}); keep each quote short (under 200 chars)
- standards_cited: exact standard names from the pack you relied on
- reviewer_questions: 2–4 specific validation questions when confidence is not High; [] when High
- suggested_owner: a role or team, never a person's name
- tshirt_size: XS | S | M | L | XL | XXL — remediation effort
- domain_tags: 1–3 short domain tags (e.g. "IAM", "Data Protection")
- gate_id: set to the gate id if this finding exists because a control gate failed; else ""
- component: the name of the system-model component (or data-flow endpoint) this finding is
  anchored to. Use a name exactly as it appears in the system model, so it can be placed on the
  diagram. If it spans several, pick the one where the weakness lives.

review_context:
- possible_unconfirmed_threats: hints without enough evidence to be findings
- assumptions: what you assumed; if wrong, findings may be inaccurate

Call the `submit_draft` tool exactly once.
