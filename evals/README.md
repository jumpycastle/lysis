# Eval cases

Each case is one folder:

```
evals/cases/<name>/
  artifacts/       required — what a reviewer would receive
  repo/            optional — source for code verification
  context.md       optional — extra reviewer context
  expected.yaml    required — what a correct review contains
```

## expected.yaml

```yaml
system_name: LabShare                    # optional: forces the name
profile: profiles/default.yaml           # optional: per-case profile
expected_decision: Conditional Approval  # worst decision across scopes
max_findings: 10                         # "fewer, higher-quality" guard

must_find:
  - id: export-cross-tenant
    # keyword groups: every group must match (AND); any keyword in a group (OR)
    # matched against title + description + attacker_path
    keywords: [["tenant"], ["export"]]
    min_severity: High                   # optional
    stride: ElevationOfPrivilege         # optional

must_not_find:                           # false-positive traps
  - id: sql-injection
    keywords: [["sql injection", "sqli"]]

gates:                                   # expected control gate answers
  security_logging: "No"
```

## Building the suite

The best cases come from past reviews where you know the right answer. Sanitize them, then
write `must_find` entries for the findings a senior reviewer would never miss, and
`must_not_find` entries for the noise the agent used to produce. Aim for 10–20 cases across
different system types (SaaS integration, internal tool, data pipeline, mobile app, AI/LLM feature).

`ctm eval` writes `runs/evals/eval_scores.json`. Save a baseline, then compare after each
prompt or model change.
