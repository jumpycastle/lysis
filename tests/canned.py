"""Canned pass outputs for the LabShare sample case, deliberately containing mistakes the
validator must catch (fabricated quote, bad framework ref, person as owner, Approved-with-High,
unanswered gates)."""

SYSTEM_MODEL = {
    "system_name": "LabShare",
    "purpose": "Share assay results from CROs with sponsor tenants.",
    "users": [{"name": "Sponsor scientists", "sources": ["architecture.md"]},
              {"name": "CRO lab technicians", "sources": ["architecture.md"]}],
    "components": [{"name": "Flask API", "kind": "service", "technologies": ["Flask", "ECS Fargate"], "trust_zone": "App tier"},
                   {"name": "Results bucket", "kind": "datastore", "technologies": ["S3"], "trust_zone": "Data tier"}],
    "data_flows": [{"source": "CRO LIMS", "destination": "Flask API", "data": "result-ready webhook",
                    "crosses_trust_boundary": True, "boundary": "vendor -> LabShare"}],
    "trust_boundaries": [{"name": "Internet -> ALB"}],
    "authn": "Okta OIDC with MFA", "authz": "role + tenant",
    "scopes": ["LabShare"],
    "has_purpose": True, "has_data_flows": True, "has_users": True,
    "gaps": ["Token revocation process"],
}


def _finding(**kw):
    base = {
        "id": "R1", "scope": "LabShare", "title": "t", "description": "d", "attacker_path": "a",
        "risk": "r", "worst_case_scenario": "w", "mitigating_factors": "", "severity": "Medium",
        "confidence": "High", "evidence_basis": "inference", "cvss_vector": "", "cwe": "",
        "remediation": "fix", "interim_guidance": "", "category": "Access Control",
        "stride_category": "ElevationOfPrivilege", "framework_refs": [], "evidence": "see docs",
        "evidence_quotes": [], "code_evidence": [], "standards_cited": [], "reviewer_questions": [],
        "suggested_owner": "Application Engineering", "tshirt_size": "S", "domain_tags": [], "gate_id": "",
    }
    base.update(kw)
    return base


F_EXPORT = _finding(
    id="R1",
    title="Export endpoint trusts tenant_id from request body, enabling cross-tenant export",
    description="POST /api/export takes tenant_id from the JSON body and never compares it to the caller's tenant.",
    attacker_path="A sponsor scientist from tenant A calls POST /api/export with tenant B's tenant_id and a study id, "
                  "and receives a pre-signed link to tenant B's results.",
    severity="High", confidence="High", evidence_basis="code_verified",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", cwe="CWE-639",
    framework_refs=["OWASP A01:2021", "NIST 800-53 AC-3", "NIST 800-53 ZZ-9", "ISO 27001 A.9"],
    evidence_quotes=[{"artifact": "architecture.md",
                      "quote": 'the UI sends `POST /api/export` with `{"tenant_id": ..., "study_id": ...}`'}],
    code_evidence=[{"file": "app/api.py", "line_start": 27, "line_end": 27,
                    "snippet": 'tenant_id = body["tenant_id"]', "note": "tenant from body"}],
    standards_cited=["Identity and Access Standard"],
    suggested_owner="Jane Smith", tshirt_size="S", domain_tags=["Multi-tenancy"],
    component="Flask API", prior_overlap="duplicate", prior_refs=["ACME-PT-LS-001"],
)

F_WEBHOOK = _finding(
    id="R2",
    title="LIMS webhook accepts unauthenticated requests that change study status",
    description="/api/webhooks/lims has no signature or token check.",
    attacker_path="Any internet user POSTs a forged result-ready event for any study id, marking studies ready.",
    severity="Medium", confidence="Medium", evidence_basis="direct",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", cwe="CWE-306",
    evidence_quotes=[{"artifact": "architecture.md", "quote": "The webhook verifies an HMAC signature"}],  # fabricated
    standards_cited=["Third-Party Risk Standard", "Vendor Webhook Policy v2"],  # second is fabricated
    reviewer_questions=["Is the ALB restricted to CRO IP ranges for /api/webhooks/*?"],
    tshirt_size="M", domain_tags=["Third-Party"], component="Flask API", prior_overlap="none",
)

F_URL = _finding(
    id="R3",
    title="Seven-day pre-signed export URLs cannot be revoked",
    description="Exports return pre-signed URLs valid for 7 days.",
    attacker_path="A leaked export link (email forward, proxy log) gives anyone the ZIP for up to 7 days, even after the user is disabled.",
    severity="High", confidence="High", evidence_basis="absence_of_documentation",
    cwe="CWE-613", tshirt_size="S", domain_tags=["Data Protection"],
)

F_DUP = _finding(
    id="R4",
    title="Export endpoint trusts tenant_id from request body enabling cross tenant export",
    severity="Medium", confidence="Medium",
)

DRAFT = {"findings": [F_EXPORT, F_WEBHOOK, F_URL, F_DUP], "gate_assessments": [],
         "review_context": {"possible_unconfirmed_threats": [], "assumptions": []}}

VERIFICATION = {
    "results": [
        {"finding_id": "R1", "verdict": "confirmed",
         "evidence": [{"file": "app/api.py", "line_start": 27, "line_end": 27,
                       "snippet": 'tenant_id = body["tenant_id"]'}]},
        {"finding_id": "R2", "verdict": "confirmed",
         "evidence": [{"file": "app/api.py", "line_start": 33, "line_end": 36,
                       "snippet": "def lims_webhook():"}]},
    ],
    "code_observations": [],
}

CRITIQUE = {"items": [{"finding_id": "R4", "action": "merge", "reason": "dup", "merge_into": "R1"}],
            "missed_threats": [], "gate_issues": []}

FINAL = {
    "findings": [F_EXPORT, F_WEBHOOK, F_URL, F_DUP],
    "gate_assessments": [
        {"gate_id": "security_logging", "answer": "No",
         "evidence": "architecture.md: 'They are not currently forwarded to the SIEM.'"},
        {"gate_id": "strong_auth", "answer": "Yes", "evidence": "Okta SSO with MFA enforced for all users"},
        {"gate_id": "rbac", "answer": "Yes", "evidence": ""},
        # ir_kill_switch intentionally missing
    ],
    "decisions": [{"scope": "LabShare", "decision": "Approved for Go-Live",
                   "rationale": "Fix [R1] and [R3] soon.", "conditions": []}],
    "attack_chains": [
        {"id": "AC1", "name": "Tenant spoof \u2192 cross-tenant export",
         "narrative": "A sponsor user forges tenant_id on export, pulling another tenant's results.",
         "severity": "High", "steps": ["R1", "R3"]},
        {"id": "AC2", "name": "Webhook forge \u2192 bogus status",
         "narrative": "Unauthenticated LIMS webhook lets an attacker mark studies ready.",
         "severity": "Medium", "steps": ["R2", "ACME-PT-LS-001"]},
    ],
    "review_context": {"possible_unconfirmed_threats": [], "assumptions": []},
}

PRIOR = {
    "source_kind": "penetration test",
    "findings": [
        {"id": "ACME-PT-LS-001", "title": "Missing server-side authorization on /api/export",
         "severity": "Critical", "status": "Open", "component": "Flask API",
         "summary": "No authz on export", "source": "prior-pentest-summary.md"},
        {"id": "ACME-PT-LS-002", "title": "Verbose error messages leak stack traces",
         "severity": "Low", "status": "Remediated", "component": "Flask API",
         "summary": "Stack traces in errors", "source": "prior-pentest-summary.md"},
    ],
}

CANNED = {
    "submit_prior": PRIOR,
    "submit_system_model": SYSTEM_MODEL,
    "submit_draft": DRAFT,
    "submit_verification": VERIFICATION,
    "submit_critique": CRITIQUE,
    "submit_final": FINAL,
}

AGENT_SCRIPT = [
    ("grep", {"pattern": "tenant_id", "path_glob": "*.py"}),
    ("read_file", {"path": "app/api.py", "start_line": 20, "end_line": 40}),
    ("read_file", {"path": "../../../etc/passwd"}),  # sandbox must refuse
]
