"""Data models.

Two layers:
- *Working* models (what the LLM passes produce): carry extra fields the validator needs
  (ids, scope, evidence_basis, quotes, code evidence, CVSS vectors, gate ids).
- *Export* model (ExportFinding / ReviewExport): the ticket-ready schema from the original
  instruction set. Built deterministically from working models by enforce.py.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field
from pydantic.json_schema import SkipJsonSchema

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
Level = Literal["High", "Medium", "Low"]
Stride = Literal["Spoofing", "Tampering", "Repudiation", "InformationDisclosure",
                 "DenialOfService", "ElevationOfPrivilege"]
TShirt = Literal["XS", "S", "M", "L", "XL", "XXL"]
Actionability = Literal["CreateTicket", "NeedsReview", "Informational"]
EvidenceBasis = Literal["direct", "code_verified", "inference", "absence_of_documentation"]
Decision = Literal["Approved for Go-Live", "Conditional Approval", "Not Approved"]
GateAnswer = Literal["Yes", "No", "Unknown"]

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def sev_rank(s: str) -> int:
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER)


# ------------------------------------------------------------------ pass 1

class SourcedItem(BaseModel):
    name: str
    detail: str = ""
    sources: list[str] = Field(default_factory=list, description="artifact file names")


class Component(BaseModel):
    name: str
    kind: str = Field("", description="service, datastore, queue, client, third-party, external-actor, etc.")
    technologies: list[str] = Field(default_factory=list, description="ONLY technologies named in the input")
    scope: str = ""
    trust_zone: str = Field("", description=(
        "short trust-zone label for grouping in the diagram, e.g. 'Internet', 'DMZ', "
        "'App tier', 'Data tier', 'Third-party', 'Internal', '<Account/VPC name>'. "
        "Components in the same zone share a boundary box."))
    sources: list[str] = Field(default_factory=list)


class DataFlow(BaseModel):
    source: str
    destination: str
    data: str = ""
    protocol: str = ""
    crosses_trust_boundary: bool = False
    boundary: str = ""
    sources: list[str] = Field(default_factory=list)


class SystemModel(BaseModel):
    system_name: str
    purpose: str
    users: list[SourcedItem] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    trust_boundaries: list[SourcedItem] = Field(default_factory=list)
    authn: str = ""
    authz: str = ""
    data_classification: str = ""
    deployment_context: str = ""
    entry_points: list[SourcedItem] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    has_purpose: bool
    has_data_flows: bool
    has_users: bool
    gaps: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------ findings

class EvidenceQuote(BaseModel):
    artifact: str
    quote: str
    verified: SkipJsonSchema[Optional[bool]] = None  # set by validator, hidden from the model


class CodeEvidence(BaseModel):
    file: str
    line_start: int
    line_end: int
    snippet: str
    note: str = ""
    verified: SkipJsonSchema[Optional[bool]] = None  # set by validator, hidden from the model


class Finding(BaseModel):
    id: str = Field(description='"R1", "R2", ...')
    scope: str = ""
    title: str
    description: str
    attacker_path: str
    risk: str
    worst_case_scenario: str
    mitigating_factors: str = ""
    severity: Severity
    confidence: Level
    evidence_basis: EvidenceBasis
    cvss_vector: str = ""
    cwe: str = ""
    remediation: str
    interim_guidance: str = ""
    category: str
    stride_category: Stride
    framework_refs: list[str] = Field(default_factory=list)
    evidence: str
    evidence_quotes: list[EvidenceQuote] = Field(default_factory=list)
    code_evidence: list[CodeEvidence] = Field(default_factory=list)
    standards_cited: list[str] = Field(default_factory=list)
    reviewer_questions: list[str] = Field(default_factory=list)
    suggested_owner: str = ""
    tshirt_size: TShirt
    domain_tags: list[str] = Field(default_factory=list)
    gate_id: str = ""
    component: str = Field("", description=(
        "name of the system-model component (or data-flow endpoint) this finding is anchored to, "
        "for placement on the diagram. Use a name that appears in the system model."))
    prior_overlap: str = Field("", description=(
        "only when prior assessment findings are provided: 'duplicate' (same issue already reported), "
        "'partial' (extends a prior finding), or 'none' (new). Empty if no prior findings were given."))
    prior_refs: list[str] = Field(default_factory=list, description="ids of related prior-assessment findings")


class PriorFinding(BaseModel):
    id: str = Field(description="the finding id from the prior report if it has one (e.g. 'ACME-PT-2026-002'), else P1, P2...")
    title: str
    severity: Severity
    status: Literal["Open", "Remediated", "Partially remediated", "Accepted", "Unknown"] = "Unknown"
    component: str = Field("", description="system-model component or endpoint this prior finding concerns")
    summary: str = ""
    source: str = Field("", description="artifact file name it came from")


class PriorAssessment(BaseModel):
    """Findings extracted from a prior assessment artifact (e.g. a penetration test report)."""
    source_kind: str = Field("", description="e.g. 'penetration test', 'audit', 'prior threat model'")
    findings: list[PriorFinding] = Field(default_factory=list)


class UnconfirmedThreat(BaseModel):
    title: str
    why_unconfirmed: str
    potential_impact: str


class Assumption(BaseModel):
    assumption: str
    impact: str


class ReviewContext(BaseModel):
    possible_unconfirmed_threats: list[UnconfirmedThreat] = Field(default_factory=list)
    assumptions: list[Assumption] = Field(default_factory=list)


class GateAssessment(BaseModel):
    gate_id: str
    answer: GateAnswer
    evidence: str = ""
    finding_ref: str = Field("", description="id of the finding covering this gate, if any")


class Draft(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    gate_assessments: list[GateAssessment] = Field(default_factory=list)
    review_context: ReviewContext = Field(default_factory=ReviewContext)


# ------------------------------------------------------------------ pass 3

class VerificationResult(BaseModel):
    finding_id: str
    verdict: Literal["confirmed", "mitigated", "partially_mitigated", "not_found", "inconclusive"]
    evidence: list[CodeEvidence] = Field(default_factory=list)
    notes: str = ""


class CodeObservation(BaseModel):
    title: str
    description: str
    attacker_path: str
    suggested_severity: Severity
    stride_category: Stride
    evidence: list[CodeEvidence] = Field(default_factory=list)


class Verification(BaseModel):
    results: list[VerificationResult] = Field(default_factory=list)
    code_observations: list[CodeObservation] = Field(default_factory=list)
    coverage_notes: str = ""


# ------------------------------------------------------------------ pass 4

class CritiqueItem(BaseModel):
    finding_id: str
    action: Literal["keep", "revise", "merge", "drop", "demote"]
    reason: str
    changes: str = Field("", description="exact changes for revise")
    merge_into: str = ""


class MissedThreat(BaseModel):
    title: str
    rationale: str
    suggested_severity: Severity
    evidence: str


class GateCritique(BaseModel):
    gate_id: str
    issue: str


class Critique(BaseModel):
    items: list[CritiqueItem] = Field(default_factory=list)
    missed_threats: list[MissedThreat] = Field(default_factory=list)
    gate_issues: list[GateCritique] = Field(default_factory=list)
    overall_notes: str = ""


# ------------------------------------------------------------------ pass 5

class ScopedDecision(BaseModel):
    scope: str
    decision: Decision
    rationale: str
    conditions: list[str] = Field(default_factory=list)


class AttackChain(BaseModel):
    id: str = Field(description='"AC1", "AC2", ...')
    name: str = Field(description="short name, e.g. 'Service key → code exec → node role'")
    narrative: str = Field("", description="1–2 sentences on how the chain works")
    steps: list[str] = Field(default_factory=list, description=(
        "ordered list of finding ids forming the path, earliest step first. Use the finding ids "
        "from this review, and/or prior-assessment finding ids where a prior finding is a step. "
        "Each step should enable the next."))
    severity: Severity = Field("High", description="overall severity of the chain's end state")


class Final(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    gate_assessments: list[GateAssessment] = Field(default_factory=list)
    decisions: list[ScopedDecision] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    review_context: ReviewContext = Field(default_factory=ReviewContext)


# ------------------------------------------------------------------ export

class ExportFinding(BaseModel):
    type: Literal["Risk", "Story"]
    title: str
    description: str
    attacker_path: str
    risk: str
    worst_case_scenario: str
    mitigating_factors: str
    severity: Severity
    confidence: Level
    priority: Level
    cvss: Optional[float]
    cwe: str
    remediation: str
    interim_guidance: str
    category: str
    stride_category: str
    framework_refs: list[str]
    evidence: str
    reviewer_questions: list[str]
    suggested_owner: str
    suggested_team: str
    tags: list[str]
    tshirt_size: TShirt
    actionability: Actionability


class Epic(BaseModel):
    title: str


class ReviewExport(BaseModel):
    epic: Epic
    findings: list[ExportFinding]
    review_context: ReviewContext


def tool_schema(model: type[BaseModel]) -> dict:
    """JSON schema for a tool's input_schema, with all $refs inlined and titles stripped."""
    schema = model.model_json_schema()
    defs = schema.pop("$defs", {})

    def resolve(node, is_props: bool = False):
        if isinstance(node, dict):
            if "$ref" in node and not is_props:
                name = node["$ref"].split("/")[-1]
                return resolve(defs[name])
            if is_props:  # keys are property names, never strip them
                return {k: resolve(v) for k, v in node.items()}
            return {k: resolve(v, is_props=(k == "properties"))
                    for k, v in node.items() if k != "title"}
        if isinstance(node, list):
            return [resolve(x) for x in node]
        return node

    return resolve(schema)
