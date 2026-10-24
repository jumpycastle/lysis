# PASS 1 — SYSTEM MODEL EXTRACTION

Build a factual model of the system under review from the artifacts. This model is the
foundation for every later pass, so accuracy matters more than completeness: record only
what the input states or shows, and cite where each element came from.

Identify:
- system_name: the name the artifacts use for the system (short, as a human would say it).
- purpose: what the system does and for whom.
- users: who uses it (human roles, service accounts, external parties, tenants).
- components: services, stores, queues, third-party integrations, clients, and the external
  actors that drive the system (users, partner systems). For each, record the technologies the
  input actually names (never guess a stack), and a `trust_zone`: a short label for the security
  boundary it sits in (e.g. "Internet", "App tier", "Data tier", "Third-party", "Internal/Dev",
  or a named account/VPC). Components that share a boundary should share a trust_zone label; this
  is used to group them in the threat-model diagram.
- data_flows: source → destination, what data, protocol, and whether it crosses a trust boundary.
- trust_boundaries: internet ↔ DMZ, tenant ↔ tenant, corp ↔ vendor, user ↔ admin, etc.
- authn / authz: how identities authenticate, how authorization decisions are made, at which layer.
- data_classification: what sensitive data exists, where it lives, and how it is classified
  (only if the input says; otherwise say "not stated").
- deployment_context: hosting, cloud/on-prem, regions, network placement. If the system includes
  hardware, an on-prem gateway, a lab instrument, embedded firmware, or other operational
  technology (OT), say so here and give such components a kind like "device", "gateway",
  "instrument", or "firmware" — this is used to decide whether the device/IoT lens applies.
- entry_points: every place an attacker could send input (APIs, UIs, webhooks, file drops, queues).
- scopes: distinct components or integrations with materially different risk profiles that
  may deserve separate go-live decisions. Most systems are one scope.

Minimum input check — set each flag honestly:
- has_purpose, has_data_flows, has_users.

Also list:
- gaps: important facts the review needs but the input does not provide.
- source refs: for each element, name the artifact(s) it came from.

Call the `submit_system_model` tool exactly once.
