# LabShare — Architecture Overview

## Purpose
LabShare lets contract research organizations (CROs) share assay results with sponsor
companies. Each sponsor is a tenant. Sponsor scientists log in to view and export results for
their own studies. CRO lab staff upload result files.

## Users
- Sponsor scientists (external, per-tenant) — view and export results for their tenant's studies.
- CRO lab technicians (external vendor staff) — upload result files for any sponsor they serve.
- LabShare support admins (internal) — manage tenants and users.

## Components
- **Web UI** — React single-page app served from CloudFront.
- **API service** — Python Flask app on AWS ECS Fargate behind an Application Load Balancer.
- **Results DB** — Amazon RDS PostgreSQL. Stores result metadata and tenant/study mappings.
- **Results bucket** — Amazon S3 bucket holding uploaded result files (CSV, PDF).
- **Export worker** — background job that builds ZIP exports and writes a pre-signed S3 URL.
- **Partner webhook** — CROs' LIMS systems POST "result ready" notifications to `/api/webhooks/lims`.

## Authentication and authorization
- Human users authenticate through Okta SSO (OIDC). MFA is enforced by the Okta policy for all users.
- The API validates the OIDC access token on every request.
- Authorization: users have a role (`sponsor_scientist`, `cro_tech`, `support_admin`) and a tenant.
- Exports: the UI sends `POST /api/export` with `{"tenant_id": ..., "study_id": ...}`.

## Data
- Assay results are Confidential and may contain coded subject identifiers.
- RDS and S3 are encrypted at rest with AWS KMS.

## Logging
- Application logs go to CloudWatch Logs with 30-day retention. They are not currently
  forwarded to the SIEM.

## Deployment
- Single AWS account, us-east-1. ECS tasks run in private subnets; only the ALB is public.
