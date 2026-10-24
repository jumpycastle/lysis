# Cloud Security Baseline

> EXAMPLE / PLACEHOLDER — replace with the client's actual standard text.

- No storage buckets or databases are publicly accessible.
- Security groups allow only required ports from required sources; no 0.0.0.0/0 on admin ports.
- Workload IAM roles follow least privilege; wildcard actions on sensitive services are prohibited.
- Secrets are stored in a managed secrets service, never in code, images, or environment files
  committed to source control.
- Audit logging (control plane) is enabled in every account and forwarded centrally.
