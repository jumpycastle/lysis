# Identity and Access Standard

> EXAMPLE / PLACEHOLDER — replace with the client's actual standard text. The agent cites
> standards only by the name on line 1, and only standards present in the pack.

- Human access uses the corporate IdP (SSO) with MFA. Local accounts are prohibited except
  documented, monitored break-glass accounts.
- Service-to-service authentication uses short-lived workload credentials; long-lived static
  keys require an approved exception and rotation at most every 90 days.
- Authorization is enforced server-side and scoped by role and tenant. Client-supplied
  identifiers (user, tenant, org) must not be trusted for authorization decisions.
- Privileged roles are granted just-in-time and reviewed quarterly.
