# Data Classification Standard

> EXAMPLE / PLACEHOLDER — replace with the client's actual standard text.

- Classes: Public, Internal, Confidential, Restricted. Personal data and credentials are Restricted.
- Restricted data is encrypted in transit (TLS 1.2+) and at rest with managed keys.
- Restricted data must not be written to application logs, analytics, or third-party
  services without an approved data processing agreement.
- Bulk export of Confidential or Restricted data requires authorization and audit logging.
