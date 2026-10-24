# DEVICE / IoT / OT LENS

This system includes hardware, an on-prem gateway, a lab instrument, embedded firmware, or other
operational technology. In addition to the core principles, assess each area below. Raise a finding
only when the input (including vendor documentation) supports it; otherwise, if the concern is
plausible but undocumented, put it in `possible_unconfirmed_threats`.

Treat vendor documentation as an architecture source: a manual that states an HTTP admin URL, a
default password, a reset-to-defaults behavior, or automatic device discovery is an **input fact**,
not an assumption. Consider an **adjacent-network attacker** (a foothold on the same VLAN/subnet)
and **limited physical access**, not only an internet attacker. Use `AV:A` in CVSS vectors for
adjacent-network paths and `AV:P` for physical-access paths.

- **Management plane** — Is the admin UI/API reachable from the LAN? Is it cleartext (HTTP, Telnet,
  unauthenticated protocols)? Which hosts or segments can reach it? Cleartext admin credentials on a
  shared segment are a secrets-exposure finding.
- **Credential lifecycle** — Shared or universal default credentials, passwords printed on labels or
  name plates, whether a change is forced at first use, and whether factory reset or firmware
  updates restore default credentials or settings.
- **Identifiers used as secrets** — Serial numbers, MACs, or hostnames that are network-discoverable
  or physically visible AND used for cloud enrollment, pairing, or authentication. Can a discovered
  identifier be used to claim, impersonate, or re-register a device to another tenant?
- **Update integrity** — Firmware signing, downgrade/rollback prevention, USB updates that auto-run
  on insertion, OTA channel trust.
- **Device trust & discovery** — Auto-discovery, ZeroConf/mDNS, "same subnet" pairing. Can a rogue
  peer impersonate an instrument, inject telemetry, or displace legitimate devices (slot/limit
  exhaustion)?
- **Alternate access paths** — Optional Wi-Fi/WLAN modules, USB ports, serial consoles, vendor
  remote-service access, cellular modems.
- **Monitoring & record integrity** — Alarm suppression or rerouting, local log overwrite/retention
  limits, clock/NTP manipulation, operator-settable time. Where records support regulated decisions,
  map to the applicable records-integrity standard.
- **Inspection exemptions** — Vendor instructions to bypass DPI, proxy, or firewall inspection for
  device traffic create monitoring blind spots.
- **Control-plane capability** — Can setpoints, thresholds, or operating modes be changed over the
  network or from the cloud? If the input does not document this, record it in
  `possible_unconfirmed_threats`, not as a finding.
