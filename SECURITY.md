# Security Policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/nlevenov/IoTSecMonitoring/security/advisories/new).
Reports are acknowledged within 72 hours.

## Threat model

The monitor sits on a network that may contain compromised devices. Every
byte it parses is chosen by a potential attacker, the dashboard holds a map
of the network, and the capture component needs elevated privileges.

| Threat | Mitigation |
|--------|------------|
| Malformed / hostile packets crashing the monitor | Bounds-checked parsers (fuzzed in tests); per-packet error isolation; capture queue drops instead of blocking |
| Script / markup injection via DHCP host names, mDNS names, SSDP banners, DNS names | Sanitized at ingestion (printable only, markup characters removed, length-capped); dashboard renders data with data components only, never `unsafe_allow_html` |
| E-mail header injection | Subjects stripped of control characters; messages built with `email.message.EmailMessage` |
| Chat / e-mail flooding by an attacker triggering alerts | Deduplication with cooldown; at most 30 notifications per hour |
| Memory exhaustion (MAC flooding, scan floods) | Inventory capped (`discovery.max_devices`) with a MAC_FLOOD alert; every per-window set bounded |
| Unauthorised dashboard access | scrypt password (bounded parameters); fails closed without a configured hash; per-session and global brute-force lockout; sliding session expiry; sign-out |
| CSRF / DNS rebinding / cross-origin use | Streamlit XSRF protection with SameSite=Strict cookie; `server.allowedHosts` allow-list; CORS on; dashboard refuses non-loopback binding without an allow-list |
| Credential exposure in transit | Loopback binding by default; documented TLS reverse proxy (`deploy/nginx.conf`) with HSTS and frame-ancestors |
| Information leakage | Error details hidden in the browser (`client.showErrorDetails = none`); files created with umask 077; database chmod 600; secrets only from environment variables and never logged |
| Privileged capture process | tshark backend: dumpcap holds the capability, the monitor runs unprivileged. Scapy backend: socket opened as root, privileges dropped (setgroups/setgid/setuid, verified) before the first packet is parsed and before any file is created. Docker: CAP_NET_RAW + SETUID/SETGID only, read-only root filesystem, no-new-privileges |
| Command injection into capture tools | No shell anywhere; interface names and capture filters validated; pcap paths resolved to absolute paths |
| Malicious model file (pickle code execution) | Detached signature (HMAC-SHA256 with `IOTSEC_MODEL_KEY`) verified before unpickling; atomic writes; warning when no key is set |
| Scanning networks the operator does not own | ARP sweeps and port probes refuse any target outside `monitored_networks`, and sweeps larger than /16 |
| SQL injection | Parameterised queries throughout; no user input in SQL text |
| Weak notification transport | SMTP over implicit TLS or STARTTLS with certificate verification only; webhooks must be https; redirects not followed |
| Vulnerable dependencies | pip-audit and bandit in CI; Dependabot for pip, Actions and Docker |

## Limits

* Detection is behavioural and signature based on metadata. Encrypted
  payloads are not inspected; a patient attacker that mimics a device's
  normal traffic can stay below thresholds.
* Devices present during the initial learning period are trusted. Deploy
  on a network you believe to be clean, then review the inventory.
* The dashboard password is a single shared secret. Put the dashboard behind
  the TLS proxy, and add client certificates or SSO there if several people
  need access.

## Deployment checklist

- [ ] `IOTSEC_MODEL_KEY` set (32+ random characters)
- [ ] Dashboard password created with `iotsec hash-password`
- [ ] Dashboard bound to 127.0.0.1 and published only through the TLS proxy
- [ ] `dashboard.allowed_hosts` set to the proxy's host name
- [ ] `monitored_networks` limited to networks you own
- [ ] Monitor runs with the tshark backend or with `capture.drop_privileges_to`
- [ ] Inventory reviewed after the learning period; unknown devices investigated
