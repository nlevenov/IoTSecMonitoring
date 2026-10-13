# Architecture

## Data flow

1. **Capture** - `capture/tshark_backend.py` runs `tshark -T fields` and
   parses one tab-separated line per packet; `capture/scapy_backend.py`
   dissects packets with Scapy. Both produce the same `PacketRecord`
   (verified by a parity test): addresses, ports, TCP flags, wire length,
   DNS query / type / response code, TLS SNI, HTTP Host, ARP opcode, DHCP
   host name and vendor class, mDNS service names and SSDP banners. Live
   sources are wrapped so the pipeline also receives idle ticks and can
   close windows on a quiet network.
2. **Inventory** - `discovery/inventory.py` keeps devices keyed by MAC,
   enriches them (OUI vendor, DHCP / mDNS / SSDP identity), classifies them
   and tracks IP-to-MAC bindings from ARP. A claim for an address whose
   owner is still active raises ARP spoofing (critical for the gateway); an
   address reassigned after its owner left does not. New MACs beyond
   `discovery.max_devices` are rejected and reported as MAC flooding.
3. **Windows** - `analysis/features.py` attributes every packet to its local
   endpoint(s) and accumulates one `DeviceWindow` per device per
   `capture.window_seconds`: counters, distinct peers / ports, SYNs, RSTs,
   Telnet targets, DNS statistics (entropy of the longest label, labels over
   30 characters, NXDOMAIN, TXT), destinations, admin-service targets,
   cleartext sessions and blocklist hits. All sets are bounded.
4. **Detection** - `analysis/detectors.py`:

   | Detector | Condition (defaults) | Needs baseline |
   |----------|----------------------|:--:|
   | Mirai scan | SYNs to port 23/2323 on >= 5 hosts | no |
   | Port / host scan | >= 20 ports or >= 20 internal hosts probed, or >= 60 ARP targets | no |
   | Flood | >= 3000 packets out and (no baseline or z >= 6) | optional |
   | DNS tunnelling / DGA | high-entropy long labels, >= 10 NXDOMAIN or >= 15 TXT queries | no |
   | Blocklist | destination IP, DNS name, SNI or Host on a feed | no |
   | Insecure protocol | Telnet / FTP / TFTP / rlogin sessions | no |
   | Exfiltration | >= 1 MB out and z >= 6 | yes |
   | Lateral movement | new SSH/Telnet/SMB/RDP/VNC targets from a non-admin device | yes |
   | New destinations | >= 5 domains / networks never seen during learning | yes |
   | Behaviour anomaly | Isolation Forest score above threshold + margin | yes |

5. **Baseline** - `analysis/baseline.py` keeps Welford running statistics
   for every window feature plus the sets of known domains, networks, ports
   and admin targets. Devices contacting too many destinations to track
   (phones, laptops) are marked *saturated* and skip the new-destination
   check. Only windows without a medium+ finding update the baseline.
6. **ML** - `analysis/ml.py` maps each window to signed, log-compressed
   z-scores against the device's baseline and trains a single Isolation
   Forest across all learned devices. It is retrained every
   `ml.retrain_hours`, written atomically and signed.
7. **Alerts** - `storage.record_alert` folds repeats within the cooldown
   into one alert (count, last seen, merged details) and escalates its
   severity when a worse finding arrives. New or escalated alerts at or
   above `notify.min_severity` are delivered by a background worker.

## Time

All logic runs on packet timestamps. Replaying last week's pcap produces
exactly the windows, baselines and alerts the live monitor would have
produced, and retention is computed relative to the newest data.

## Storage

SQLite in WAL mode: `devices`, `ip_bindings`, `windows` (features and
anomaly score per device-minute), `traffic` (network-wide series for the
dashboard), `baselines` (JSON), `alerts` and `meta`. Retention pruning runs
during housekeeping; open alerts are never pruned.

## Dashboard

`dashboard/app.py` is a Streamlit app started by `iotsec dashboard`, which
fixes the server options (loopback binding, XSRF with SameSite=Strict, Host
allow-list, no static serving, no file watcher, hidden error details).
`dashboard/auth.py` gates every render. The overview refreshes itself with
`st.fragment(run_every=...)`; analyst actions (approve / label devices,
acknowledge / resolve alerts) write through the same `Store`.
