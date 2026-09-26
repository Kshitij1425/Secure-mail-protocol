# Known Limitations (verified 2026-09-26)

## What passive analysis cannot establish

| Property | Status in SecureMailScope |
|---|---|
| Server capabilities not exercised in the capture (e.g. would it accept TLS 1.0?) | NOT OBSERVED - only the negotiated result is known |
| Certificates in TLS 1.3 sessions | NOT OBSERVED - the Certificate message is encrypted; reported as `encrypted_tls13` |
| Certificate trust | UNKNOWN - no trust-anchor store, CRL or OCSP is consulted. Chain *linkage* (each cert signed by the next) is verified cryptographically |
| Whether a STARTTLS rejection was an attack | UNKNOWN - reported as a POTENTIAL_INDICATOR (misconfiguration vs. stripping cannot be distinguished) |
| Anything inside TLS (commands, auth, message content) | NOT OBSERVED - no decryption, no key-log support |
| DANE / MTA-STS / DNSSEC policy | Not evaluated (requires DNS, not in a capture) |
| S/MIME, PGP, DLP | Out of scope |

## Protocol and capture coverage

* Supported: SMTP (25/587/2525 and any port with an SMTP banner), IMAP (143/993), POP3
  (110/995), STARTTLS/STLS, implicit TLS on 465/993/995, SSLv2 ClientHello detection,
  SSLv3-TLS 1.3, IPv4/IPv6, Ethernet (incl. VLAN), Linux SLL/SLL2, raw IP, loopback,
  PCAP and PCAPNG.
* Implicit TLS on non-standard ports is not classified as email (no plaintext signal).
* IP fragment reassembly is not implemented.
* TCP: first-wins overlap policy. If the receiving host used a different policy, the
  analyzer's view can differ; such streams are flagged `inconsistent`.
* Capture must contain the handshake: if a capture starts mid-session, TLS parameters are
  NOT OBSERVED and no TLS finding is raised.
* Resource limits (see SECURITY_POLICY.md) truncate very large streams; truncation is
  recorded (`truncated_by_limit`, quality `partial`).

## Rules and scoring

* The scoring weights are a documented policy choice, not an empirically calibrated risk
  model. Each root cause is charged its full severity impact even at low prevalence, so a
  capture where 1 of 12 sessions is legacy (TLS 1.0 + RSA-1024) scores 25/100 "Critical"
  although it has no CRITICAL finding. Dimension scores and the remediation plan show the
  actual distribution.
* Severity choices follow NIST SP 800-52r2 / 800-131A (e.g. 3DES = insecure, CRITICAL).
* Rules never fire on unknown values (unknown cipher code, missing ServerHello).

## ML

Unsupervised, per capture, no labelled evaluation data: see ML_DESIGN.md. On heterogeneous
captures about 30% of sessions are flagged; anomalies are triage hints, not findings.

## Evidence traceability

Findings cite 1-based frame numbers of the capture: the frame that completed the relevant
message (ServerHello, Certificate, alert, STARTTLS command/response, AUTH command). For
data reassembled from several segments, the frame is the one that made the data available.

## Deployment

* No authentication on the API; local single-analyst use only (binds 127.0.0.1).
* Analysis is synchronous in the request (large captures hold the upload request open).
* SQLite; databases created by pre-2.0 versions are moved aside to a `.bak` file on start.
* Docker files are provided but were not built in the audit environment.

## Test data

No real-world third-party mail captures were available. All fixtures contain TLS bytes
produced by OpenSSL 3.0.13 (real handshakes, certificates, encrypted records) wrapped in
synthesised TCP/IP framing; one fixture (`smtp_tls12_3des_synthetic`) is fully hand-built
because OpenSSL 3 cannot negotiate 3DES/RC4. See `backend/tests/robustness/fixture_factory.py`.
