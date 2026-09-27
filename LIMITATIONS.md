# Known Limitations (verified 2026-09-27)

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

Unsupervised, per capture. Evaluated on lab-generated labelled sessions only (ML_DESIGN.md):
no real-world accuracy is claimed. On that data the Isolation Forest performs the same as the
simple rule "below the capture norm on any feature"; its added value is a graded score. A
weakness shared by most of a capture is not an outlier (the rules still report it).

## Evidence traceability

Findings cite 1-based frame numbers of the capture: the frame that completed the relevant
message (ServerHello, Certificate, alert, STARTTLS command/response, AUTH command). For
data reassembled from several segments, the frame is the one that made the data available.

## Deployment

* No authentication on the API; local single-analyst use only (binds 127.0.0.1).
* Analysis is synchronous in the request (large captures hold the upload request open).
* SQLite; databases created by pre-2.0 versions are moved aside to a `.bak` file on start.
* Docker files are provided but were not built in the audit environment.

## Policy profiles, comparison, redaction, exports

* Policy profiles change thresholds and severities only; they are policy choices, not
  calibrated risk models. `balanced` reproduces the behaviour of earlier releases exactly.
* Comparison matches findings by rule and server (protocol, address, port). A server that
  moved address appears as resolved + new.
* Redaction pseudonymises IP addresses, host names, organisation names, e-mail addresses and
  the file name. Certificate fingerprints, serial numbers and key parameters are kept on
  purpose and can be looked up in public Certificate Transparency logs, which may re-identify
  a public server. Redaction applies to the outputs, not to the stored database.
* STIX 2.1 export contains observations and notes only. In redacted mode addresses are
  pseudonyms, so sessions are described by a custom `x-securemailscope-redacted-session`
  object instead of `ipv4-addr` / `network-traffic`; consumers that ignore custom objects see
  only certificates and notes.
* The evidence bundle contains analysis results and metadata, never packet payloads; it is not
  a substitute for preserving the original capture.

## Analyst metadata

* Notes and "include in investigation report" selections are stored with the analysis and appear
  (selected ones only) in an appendix of generated reports. Redaction pseudonymises addresses,
  host names and e-mail addresses inside notes, but not other free text (names, ticket numbers).
* The posture trend relates analyses that share a server (protocol, address, port). Address
  reuse or NAT can relate unrelated servers; different policy profiles change scores.
* Server grouping is an association of observed connections, not ownership or identity.

## User interface

* The live NTRO website could not be reached from the build environment; archived public pages
  of NTRO and NCIIPC and the public GIGW 3.0 guidance informed the restrained layout (see
  DESIGN_SYSTEM.md). No government emblem, seal, logo, branding or content is used.
* Browser verification is a scripted Playwright walkthrough plus manual review in Chromium;
  other browsers and screen readers were not tested.

## Test data

No enterprise or operational mail traffic was used. Validation layers:

* 15 captures in `backend/tests/real_captures/`: real mail server/client sessions generated in a
  controlled local environment (Mailpit, aiosmtpd, pymap servers; Python smtplib/poplib/imaplib
  clients) covering SMTP, IMAP and POP3, healthy and weak. Recorded by a TCP relay: application
  bytes and timing are real, TCP/IP headers are reconstructed (no raw capture driver, Docker or
  WSL was available). The Mailpit greeting host name was replaced by a same-length placeholder
  in plaintext only (recorded in `manifest.json`). The IMAPS listener is added by a small lab
  launcher around pymap (pymap offers STARTTLS only).
* 5 independently produced public captures (Wireshark wiki; downloaded at test time, GPL, not
  redistributed). They are single sessions from lab-style servers, not a representative sample.
* The Docker lab with Postfix/Dovecot and tcpdump (`lab/docker/`) was not run.

All other fixtures contain TLS bytes
produced by OpenSSL 3.0.13 (real handshakes, certificates, encrypted records) wrapped in
synthesised TCP/IP framing; one fixture (`smtp_tls12_3des_synthetic`) is fully hand-built
because OpenSSL 3 cannot negotiate 3DES/RC4. See `backend/tests/robustness/fixture_factory.py`.
