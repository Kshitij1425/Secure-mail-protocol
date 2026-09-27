# Real Email Traffic Validation Lab

SIH26159 dataset guidance allows participants to *"generate IMAPS, POP3S, SMTPS data using any
e-mail server/client of their interest and capture pcap dump"*. This lab does that in a fully
local, reproducible way. Its captures are **real email-server/client captures generated in a
controlled test environment** - not real-world or enterprise traffic.

Two validation layers exist and both are kept:

| Layer | Location | What is real | Purpose |
|---|---|---|---|
| 1. Controlled fixtures | `backend/tests/robustness/` | TLS bytes from OpenSSL; dialogues and TCP framing synthesised | Precise coverage of edge cases (TCP impairments, 3DES, weak DH, ...) |
| 2. Real mail server/client | `backend/tests/real_captures/` (this lab) | Mail servers, mail clients, their full SMTP/POP3 dialogue, TLS negotiation and timing | End-to-end realism with independent implementations |

## A. Local lab (verified; no admin rights, no packet driver needed)

```
Python smtplib / poplib /  --->  recording relay (127.0.0.1)  --->  Mailpit (Go TLS) / aiosmtpd (OpenSSL) /
imaplib (real mail clients)       lab/recording_relay.py              pymap IMAP4rev1 (OpenSSL) (real mail servers)
                                       |
                                       v
                        backend/tests/real_captures/*.pcap + manifest.json
```

The recording relay forwards bytes unchanged and records every read with its timestamp.
Application bytes and timing are genuine; **Ethernet/IPv4/TCP headers are reconstructed**
(lab addresses 10.77.0.0/16, standard server ports, consistent sequence numbers, one segment per
socket read). Mailpit greets with the OS hostname; the relay replaces it with a placeholder of the
same length in plaintext bytes only (never in TLS bytes). Both facts are recorded in the manifest.

### Reproduce

```powershell
# 1. Server binaries (not committed). Mailpit v1.31.2, verify the published SHA-256.
mkdir lab\tools
curl.exe -L -o lab\tools\mailpit.zip https://github.com/axllent/mailpit/releases/download/v1.31.2/mailpit-windows-amd64.zip
certutil -hashfile lab\tools\mailpit.zip SHA256
#   expected: 42c20e5c3254125ea7489847811f10d70e39de573fe41d03a61412c87913e995
tar -xf lab\tools\mailpit.zip -C lab\tools
python -m pip install aiosmtpd==1.4.6
# IMAP server: pymap 0.36.7 (MIT) in its own virtual environment
python -m venv lab\tools\imapvenv
lab\tools\imapvenv\Scripts\python -m pip install pymap==0.36.7

# 2. Generate captures + manifest (all servers bind 127.0.0.1 only)
python lab\real_mail_lab.py                   # all 15 scenarios
python lab\real_mail_lab.py --only-imap-pop3  # only scenarios 10-15; other entries kept

# 3. Validate
cd backend
python -m pytest tests\test_real_mail_captures.py -v
```

On Linux/macOS use the matching Mailpit archive and adjust `MAILPIT` in `real_mail_lab.py`.

### Captures (see `manifest.json` for hashes, software versions and expected observations)

| Capture | Server | Intended condition | Expected observations |
|---|---|---|---|
| `real_smtp_starttls_tls13` | Mailpit | Secure modern TLS (STARTTLS, TLS 1.3) | TLS 1.3, no findings, certificate *not observable* |
| `real_smtps_tls12_chain` | Mailpit | Implicit TLS 465, TLS 1.2 ECDHE-AEAD, leaf + intermediate | 2 certificates, chain linked, no findings |
| `real_smtp_cert_expired_selfsigned` | Mailpit | Certificate issue | CERT-001 expired, CERT-005 self-signed |
| `real_smtp_tls10_legacy` | aiosmtpd | Deprecated/weak TLS: TLS 1.0, static RSA, RSA-1024 | TLS-001, TLS-004, CERT-003 |
| `real_smtp_tls_handshake_refused` | Mailpit | STARTTLS transition failure (TLS 1.0-only client refused) | TLS_FAILED, TLS-002, TLS-006 (client offered anonymous suites) |
| `real_smtp_starttls_rejected_plain_auth` | Mailpit | Insecure transition: STARTTLS rejected, AUTH + mail in plaintext | STLS-001, PROTO-001, PROTO-002; credentials never stored |
| `real_mixed_multiprotocol` | Mailpit + aiosmtpd | SMTP+STARTTLS, SMTPS, POP3S, plaintext SMTP | 4 sessions with the respective results |
| `real_remediation_before` / `_after` | aiosmtpd / Mailpit | Same server address before and after remediation | TLS-001, TLS-004, CERT-001/003/005, then no findings |
| `real_imaps_tls12_chain` | pymap | IMAPS (implicit TLS, 993), TLS 1.2 ECDHE-RSA-AES256-GCM, leaf + intermediate | IMAP on 993, 2 certificates, no findings |
| `real_imaps_tls13` | pymap | IMAPS negotiating TLS 1.3 | TLS 1.3, certificate *not observable*, no findings |
| `real_imap_starttls_tls12` | pymap | IMAP STARTTLS on 143 (advertised, requested, accepted), TLS 1.2 | TLS_ESTABLISHED, 2 certificates, no findings |
| `real_imap_starttls_weak_tls10` | pymap | Weak IMAP STARTTLS: TLS 1.0, static RSA, expired self-signed RSA-1024 | CERT-001, CERT-003, CERT-005, TLS-001, TLS-004 |
| `real_imap_starttls_rejected_plain_login` | pymap (no TLS) | STARTTLS not advertised and rejected (`NO [CANNOT]`); LOGIN and mailbox access in plaintext | STARTTLS_REJECTED, STLS-001, PROTO-001, PROTO-002; password never stored |
| `real_pop3s_expired_selfsigned` | Mailpit | Weak POP3S: expired self-signed certificate | CERT-001, CERT-005 |

### IMAP server configuration (exact)

* Server: pymap 0.36.7 with its in-memory `dict` backend and `--demo-data` mailbox, user `alice`,
  lab password `lab-imap-password`; greeting host name set to `imap.lab.test` (`FQDN`), so the
  OS host name never appears.
* `lab/imap_server.py` replaces pymap's command-line entry point (which uses asyncio signal
  handlers that do not exist on Windows) and adds an implicit-TLS listener for IMAPS (pymap
  itself offers STARTTLS only) using asyncio's standard `ssl=` option. All IMAP protocol handling
  (greeting, CAPABILITY, STARTTLS, LOGIN, SELECT, FETCH, LOGOUT) is pymap's own code.
* TLS: Python `ssl` (OpenSSL 3.0). Weak scenario: `minimum_version = maximum_version = TLSv1`,
  ciphers `AES128-SHA:@SECLEVEL=0`, 1024-bit RSA self-signed certificate that expired 3 days before
  capture. Healthy scenarios: default suites; lab CA chain (root, issuing CA, leaf, RSA-2048).
* Client: Python `imaplib` (`IMAP4_SSL` for 993, `IMAP4` + `starttls()` for 143): LOGIN,
  SELECT INBOX, FETCH 1 (FLAGS RFC822.SIZE), LOGOUT. Certificate verification is disabled in the
  lab client because the lab CA is not in any trust store.
* Capture: the same recording relay (application bytes and timing real, TCP/IP headers
  reconstructed); ports 993 / 143 in the capture; addresses 10.77.4.0/24 (clients) and
  10.77.0.143-147 (servers).
* Privacy: the only plaintext secret is the lab password in the deliberately insecure scenario
  (it is the point of that capture). Tests verify it is never stored in the database, reports,
  bundle or STIX output.

## B. Docker lab with raw packet capture (not executed here)

`lab/docker/` runs Postfix (25/465/587) and Dovecot (143/993/110/995) with tcpdump in the server's
network namespace on an internal network, and a stdlib client that exercises SMTP STARTTLS, SMTPS,
IMAP STARTTLS, IMAPS, POP3 STLS, POP3S and plaintext SMTP.

```bash
cd lab/docker
docker compose up --build --abort-on-container-exit client
docker compose down
# capture: lab/docker/captures/lab.pcapng  -> upload to SecureMailScope or:
securemailscope analyze captures/lab.pcapng --json --html
```

This configuration was written but **not run** in the environment that produced this repository
(no Docker, no admin rights). Treat its first run as a test of the lab itself; add the resulting
capture and its expected observations to a manifest before relying on it.

## Safety

* All lab servers bind to 127.0.0.1 (local lab) or an internal Docker network (Docker lab).
* Weak configurations (TLS 1.0, RSA-1024, expired/self-signed certificates, plaintext AUTH) exist
  only inside the lab. Credentials used are dummy lab values.

## ML evaluation pool

`python lab/ml_eval_pool.py` records 80 real TLS mail sessions (20 server configurations x 4)
with aiosmtpd and smtplib, labelled healthy / weak by configuration before any analysis, into
`backend/tests/ml_eval/pool/` (+ `pool_manifest.json`). They are used by
`python -m tests.ml_eval.evaluate` (from `backend/`) to compare the ML models; see `ML_DESIGN.md`.

## External validation captures (independent, not generated here)

`backend/tests/external_captures/sources.json` lists five public captures from the Wireshark wiki
sample captures page (IMAP STARTTLS and POP3 STLS against Dovecot, SMTP STARTTLS on ports 25 and
2525, plaintext SMTP with AUTH LOGIN). They are licensed under the GNU GPL (Wireshark wiki licence)
and are **not redistributed**: `python -m tests.external_captures.fetch` (from `backend/`)
downloads them and verifies the pinned SHA-256; `tests/test_external_captures.py` checks
SecureMailScope's observations and cross-checks TLS version / cipher / offered suites with an
independent parser (dpkt.ssl). Two further wiki captures (`imap.cap`, `sample-imf.pcap.gz`)
returned a bot-protection page and were not used.

