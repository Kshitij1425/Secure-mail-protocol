"""
Targeted regression tests for defects found during the audit (see VULNERABILITY_REMEDIATION.md).
"""
import struct
from datetime import datetime, timedelta, timezone

import dpkt
import pytest

from securemailscope.certificates.analyzer import CertificateAnalyzer
from securemailscope.protocols.detector import EmailProtocol, ProtocolDetector
from securemailscope.rules.engine import RULE_CATALOGUE, SecurityPolicyEngine, Severity
from securemailscope.scoring.config import DEFAULT_POLICY
from securemailscope.scoring.engine import SecurityPostureScorer
from securemailscope.starttls.machine import StartTLSMachine, TLSState
from securemailscope.tcp.stream import TCPLimits, TCPReconstructor
from securemailscope.tls.ciphers import classify_cipher
from securemailscope.tls.parser import TLSParser, TLSSessionData

C, S = b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"


def pkt(src, dst, sport, dport, seq, flags=dpkt.tcp.TH_ACK, data=b"", ack=0):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, data=data)
    ip = dpkt.ip.IP(src=src, dst=dst, p=6, data=tcp)
    ip.len = len(ip)
    return dpkt.ip.IP(bytes(ip))


def stream_bytes(packets, direction="s2c", limits=None):
    r = TCPReconstructor(limits=limits)
    for i, p in enumerate(packets, 1):
        r.process_packet(p, float(i), i)
    s = r.get_streams()[0]
    return s, s.direction_payload(direction)


# ------------------------------------------------------------------ TCP
def test_tcp_reorders_and_dedups():
    syn = pkt(C, S, 5000, 25, 99, dpkt.tcp.TH_SYN)
    synack = pkt(S, C, 25, 5000, 499, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
    a, b, c = pkt(S, C, 25, 5000, 500, data=b"220 "), pkt(S, C, 25, 5000, 504, data=b"mail "), pkt(S, C, 25, 5000, 509, data=b"ready\r\n")
    s, data = stream_bytes([syn, synack, c, a, b, a, b])
    assert data == b"220 mail ready\r\n"
    assert s.reconstruction_quality == "complete"
    assert s.quality_summary()["retransmitted_segments"] == 2
    assert s.quality_summary()["out_of_order_segments"] >= 1


def test_tcp_conflicting_overlap_first_wins_and_flags():
    syn = pkt(C, S, 5000, 25, 99, dpkt.tcp.TH_SYN)
    synack = pkt(S, C, 25, 5000, 499, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
    s, data = stream_bytes([syn, synack, pkt(S, C, 25, 5000, 500, data=b"GOOD"), pkt(S, C, 25, 5000, 500, data=b"EVIL")])
    assert data == b"GOOD" and s.reconstruction_quality == "inconsistent"


def test_tcp_sequence_wraparound():
    isn = (1 << 32) - 3
    syn = pkt(C, S, 5000, 25, 99, dpkt.tcp.TH_SYN)
    synack = pkt(S, C, 25, 5000, isn, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
    p1 = pkt(S, C, 25, 5000, (isn + 1) % (1 << 32), data=b"220 wr")
    p2 = pkt(S, C, 25, 5000, (isn + 7) % (1 << 32), data=b"ap ok\r\n")
    s, data = stream_bytes([syn, synack, p2, p1])
    assert data == b"220 wrap ok\r\n" and not s.missing_sequences


def test_tcp_gap_recorded_and_delivery_resumes():
    syn = pkt(C, S, 5000, 25, 99, dpkt.tcp.TH_SYN)
    synack = pkt(S, C, 25, 5000, 499, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
    s, data = stream_bytes([syn, synack, pkt(S, C, 25, 5000, 500, data=b"220 a\r\n"), pkt(S, C, 25, 5000, 600, data=b"250 b\r\n")])
    assert data.startswith(b"220 a\r\n") and data.endswith(b"250 b\r\n")
    assert s.reconstruction_quality == "partial" and s.quality_summary()["missing_bytes"] == 93


def test_tcp_client_server_from_syn_even_if_synack_first():
    synack = pkt(S, C, 25, 5000, 499, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
    r = TCPReconstructor()
    r.process_packet(synack, 1.0, 1)
    s = r.get_streams()[0]
    assert (s.client_ip, s.src_port, s.server_ip, s.dst_port) == ("10.0.0.1", 5000, "10.0.0.2", 25)


def test_tcp_port_reuse_creates_new_stream():
    pk = [pkt(C, S, 5000, 25, 99, dpkt.tcp.TH_SYN), pkt(S, C, 25, 5000, 499, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK),
          pkt(S, C, 25, 5000, 500, data=b"220 x\r\n"), pkt(C, S, 5000, 25, 100, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK),
          pkt(C, S, 5000, 25, 7000, dpkt.tcp.TH_SYN)]
    r = TCPReconstructor()
    for i, p in enumerate(pk, 1):
        r.process_packet(p, float(i), i)
    ids = [s.stream_id for s in r.get_streams()]
    assert len(ids) == 2 and len(set(ids)) == 2


def test_tcp_limits_bound_memory():
    limits = TCPLimits(max_retained_bytes_per_direction=100, max_pending_segments_per_direction=5, max_streams=3)
    syn = pkt(C, S, 5000, 25, 99, dpkt.tcp.TH_SYN)
    synack = pkt(S, C, 25, 5000, 499, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
    big = [pkt(S, C, 25, 5000, 500 + i * 50, data=b"x" * 50) for i in range(10)]
    s, data = stream_bytes([syn, synack] + big, limits=limits)
    assert len(data) == 100 and s.truncated_by_limit and s.reconstruction_quality == "partial"
    holes = [pkt(S, C, 25, 5000, 10_000 + i * 100, data=b"y") for i in range(20)]
    s, _ = stream_bytes([syn, synack] + holes, limits=limits)
    assert len(s.s2c.pending) <= 5
    r = TCPReconstructor(limits=limits)
    for i in range(10):
        r.process_packet(pkt(C, S, 6000 + i, 25, 1, dpkt.tcp.TH_SYN), 1.0, i + 1)
    assert len(r.get_streams()) == 3 and r.dropped_streams == 7


def test_tcp_ipv6():
    tcp = dpkt.tcp.TCP(sport=5000, dport=25, seq=1, flags=dpkt.tcp.TH_SYN)
    ip6 = dpkt.ip6.IP6(src=b"\x20\x01" + b"\x00" * 13 + b"\x05", dst=b"\x20\x01" + b"\x00" * 13 + b"\x25",
                       nxt=6, hlim=64, data=tcp, plen=len(bytes(tcp)))
    r = TCPReconstructor()
    r.process_packet(dpkt.ip6.IP6(bytes(ip6)), 1.0, 1)
    assert r.get_streams()[0].client_ip == "2001::5"


# ------------------------------------------------------------------ Detector
@pytest.mark.parametrize("server,client,port", [
    (b"SSH-2.0-OpenSSH_9.6\r\n", b"", 2222), (b"SSH-2.0-OpenSSH_9.6\r\n", b"", 25),
    (b"HTTP/1.1 200 OK\r\n", b"GET / HTTP/1.1\r\n", 587), (b"", b"\x16\x03\x01\x00\x10", 443),
])
def test_detector_rejects_non_email(server, client, port):
    assert ProtocolDetector().detect(server, port=port, client_payload=client).protocol == EmailProtocol.UNKNOWN


def test_detector_implicit_tls_ports():
    for port, proto in ((993, EmailProtocol.IMAP), (995, EmailProtocol.POP3), (465, EmailProtocol.SMTP)):
        d = ProtocolDetector().detect(b"", port=port, client_payload=b"\x16\x03\x01\x02\x00\x01")
        assert d.protocol == proto and d.implicit_tls


def test_detector_bounded_on_hostile_banner():
    """Cost must not grow with banner size (bounded inspection window, no backtracking).

    Compared as a ratio against a small banner, best of several runs, so the test is
    not sensitive to machine load (an absolute wall-clock bound was flaky under CI load).
    """
    import time

    def best(payload):
        d = ProtocolDetector()
        runs = []
        for _ in range(5):
            t = time.perf_counter()
            d.detect(payload, port=25)
            runs.append(time.perf_counter() - t)
        return min(runs)

    small = best(b"220 " + b"a" * 2_000 + b"\r\n")
    huge = best(b"220 " + b"a" * 2_000_000 + b"\r\n")
    assert huge < max(small * 20, 0.05)


# ------------------------------------------------------------------ STARTTLS
def test_smtp_454_is_rejection():
    m = StartTLSMachine(EmailProtocol.SMTP)
    m.process_payload("STARTTLS\r\n", True)
    m.process_payload("454 4.7.0 TLS not available\r\n", False)
    assert m.state.current_state == TLSState.STARTTLS_REJECTED


def test_smtp_multiline_220_waits_for_final_line():
    m = StartTLSMachine(EmailProtocol.SMTP)
    m.process_payload("STARTTLS\r\n", True)
    m.process_payload("220-first\r\n", False)
    assert m.state.current_state == TLSState.STARTTLS_REQUESTED
    m.process_payload("220 go ahead\r\n", False)
    assert m.state.current_state == TLSState.STARTTLS_ACCEPTED


def test_imap_tag_must_match_and_untagged_ignored():
    m = StartTLSMachine(EmailProtocol.IMAP)
    m.process_payload("a7 STARTTLS\r\n", True)
    m.process_payload("* OK still here\r\n", False)
    m.process_payload("zz OK unrelated\r\n", False)
    assert m.state.current_state == TLSState.STARTTLS_REQUESTED
    m.process_payload("a7 OK Begin TLS\r\n", False)
    assert m.state.current_state == TLSState.STARTTLS_ACCEPTED


def test_command_split_across_segments():
    m = StartTLSMachine(EmailProtocol.SMTP)
    m.process_payload("START", True)
    assert m.state.current_state == TLSState.PLAINTEXT
    m.process_payload("TLS\r\n", True)
    assert m.state.current_state == TLSState.STARTTLS_REQUESTED


def test_plaintext_auth_records_mechanism_not_secret():
    m = StartTLSMachine(EmailProtocol.POP3)
    m.process_payload("USER alice\r\nPASS hunter2\r\n", True)
    assert m.state.plaintext_auth_mechanisms == ["USER/PASS"]
    assert "hunter2" not in repr(m.state.__dict__) and "alice" not in repr(m.state.__dict__)


def test_pipelined_starttls_flagged():
    m = StartTLSMachine(EmailProtocol.SMTP)
    m.process_payload("STARTTLS\r\nMAIL FROM:<x@y>\r\n", True)
    assert m.state.pipelined_after_starttls


def test_hostile_lines_bounded():
    m = StartTLSMachine(EmailProtocol.SMTP)
    m.process_payload("A" * 1_000_000, True)
    m.process_payload("\r\n" * 100_000, True)
    assert m._lines_seen[True] <= 5000 and len(m._partial[True]) <= 8192


# ------------------------------------------------------------------ TLS
def rec(ct, body, ver=0x0303):
    return bytes([ct]) + struct.pack("!HH", ver, len(body)) + body


def hs(t, body):
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def server_hello(code, ver=0x0303, ext=b""):
    body = struct.pack("!H", ver) + b"\x11" * 32 + b"\x00" + struct.pack("!H", code) + b"\x00"
    if ext:
        body += struct.pack("!H", len(ext)) + ext
    return hs(2, body)


def test_handshake_fragmented_across_records():
    msg = server_hello(0xC02F)
    p = TLSParser()
    p.process_payload(rec(22, msg[:10]), "s2c")
    assert p.session.cipher_suite_hex is None
    p.process_payload(rec(22, msg[10:]), "s2c")
    assert p.session.cipher_suite_name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


def test_record_split_across_tcp_chunks():
    data = rec(22, server_hello(0x002F))
    p = TLSParser()
    for i in range(0, len(data), 3):
        p.process_payload(data[i:i + 3], "s2c")
    assert p.session.cipher_suite_hex == 0x002F and p.session.has_forward_secrecy is False


def test_directions_do_not_corrupt_each_other():
    ch_body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    ch = rec(22, hs(1, ch_body), 0x0301)
    sh = rec(22, server_hello(0x1301, ext=b"\x00\x2b\x00\x02\x03\x04"))
    p = TLSParser()
    p.process_payload(ch[:7], "c2s")
    p.process_payload(sh[:9], "s2c")
    p.process_payload(ch[7:], "c2s")
    p.process_payload(sh[9:], "s2c")
    assert p.session.client_version == "TLSv1.2" and p.session.server_version == "TLSv1.3"


def test_tls13_plaintext_certificate_is_not_trusted_evidence():
    cert = hs(11, b"\x00\x00\x05\x00\x00\x02AB")
    p = TLSParser()
    p.process_payload(rec(22, server_hello(0x1301, ext=b"\x00\x2b\x00\x02\x03\x04")) + rec(22, cert), "s2c")
    assert p.session.certificates == [] and "plaintext_certificate_in_tls13" in p.session.protocol_violations


def test_non_tls_or_oversized_input_is_abandoned_not_buffered():
    p = TLSParser()
    p.process_payload(b"\x16\x03\x03\xff\xff" + b"A" * 100, "s2c")  # length > 2^14+2048
    p.process_payload(b"A" * 1_000_000, "s2c")
    assert p._dirs["s2c"].abandoned and len(p._dirs["s2c"].buffer) == 0


def test_hello_retry_request_detected():
    from securemailscope.tls.parser import HRR_RANDOM
    body = struct.pack("!H", 0x0303) + HRR_RANDOM + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
    ext = b"\x00\x2b\x00\x02\x03\x04"
    p = TLSParser()
    p.process_payload(rec(22, hs(2, body + struct.pack("!H", len(ext)) + ext)), "s2c")
    assert p.session.hello_retry_request


def test_fatal_alert_marks_failure():
    p = TLSParser()
    p.process_payload(rec(22, hs(1, struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00\x00\x02\x13\x01\x01\x00")), "c2s")
    p.process_payload(rec(21, b"\x02\x28"), "s2c")
    assert p.session.handshake_status == "failed"
    assert p.session.alert_details[0]["description"] == "handshake_failure"


def test_sni_is_neutralised():
    name = b"mail<script>.example"
    sni = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    ext = struct.pack("!HH", 0, len(sni)) + sni
    body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00\x00\x02\xc0\x2f\x01\x00" + struct.pack("!H", len(ext)) + ext
    p = TLSParser()
    p.process_payload(rec(22, hs(1, body)), "c2s")
    assert p.session.sni == "mail?script?.example"


# ------------------------------------------------------------------ Ciphers / rules
def test_cipher_classification_covers_registry():
    from securemailscope.tls.cipher_registry import CIPHER_SUITE_NAMES
    for code in CIPHER_SUITE_NAMES:
        info = classify_cipher(code)
        assert info.strength in {"insecure", "weak", "legacy", "recommended", "signaling"}
    assert classify_cipher(0x000A).strength == "insecure"     # 3DES (SP 800-131A)
    assert classify_cipher(0xC013).forward_secrecy is True     # previously UNKNOWN -> false "No FS"
    assert classify_cipher(0xFFFF).forward_secrecy is None


def test_unknown_cipher_never_produces_fs_or_weak_finding():
    tls = TLSSessionData(server_version="TLSv1.2", cipher_suite_hex=0xFEFE, cipher_suite_name="UNKNOWN_CIPHER_0xFEFE",
                         has_forward_secrecy=None)
    f = SecurityPolicyEngine.evaluate_session("s", EmailProtocol.SMTP, TLSState.TLS_ESTABLISHED, tls, [])
    assert not {x.rule_id for x in f} & {"TLS-003", "TLS-004"}


def _cert(**kw):
    from securemailscope.certificates.analyzer import CertificateDetails
    base = dict(fingerprint_sha256="f", subject="CN=a", issuer="CN=a", serial_number="0x1",
                not_before=datetime(2024, 1, 1, tzinfo=timezone.utc), not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
                is_expired=False, is_not_yet_valid=False, is_self_signed=False, public_key_algorithm="RSA",
                public_key_size_bits=2048, signature_algorithm="sha256WithRSAEncryption")
    base.update(kw)
    return CertificateDetails(**base)


def test_self_signed_root_in_chain_is_not_flagged():
    leaf = _cert(subject="CN=leaf", issuer="CN=root", chain_position=0)
    root = _cert(subject="CN=root", issuer="CN=root", is_self_signed=True, chain_position=1,
                 signature_algorithm="sha1WithRSAEncryption", weak_signature=True)
    f = SecurityPolicyEngine.evaluate_session("s", EmailProtocol.SMTP, TLSState.TLS_ESTABLISHED,
                                              TLSSessionData(server_version="TLSv1.2"), [leaf, root])
    assert not {x.rule_id for x in f} & {"CERT-005", "CERT-004"}


def test_finding_ids_unique_per_certificate():
    certs = [_cert(is_expired=True, chain_position=i) for i in range(3)]
    f = SecurityPolicyEngine.evaluate_session("s", EmailProtocol.SMTP, TLSState.TLS_ESTABLISHED,
                                              TLSSessionData(server_version="TLSv1.2"), certs)
    ids = [x.finding_id for x in f]
    assert len(ids) == len(set(ids)) == 3


def test_every_rule_mapped_to_one_scoring_dimension():
    for rule_id in RULE_CATALOGUE:
        owners = [d for d, cfg in DEFAULT_POLICY.dimensions.items() if rule_id in cfg.rules]
        assert len(owners) == 1, rule_id


def test_score_bands_have_no_gaps():
    for x in [i / 10 for i in range(0, 1001)]:
        assert DEFAULT_POLICY.get_status(x).value != "Unknown", x


def test_insufficient_evidence_is_not_penalised():
    tls = None
    f = SecurityPolicyEngine.evaluate_session("s", EmailProtocol.SMTP, TLSState.STARTTLS_REQUESTED, tls, [])
    assert [x.rule_id for x in f] == ["STLS-002"]
    p = SecurityPostureScorer().calculate_posture(f, 0, 1, "t")
    assert p.overall_score == 100.0


def test_certificate_validity_uses_reference_time():
    from tests.robustness.fixture_factory import issue
    c = issue("x", not_before=datetime(2025, 1, 1, tzinfo=timezone.utc), not_after=datetime(2025, 6, 1, tzinfo=timezone.utc))
    at_capture = CertificateAnalyzer.analyze_der(c.der, reference_time=datetime(2025, 3, 1, tzinfo=timezone.utc))
    later = CertificateAnalyzer.analyze_der(c.der, reference_time=datetime(2026, 3, 1, tzinfo=timezone.utc))
    assert not at_capture.is_expired and later.is_expired


def test_malformed_der_returns_none():
    for bad in (b"", b"\x30", b"\x30\x82\xff\xff" + b"\x00" * 10, b"\x00" * 70_000):
        assert CertificateAnalyzer.analyze_der(bad) is None
