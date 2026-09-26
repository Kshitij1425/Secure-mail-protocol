"""
Property-based and fuzz tests (Hypothesis).

Core invariant: malformed or hostile input never crashes or hangs the analyzer.
Every crash found by these tests is kept as an explicit regression example.
"""
import io
import random
import struct
from pathlib import Path

import dpkt
import pytest
from hypothesis import HealthCheck, assume, example, given, settings, strategies as st

from securemailscope.certificates.analyzer import CertificateAnalyzer
from securemailscope.core.orchestrator import Orchestrator
from securemailscope.protocols.detector import EmailProtocol, ProtocolDetector
from securemailscope.rules.engine import FindingResult, Severity
from securemailscope.scoring.engine import SecurityPostureScorer
from securemailscope.starttls.machine import StartTLSMachine
from securemailscope.tcp.stream import TCPReconstructor
from securemailscope.tls.parser import TLSParser

PCAPS = Path(__file__).parent / "robustness" / "fixtures" / "pcaps"
FUZZ = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])  # example count: see conftest profiles
SEEDS = sorted(PCAPS.glob("*.pcap*"))


# ---------------------------------------------------------------- captures
@FUZZ
@given(seed=st.sampled_from(SEEDS), flips=st.lists(st.tuples(st.integers(0, 10**7), st.integers(0, 255)), max_size=40),
       cut=st.one_of(st.none(), st.integers(0, 10**6)))
def test_mutated_captures_never_crash(tmp_path_factory, seed, flips, cut):
    data = bytearray(seed.read_bytes())
    for pos, val in flips:
        data[24 + pos % max(1, len(data) - 24)] = val  # keep the global header so parsing proceeds
    if cut is not None:
        data = data[:max(24, cut % (len(data) + 1))]
    path = tmp_path_factory.mktemp("fz") / ("m" + seed.suffix)
    path.write_bytes(bytes(data))
    try:
        r = Orchestrator().analyze(str(path))
    except ValueError:
        return  # unreadable header is a clean, reported rejection
    assert r.posture.overall_score is None or 0 <= r.posture.overall_score <= 100
    assert r.packet_count >= 0


@FUZZ
@given(blob=st.binary(max_size=4096))
def test_random_bytes_as_capture(tmp_path_factory, blob):
    for header in (b"", struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)):
        p = tmp_path_factory.mktemp("rb") / "r.pcap"
        p.write_bytes(header + blob)
        try:
            Orchestrator().analyze(str(p))
        except ValueError:
            pass


# --------------------------------------------------------------------- TCP
def _seg(seq, data, src=b"\x0a\x00\x00\x02", dst=b"\x0a\x00\x00\x01", sport=25, dport=4000, flags=dpkt.tcp.TH_ACK):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq % (1 << 32), flags=flags, data=data)
    ip = dpkt.ip.IP(src=src, dst=dst, p=6, data=tcp)
    ip.len = len(ip)
    return dpkt.ip.IP(bytes(ip))


@FUZZ
@given(payload=st.binary(min_size=1, max_size=3000), isn=st.integers(0, (1 << 32) - 1),
       cuts=st.lists(st.integers(1, 2999), max_size=25), seed=st.integers(0, 10**6),
       dups=st.integers(0, 10))
def test_reassembly_recovers_exact_bytes(payload, isn, cuts, seed, dups):
    """Any permutation + duplication of a stream's segments reassembles to the original."""
    bounds = sorted({0, len(payload), *[c for c in cuts if c < len(payload)]})
    segs = [(isn + 1 + a, payload[a:b]) for a, b in zip(bounds, bounds[1:])]
    rng = random.Random(seed)
    order = segs + [rng.choice(segs) for _ in range(dups)]
    rng.shuffle(order)
    r = TCPReconstructor()
    r.process_packet(_seg(isn, b"", flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK), 0.0, 1)
    for i, (seq, data) in enumerate(order, 2):
        r.process_packet(_seg(seq, data), float(i), i)
    s = r.get_streams()[0]
    assert s.direction_payload("s2c") == payload
    assert s.reconstruction_quality in ("complete", "incomplete")


@FUZZ
@given(st.lists(st.tuples(st.integers(0, (1 << 32) - 1), st.binary(max_size=200), st.integers(0, 255),
                          st.booleans()), max_size=80))
def test_arbitrary_segments_never_crash(segments):
    r = TCPReconstructor()
    for i, (seq, data, flags, rev) in enumerate(segments, 1):
        p = _seg(seq, data, flags=flags) if not rev else _seg(seq, data, src=b"\x0a\x00\x00\x01",
                                                              dst=b"\x0a\x00\x00\x02", sport=4000, dport=25, flags=flags)
        r.process_packet(p, float(i), i)
    for s in r.get_streams():
        s.quality_summary()
        assert len(s.direction_payload("c2s")) <= 256 * 1024


# --------------------------------------------------------------------- TLS
TLS_SEEDS = []


def _tls_seed_bytes():
    if TLS_SEEDS:
        return TLS_SEEDS
    r = Orchestrator().analyze(str(PCAPS / "smtp_starttls_tls12_chain.pcap"))
    s = r.sessions[0].stream
    TLS_SEEDS.extend([s.direction_payload("s2c").split(b"TLS\r\n")[-1], s.direction_payload("c2s").split(b"TLS\r\n")[-1]])
    return TLS_SEEDS


@FUZZ
@given(blob=st.binary(max_size=5000), splits=st.lists(st.integers(1, 400), max_size=20))
@example(blob=b"\x16\x03\x03\x00\x04\x0b\xff\xff\xff", splits=[])
@example(blob=b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00", splits=[2])
@example(blob=b"\x80\x03\x01", splits=[])
def test_tls_parser_arbitrary_bytes(blob, splits):
    p = TLSParser()
    pos = 0
    for n in splits + [len(blob)]:
        p.process_payload(blob[pos:pos + n], direction="s2c")
        pos += n
    assert len(p._dirs["s2c"].buffer) <= (1 << 14) + 2048 + 5


@FUZZ
@given(which=st.integers(0, 1), flips=st.lists(st.tuples(st.integers(0, 10**6), st.integers(0, 255)), min_size=1,
                                                max_size=30), chunk=st.integers(1, 700))
def test_tls_parser_mutated_real_handshakes(which, flips, chunk):
    data = bytearray(_tls_seed_bytes()[which])
    for pos, val in flips:
        data[pos % len(data)] = val
    p = TLSParser()
    for i in range(0, len(data), chunk):
        p.process_payload(bytes(data[i:i + chunk]), direction="c2s" if which else "s2c")
    for c in p.session.certificates:
        CertificateAnalyzer.analyze_der(c.raw_der)


# -------------------------------------------------------------------- X.509
@FUZZ
@given(flips=st.lists(st.tuples(st.integers(0, 10**6), st.integers(0, 255)), min_size=1, max_size=20),
       cut=st.integers(0, 5000))
def test_mutated_certificates_never_raise(flips, cut):
    from tests.robustness.fixture_factory import issue
    global _CERT
    try:
        der = _CERT
    except NameError:
        der = _CERT = issue("fuzz.example").der
    data = bytearray(der)
    for pos, val in flips:
        data[pos % len(data)] = val
    CertificateAnalyzer.analyze_der(bytes(data[:cut or len(data)]))


# ------------------------------------------------------- text protocol layers
@FUZZ
@given(proto=st.sampled_from([EmailProtocol.SMTP, EmailProtocol.IMAP, EmailProtocol.POP3]),
       chunks=st.lists(st.tuples(st.booleans(), st.text(max_size=300)), max_size=40))
def test_starttls_machine_arbitrary_text(proto, chunks):
    m = StartTLSMachine(proto)
    for is_client, text in chunks:
        m.process_payload(text, is_client)
    m.flush()
    m.finalize(None)


@FUZZ
@given(server=st.binary(max_size=3000), client=st.binary(max_size=3000), port=st.integers(0, 65535))
def test_detector_arbitrary_bytes(server, client, port):
    d = ProtocolDetector().detect(server, port=port, client_payload=client)
    assert 0.0 <= d.confidence <= 1.0


# ------------------------------------------------------------------ scoring
RULES = ["PROTO-001", "PROTO-002", "STLS-001", "STLS-003", "TLS-001", "TLS-003", "TLS-004", "TLS-005",
         "CERT-001", "CERT-003", "CERT-004", "CERT-005", "CERT-006"]
finding_st = st.builds(lambda r, sev, s, conf: FindingResult(
    finding_id=f"s{s}:{r}", rule_id=r, category="c", title=r, severity=sev, confidence=conf, description="",
    recommendation="", session_id=f"s{s}"),
    st.sampled_from(RULES), st.sampled_from(list(Severity)), st.integers(0, 9), st.floats(0.5, 1.0))


def score(findings, n=10):
    return SecurityPostureScorer().calculate_posture(findings, n, n, "t").overall_score


@FUZZ
@given(st.lists(finding_st, max_size=40))
def test_score_bounded_and_deterministic(findings):
    a, b = score(findings), score(list(findings))
    assert a == b and 0.0 <= a <= 100.0


def _f(rule, sev, s):
    return FindingResult(finding_id=f"s{s}:{rule}", rule_id=rule, category="c", title=rule, severity=sev,
                         confidence=1.0, description="", recommendation="", session_id=f"s{s}")


@FUZZ
@given(st.lists(finding_st, max_size=30), finding_st)
@example(findings=[_f("PROTO-001", Severity.CRITICAL, s) for s in (0, 1, 3, 4)],
         extra=_f("PROTO-001", Severity.CRITICAL, 2))  # found by the deep campaign: prevalence cliff at 50%
def test_adding_weakness_never_improves_score(findings, extra):
    assert score(findings + [extra]) <= score(findings)


@FUZZ
@given(st.lists(finding_st, min_size=1, max_size=30), st.integers(2, 50))
def test_duplicate_evidence_does_not_collapse_score(findings, k):
    assert score(findings * k) == score(findings)


@FUZZ
@given(st.lists(finding_st, min_size=1, max_size=30))
def test_removing_weakness_never_worsens_score(findings):
    assert score(findings[1:]) >= score(findings)
