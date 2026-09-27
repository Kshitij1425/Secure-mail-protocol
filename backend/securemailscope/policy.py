"""
Security policy profiles.

A profile changes rule thresholds and severities in a documented way; it never changes
what is observed. Every analysis records the profile used (scoring policy version
becomes "<scoring version>/<profile id>").

* balanced     - default. NIST SP 800-52 Rev. 2 / SP 800-131A Rev. 2 baseline (identical to the
                 behaviour before profiles existed).
* strict       - forward-looking: 128-bit security strength beyond 2030 (NIST SP 800-57 Pt. 1
                 Rev. 5, Table 2/4), AEAD-only guidance (RFC 9325), RFC 8996 "MUST NOT" for TLS 1.0/1.1.
* legacy_audit - triage of estates known to run legacy mail systems: keeps every issue visible
                 but lowers severities of well-known legacy conditions so the most dangerous
                 exposures (plaintext, broken ciphers) dominate. NOT a compliance baseline.
"""
from dataclasses import dataclass, field
from typing import Dict, Optional

from securemailscope.rules.engine import Severity


@dataclass(frozen=True)
class PolicyProfile:
    id: str
    name: str
    description: str
    min_rsa_bits: int
    min_ec_bits: int
    min_dh_bits: int
    deprecated_version_severity: Dict[str, Severity]
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)
    disabled_rules: frozenset = frozenset()
    enabled_optional_rules: frozenset = frozenset()   # rules off in the default profile
    rationale: Dict[str, str] = field(default_factory=dict)

    def weak_key(self, algorithm: Optional[str], bits: Optional[int]) -> bool:
        algo = (algorithm or "").upper()
        if not bits:
            return False
        if algo.startswith("RSA"):
            return bits < self.min_rsa_bits
        if algo.startswith("EC"):
            return bits < self.min_ec_bits
        if algo.startswith("DSA"):
            return True
        return False

    def severity(self, rule_id: str, default: Severity) -> Severity:
        return self.severity_overrides.get(rule_id, default)

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "min_rsa_bits": self.min_rsa_bits, "min_ec_bits": self.min_ec_bits, "min_dh_bits": self.min_dh_bits,
            "deprecated_version_severity": {k: v.value for k, v in self.deprecated_version_severity.items()},
            "severity_overrides": {k: v.value for k, v in self.severity_overrides.items()},
            "disabled_rules": sorted(self.disabled_rules), "enabled_optional_rules": sorted(self.enabled_optional_rules),
            "rationale": self.rationale,
        }


C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

PROFILES: Dict[str, PolicyProfile] = {p.id: p for p in [
    PolicyProfile(
        id="balanced", name="Balanced",
        description="Default. NIST SP 800-52 Rev. 2 / SP 800-131A Rev. 2 baseline.",
        min_rsa_bits=2048, min_ec_bits=224, min_dh_bits=2048,
        deprecated_version_severity={"SSLv2": C, "SSLv3": C, "TLSv1.0": H, "TLSv1.1": H},
        rationale={
            "min_rsa_bits": "2048: 112-bit security, minimum acceptable per NIST SP 800-131A Rev. 2",
            "min_ec_bits": "224: 112-bit security per NIST SP 800-57 Pt. 1 Rev. 5 Table 2",
            "min_dh_bits": "2048: 112-bit security (NIST SP 800-57); Logjam mitigation (RFC 7919 ffdhe2048)",
            "TLSv1.0/1.1": "HIGH: deprecated by RFC 8996",
        }),
    PolicyProfile(
        id="strict", name="Strict",
        description="128-bit security strength and AEAD-only suites; for systems that must remain acceptable beyond 2030.",
        min_rsa_bits=3072, min_ec_bits=256, min_dh_bits=3072,
        deprecated_version_severity={"SSLv2": C, "SSLv3": C, "TLSv1.0": C, "TLSv1.1": C},
        severity_overrides={"TLS-004": H, "CERT-005": H, "TLS-006": M},
        enabled_optional_rules=frozenset({"TLS-007"}),
        rationale={
            "min_rsa_bits": "3072: 128-bit security, required for protection beyond 2030 (NIST SP 800-57 Pt. 1 Rev. 5)",
            "min_ec_bits": "256: 128-bit security (NIST SP 800-57 Pt. 1 Rev. 5)",
            "min_dh_bits": "3072: 128-bit security (NIST SP 800-57 Pt. 1 Rev. 5)",
            "TLSv1.0/1.1": "CRITICAL: RFC 8996 states they MUST NOT be used",
            "TLS-004": "HIGH: forward secrecy expected for all sessions (RFC 9325 Section 4.2)",
            "CERT-005": "HIGH: server authentication required for all peers",
            "TLS-006": "MEDIUM: clients must not offer insecure suites",
            "TLS-007": "enabled: RFC 9325 recommends AEAD cipher suites only",
        }),
    PolicyProfile(
        id="legacy_audit", name="Legacy audit",
        description="Triage for estates with known legacy systems: all issues stay visible, well-known legacy "
                    "conditions are down-weighted so plaintext and broken ciphers dominate. Not a compliance baseline.",
        min_rsa_bits=2048, min_ec_bits=224, min_dh_bits=2048,
        deprecated_version_severity={"SSLv2": C, "SSLv3": H, "TLSv1.0": M, "TLSv1.1": M},
        severity_overrides={"TLS-004": L, "CERT-005": L},
        disabled_rules=frozenset({"TLS-006"}),
        rationale={
            "TLSv1.0/1.1": "MEDIUM: expected in the audited legacy estate; still reported",
            "SSLv3": "HIGH instead of CRITICAL: still prioritised above TLS 1.0/1.1",
            "TLS-004": "LOW: static RSA common in legacy MTAs; still reported",
            "CERT-005": "LOW: internal relays often use self-signed certificates; still reported",
            "TLS-006": "disabled: legacy clients commonly offer old suites; negotiated suites are still assessed",
            "unchanged": "PROTO-001/002, STLS-001, TLS-003 and certificate validity keep their Balanced severities",
        }),
]}

DEFAULT_PROFILE = "balanced"


def get_profile(profile_id: Optional[str]) -> PolicyProfile:
    if profile_id is None:
        return PROFILES[DEFAULT_PROFILE]
    if profile_id not in PROFILES:
        raise ValueError(f"Unknown policy profile '{profile_id}'. Available: {', '.join(PROFILES)}")
    return PROFILES[profile_id]
