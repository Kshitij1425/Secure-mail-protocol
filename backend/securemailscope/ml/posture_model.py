"""
Posture outlier model (isolation-forest/2).

Question answered: *which TLS sessions in this capture are cryptographically weaker than the
capture's own norm, and how unusual is that weakness here?*  It is an investigation aid; it
never creates findings or changes the score.

Changes from isolation-forest/1 (see ML_DESIGN.md for the measured effect):

* Security-relevant features only, oriented so that higher = stronger. Traffic volume
  (packets, duration) and certificate age were removed: they describe mail volume, not posture.
* Values above an "acceptable" level are saturated (e.g. key strength is capped at 112-bit
  security, TLS 1.3 and TLS 1.2 are both "current"), so healthy diversity is not isolatable.
* Not observable values (e.g. the certificate in TLS 1.3) are *missing*, not zero. They are
  imputed with the capture's typical value, so missing data is neutral.
* One-sided: each feature is capped at the capture median before fitting, so a session that is
  stronger than the norm looks exactly like the norm. A session that is not weaker than the
  norm on any feature is never reported as an outlier.
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np

# name, cap (acceptable level), human label
FEATURES = [
    ("protocol_version", 4.0, "TLS version"),
    ("forward_secrecy", 1.0, "Forward secrecy"),
    ("aead_cipher", 1.0, "AEAD cipher"),
    ("cipher_class", 3.0, "Cipher suite class"),
    ("key_exchange_security_bits", 112.0, "Key exchange strength"),
    ("certificate_key_security_bits", 112.0, "Certificate key strength"),
    ("certificate_signature_hash", 2.0, "Certificate signature hash"),
    ("certificate_valid_at_capture", 1.0, "Certificate valid at capture time"),
    ("certificate_days_to_expiry", 30.0, "Days to certificate expiry"),
    ("certificate_not_self_signed", 1.0, "Certificate not self-signed"),
]
NAMES = [f[0] for f in FEATURES]
CAPS = np.array([f[1] for f in FEATURES], dtype=np.float64)
LABELS = {f[0]: f[2] for f in FEATURES}

_VERSIONS = {"SSLv2": 0.0, "SSL 2.0": 0.0, "SSLv3": 1.0, "SSL 3.0": 1.0, "TLSv1.0": 2.0, "TLS 1.0": 2.0,
             "TLSv1.1": 3.0, "TLS 1.1": 3.0, "TLSv1.2": 4.0, "TLS 1.2": 4.0, "TLSv1.3": 5.0, "TLS 1.3": 5.0}
_CIPHER_CLASS = {"insecure": 0.0, "weak": 1.0, "legacy": 2.0, "recommended": 3.0}
_GROUP_BITS = {"x25519": 128, "x448": 224, "secp256r1": 128, "prime256v1": 128, "secp384r1": 192,
               "secp521r1": 256, "ffdhe2048": 112, "ffdhe3072": 128, "ffdhe4096": 152, "ffdhe6144": 176,
               "ffdhe8192": 200}


def modulus_security_bits(bits: int) -> float:
    """Security strength of an RSA / finite-field DH modulus (NIST SP 800-57 Part 1, Table 2)."""
    for limit, strength in ((15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80)):
        if bits >= limit:
            return float(strength)
    return float(max(0, bits // 16))  # below 1024 bits: far below any current minimum


def key_security_bits(algorithm: str, bits: int) -> Optional[float]:
    if not bits:
        return None
    a = (algorithm or "").upper()
    if a.startswith("EC"):
        return float(bits // 2)
    if a == "ED25519":
        return 128.0
    if a == "ED448":
        return 224.0
    return modulus_security_bits(bits)  # RSA, DSA


def _group_bits(tls) -> Optional[float]:
    if tls.dh_prime_bits:
        return modulus_security_bits(tls.dh_prime_bits)
    g = (tls.key_exchange_group or "").lower()
    for name, bits in _GROUP_BITS.items():
        if name in g:
            return float(bits)
    return None


def _signature_hash(sig: str) -> float:
    s = (sig or "").lower()
    if "md5" in s or "md2" in s:
        return 0.0
    if "sha1" in s:
        return 1.0
    return 2.0


@dataclass
class PostureVector:
    session_id: str
    protocol: str
    values: List[Optional[float]]   # raw, in FEATURES order; None = not observable
    notes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"protocol": self.protocol}
        for n, v in zip(NAMES, self.values):
            d[n] = None if v is None else float(v)
        return d


def extract(session_id: str, protocol, tls, certs, reference_time) -> Optional[PostureVector]:
    """Posture features of one TLS session; None when no negotiated version was observed."""
    if not tls or not tls.server_version:
        return None
    notes = []
    cipher = tls.cipher
    tls13 = tls.server_version in ("TLSv1.3", "TLS 1.3")
    fs = True if tls13 else (cipher.forward_secrecy if cipher and cipher.forward_secrecy is not None
                             else tls.has_forward_secrecy)
    aead = True if tls13 else (cipher.aead if cipher and cipher.known else None)
    cclass = _CIPHER_CLASS.get(cipher.strength) if cipher else None
    kx = _group_bits(tls)
    if kx is None and fs is False:
        notes.append("static key exchange (strength follows the certificate key)")
    leaf = certs[0] if certs else None
    if leaf is None:
        notes.append("certificate not observable" + (" (encrypted by TLS 1.3)" if tls13 else ""))
        ckey = csig = cvalid = cdays = cself = None
    else:
        ckey = key_security_bits(leaf.public_key_algorithm, leaf.public_key_size_bits)
        csig = _signature_hash(leaf.signature_algorithm)
        cvalid = 0.0 if (leaf.is_expired or leaf.is_not_yet_valid) else 1.0
        cdays = None
        if reference_time is not None and leaf.not_after is not None:
            cdays = float((leaf.not_after - reference_time).days)
        cself = 0.0 if leaf.is_self_signed else 1.0
    values = [_VERSIONS.get(tls.server_version), None if fs is None else float(bool(fs)),
              None if aead is None else float(bool(aead)), cclass, kx, ckey, csig, cvalid, cdays, cself]
    return PostureVector(session_id, getattr(protocol, "name", str(protocol)), values, notes)


def _describe(name: str, v: float) -> str:
    if name == "protocol_version":
        return {0: "SSL 2.0", 1: "SSL 3.0", 2: "TLS 1.0", 3: "TLS 1.1"}.get(int(v), "TLS 1.2 or newer")
    if name in ("forward_secrecy", "aead_cipher", "certificate_valid_at_capture", "certificate_not_self_signed"):
        return "yes" if v >= 1 else "no"
    if name == "cipher_class":
        return {0: "insecure", 1: "weak", 2: "legacy (non-AEAD or no forward secrecy)"}.get(int(v), "recommended")
    if name == "certificate_signature_hash":
        return {0: "MD5/MD2", 1: "SHA-1"}.get(int(v), "SHA-2 or stronger")
    if name.endswith("security_bits"):
        return f"{v:.0f}-bit security" + (" or more" if v >= 112 else "")
    if name == "certificate_days_to_expiry":
        return f"{v:.0f} days" if v < 30 else "30 days or more"
    return f"{v:g}"


class PostureOutlierDetector:
    MODEL_VERSION = "isolation-forest/2"

    def __init__(self, contamination="auto", random_state: int = 42, n_estimators: int = 200):
        from sklearn.ensemble import IsolationForest
        self._IF = IsolationForest
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.model = None
        self.norm: Optional[np.ndarray] = None
        self.feature_names = list(NAMES)

    # -- preparation ------------------------------------------------------------------
    @staticmethod
    def _raw(vectors: List[PostureVector]) -> np.ndarray:
        return np.array([[np.nan if v is None else v for v in p.values] for p in vectors], dtype=np.float64)

    def _prepare(self, raw: np.ndarray) -> np.ndarray:
        X = np.minimum(raw, CAPS)                     # saturate at the acceptable level
        X = np.where(np.isnan(X), self.norm, X)       # not observable -> capture norm (neutral)
        return np.minimum(X, self.norm)               # one-sided: stronger than the norm == the norm

    def fit(self, vectors: List[PostureVector]) -> bool:
        if len(vectors) < 3:
            return False
        raw = np.minimum(self._raw(vectors), CAPS)
        # The norm counts not-observable values as acceptable. Otherwise, in a mostly TLS 1.3
        # capture, the few observable certificates (possibly all weak) would define the norm and
        # a minority weakness would look normal. A fully observed legacy fleet is unaffected.
        self.norm = np.median(np.where(np.isnan(raw), CAPS, raw), axis=0)
        X = self._prepare(self._raw(vectors))
        self.model = self._IF(n_estimators=self.n_estimators, contamination=self.contamination,
                              random_state=self.random_state)
        self.model.fit(X)
        self._freq = [dict(zip(*np.unique(X[:, i], return_counts=True))) for i in range(X.shape[1])]
        self._n = len(X)
        return True

    # -- scoring ----------------------------------------------------------------------
    def score(self, vectors: List[PostureVector]):
        from securemailscope.ml.anomaly_detector import AnomalyLevel, AnomalyResult
        if self.model is None or not vectors:
            return [AnomalyResult(p.session_id, False, 1.0, AnomalyLevel.NORMAL, p.to_dict(),
                                  "No anomaly model available (untrained).") for p in vectors]
        raw = self._raw(vectors)
        X = self._prepare(raw)
        decisions = self.model.decision_function(X)
        out = []
        for p, x, decision in zip(vectors, X, decisions):
            below = [i for i in range(len(NAMES)) if x[i] < self.norm[i]]
            # /0.3: observed decision values lie in about [-0.3, 0.2]; a smaller divisor saturates at -1 and
            # erases the ranking between sessions with one and several weaknesses.
            norm_score = float(np.clip(float(decision) / 0.3, -1.0, 1.0))
            is_anomaly = bool(decision < 0) and bool(below)
            if not below:
                norm_score = max(norm_score, 0.0)  # not weaker than the norm on any feature
            if not is_anomaly:
                level = AnomalyLevel.NORMAL
            elif norm_score < -0.75:
                level = AnomalyLevel.SEVERE
            elif norm_score < -0.25:
                level = AnomalyLevel.MODERATE
            else:
                level = AnomalyLevel.MILD
            out.append(AnomalyResult(p.session_id, is_anomaly, norm_score, level, p.to_dict(),
                                     self._explain(p, x, below, is_anomaly)))
        return out

    def _explain(self, p: PostureVector, x: np.ndarray, below: List[int], is_anomaly: bool) -> str:
        if not below:
            text = "Not weaker than this capture's norm on any posture feature."
        else:
            parts = []
            for i in below:
                share = self._freq[i].get(x[i], 0) / self._n * 100
                parts.append(f"{LABELS[NAMES[i]]}: {_describe(NAMES[i], x[i])} "
                             f"(capture norm {_describe(NAMES[i], self.norm[i])}; {share:.0f}% of sessions)")
            text = ("Weaker than this capture's norm and rare here: " if is_anomaly
                    else "Weaker than the norm on some features but common in this capture: ") + "; ".join(parts) + "."
        if p.notes:
            text += " Note: " + "; ".join(p.notes) + " - treated as neutral."
        return text

    def to_dict(self) -> Dict[str, Any]:
        return {"model_type": "IsolationForest", "model_version": self.MODEL_VERSION,
                "random_state": self.random_state, "contamination": self.contamination,
                "n_estimators": self.n_estimators, "feature_names": self.feature_names,
                "is_trained": self.model is not None}
