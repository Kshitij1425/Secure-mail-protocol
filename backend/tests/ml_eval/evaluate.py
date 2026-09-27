"""
Evaluation of the ML anomaly detector on labelled real sessions.

Data: tests/ml_eval/pool/*.pcap - real TLS mail sessions from 20 server configurations,
labelled healthy / weak by configuration before analysis (see lab/ml_eval_pool.py and
pool/pool_manifest.json). Labels do not come from SecureMailScope's rules.

Protocol: many synthetic "estates" (captures of a mail estate) are composed by sampling
sessions from the pool. Each estate has
  * a dominant fleet configuration (healthy) that makes up most sessions,
  * 0-3 *minority healthy* configurations (e.g. a few TLS 1.3 or ECDSA servers),
  * 0-3 weak configurations at 0-20 % of sessions.
The detector is fitted on each estate (as in the product: per capture) and every session is
scored. A flag on a healthy session is a false positive; a flag on a weak session is a hit.

Configurations are split into two disjoint halves (A / B) for minority-healthy and weak roles.
Design decisions were made looking at split A only ("dev"); split B ("held-out") is reported
separately to show whether the result generalises to configurations not used for design.

Usage (from backend/):
    python -m tests.ml_eval.evaluate                 # current model vs frozen v1
    python -m tests.ml_eval.evaluate --estates 400 --json out.json
"""
import argparse
import json
import logging
import random
from datetime import datetime
from pathlib import Path
from statistics import mean

POOL = Path(__file__).resolve().parent / "pool"


def load_pool():
    """Analyse every pool capture once; return {config: [row, ...]}, labels, reference time."""
    logging.disable(logging.CRITICAL)
    from securemailscope.core.orchestrator import Orchestrator
    manifest = json.loads((POOL / "pool_manifest.json").read_text(encoding="utf-8"))
    rows, labels, ref = {}, {}, None
    for c in manifest["configs"]:
        result = Orchestrator().analyze(str(POOL / c["file"]))
        ref = ref or datetime.fromisoformat(result.metadata["capture_start"])
        rows[c["config"]] = [{
            "protocol": s.protocol, "tls_data": s.tls_data, "certs": s.certificates,
            "packet_count": s.stream.packets_analyzed, "duration": max(0.0, s.stream.end_time - s.stream.start_time),
        } for s in result.sessions if s.tls_data and s.tls_data.server_version]
        labels[c["config"]] = c["label"]
    logging.disable(logging.NOTSET)
    return rows, labels, ref


def split(labels):
    """Disjoint halves of the configurations, per label (alternating in manifest order)."""
    out = {"A": {"healthy": [], "weak": []}, "B": {"healthy": [], "weak": []}}
    for lab in ("healthy", "weak"):
        names = [n for n, v in labels.items() if v == lab]
        for i, n in enumerate(names):
            out["A" if i % 2 == 0 else "B"][lab].append(n)
    return out


def compose(rng, pool, labels, halves, part, legacy_fleet=False):
    healthy_all = [n for n, v in labels.items() if v == "healthy"]
    dominant = rng.choice(halves[part]["weak"] if legacy_fleet else healthy_all)
    minority_choices = [n for n in halves[part]["healthy"] if n != dominant]
    minority = rng.sample(minority_choices, rng.randint(0, min(3, len(minority_choices))))
    weak = rng.sample([w for w in halves[part]["weak"] if w != dominant], rng.randint(0, 3 if not legacy_fleet else 2))
    n = rng.randint(20, 200)
    weak_frac = rng.choice([0.0, 0.02, 0.05, 0.1, 0.2]) if weak else 0.0
    n_weak = max(len(weak), round(n * weak_frac)) if weak else 0
    n_min = sum(max(1, round(n * rng.uniform(0.02, 0.10))) for _ in minority)
    plan = [dominant] * max(1, n - n_weak - n_min)
    for m in minority:
        plan += [m] * max(1, round(n * rng.uniform(0.02, 0.10)))
    for i in range(n_weak):
        plan.append(weak[i % len(weak)])
    sessions, truth = [], {}
    for i, cfg in enumerate(plan):
        row = dict(rng.choice(pool[cfg]))
        row["session_id"] = f"s{i}"
        sessions.append(row)
        truth[row["session_id"]] = (cfg, labels[cfg], "dominant" if cfg == dominant else
                                    "minority" if labels[cfg] == "healthy" else "weak")
    share = n_weak / len(plan)
    return sessions, truth, share


def auc(scores_pos, scores_neg):
    """P(score of a weak session is more anomalous than a healthy one); ties count 1/2."""
    if not scores_pos or not scores_neg:
        return None
    wins = sum((p < q) + 0.5 * (p == q) for p in scores_pos for q in scores_neg)
    return wins / (len(scores_pos) * len(scores_neg))


def evaluate(engine_factory, pool, labels, ref, part, estates, seed0, legacy_fleet=False):
    halves = split(labels)
    c = {"dominant": [0, 0], "minority": [0, 0], "weak": [0, 0]}  # [flagged, total]
    per_weak, by_share = {}, {}
    clean_estates, clean_with_flags, aucs, flag_rates = 0, 0, [], []
    for k in range(estates):
        rng = random.Random(seed0 + k)
        sessions, truth, share = compose(rng, pool, labels, halves, part, legacy_fleet)
        eng = engine_factory()
        flagged, score = set(), {}
        if eng.train_on_sessions(sessions, None, reference_time=ref):
            for r in eng.detect_anomalies(sessions, reference_time=ref):
                score[r.session_id] = r.anomaly_score
                if r.is_anomaly:
                    flagged.add(r.session_id)
        for sid, (cfg, _lab, role) in truth.items():
            c[role][0] += sid in flagged
            c[role][1] += 1
            if role == "weak":
                pw = per_weak.setdefault(cfg, [0, 0])
                pw[0] += sid in flagged
                pw[1] += 1
                b = by_share.setdefault("<=5%" if share <= 0.05 else "5-12%" if share <= 0.12 else ">12%", [0, 0])
                b[0] += sid in flagged
                b[1] += 1
        flag_rates.append(len(flagged) / len(sessions))
        if not any(r == "weak" for _, _, r in truth.values()):
            clean_estates += 1
            clean_with_flags += bool(flagged)
        a = auc([score.get(s, 1.0) for s, t in truth.items() if t[2] == "weak"],
                [score.get(s, 1.0) for s, t in truth.items() if t[2] != "weak"])
        if a is not None:
            aucs.append(a)
    tp, fp = c["weak"][0], c["dominant"][0] + c["minority"][0]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / c["weak"][1] if c["weak"][1] else None
    rate = lambda x: round(x[0] / x[1], 4) if x[1] else None  # noqa: E731
    return {
        "estates": estates, "split": part,
        "weak_recall": rate(c["weak"]),
        "precision": round(precision, 4) if precision is not None else None,
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision and recall else 0.0,
        "flag_rate_dominant_config": rate(c["dominant"]),
        "false_positive_rate_minority_healthy": rate(c["minority"]),
        "mean_flag_rate": round(mean(flag_rates), 4),
        "clean_estates_with_any_flag": f"{clean_with_flags}/{clean_estates}",
        "mean_auc": round(mean(aucs), 4) if aucs else None,
        "recall_per_weak_config": {k: rate(v) for k, v in sorted(per_weak.items())},
        "recall_by_weak_share_of_estate": {k: rate(v) for k, v in sorted(by_share.items())},
    }


def engines():
    from securemailscope.ml.anomaly_detector import AnomalyDetectionEngine
    from securemailscope.core.orchestrator import MIN_ML_SESSIONS
    from tests.ml_eval.v1_reference import AnomalyDetectionEngine as V1
    return {
        "v1 (isolation-forest/1)": lambda: V1(contamination="auto", min_training_sessions=MIN_ML_SESSIONS),
        f"current ({AnomalyDetectionEngine(contamination='auto').detector.MODEL_VERSION})":
            lambda: AnomalyDetectionEngine(contamination="auto", min_training_sessions=MIN_ML_SESSIONS),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--estates", type=int, default=300)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    pool, labels, ref = load_pool()
    out = {"pool_sessions": sum(len(v) for v in pool.values()), "configs": len(pool), "results": {}}
    for name, factory in engines().items():
        out["results"][name] = {
            "dev (split A)": evaluate(factory, pool, labels, ref, "A", args.estates, 0),
            "held-out (split B)": evaluate(factory, pool, labels, ref, "B", args.estates, 100000),
            "legacy fleet (dominant config weak, split B)": evaluate(factory, pool, labels, ref, "B", args.estates,
                                                                     200000, legacy_fleet=True),
        }
    print(json.dumps(out, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
