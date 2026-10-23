"""Replay labelled event data against digest-verified packages; execute no attacks.

Example:
  python tools/evaluate_detections.py --active examples/cohorts/active.json \
    --candidate examples/cohorts/candidate.json --cohort examples/cohorts/labelled.json \
    --output comparison.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys

from angerona.core.atomic_io import replace_with_retry
from angerona.core.detection_evaluation import (
    CohortLoss, MAX_COHORT_ROWS, capture_replay_cohort, compare_detection_packages,
)
from angerona.core.detection_packages import load_package

INPUT_SCHEMA = "angerona.curated-detection-cohort.v1"
REPORT_SCHEMA = "angerona.labelled-detection-quality.v1"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 16
MAX_TRAINING_COHORTS = 8
MAX_HOLDOUT_COMPARISON_ROWS = 40_000


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate cohort JSON fields")
        result[key] = value
    return result


def load_cohort(path):
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Cohort must be a regular file")
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Cohort exceeds 8 MiB input budget")
    def constant(_value):
        raise ValueError("Cohort JSON must use finite numbers")
    document = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique,
                          parse_constant=constant)
    fields = {"schema", "source_id", "source_kind", "high_water", "loss", "rows"}
    if type(document) is not dict or set(document) != fields or document["schema"] != INPUT_SCHEMA:
        raise ValueError("Unsupported or ambiguous labelled cohort schema")
    if document["source_kind"] not in {"curated-replay", "synthetic"}:
        raise ValueError("CLI cohort source must be curated-replay or synthetic")
    rows = document["rows"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_COHORT_ROWS:
        raise ValueError("Cohort must contain 1 through 20000 rows")
    for row in rows:
        if (type(row) is not dict or set(row) != {
                "event_id", "revision", "event", "label", "label_source"}
                or type(row["label"]) is not bool
                or not isinstance(row["label_source"], str) or not row["label_source"].strip()):
            raise ValueError("Every cohort row requires an explicit boolean label and label source")
    loss = document["loss"]
    if type(loss) is not dict or set(loss) != {
        "overflow", "dropped_rows", "incomplete_reason", "excluded_after_high_water",
    }:
        raise ValueError("Exact cohort loss metadata is required")
    return capture_replay_cohort(
        rows, source_id=document["source_id"], source_kind=document["source_kind"],
        high_water=document["high_water"], loss=CohortLoss(**loss),
    )


def build_report(cohort, comparison):
    cohort.assert_intact()
    comparison.assert_intact()
    if comparison.cohort_digest != cohort.cohort_digest:
        raise ValueError("Comparison does not belong to this exact cohort")
    quality_available = comparison.complete and cohort.fully_labelled and cohort.loss.complete
    positives = {row.event_id for row in cohort.rows if row.label is True}
    negatives = {row.event_id for row in cohort.rows if row.label is False}

    def quality(matches):
        if not quality_available:
            return dict(true_positive=None, false_positive=None, false_negative=None,
                        true_negative=None, precision=None, recall=None, false_positive_rate=None)
        predicted = set(matches)
        tp, fp = len(predicted & positives), len(predicted & negatives)
        fn, tn = len(positives - predicted), len(negatives - predicted)
        return dict(true_positive=tp, false_positive=fp, false_negative=fn, true_negative=tn,
                    precision=tp / (tp + fp) if tp + fp else None,
                    recall=tp / (tp + fn) if tp + fn else None,
                    false_positive_rate=fp / (fp + tn) if fp + tn else None)

    body = {
        "schema": REPORT_SCHEMA, "cohort": cohort.summary(),
        "comparison": comparison.to_dict(), "quality_available": quality_available,
        "denominators": {"labelled_positive": len(positives), "labelled_benign": len(negatives)},
        "active": quality(comparison.active_event_ids),
        "candidate": quality(comparison.candidate_event_ids),
        "limitations": [
            "Labels are supplied by the cohort curator; this tool does not independently prove them.",
            "Synthetic or curated event replay is not live attack execution, containment, or fleet efficacy proof.",
            "A content digest detects changed report bytes; it is not a publisher signature or independent timestamp.",
            "Incomplete/lost evidence withholds quality counts and rates. Matches still describe the observed cohort.",
        ],
    }
    return {**body, "report_digest": "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()}


def assess_holdout(cohort, training, packages):
    """Check exact payload disjointness, without claiming independent curation.

    IDs, labels and revisions cannot disguise an identical replayed event.
    Semantic duplicates, unreported training sets and prior human exposure are
    outside this check; the report keeps those limits alongside its digests.
    """
    if not 1 <= len(training) <= MAX_TRAINING_COHORTS:
        raise ValueError("Held-out evaluation requires 1 through 8 explicit training cohorts")
    cohorts = [cohort, *training]
    if sum(len(item.rows) for item in cohorts) > MAX_HOLDOUT_COMPARISON_ROWS:
        raise ValueError("Held-out comparison exceeds 40000 total rows")
    if not 1 <= len(packages) <= MAX_PACKAGES * 2:
        raise ValueError("Held-out package bound exceeded")
    for item in cohorts:
        item.assert_intact()
        if not item.loss.complete or not item.fully_labelled:
            raise ValueError("Held-out comparison requires complete labelled cohorts")
    if {row.label for row in cohort.rows} != {True, False}:
        raise ValueError("Held-out cohort requires both positive and benign observations")
    def fingerprint(event):
        return hashlib.sha256(_canonical(event)).digest()
    evaluation = {fingerprint(row.event()) for row in cohort.rows}
    if len(evaluation) != len(cohort.rows):
        raise ValueError("Held-out denominator contains duplicate event payloads")
    seen = set()
    for item in training:
        if item.source_digest in seen:
            raise ValueError("Duplicate training cohort")
        seen.add(item.source_digest)
        if any(fingerprint(row.event()) in evaluation for row in item.rows):
            raise ValueError("Held-out payload overlaps a training cohort")
    from angerona.core.detection_packages import validate_package
    package_digests = []
    for package in packages:
        document = validate_package(package.document)
        package_digests.append(document["digest"])
        if any(fingerprint(fixture["event"]) in evaluation for fixture in document["fixtures"]):
            raise ValueError("Held-out payload overlaps a package fixture")
    return {
        "schema": "angerona.exact-payload-holdout.v1", "status": "disjoint",
        "evaluation_source_digest": cohort.source_digest,
        "training_source_digests": sorted(seen),
        "package_digests": sorted(set(package_digests)),
        "evaluation_rows": len(cohort.rows),
        "training_rows": sum(len(item.rows) for item in training),
        "independent_review_verified": False,
        "limitations": [
            "Checks exact canonical event payloads against declared training cohorts and package fixtures only.",
            "Cannot prove semantic disjointness, absence of undeclared training data or prior curator exposure.",
            "Labels remain curator-supplied; this is not independent review or live-host efficacy proof.",
        ],
    }


def write_report(path, report):
    target = Path(path).absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False,
                         allow_nan=False).encode("utf-8") + b"\n"
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError("Comparison report exceeds 16 MiB output budget")
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(16)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        replace_with_retry(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active", type=Path, action="append", default=[],
                        help="Active package; repeatable, maximum 16")
    parser.add_argument("--candidate", type=Path, action="append", required=True,
                        help="Candidate package; repeatable, maximum 16")
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--training-cohort", type=Path, action="append", default=[],
                        help="Enable exact-payload holdout checks; repeat for 1..8 declared training cohorts")
    parser.add_argument("--max-false-positives", type=int)
    parser.add_argument("--max-false-negatives", type=int)
    args = parser.parse_args(argv)
    try:
        if max(len(args.active), len(args.candidate)) > MAX_PACKAGES:
            raise ValueError("At most 16 packages per side")
        if len(args.training_cohort) > MAX_TRAINING_COHORTS:
            raise ValueError("At most 8 training cohorts")
        if any(value is not None and value < 0 for value in (
            args.max_false_positives, args.max_false_negatives,
        )):
            raise ValueError("Quality thresholds must be non-negative")
        inputs = [args.cohort, *args.active, *args.candidate, *args.training_cohort]
        if args.output.resolve() in {path.resolve() for path in inputs}:
            raise ValueError("Output may not overwrite a cohort or package input")
        cohort = load_cohort(args.cohort)
        active = [load_package(path) for path in args.active]
        candidate = [load_package(path) for path in args.candidate]
        holdout = assess_holdout(cohort, [load_cohort(path) for path in args.training_cohort],
                                 [*active, *candidate]) if args.training_cohort else None
        comparison = compare_detection_packages(cohort, active=active, candidate=candidate)
        report = build_report(cohort, comparison)
        failures = []
        if report["quality_available"]:
            for name, limit in (("false_positive", args.max_false_positives),
                                ("false_negative", args.max_false_negatives)):
                if limit is not None and report["candidate"][name] > limit:
                    failures.append(f"candidate {name} exceeds {limit}")
        # Gate metadata is part of the outer seal, not the core evaluator digest.
        report.pop("report_digest")
        if holdout is not None:
            report["holdout"] = holdout
        thresholds_configured = (
            args.max_false_positives is not None or args.max_false_negatives is not None
        )
        report["quality_gate"] = {
            "status": ("withheld" if not report["quality_available"] else "fail" if failures
                       else "pass" if thresholds_configured else "measured"),
            "max_false_positives": args.max_false_positives,
            "max_false_negatives": args.max_false_negatives, "failures": failures,
        }
        report["report_digest"] = "sha256:" + hashlib.sha256(_canonical(report)).hexdigest()
        write_report(args.output, report)
        print(f"{report['quality_gate']['status']}: {args.output}")
        if report["quality_available"]:
            measured = report["candidate"]
            print(f"Candidate: TP={measured['true_positive']} FP={measured['false_positive']} "
                  f"FN={measured['false_negative']} TN={measured['true_negative']}")
        return 3 if not report["quality_available"] else 1 if failures else 0
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(f"Detection replay rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
