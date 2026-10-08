#!/usr/bin/env python3
"""
Validate simulate/atomic/atomic-map.yaml against the detection library.

Checks, all offline (CI-safe):
  * YAML well-formed, required keys present, types correct
  * every `detection` ID exists in detections/
  * every `technique` is declared by that detection (techniques or
    sub_techniques), so the map can't claim a test exercises a rule it doesn't
  * `guid` is either null or a well-formed GUID; duplicate (detection, guid)
    pairs are rejected
  * platform/risk/booleans are from the allowed sets
And reports coverage: which detections have >=1 atomic, which have none.

Usage:
  scripts/validate_atomics.py                 # validate + coverage summary
  scripts/validate_atomics.py --strict-pinned # also fail on any null guid
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS = ROOT / "detections"
MAP = ROOT / "simulate" / "atomic" / "atomic-map.yaml"

REQUIRED = {"detection", "name", "technique", "guid", "platform", "risk",
            "elevation_required", "cleanup"}
PLATFORMS = {"windows", "linux", "macos"}
RISKS = {"safe", "moderate", "high"}
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
TECH = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_detections() -> dict[str, set[str]]:
    """detection id -> set of techniques + sub_techniques it declares."""
    out: dict[str, set[str]] = {}
    for f in DETECTIONS.rglob("*.yaml"):
        doc = yaml.safe_load(f.read_text())
        if not isinstance(doc, dict) or "id" not in doc:
            continue
        techs = set(doc.get("techniques", [])) | set(doc.get("sub_techniques", []))
        out[doc["id"]] = techs
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict-pinned", action="store_true",
                    help="fail if any entry has a null guid")
    args = ap.parse_args()

    if not MAP.exists():
        print(f"atomic map not found: {MAP}", file=sys.stderr)
        return 1

    detections = load_detections()
    doc = yaml.safe_load(MAP.read_text())
    tests = doc.get("tests", []) if isinstance(doc, dict) else []
    errors: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()
    covered: set[str] = set()
    unpinned = 0

    if not tests:
        errors.append("no tests defined")

    for i, t in enumerate(tests):
        where = f"tests[{i}]"
        if not isinstance(t, dict):
            errors.append(f"{where}: not a mapping")
            continue
        missing = REQUIRED - set(t)
        if missing:
            errors.append(f"{where}: missing keys {sorted(missing)}")
            continue

        det, tech, guid = t["detection"], t["technique"], t["guid"]

        if det not in detections:
            errors.append(f"{where}: detection {det!r} does not exist")
        else:
            covered.add(det)
            if not TECH.match(str(tech)):
                errors.append(f"{where}: technique {tech!r} malformed")
            elif tech not in detections[det]:
                errors.append(
                    f"{where}: {det} does not declare technique {tech} "
                    f"(declares {sorted(detections[det])})")

        if guid is None:
            unpinned += 1
            if args.strict_pinned:
                errors.append(f"{where}: guid is null (strict-pinned)")
        elif not GUID.match(str(guid)):
            errors.append(f"{where}: guid {guid!r} is not a valid GUID")
        else:
            pair = (det, str(guid).lower())
            if pair in seen_pairs:
                errors.append(f"{where}: duplicate (detection, guid) {pair}")
            seen_pairs.add(pair)

        if t["platform"] not in PLATFORMS:
            errors.append(f"{where}: platform {t['platform']!r} invalid")
        if t["risk"] not in RISKS:
            errors.append(f"{where}: risk {t['risk']!r} invalid")
        for b in ("elevation_required", "cleanup"):
            if not isinstance(t[b], bool):
                errors.append(f"{where}: {b} must be boolean")

    if errors:
        print("Atomic map validation FAILED:\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    pinned = len(tests) - unpinned
    print(f"OK: {len(tests)} atomic tests valid ({pinned} pinned, {unpinned} unpinned)")

    # Coverage: host/endpoint detections are the ones ART can exercise.
    host_prefixes = ("SYS-", "WIN-", "LNX-")
    host_dets = sorted(d for d in detections if d.startswith(host_prefixes))
    uncovered = [d for d in host_dets if d not in covered]
    print(f"Endpoint detection coverage: {len(set(host_dets) & covered)}/{len(host_dets)}")
    if uncovered:
        print("  no atomic yet: " + ", ".join(uncovered))
    return 0


if __name__ == "__main__":
    sys.exit(main())
