#!/usr/bin/env python3
"""
Lint the detection-as-code YAML files and (optionally) generate the catalog.

Catches the mistakes that otherwise only surface as a failed `terraform apply`
or, worse, as a rule that deploys fine and never fires:
  * schema / required fields, duplicate IDs, ID <-> filename mismatch
  * Sentinel limits (frequency 5m-14d, period <= 14d, period >= frequency,
    <= 10 entity mappings, 1-3 field mappings, <= 20 custom details)
  * valid Sentinel tactic names and ATT&CK technique ID formats
  * entity / custom-detail columns that never appear in the query text
  * simulation script referenced by the rule actually exists

Usage:
  scripts/validate_detections.py                 # validate
  scripts/validate_detections.py --catalog       # validate + write docs/detection-catalog.md
  scripts/validate_detections.py --check-catalog # fail if the catalog is stale (CI)
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS = ROOT / "detections"
CATALOG = ROOT / "docs" / "detection-catalog.md"

TEMPLATE_VARS = {
    "canary_secret_name": "svc-backup-sql-prod-password",
    "canary_blob_name": "finance/2026-payroll-export.csv",
    "canary_blob_leaf": "2026-payroll-export.csv",
    "key_vault_name": "kv-<prefix>-<suffix>",
    "storage_name": "st<prefix><suffix>",
    "watchlist_alias": "LabApprovedPrivilegedCallers",
    "canary_watchlist_alias": "LabCanaryAccounts",
    "victim_subnet_cidr": "10.42.1.0/24",
    "internal_mgmt_ports": "22, 3389, 5985, 5986, 445, 135, 1433, 3306, 5432, 6379, 27017",
}

REQUIRED = [
    "id", "name", "description", "severity", "requires", "tactics", "techniques",
    "query_frequency", "query_period", "query", "entity_mappings", "simulation",
]
SEVERITIES = {"Informational", "Low", "Medium", "High"}
SOURCES = {"azure_activity", "key_vault", "storage", "windows_vm", "linux_vm", "entra_id", "entra_id_p2", "flow_logs", "sysmon"}
OVERRIDE_KEYS = {"display_name_format", "description_format", "severity_column_name", "tactics_column_name"}
# Kill-chain order (a list, not a set, so generated output is deterministic).
TACTIC_ORDER = [
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery",
    "LateralMovement", "Collection", "CommandAndControl", "Exfiltration", "Impact",
    "PreAttack", "ImpairProcessControl", "InhibitResponseFunctions",
]
TACTICS = set(TACTIC_ORDER)
TACTIC_DISPLAY = {t: re.sub(r"(?<!^)(?=[A-Z])", " ", t) for t in TACTICS}
ENTITY_IDENTIFIERS = {
    "Account": {"Name", "FullName", "NTDomain", "DnsDomain", "UPNSuffix", "Sid",
                "AadTenantId", "AadUserId", "PUID", "IsDomainJoined", "DisplayName", "ObjectGuid"},
    "Host": {"DnsDomain", "NTDomain", "HostName", "FullName", "NetBiosName",
             "AzureID", "OMSAgentID", "OSFamily", "OSVersion", "IsDomainJoined"},
    "IP": {"Address"},
    "AzureResource": {"ResourceId"},
    "URL": {"Url"},
    "FileHash": {"Algorithm", "Value"},
    "Process": {"ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "DNS": {"DomainName"},
    "File": {"Directory", "Name"},
    "RegistryKey": {"Hive", "Key"},
}
DURATION = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$")


def minutes(iso: str) -> int:
    m = DURATION.match(iso or "")
    if not m or not any(m.groups()):
        raise ValueError(f"invalid ISO-8601 duration {iso!r}")
    d, h, mi = (int(x) if x else 0 for x in m.groups())
    return d * 1440 + h * 60 + mi


def render(text: str) -> str:
    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in TEMPLATE_VARS:
            raise KeyError(f"unknown template variable ${{{key}}}")
        return TEMPLATE_VARS[key]
    return re.sub(r"\$\{([a-z_]+)\}", sub, text)


def validate(path: Path, doc: dict, seen: dict[str, Path]) -> list[str]:
    e: list[str] = []
    rel = path.relative_to(ROOT)

    for k in REQUIRED:
        if k not in doc:
            e.append(f"missing required field '{k}'")
    if e:
        return e

    rid = doc["id"]
    if not re.fullmatch(r"[A-Z]+(-[A-Z]+)?-\d{3}", rid):
        e.append(f"id {rid!r} must look like ABC-001 or ABC-DEF-001")
    if not path.stem.upper().startswith(rid):
        e.append(f"filename must start with the id ({rid.lower()}-...)")
    if rid in seen:
        e.append(f"duplicate id {rid} (also in {seen[rid].relative_to(ROOT)})")
    seen[rid] = path

    if doc["severity"] not in SEVERITIES:
        e.append(f"severity must be one of {sorted(SEVERITIES)}")
    for s in doc["requires"]:
        if s not in SOURCES:
            e.append(f"unknown data source {s!r} in requires (known: {sorted(SOURCES)})")

    for t in doc["tactics"]:
        if t not in TACTICS:
            e.append(f"invalid Sentinel tactic {t!r}")
    for t in doc["techniques"]:
        if not re.fullmatch(r"T\d{4}", t):
            e.append(f"technique {t!r} must be a parent ID like T1098 (put sub-techniques in sub_techniques)")
    for st in doc.get("sub_techniques", []):
        if not re.fullmatch(r"T\d{4}\.\d{3}", st):
            e.append(f"sub-technique {st!r} must look like T1098.003")
        elif st.split(".")[0] not in doc["techniques"]:
            e.append(f"sub-technique {st} has no parent {st.split('.')[0]} in techniques")

    try:
        freq, period = minutes(doc["query_frequency"]), minutes(doc["query_period"])
        if not 5 <= freq <= 20160:
            e.append("query_frequency must be between PT5M and P14D")
        if period > 20160:
            e.append("query_period must be <= P14D")
        if period < freq:
            e.append("query_period must be >= query_frequency or events will be missed")
    except ValueError as ex:
        e.append(str(ex))

    query = doc["query"]
    if not query.strip():
        e.append("query is empty")

    ems = doc["entity_mappings"]
    if len(ems) > 10:
        e.append("max 10 entity mappings")
    for em in ems:
        et = em.get("entity_type")
        if et not in ENTITY_IDENTIFIERS:
            e.append(f"unknown entity_type {et!r}")
            continue
        fms = em.get("field_mappings", [])
        if not 1 <= len(fms) <= 3:
            e.append(f"{et}: 1-3 field_mappings required")
        for fm in fms:
            if fm.get("identifier") not in ENTITY_IDENTIFIERS[et]:
                e.append(f"{et}: invalid identifier {fm.get('identifier')!r}")
            col = fm.get("column_name", "")
            if not re.search(rf"\b{re.escape(col)}\b", query):
                e.append(f"{et}: column {col!r} not found in query")

    cds = doc.get("custom_details") or {}
    if len(cds) > 20:
        e.append("max 20 custom_details")
    for key, col in cds.items():
        if not re.fullmatch(r"[A-Za-z0-9]{1,20}", key):
            e.append(f"custom_details key {key!r} must be alphanumeric, <= 20 chars")
        if not re.search(rf"\b{re.escape(col)}\b", query):
            e.append(f"custom_details column {col!r} not found in query")

    ado = doc.get("alert_details_override")
    if ado is not None:
        if not isinstance(ado, dict) or not ado:
            e.append("alert_details_override must be a non-empty mapping")
        else:
            for k in set(ado) - OVERRIDE_KEYS:
                e.append(f"alert_details_override: unknown key {k!r}")
            fmt = ado.get("display_name_format")
            if fmt is not None and not str(fmt).startswith(f"[{rid}] "):
                e.append(f"display_name_format must start with '[{rid}] ' (verify.sh matches on it)")
            for k in ("display_name_format", "description_format"):
                for col in re.findall(r"\{\{(\w+)\}\}", str(ado.get(k, ""))):
                    if not re.search(rf"\b{re.escape(col)}\b", query):
                        e.append(f"{k}: placeholder {{{{{col}}}}} is not a column in the query")
            for k in ("severity_column_name", "tactics_column_name"):
                col = ado.get(k)
                if col and not re.search(rf"\b{re.escape(col)}\b", query):
                    e.append(f"{k}: column {col!r} not found in query")

    sim = ROOT / doc["simulation"]
    if not sim.is_file():
        e.append(f"simulation script {doc['simulation']} does not exist")

    return [f"{rel}: {msg}" for msg in e]


def load_all() -> tuple[list[tuple[Path, dict]], list[str]]:
    errors: list[str] = []
    docs: list[tuple[Path, dict]] = []
    seen: dict[str, Path] = {}
    files = sorted(DETECTIONS.rglob("*.yaml"))
    if not files:
        errors.append("no detections found")
    for f in files:
        try:
            doc = yaml.safe_load(render(f.read_text()))
        except (yaml.YAMLError, KeyError) as ex:
            errors.append(f"{f.relative_to(ROOT)}: {ex}")
            continue
        errors += validate(f, doc, seen)
        docs.append((f, doc))
    return docs, errors


def catalog(docs: list[tuple[Path, dict]]) -> str:
    lines = [
        "# Detection catalog",
        "",
        "<!-- Generated by scripts/validate_detections.py --catalog. Do not edit by hand. -->",
        "",
        f"{len(docs)} detections. Every rule has a simulation that generates its telemetry.",
        "",
        "| ID | Name | Severity | Tactics | ATT&CK | Data source | Simulation |",
        "|----|------|----------|---------|--------|-------------|------------|",
    ]
    for f, d in sorted(docs, key=lambda x: (x[1]["id"].split("-")[0], x[1]["id"])):
        subs = d.get("sub_techniques", [])
        covered = {st.split(".")[0] for st in subs}
        techs = sorted(subs + [t for t in d["techniques"] if t not in covered])
        attack = ", ".join(
            f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in techs
        )
        tactics = ", ".join(TACTIC_DISPLAY.get(t, t) for t in d["tactics"])
        rule = f"[{d['name']}](../{f.relative_to(ROOT).as_posix()})"
        sim = f"[`{Path(d['simulation']).name}`](../{d['simulation']})"
        lines.append(
            f"| {d['id']} | {rule} | {d['severity']} | {tactics} | {attack} | "
            f"{', '.join(d['requires'])} | {sim} |"
        )

    # ATT&CK coverage summary by tactic
    lines += ["", "## Coverage by tactic", "", "| Tactic | Detections |", "|--------|------------|"]
    by_tactic: dict[str, list[str]] = {}
    for _, d in docs:
        for t in d["tactics"]:
            by_tactic.setdefault(t, []).append(d["id"])
    for t in sorted(by_tactic, key=TACTIC_ORDER.index):
        lines.append(f"| {TACTIC_DISPLAY.get(t, t)} | {', '.join(sorted(by_tactic[t]))} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--catalog", action="store_true", help="write docs/detection-catalog.md")
    g.add_argument("--check-catalog", action="store_true", help="fail if catalog is out of date")
    args = ap.parse_args()

    docs, errors = load_all()
    if errors:
        print("Detection validation FAILED:\n", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"OK: {len(docs)} detections valid")

    rendered = catalog(docs)
    if args.catalog:
        CATALOG.parent.mkdir(parents=True, exist_ok=True)
        CATALOG.write_text(rendered)
        print(f"wrote {CATALOG.relative_to(ROOT)}")
    elif args.check_catalog:
        if not CATALOG.exists() or CATALOG.read_text() != rendered:
            print("docs/detection-catalog.md is stale - run: make catalog", file=sys.stderr)
            return 1
        print("catalog up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
