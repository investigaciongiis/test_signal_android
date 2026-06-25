#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CI helper - prepare VISION360 inputs in /mnt/data (deterministic, local-only)

Goal:
- Downloaded GitHub Actions artifacts can come in varied names/structures.
- This helper normalizes inputs to the exact 5 ZIPs expected by vision360_generator.py:

  /mnt/data/mobsf-report.zip           -> mobsf_results.json
  /mnt/data/mobsf-dynamic-report.zip   -> mobsf_dynamic_results.json
  /mnt/data/app.zip                -> source code zip
  /mnt/data/sast-findings.zip          -> merged.sarif, semgrep.sarif
  /mnt/data/trivy-payload.zip          -> trivy.json, agent_payload.json

It supports either:
- already-zipped artifacts containing the expected member names, OR
- raw JSON/SARIF files that it will wrap into the expected ZIPs.

Exit codes:
- 0 success
- 2 missing required inputs
"""

import argparse
import os
import shutil
import sys
import zipfile
from typing import Dict, List, Optional, Tuple


REQUIRED = {
    "mobsf-report.zip": {
        "members_any": ["mobsf_results.json"],
        "members_all": ["mobsf_results.json"],
        "raw_fallback": ["mobsf_results.json"],
    },
    "mobsf-dynamic-report.zip": {
        "members_any": ["mobsf_dynamic_results.json"],
        "members_all": ["mobsf_dynamic_results.json"],
        "raw_fallback": ["mobsf_dynamic_results.json"],
    },
    "app.zip": {
        "members_any": [],  # source zip can be arbitrary; filename is the key
        "members_all": [],
        "raw_fallback": [],
    },
    "sast-findings.zip": {
        "members_any": ["merged.sarif", "semgrep.sarif"],
        "members_all": ["merged.sarif", "semgrep.sarif"],
        "raw_fallback": ["merged.sarif", "semgrep.sarif"],
    },
    "trivy-payload.zip": {
        "members_any": ["trivy.json", "agent_payload.json"],
        "members_all": ["trivy.json", "agent_payload.json"],
        "raw_fallback": ["trivy.json", "agent_payload.json"],
    },
}


def walk_files(root: str) -> List[str]:
    out = []
    for base, _, files in os.walk(root):
        for fn in files:
            out.append(os.path.join(base, fn))
    return out


def is_zip(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    if not path.lower().endswith(".zip"):
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            zf.testzip()  # validates CRCs
        return True
    except Exception:
        return False


def zip_has_members(zip_path: str, members_all: List[str]) -> bool:
    if not is_zip(zip_path):
        return False
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = set(zf.namelist())
        return all(m in names for m in members_all)
    except Exception:
        return False


def find_best_zip_candidate(files: List[str], expected_name: str, members_all: List[str]) -> Optional[str]:
    # 1) Exact filename match (case-insensitive), anywhere
    exp_low = expected_name.lower()
    exact = [p for p in files if os.path.basename(p).lower() == exp_low and is_zip(p)]
    for p in exact:
        if not members_all or zip_has_members(p, members_all):
            return p

    # 2) Any ZIP containing required members
    if members_all:
        zips = [p for p in files if is_zip(p)]
        for p in zips:
            if zip_has_members(p, members_all):
                return p

    return None


def find_raw_members(files: List[str], raw_names: List[str]) -> Dict[str, str]:
    # Returns mapping member_name -> path on disk
    found: Dict[str, str] = {}
    want = {n.lower(): n for n in raw_names}
    for p in files:
        bn = os.path.basename(p).lower()
        if bn in want and bn not in found:
            found[want[bn]] = p
    return found


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def copy_to(src: str, dst: str) -> None:
    ensure_dir(os.path.dirname(dst))
    shutil.copy2(src, dst)


def build_zip_from_raw(raw_map: Dict[str, str], dst_zip: str) -> None:
    ensure_dir(os.path.dirname(dst_zip))
    with zipfile.ZipFile(dst_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member_name, src_path in raw_map.items():
            zf.write(src_path, arcname=member_name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts-dir", required=True, help="Directory where actions/download-artifact stored files.")
    ap.add_argument("--out-dir", default="/mnt/data", help="Output directory (default: /mnt/data).")
    args = ap.parse_args()

    artifacts_dir = os.path.abspath(args.artifacts_dir)
    out_dir = os.path.abspath(args.out_dir)

    if not os.path.isdir(artifacts_dir):
        print(f"[ERR] artifacts-dir not found: {artifacts_dir}", file=sys.stderr)
        return 2

    ensure_dir(out_dir)
    files = walk_files(artifacts_dir)

    plan: List[Tuple[str, str]] = []  # (expected_zip_name, method_desc)
    missing: List[str] = []

    for expected_zip, spec in REQUIRED.items():
        dst = os.path.join(out_dir, expected_zip)

        # Special: app.zip should be found by filename first; if not found, try any zip named similarly.
        if expected_zip == "app.zip":
            cand = None
            # exact basename match first:
            for p in files:
                if os.path.basename(p).lower() in {"app.zip", "app-zip.zip", "app_source.zip"} and is_zip(p):
                    cand = p
                    break
            # otherwise any file named app.zip anywhere
            if cand is None:
                cand = find_best_zip_candidate(files, "app.zip", [])
            if cand is None:
                missing.append(expected_zip)
                continue
            copy_to(cand, dst)
            plan.append((expected_zip, f"copied zip from {os.path.relpath(cand, artifacts_dir)}"))
            continue

        # 1) prefer: a ZIP that already matches expected name or contains required members
        cand_zip = find_best_zip_candidate(files, expected_zip, spec.get("members_all", []))
        if cand_zip:
            copy_to(cand_zip, dst)
            plan.append((expected_zip, f"copied zip from {os.path.relpath(cand_zip, artifacts_dir)}"))
            continue

        # 2) fallback: raw files exist; wrap into expected zip
        raw_needed = spec.get("raw_fallback", [])
        raw_map = find_raw_members(files, raw_needed)
        if raw_needed and all(k in raw_map for k in raw_needed):
            build_zip_from_raw(raw_map, dst)
            srcs = ", ".join(os.path.relpath(raw_map[k], artifacts_dir) for k in raw_needed)
            plan.append((expected_zip, f"built zip from raw files: {srcs}"))
            continue

        missing.append(expected_zip)

    if missing:
        print("[ERR] Missing required VISION360 inputs after artifact download:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        print("\n[HINT] Ensure upstream jobs upload artifacts containing these members:", file=sys.stderr)
        print("  - mobsf_results.json (static) and mobsf_dynamic_results.json (dynamic) as zips or raw json", file=sys.stderr)
        print("  - merged.sarif and semgrep.sarif (SAST) as zip or raw files", file=sys.stderr)
        print("  - trivy.json and agent_payload.json as zip or raw files", file=sys.stderr)
        print("  - app.zip from package_source_zip job", file=sys.stderr)
        return 2

    print("[OK] Prepared VISION360 inputs in:", out_dir)
    for name, how in plan:
        print(f"  - {name}: {how}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
