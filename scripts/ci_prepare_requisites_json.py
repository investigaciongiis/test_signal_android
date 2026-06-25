#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def _second_non_ws_chars(s: str):
    i = 0
    while i < len(s) and s[i].isspace():
        i += 1
    if i >= len(s):
        return None, None
    a = s[i]
    i += 1
    while i < len(s) and s[i].isspace():
        i += 1
    b = s[i] if i < len(s) else None
    return a, b


def _try_load_json(text: str):
    return json.loads(text)


def _one_minimal_repair_pass(text: str):
    """
    Deterministic minimal repair for known structural issues:
    - Case A: accidental outer "{ { ... } ... }" wrapper -> remove the extra outer braces
    - Case B: early closed object followed by more fields (Extra data) after outer brace removal
             and first object looks like metadata -> wrap it under "metadata"
    """
    s = text.lstrip()
    a, b = _second_non_ws_chars(s)
    if a == "{" and b == "{":
        # Remove ONE leading "{" and ONE trailing "}" (outer wrapper)
        inner = s[1:].rstrip()
        if inner.endswith("}"):
            inner = inner[:-1]
        inner = inner.strip()

        # First attempt: parse directly
        try:
            return _try_load_json(inner)
        except json.JSONDecodeError as e:
            # If it looks like: <metadata_object> , "requirements_count": ... , "requirements": [...]
            # then wrap the first object under "metadata" and close the object.
            try:
                dec = json.JSONDecoder()
                first_obj, idx = dec.raw_decode(inner)
                rest = inner[idx:].lstrip()
                if isinstance(first_obj, dict) and rest.startswith(","):
                    repaired = '{"metadata": ' + inner[:idx] + inner[idx:] + "}"
                    return _try_load_json(repaired)
            except Exception:
                pass
            raise e

    # If it doesn't match our known repair shape, return None to indicate no repair applied
    return None


def _extract_requirements_array(data):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("requirements", "requisites", "items", "data"):
            if key in data and isinstance(data[key], list):
                return data[key]
        raise ValueError(
            "Top-level JSON is an object but does not contain a list under any known key "
            "(requirements, requisites, items, data)."
        )

    raise ValueError(f"Top-level JSON must be an array or object, got {type(data).__name__}.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    args = ap.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)

    raw = in_path.read_text(encoding="utf-8")

    # 1) Parse
    try:
        data = _try_load_json(raw)
    except json.JSONDecodeError as e1:
        # 2) One deterministic repair pass
        try:
            repaired = _one_minimal_repair_pass(raw)
        except json.JSONDecodeError as e2:
            print(
                f"Error parseando requirements.json: {type(e2).__name__}: {e2.msg} (línea {e2.lineno}, col {e2.colno})",
                file=sys.stderr,
            )
            sys.exit(1)

        if repaired is None:
            print(
                f"Error parseando requirements.json: {type(e1).__name__}: {e1.msg} (línea {e1.lineno}, col {e1.colno})",
                file=sys.stderr,
            )
            sys.exit(1)
        data = repaired

    # 3) Normalize to array
    reqs = _extract_requirements_array(data)

    if not isinstance(reqs, list) or len(reqs) == 0:
        print("requirements.json debe ser un array JSON de requisitos no vacío.", file=sys.stderr)
        sys.exit(1)

    # Minimal schema sanity checks (fast-fail)
    sample = reqs[:20]
    for i, r in enumerate(sample):
        if not isinstance(r, dict):
            print(f"Requisito en índice {i} no es un objeto JSON.", file=sys.stderr)
            sys.exit(1)
        if "PUID" not in r:
            print(f"Requisito en índice {i} no tiene campo 'PUID'.", file=sys.stderr)
            sys.exit(1)
        if "Requirement description" not in r:
            print(f"Requisito en índice {i} no tiene campo 'Requirement description'.", file=sys.stderr)
            sys.exit(1)
        if "Flags" not in r or not isinstance(r["Flags"], list):
            print(f"Requisito en índice {i} no tiene campo 'Flags' como lista.", file=sys.stderr)
            sys.exit(1)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(reqs, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"OK: wrote {len(reqs)} requirements as a JSON array to {out_path}")


if __name__ == "__main__":
    main()
