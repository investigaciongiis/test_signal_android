#!/usr/bin/env python3
"""
AI Security Audit -> Excel (English-only output)

Reads (mandatory paths):
  - /mnt/data/vision360_fingerprint.json
  - /mnt/data/requirements.json

Writes:
  - /mnt/data/security_audit_requirements.xlsx (exactly one sheet named "audit")

Hard requirement:
  - Everything the script GENERATES must be in English (logs, errors, headers, results, justifications).
  - If input requirement descriptions are not English, they are translated to English via OpenAI (JSON-as-text).
  - If translation is required but OpenAI is unavailable, the script FAILS by default (strict English output).

Key constraint:
  - Avoid OpenAI file inputs (PDF-only). Send compact JSON-as-text payloads instead.
"""

from __future__ import annotations

import unicodedata
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import openpyxl

try:
    from openai import OpenAI
except Exception:
    OpenAI = None  # type: ignore

try:
    from pydantic import BaseModel
except Exception:
    BaseModel = None  # type: ignore


FINGERPRINT_PATH = Path("/mnt/data/vision360_fingerprint.json")
REQUISITES_PATH = Path("/mnt/data/requirements.json")
OUTPUT_XLSX_PATH = Path("/mnt/data/security_audit_requirements.xlsx")

NEGATIVE_RISK_TOKENS = [
    "insecure",
    "unsafe",
    "weak",
    "debug",
    "debuggable",
    "cleartext",
    "allow_clear_text",
    "trust_all",
    "accept_all",
    "ignore_ssl",
    "skip_verification",
    "bypass",
    "hardcoded",
    "leak",
    "plaintext",
    "world_readable",
    "world_writable",
    "sha1",
    "md5",
    "debug_certificate",
    "janus",
    "v1_signature",
    "exported_true",
    "backup_enabled_true",
    "http_based",
]

APPLICABILITY_TOKENS = [
    "components",
    "present",
    "detected",
    "uses_",
    "is_used",
    "feature",
    "webview_components",
]

PASSWORD_HASHING_POSITIVE_IDS = {"has_password_hashing_uses_salts", "has_password_hashing_uses_kdf"}

MALWARE_REQ_TOKENS = [
    "malware",
    "adware",
    "virus",
    "trojan",
    "spyware",
    "ransomware",
    "malicious code",
    "malicious",
]
MALWARE_FLAG_TOKENS = ["malware", "adware", "virus", "trojan", "spyware", "ransomware", "malicious"]

OVERRIDE_SCOPE_FLAG_IDS = {
    "has_org_notifies_users_of_security_updates",
    "has_manifest_allow_clear_text_traffic_true",
    "has_uses_os_level_update_mechanisms",
    "has_android_dynamic_code_loading",
    "has_webview_remote_content",
    "has_soap_uses_mutual_tls",
    "has_defined_certificate_management_policy",
    "has_defined_identity_lifecycle_policy",
    "has_webview_components",
    "has_webview_javascript",
    "has_webview_file_scheme",
    "has_insecure_http_based_webview_communication",
    "has_webview_javascript_interface_limited_to_trusted_content",
    "has_soap_api_usage",
    "has_proper_ws_security_headers",
    "has_soap_message_level_encryption",
    "has_soap_message_level_signatures",
    "has_soap_prevents_replay_attacks",
    "has_saml_based_sso",
    "has_soap_validates_saml_token_expiry",
    "has_uses_xml_signatures",
    "has_uses_xml_encryption",
    "has_soap_uses_strict_schema_validation",
    "has_content_provider_actively_exposed",
    "has_manifest_custom_permission_defined",
}

GATE_FLAG_IDS = {
    "has_webview_components",
    "has_webview_remote_content",
    "has_android_dynamic_code_loading",
    "has_soap_api_usage",
    "has_saml_based_sso",
    "has_content_provider_actively_exposed",
    "has_manifest_custom_permission_defined",
    "has_uses_os_level_update_mechanisms",
    "has_org_notifies_users_of_security_updates",
    "has_defined_certificate_management_policy",
    "has_defined_identity_lifecycle_policy",
}


def _json_decode_error_details(e: json.JSONDecodeError) -> str:
    return f"{type(e).__name__}: {e.msg} (line {e.lineno}, col {e.colno})"


def load_json_with_one_repair(path: Path) -> Any:
    """
    Robust loading + ONE deterministic, minimal repair pass.

    Repair pass covers:
    - 'Extra data' JSONDecodeError: keep the first valid JSON chunk (up to error.pos)
    - Leading '{{' (accidental double-opening brace): drop one '{'
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Error parsing {path.name}: {_json_decode_error_details(e)}", file=sys.stderr)

        patched: Optional[str] = None
        if "Extra data" in e.msg:
            patched = raw[: e.pos].rstrip()
        elif raw.lstrip().startswith("{{"):
            s = raw.lstrip()
            idx = raw.find(s)
            patched = raw[:idx] + s[1:]
        else:
            patched = None

        if patched is None:
            raise

        try:
            return json.loads(patched)
        except json.JSONDecodeError as e2:
            print(f"Minimal repair failed for {path.name}: {_json_decode_error_details(e2)}", file=sys.stderr)
            raise


def normalize_requirements(data: Any) -> List[Dict[str, Any]]:
    """
    requirements.json may be:
      - list of requirement objects (preferred), OR
      - object containing a 'requirements' list
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("requirements"), list):
        return data["requirements"]
    raise ValueError("requirements.json must be a JSON array of requirements (or an object with a 'requirements' array).")


def normalize_fingerprint_flags(data: Any) -> List[Dict[str, Any]]:
    """
    fingerprint may be:
      - list of flags, OR
      - object containing 'flags' (array), OR
      - object containing 'results'/'items' (array)
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("flags"), list):
            return data["flags"]
        for k in ("results", "items"):
            if isinstance(data.get(k), list):
                return data[k]
    raise ValueError("vision360_fingerprint.json does not contain a recognizable list of flags.")


def is_prohibitive(req_desc: str) -> bool:
    s = req_desc.lower()
    return ("must not" in s) or ("shall not" in s) or ("should not" in s)


def is_conditional(req_desc: str) -> bool:
    s = req_desc.lower()
    patterns = [r"\bif\b", r"\bwhen\b", r"where applicable", r"on older versions"]
    return any(re.search(p, s) for p in patterns)


def req_mentions_malware(req_desc: str) -> bool:
    s = req_desc.lower()
    return any(t in s for t in MALWARE_REQ_TOKENS)


def classify_flag_for_requirement(flag_id: str, flag_title: str, req_desc: str) -> str:
    """
    Returns one of: POSITIVE_CONTROL, NEGATIVE_RISK, APPLICABILITY
    """
    fid = (flag_id or "").lower()
    title = (flag_title or "").lower()

    # 1) PASSWORD HASHING OVERRIDE
    if flag_id in PASSWORD_HASHING_POSITIVE_IDS:
        return "POSITIVE_CONTROL"

    # 2) MALWARE SPECIAL-CASE
    if req_mentions_malware(req_desc):
        if any(t in fid or t in title for t in MALWARE_FLAG_TOKENS):
            return "NEGATIVE_RISK"

    # 3) NEGATIVE_RISK tokens
    if any(tok in fid or tok in title for tok in NEGATIVE_RISK_TOKENS):
        return "NEGATIVE_RISK"

    # 4) APPLICABILITY tokens
    if any(tok in fid or tok in title for tok in APPLICABILITY_TOKENS):
        return "APPLICABILITY"

    # 5) Default
    return "POSITIVE_CONTROL"


def parse_summary_normalized(summary: Any) -> str:
    """
    Extract value after '=' from app_verdict.summary and normalize to YES/NO/NA.
    """
    if not isinstance(summary, str) or not summary.strip():
        return "NA"
    s = summary.strip()

    if "=" in s:
        v = s.split("=")[-1].strip()
    else:
        v = s

    v_up = v.upper().replace(" ", "")
    if v_up in ("YES", "Y"):
        return "YES"
    if v_up in ("NO", "N"):
        return "NO"
    if v_up in ("NA", "N/A"):
        return "NA"

    m = re.search(r"\b(YES|NO|NA|N/A)\b", s.upper())
    if m:
        tok = m.group(1)
        return "NA" if tok in ("NA", "N/A") else tok
    return "NA"


def eval_against_expected(observed: str, expected: str) -> str:
    """
    expected is 'YES' or 'NO'
    returns SUPPORT / CONTRADICT / UNKNOWN
    """
    if observed == "NA":
        return "UNKNOWN"
    if expected == "YES":
        return "SUPPORT" if observed == "YES" else "CONTRADICT"
    if expected == "NO":
        return "SUPPORT" if observed == "NO" else "CONTRADICT"
    return "UNKNOWN"


@dataclass
class FlagEvidence:
    id: str
    title: str
    state: str
    summary: str
    summary_norm: str
    notes: str
    evidence_count: int
    classification: str
    expected: Optional[str]  # YES/NO, None for APPLICABILITY
    outcome: str  # SUPPORT/CONTRADICT/UNKNOWN/MISSING/NA_OR_GATE


@dataclass
class RequirementAudit:
    puid: str
    description_en: str
    result: str  # yes/no/n/a
    flags_used: List[str]
    justification_en: str


def build_flag_evidence(
    flag_obj: Optional[Dict[str, Any]],
    flag_id: str,
    classification: str,
    expected: Optional[str],
) -> FlagEvidence:
    if not flag_obj:
        return FlagEvidence(
            id=flag_id,
            title="",
            state="missing",
            summary="",
            summary_norm="NA",
            notes="flag not present in fingerprint",
            evidence_count=0,
            classification=classification,
            expected=expected,
            outcome="MISSING",
        )

    app_verdict = flag_obj.get("app_verdict") or {}
    summary = app_verdict.get("summary", "")
    summary_norm = parse_summary_normalized(summary)
    state = str(app_verdict.get("state", "") or "")
    notes = str(app_verdict.get("notes", "") or "")
    evidence_count = int(app_verdict.get("evidence_count", 0) or 0)

    if classification == "APPLICABILITY":
        outcome = "NA_OR_GATE"
    else:
        assert expected in ("YES", "NO")
        outcome = eval_against_expected(summary_norm, expected)

    return FlagEvidence(
        id=str(flag_obj.get("id") or flag_id),
        title=str(flag_obj.get("title") or ""),
        state=state,
        summary=str(summary),
        summary_norm=summary_norm,
        notes=notes,
        evidence_count=evidence_count,
        classification=classification,
        expected=expected,
        outcome=outcome,
    )


def compute_override_scenario_activated(
    flag_evidences: List[FlagEvidence],
    flag_ids: List[str],
) -> Tuple[bool, List[FlagEvidence]]:
    gate_evs = [fe for fe in flag_evidences if fe.id in flag_ids and fe.id in GATE_FLAG_IDS]
    activated = any(fe.summary_norm == "YES" for fe in gate_evs)
    return activated, gate_evs


def compute_conditional_scenario_activated(flag_evidences: List[FlagEvidence]) -> Optional[bool]:
    """
    Returns:
      - TRUE  if at least one APPLICABILITY flag exists and is YES
      - FALSE if at least one APPLICABILITY flag exists and none are YES
      - None  if no APPLICABILITY flags exist in the requirement
    """
    app_flags = [fe for fe in flag_evidences if fe.classification == "APPLICABILITY"]
    if not app_flags:
        return None
    return any(fe.summary_norm == "YES" for fe in app_flags)


def _split_flags_string(flags_str: str) -> List[str]:
    """
    Deterministically split a string of flags into individual IDs.

    Supported delimiters: ';' ',' newlines.
    Also supports JSON-like list strings: '["a","b"]'.
    """
    s = (flags_str or "").strip()
    if not s:
        return []

    # If it looks like a JSON list, attempt to parse deterministically.
    if s.startswith("[") and s.endswith("]"):
        try:
            obj = json.loads(s)
            if isinstance(obj, list):
                return [str(x).strip() for x in obj if str(x).strip()]
        except Exception:
            pass

    parts = re.split(r"[,\n;]+", s)
    out = [p.strip() for p in parts if p.strip()]
    return out


def extract_req_fields(req_obj: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    """
    Reads requirement fields; supports common key variants (including non-English keys) for resilience.
    Output strings are later enforced/translated to English for generated artifacts.
    """
    puid = str(req_obj.get("PUID") or req_obj.get("id") or "").strip()
    desc = str(
        req_obj.get("Requirement description")
        or req_obj.get("Description")
        or req_obj.get("Descripción")
        or ""
    ).strip()

    flags = req_obj.get("Flags", [])
    if isinstance(flags, str):
        flags_list = _split_flags_string(flags)
    elif isinstance(flags, list):
        flags_list = [str(x).strip() for x in flags if str(x).strip()]
    else:
        flags_list = []
    return puid, desc, flags_list


def audit_requirement(
    puid: str,
    desc: str,
    flag_ids: List[str],
    flags_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[str, List[FlagEvidence], Dict[str, Any]]:
    prohibitive = is_prohibitive(desc)
    conditional = is_conditional(desc)

    flag_evs: List[FlagEvidence] = []
    for fid in flag_ids:
        fobj = flags_by_id.get(fid)
        title = str((fobj or {}).get("title") or "")
        classification = classify_flag_for_requirement(fid, title, desc)
        expected: Optional[str] = None
        if classification == "POSITIVE_CONTROL":
            expected = "YES"
        elif classification == "NEGATIVE_RISK":
            expected = "NO"
        fe = build_flag_evidence(fobj, fid, classification, expected)
        flag_evs.append(fe)

    override_used = bool(flag_ids) and set(flag_ids).issubset(OVERRIDE_SCOPE_FLAG_IDS)
    override_scenario_activated: Optional[bool] = None
    gate_flags: List[FlagEvidence] = []
    conditional_scenario_activated: Optional[bool] = None

    has_negative_risk_yes = any(
        (fe.classification == "NEGATIVE_RISK" and fe.summary_norm == "YES")
        for fe in flag_evs
        if fe.outcome != "MISSING"
    )

    # OVERRIDE scope
    if override_used:
        override_scenario_activated, gate_flags = compute_override_scenario_activated(flag_evs, flag_ids)
        if override_scenario_activated is False:
            if prohibitive:
                result = "no" if has_negative_risk_yes else "yes"
            else:
                result = "no" if has_negative_risk_yes else "n/a"
            meta = dict(
                prohibitive=prohibitive,
                conditional=conditional,
                override_used=True,
                override_scenario_activated=override_scenario_activated,
                gate_flags=[ge.id for ge in gate_flags],
                conditional_scenario_activated=None,
            )
            return result, flag_evs, meta

    if conditional:
        conditional_scenario_activated = compute_conditional_scenario_activated(flag_evs)

    non_app = [fe for fe in flag_evs if fe.classification != "APPLICABILITY"]
    any_contradict = any(fe.outcome == "CONTRADICT" for fe in non_app)
    all_support = (len(non_app) > 0) and all(fe.outcome == "SUPPORT" for fe in non_app)
    any_unknown = any(fe.outcome in ("UNKNOWN", "MISSING") for fe in non_app)

    if any_contradict:
        result = "no"
    elif all_support and not any_unknown:
        result = "yes"
    else:
        if conditional and (conditional_scenario_activated is False):
            result = "yes" if prohibitive else "n/a"
        else:
            result = "n/a"

    meta = dict(
        prohibitive=prohibitive,
        conditional=conditional,
        override_used=override_used,
        override_scenario_activated=override_scenario_activated,
        gate_flags=[ge.id for ge in gate_flags],
        conditional_scenario_activated=conditional_scenario_activated,
    )
    return result, flag_evs, meta


def openai_client() -> Optional[Any]:
    api_key = os.getenv("LLM_API_KEY", "").strip()
    if not api_key or OpenAI is None:
        return None
    #return OpenAI(api_key=api_key)
    return OpenAI(api_key=api_key, base_url=os.getenv("LLM_BASE_URL"));


def env_int(name: str, default: int) -> int:
    v = os.getenv(name, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name, "").strip().lower()
    if not v:
        return default
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    return default


def _normalize_typography(s: str) -> str:
    # Normalize common "smart" punctuation to ASCII equivalents.
    repl = {
        "\u2018": "'",  # ‘
        "\u2019": "'",  # ’
        "\u201C": '"',  # “
        "\u201D": '"',  # ”
        "\u2013": "-",  # –
        "\u2014": "-",  # —
        "\u00A0": " ",  # non-breaking space
    }
    return "".join(repl.get(ch, ch) for ch in s)


def looks_non_english(text: str) -> bool:
    """
    Conservative heuristic:
    - DO NOT treat non-ASCII punctuation as non-English.
    - Treat non-ASCII LETTERS/MARKS (e.g., á, ñ) as likely non-English.
    - Also check a small list of Spanish marker words.
    """
    if not text or not text.strip():
        return False

    s = _normalize_typography(text.strip())

    # Non-ASCII letters/marks are strong signals; punctuation/symbols are not.
    for ch in s:
        if ord(ch) <= 127:
            continue
        cat = unicodedata.category(ch)
        if cat.startswith("L") or cat.startswith("M"):
            return True

    spanish_markers = [
        " el ", " la ", " los ", " las ", " de ", " del ", " para ", " y ", " o ",
        " debe ", " deberán ", " cuando ", " donde ", " aplicación ",
        " seguridad ", " requisito ", " descripción ", " evidencias ",
    ]
    s_low = f" {s.lower()} "
    return any(m in s_low for m in spanish_markers)


def translate_texts_to_english_via_openai(items: List[Dict[str, str]]) -> Dict[str, str]:
    """
    items: [{"id": "...", "text": "..."}, ...]
    returns: {id: translated_text_en}

    Always JSON-as-text. No file uploads.
    """
    client = openai_client()
    if client is None or BaseModel is None:
        return {}

    model = os.getenv("LLM_MODEL")
    effort = os.getenv("LLM_REASONING_EFFORT", "medium").strip() or "medium"
    max_tokens = env_int("LLM_MAX_OUTPUT_TOKENS", 2000)

    supports_parse = hasattr(client.responses, "parse")

    class TranslationItem(BaseModel):  # type: ignore
        id: str
        text_en: str

    class TranslationBatch(BaseModel):  # type: ignore
        items: List[TranslationItem]

    system = (
        "You translate short requirement descriptions to English.\n"
        "Strict rules:\n"
        "- Output English only.\n"
        "- Preserve meaning. Do not add new requirements.\n"
        "- Keep the translation concise and professional.\n"
        "- Return ONLY JSON in the form: {\"items\": [{\"id\": \"...\", \"text_en\": \"...\"}, ...]}.\n"
    )

    user_payload = {"items": items}

    last_err: Optional[Exception] = None
    for attempt in range(1, 4):
        try:
            if supports_parse:
                resp = client.responses.parse(
                    model=model,
                    input=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
                    ],
                    text_format=TranslationBatch,
                    max_output_tokens=max_tokens,
                    reasoning={"effort": effort},
                )
                parsed = resp.output_parsed  # type: ignore[attr-defined]
                return {it.id: it.text_en.strip() for it in parsed.items}

            resp = client.responses.create(
                model=model,
                input=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
                ],
                max_output_tokens=max_tokens,
                reasoning={"effort": effort},
            )
            txt = (getattr(resp, "output_text", "") or "").strip()
            m = re.search(r"\{.*\}\s*$", txt, flags=re.DOTALL)
            if not m:
                raise ValueError("No valid JSON object found in model response.")
            obj = json.loads(m.group(0))
            out: Dict[str, str] = {}
            for it in obj.get("items", []):
                if isinstance(it, dict) and "id" in it and "text_en" in it:
                    out[str(it["id"])] = str(it.get("text_en") or "").strip()
            return out

        except Exception as e:
            last_err = e
            time.sleep(0.6 * attempt)

    print(f"[WARN] OpenAI translation failed after retries: {last_err}", file=sys.stderr)
    return {}


def generate_justifications_via_openai(batch_ctx: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Returns mapping: puid -> justification (English, 2–5 sentences).
    Avoids any file uploads; sends compact JSON-as-text.
    """
    client = openai_client()
    if client is None or BaseModel is None:
        return {}

    model = os.getenv("LLM_MODEL")
    effort = os.getenv("LLM_REASONING_EFFORT", "medium").strip() or "medium"
    max_tokens = env_int("LLM_MAX_OUTPUT_TOKENS", 2000)

    supports_parse = hasattr(client.responses, "parse")

    class JustificationItem(BaseModel):  # type: ignore
        id: str
        justification: str

    class JustificationBatch(BaseModel):  # type: ignore
        items: List[JustificationItem]

    system = (
        "You draft audit justifications in English for security requirement outcomes.\n"
        "Strict rules:\n"
        "- Output English only.\n"
        "- If any provided notes contain non-English text, paraphrase them into English and do not quote them verbatim.\n"
        "- Do not invent evidence or flags.\n"
        "- Use only the provided context.\n"
        "- Keep 1 to 3 sentences per requirement.\n"
        "- Explicitly mention: app_verdict.state, normalized app_verdict.summary (YES/NO/NA), notes "
        "(include 'Fallback verdict' if present), and evidence_count.\n"
        "- If a flag is not present in the fingerprint, state: 'flag not present in fingerprint'.\n"
        "- Do not change the precomputed result.\n"
        "- Return ONLY JSON in the form: {\"items\": [{\"id\": \"...\", \"justification\": \"...\"}, ...]}.\n"
    )


    user_payload = {"batch": batch_ctx}

    last_err: Optional[Exception] = None
    for attempt in range(1, 4):
        try:
            if supports_parse:
                resp = client.responses.parse(
                    model=model,
                    input=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
                    ],
                    text_format=JustificationBatch,
                    max_output_tokens=max_tokens,
                    reasoning={"effort": effort},
                )
                parsed = getattr(resp, "output_parsed", None)
                if parsed is not None:
                    return {it.id: it.justification.strip() for it in parsed.items}

            resp = client.responses.create(
                model=model,
                input=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
                ],
                max_output_tokens=max_tokens,
                reasoning={"effort": effort},
            )
            txt = (getattr(resp, "output_text", "") or "").strip()
            m = re.search(r"\{.*\}\s*$", txt, flags=re.DOTALL)
            if not m:
                raise ValueError("No valid JSON object found in model response.")
            obj = json.loads(m.group(0))
            out: Dict[str, str] = {}
            for it in obj.get("items", []):
                if isinstance(it, dict) and "id" in it and "justification" in it:
                    out[str(it["id"])] = str(it.get("justification") or "").strip()
            return out

        except Exception as e:
            last_err = e
            time.sleep(0.6 * attempt)

    print(f"[WARN] OpenAI justification generation failed after retries: {last_err}", file=sys.stderr)
    return {}


def deterministic_justification(req: RequirementAudit, flag_evidences: List[FlagEvidence], meta: Dict[str, Any]) -> str:
    """
    Deterministic richer English justification (3–6 sentences).
    Uses only fingerprint-derived fields; does not invent evidence or locations.
    """

    def _note_hint(fe: FlagEvidence) -> str:
        return " (Fallback verdict)" if "fallback verdict" in (fe.notes or "").lower() else ""

    def _brief(fe: FlagEvidence) -> str:
        # Compact but information-dense; stays English-only.
        exp = f", expected={fe.expected}" if fe.expected in ("YES", "NO") else ""
        return (
            f"{fe.id}={fe.summary_norm} "
            f"(state={fe.state}, evidence_count={fe.evidence_count}{_note_hint(fe)}{exp})"
        )

    result = req.result  # yes/no/n/a
    present = [fe for fe in flag_evidences if fe.outcome != "MISSING"]
    missing = [fe for fe in flag_evidences if fe.outcome == "MISSING"]

    contradicts = [fe for fe in present if fe.outcome == "CONTRADICT"]
    supports = [fe for fe in present if fe.outcome == "SUPPORT"]
    unknowns = [fe for fe in present if fe.outcome == "UNKNOWN"]

    # Sentence 1: mandatory anchor
    s1 = f"Result: {result} for requirement {req.puid}."

    # Sentence 2: outcome rationale headline
    if result == "yes":
        s2 = (
            "Based on the fingerprint and the flags mapped to this requirement, the application is compliant "
            "because the evaluated signals support the expected secure posture and no contradicting signals "
            "were observed among the mapped flags."
        )
    elif result == "no":
        s2 = (
            "Based on the fingerprint and the flags mapped to this requirement, the application is not compliant "
            "because at least one mapped signal contradicts the expected outcome."
        )
    else:
        # n/a
        s2 = (
            "Based on the fingerprint and the flags mapped to this requirement, the result is n/a because the available "
            "signals are insufficient, not applicable under the detected scenario, or contain unknown/NA coverage for the mapped flags."
        )

    # Sentence 3: key signals (prioritize contradictions for 'no', supports for 'yes')
    if result == "no" and contradicts:
        top = contradicts[:3]
        details = "; ".join(_brief(fe) for fe in top)
        s3 = f"Contradicting signals: {details}."
    elif supports:
        top = supports[:3]
        details = "; ".join(_brief(fe) for fe in top)
        s3 = f"Key supporting signals: {details}."
    else:
        # If we have no supports, still report what exists without inventing.
        any_present = present[:3]
        details = "; ".join(_brief(fe) for fe in any_present) if any_present else "none"
        s3 = f"Observed mapped signals: {details}."

    # Sentence 4: transparency about gaps/coverage
    gaps = []
    if missing:
        gaps.append(f"{len(missing)} flag(s) were not present in the fingerprint (flag not present in fingerprint).")
    if unknowns:
        gaps.append("Some mapped flag summaries were NA/unknown, limiting certainty to fingerprint coverage.")
    if not gaps:
        gaps.append("This justification is derived solely from the fingerprint summaries, states, notes, and evidence counts for the mapped flags.")
    s4 = " ".join(gaps)

    sentences = [s1, s2, s3, s4]

    # Optional: mention feature-gating / override mechanics when used
    if meta.get("override_used") and meta.get("override_scenario_activated") is not None:
        sentences.append(
            "Feature-gating (override scope) was applied; "
            f"scenario_activated={'TRUE' if meta.get('override_scenario_activated') else 'FALSE'} "
            "based on the gate flags included in the requirement flag list."
        )

    # Optional: mention conditional scenario evaluation when present
    if meta.get("conditional") and meta.get("conditional_scenario_activated") is not None:
        sentences.append(
            "Conditional applicability was evaluated using the mapped applicability signals; "
            f"scenario_activated={'TRUE' if meta.get('conditional_scenario_activated') else 'FALSE'}."
        )

    # Keep it within 3–6 sentences
    sentences = [s.strip() for s in sentences if s and s.strip()]
    if len(sentences) > 6:
        sentences = sentences[:6]
    return " ".join(sentences)



def main() -> None:
    strict_english = env_bool("STRICT_ENGLISH_OUTPUT", True)

    if not FINGERPRINT_PATH.exists():
        raise SystemExit(f"Missing required file: {FINGERPRINT_PATH}.")
    if not REQUISITES_PATH.exists():
        raise SystemExit(f"Missing required file: {REQUISITES_PATH}.")

    fingerprint_data = load_json_with_one_repair(FINGERPRINT_PATH)
    requisites_data = load_json_with_one_repair(REQUISITES_PATH)

    requirements = normalize_requirements(requisites_data)
    flags_list = normalize_fingerprint_flags(fingerprint_data)

    flags_by_id: Dict[str, Dict[str, Any]] = {}
    for f in flags_list:
        if isinstance(f, dict) and f.get("id"):
            flags_by_id[str(f["id"])] = f

    # Pre-scan requirement descriptions and translate to English if needed
    raw_desc_by_puid: Dict[str, str] = {}
    to_translate: List[Dict[str, str]] = []

    for req_obj in requirements:
        if not isinstance(req_obj, dict):
            continue
        puid, desc, _ = extract_req_fields(req_obj)
        if not puid:
            continue
        if not desc:
            desc = "(missing description)"
        raw_desc_by_puid[puid] = desc
        if looks_non_english(desc):
            to_translate.append({"id": puid, "text": desc})

    translations: Dict[str, str] = {}
    if to_translate:
        client = openai_client()
        if client is None:
            if strict_english:
                raise SystemExit(
                    "STRICT_ENGLISH_OUTPUT is enabled, but non-English requirement descriptions were detected and "
                    "LLM_API_KEY is not set. Provide an English requirements.json OR set LLM_API_KEY to enable translation."
                )
            print("[WARN] Non-English descriptions detected; translation skipped because OpenAI is unavailable.", file=sys.stderr)
        else:
            print(f"[AI] Translating {len(to_translate)} requirement description(s) to English...")
            translations = translate_texts_to_english_via_openai(to_translate)
            missing = [it["id"] for it in to_translate if it["id"] not in translations or not translations[it["id"]].strip()]
            if missing and strict_english:
                raise SystemExit(
                    "STRICT_ENGLISH_OUTPUT is enabled, but translation failed for one or more items: "
                    + ", ".join(missing)
                )
            if missing:
                print(f"[WARN] Translation missing for {len(missing)} item(s); originals may remain.", file=sys.stderr)

    desc_en_by_puid: Dict[str, str] = {}
    for puid, desc in raw_desc_by_puid.items():
        desc_en = translations.get(puid, "").strip() or desc
        if strict_english and looks_non_english(desc_en):
            raise SystemExit(
                f"STRICT_ENGLISH_OUTPUT is enabled, but the final description for PUID={puid} is not English. "
                "Provide an English requirements.json or ensure translation succeeds."
            )
        desc_en_by_puid[puid] = desc_en

    batch_size = env_int("LLM_BATCH_SIZE", 25)
    batch_size = 25 if batch_size <= 0 else batch_size

    audits: List[RequirementAudit] = []
    counts = {"yes": 0, "no": 0, "n/a": 0}

    total = len(requirements)
    n_batches = (total + batch_size - 1) // batch_size if total else 0

    for b in range(n_batches):
        start = b * batch_size
        end = min(total, start + batch_size)
        req_slice = requirements[start:end]
        print(f"[AI] Batch {b + 1}/{n_batches}: {len(req_slice)} requirements")

        batch_ctx: List[Dict[str, Any]] = []
        batch_results: List[Tuple[RequirementAudit, List[FlagEvidence], Dict[str, Any]]] = []

        for req_obj in req_slice:
            if not isinstance(req_obj, dict):
                continue
            puid, _desc_raw, flag_ids = extract_req_fields(req_obj)
            if not puid:
                continue

            desc_en = desc_en_by_puid.get(puid, "(missing description)")

            result, flag_evs, meta = audit_requirement(puid, desc_en, flag_ids, flags_by_id)

            req_audit = RequirementAudit(
                puid=puid,
                description_en=desc_en,
                result=result,
                flags_used=flag_ids,
                justification_en="",
            )
            batch_results.append((req_audit, flag_evs, meta))

            flags_ctx = []
            for fe in flag_evs:
                note_hint = "Fallback verdict" if "fallback verdict" in (fe.notes or "").lower() else ""
                # 1) Sanitize/truncate notes before sending them to the LLM
                notes_raw = fe.notes or ""
                notes_trim = notes_raw[:800]  # ajusta si quieres (400–1200 es razonable)

                # 2) If STRICT_ENGLISH_OUTPUT is enabled and notes are not in English, do not send them as-is
                if strict_english and looks_non_english(notes_trim):
                    notes_trim = "Non-English notes detected in fingerprint. Do not quote verbatim; provide an English paraphrase."

                flags_ctx.append(
                    {
                        "id": fe.id,
                        "classification": fe.classification,
                        "expected": fe.expected,
                        "observed_summary_norm": fe.summary_norm,
                        "app_verdict": {
                            "state": fe.state,
                            "summary": fe.summary,
                            "notes": notes_trim,
                            "evidence_count": fe.evidence_count,
                            "note_hint": note_hint,
                        },
                        "outcome": fe.outcome,
                    }
                )

            batch_ctx.append(
                {
                    "id": puid,
                    "description_en": desc_en,
                    "result": result,
                    "flags_used": flag_ids,
                    "meta": meta,
                    "flags": flags_ctx,
                }
            )

        use_openai_just = env_bool("USE_OPENAI_JUSTIFICATIONS", False)
        just_map = generate_justifications_via_openai(batch_ctx) if use_openai_just else {}

        for req_audit, flag_evs, meta in batch_results:
            just = (just_map.get(req_audit.puid, "") or "").strip()
            if not just:
                just = deterministic_justification(req_audit, flag_evs, meta)

            if strict_english and looks_non_english(just):
                # safe fallback: enforce a deterministic justification in English
                just = deterministic_justification(req_audit, flag_evs, meta)
                
                if strict_english and looks_non_english(just):
                    raise SystemExit(
                        f"STRICT_ENGLISH_OUTPUT is enabled, but the generated justification for PUID={req_audit.puid} is not English."
                    )

            req_audit.justification_en = just
            audits.append(req_audit)
            counts[req_audit.result] += 1

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "audit"

    headers = ["id (PUID)", "Description (EN)", "Result", "Justification (EN)", "Flags used"]
    ws.append(headers)

    for a in audits:
        ws.append([a.puid, a.description_en, a.result, a.justification_en, ", ".join(a.flags_used)])

    OUTPUT_XLSX_PATH.parent.mkdir(parents=True, exist_ok=True)
    wb.save(OUTPUT_XLSX_PATH)

    print(f"[OK] Excel generated: {OUTPUT_XLSX_PATH}")
    print(f"[SUMMARY] total={len(audits)} yes={counts['yes']} no={counts['no']} n/a={counts['n/a']}")


if __name__ == "__main__":
    try:
        main()
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {_json_decode_error_details(e)}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
