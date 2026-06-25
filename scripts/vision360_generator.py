# -*- coding: utf-8 -*-
"""
VISION360 — generator (deterministic, local-only)
Date: 2025-12-18
Mode: LOCAL-ONLY / DETERMINISTIC

Inputs (exactly 5 ZIPs in /mnt/data):
- mobsf-report.zip              -> mobsf_results.json
- mobsf-dynamic-report.zip      -> mobsf_dynamic_results.json
- app.zip                   -> source code
- sast-findings.zip             -> merged.sarif, semgrep.sarif
- trivy-payload.zip             -> trivy.json, agent_payload.json

Outputs:
- /mnt/data/vision360_fingerprint.json
- /mnt/data/vision360_output.json

Key fixes included:
1) Robust MobSF manifest_findings parsing (dict or list) so rules like app_allowbackup/app_is_debuggable are detected.
2) Evidence list per flag (non-breaking addition): app_verdict.evidence + evidence_count = len(evidence).
3) Notes style: permissions are listed WITHOUT parentheses.
4) has_os_time_source populated from SOURCE_CODE_APP evidence (prioritizes VisitRepository.java / System.currentTimeMillis()).
5) CRITICAL: Correct primary AndroidManifest.xml selection using deterministic content scoring (prefers manifest with <application>, services, activities, app-client).
6) NEW: has_manifest_services_explicit_accessibility_attributes
   Operational meaning: every <service ...> in PRIMARY AndroidManifest.xml declares android:exported explicitly.
7) REFINED:
   - has_password_hashing_uses_salts: detects BCrypt.gensalt / explicit salt usage
   - has_password_hashing_uses_kdf: detects BCrypt.hashpw, PBKDF2, scrypt, Argon2 patterns
"""

import json, zipfile, re, os, hashlib, base64, zlib
from datetime import datetime
from typing import Any, Dict, List

# ============================================================
# Helpers: load from ZIP
# ============================================================

def load_json_from_zip(zip_path, member_name):
    encodings = ["utf-8", "cp1252", "latin-1"]
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            try:
                raw = zf.read(member_name)
            except KeyError:
                return None
    except Exception:
        return None

    last_exc = None
    for enc in encodings:
        try:
            text = raw.decode(enc)
            return json.loads(text)
        except Exception as e:
            last_exc = e
    if last_exc:
        raise last_exc


def load_text_from_zip_member(zip_path, member_name, encodings=("utf-8", "cp1252", "latin-1")):
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            raw = zf.read(member_name)
    except Exception:
        return None
    last_exc = None
    for enc in encodings:
        try:
            return raw.decode(enc)
        except Exception as e:
            last_exc = e
    if last_exc:
        raise last_exc
    return None


def read_all_text_files_from_zip(zip_path):
    texts = {}
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                lower = name.lower()
                if lower.endswith((".java", ".kt", ".gradle", ".xml", ".yml", ".yaml", ".md", ".txt", ".pro")):
                    content = load_text_from_zip_member(zip_path, name)
                    if content is not None:
                        texts[name] = content
    except Exception:
        return {}
    return texts


def flatten_to_text(obj, max_len=500000):
    """Convert a (possibly large) JSON-ish object to lowercase text for keyword search."""
    try:
        s = json.dumps(obj, ensure_ascii=False)
    except Exception:
        s = str(obj)
    s = s.lower()
    if len(s) > max_len:
        s = s[:max_len]
    return s

# ============================================================
# Evidence helpers
# ============================================================

def ev(source, path, rule_id, excerpt):
    ex = excerpt if excerpt is not None else ""
    ex = str(ex)
    if len(ex) > 200:
        ex = ex[:200] + "..."
    return {
        "source": source,
        "path": path,
        "rule_id": rule_id,
        "excerpt": ex
    }

def _extract_line_excerpt(txt, idx):
    if not txt or idx is None:
        return ""
    start = txt.rfind("\n", 0, idx)
    end = txt.find("\n", idx)
    start = 0 if start == -1 else start + 1
    end = len(txt) if end == -1 else end
    return txt[start:end].strip()

def evidence_id(*parts: str) -> str:
    """Deterministic short identifier for evidence items."""
    s = "||".join(str(p) for p in parts if p is not None)
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:16]


# ============================================================
# Load the 5 inputs
# ============================================================

mobsf_static = load_json_from_zip("/mnt/data/mobsf-report.zip", "mobsf_results.json") or {}
mobsf_dynamic = load_json_from_zip("/mnt/data/mobsf-dynamic-report.zip", "mobsf_dynamic_results.json") or {}
sast_merged = load_json_from_zip("/mnt/data/sast-findings.zip", "merged.sarif") or {}
sast_semgrep = load_json_from_zip("/mnt/data/sast-findings.zip", "semgrep.sarif") or {}
trivy = load_json_from_zip("/mnt/data/trivy-payload.zip", "trivy.json") or {}
agent_payload = load_json_from_zip("/mnt/data/trivy-payload.zip", "agent_payload.json") or {}

app_zip_path = "/mnt/data/app.zip"
app_texts = read_all_text_files_from_zip(app_zip_path)

combined_code = "\n".join(app_texts.values())
code_lower = combined_code.lower()

readme_text = ""
for path, content in app_texts.items():
    if path.lower().endswith("readme.md"):
        readme_text = content
        break
readme_lower = readme_text.lower()

# ============================================================
# Manifest selection (CRITICAL FIX)
# ============================================================

def find_source_manifests(app_texts_obj):
    candidates = []
    for path in app_texts_obj:
        if path.lower().endswith("androidmanifest.xml"):
            candidates.append(path)
    return candidates


def sort_manifests_by_content(manifest_paths, app_texts_obj):
    """
    Deterministic primary manifest selection by content:
      +1000 if contains <application
      +50 per <service
      +20 per <activity
      +200 if path contains app-client
      +150 if path contains /app/
    Tie-break:
      1) higher score
      2) shorter normalized path
      3) lexicographic normalized path
    """
    scored = []
    for p in (manifest_paths or []):
        txt = (app_texts_obj or {}).get(p) or ""
        low = txt.lower()
        score = 0
        if "<application" in low:
            score += 1000
        score += 50 * low.count("<service")
        score += 20 * low.count("<activity")
        norm = p.replace("\\", "/").lower()
        if "app-client" in norm:
            score += 200
        if "/app/" in norm:
            score += 150
        scored.append((-score, len(norm), norm, p))
    scored.sort()
    return [p for _, _, _, p in scored]


source_manifest_paths = sort_manifests_by_content(find_source_manifests(app_texts), app_texts)
source_manifest_text = app_texts.get(source_manifest_paths[0]) if source_manifest_paths else None
source_manifest_lower = source_manifest_text.lower() if source_manifest_text else ""

# ============================================================
# ORG text index (README + MD + code)
# ============================================================

md_texts_lower = []
for path, content in app_texts.items():
    if path.lower().endswith(".md"):
        md_texts_lower.append(content.lower())
md_texts_joined = "\n".join(md_texts_lower)

org_text_index = {
    "readme_and_md": md_texts_joined,
    "app_code": code_lower,
}

# ============================================================
# MobSF indices and features
# ============================================================

ms = mobsf_static or {}
manifest_analysis = ms.get("manifest_analysis") or {}
code_analysis = ms.get("code_analysis") or {}
mobsf_findings = code_analysis.get("findings") or {}
if not isinstance(mobsf_findings, dict):
    mobsf_findings = {}

mobsf_permissions_table = ms.get("permissions") or {}
if not isinstance(mobsf_permissions_table, dict):
    mobsf_permissions_table = {}

uses_perm_list = (manifest_analysis.get("uses_permission_list") or [])
if not isinstance(uses_perm_list, list):
    uses_perm_list = []

def analyze_mobsf_permission_status(perms_table, uses_list):
    requested = set()
    for p in (perms_table or {}).keys():
        if isinstance(p, str):
            requested.add(p)
    for p in (uses_list or []):
        if isinstance(p, str):
            requested.add(p)

    statuses = {}
    dangerous = []
    privileged = []
    normal = []
    signature = []
    unknown = []

    for perm in sorted(requested):
        meta = (perms_table or {}).get(perm) or {}
        st = str(meta.get("status", "unknown")).lower().strip() if isinstance(meta, dict) else "unknown"
        statuses[st] = statuses.get(st, 0) + 1
        if st == "dangerous":
            dangerous.append(perm)
        elif st == "privileged":
            privileged.append(perm)
        elif st == "signature":
            signature.append(perm)
        elif st == "normal":
            normal.append(perm)
        else:
            unknown.append(perm)

    privileged_like = set(privileged) | set(signature)
    for perm, meta in (perms_table or {}).items():
        if not isinstance(perm, str) or not isinstance(meta, dict):
            continue
        st = str(meta.get("status", "")).lower()
        if st in {"signature|privileged", "signatureorsystem", "system"}:
            privileged_like.add(perm)

    return {
        "requested_permissions": sorted(requested),
        "status_counts": statuses,
        "dangerous_permissions": sorted(set(dangerous)),
        "signature_permissions": sorted(set(signature)),
        "privileged_permissions": sorted(set(privileged)),
        "privileged_like_permissions": sorted(privileged_like),
        "has_dangerous": bool(dangerous),
        "has_privileged_like": bool(privileged_like),
    }

perm_features = analyze_mobsf_permission_status(mobsf_permissions_table, uses_perm_list)
requested_permissions = set(perm_features["requested_permissions"])

SPECIAL_OS_PERMS = {
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}
special_os_permissions_requested = sorted([p for p in requested_permissions if p in SPECIAL_OS_PERMS])

RISKY_PERMS = {
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SECURE_SETTINGS",
}
risky_permissions_requested = sorted([p for p in requested_permissions if p in RISKY_PERMS])

# ------------------------------------------------------------
# Malware flags
# ------------------------------------------------------------

def index_malware_flags(mobsf_static_obj):
    ms_local = mobsf_static_obj or {}
    details = []
    mw = ms_local.get("malware_permissions") or {}
    if isinstance(mw, dict):
        for k, v in mw.items():
            details.append({"id": k, "value": v})
    has_malware_local = any(
        "malicious" in str(d).lower() or "suspicious" in str(d).lower()
        for d in details
    )
    return has_malware_local, details

has_malware, malware_details = index_malware_flags(mobsf_static)

# ------------------------------------------------------------
# Trackers
# ------------------------------------------------------------

trackers_section = ms.get("trackers") or {}
privacy_trackers = trackers_section.get("trackers") or []
if not isinstance(privacy_trackers, list):
    privacy_trackers = []
privacy_trackers_count = len(privacy_trackers)

# ------------------------------------------------------------
# TLS / Pinning (MobSF)
# ------------------------------------------------------------

android_ssl_pinning = (code_analysis.get("findings", {}).get("android_ssl_pinning") or {})
android_ssl_pinning_files = list((android_ssl_pinning.get("files") or {}).keys()) if isinstance(android_ssl_pinning, dict) else []
android_ssl_pinning_meta = android_ssl_pinning.get("metadata") or {} if isinstance(android_ssl_pinning, dict) else {}

appsec = ms.get("appsec") or {}
secure_entries = appsec.get("secure") or []
if not isinstance(secure_entries, list):
    secure_entries = []

tls_features = {
    "android_ssl_pinning_full": android_ssl_pinning,
    "android_ssl_pinning_files": android_ssl_pinning_files,
    "android_ssl_pinning_metadata": android_ssl_pinning_meta,
    "has_android_ssl_pinning_block": bool(android_ssl_pinning),
    "has_secure_ssl_pinning_message": any(
        isinstance(item, dict)
        and "ssl certificate pinning" in str(item.get("description", "")).lower()
        for item in secure_entries
    ),
}

# ------------------------------------------------------------
# Certificate analysis
# ------------------------------------------------------------

cert_analysis = ms.get("certificate_analysis") or {}
certificate_info = cert_analysis.get("certificate_info") or ""
certificate_findings = cert_analysis.get("certificate_findings") or []
if not isinstance(certificate_findings, list):
    certificate_findings = []
certificate_info_lower = str(certificate_info).lower()

# ------------------------------------------------------------
# Hardcoded secrets
# ------------------------------------------------------------

def extract_hardcoded_secrets_from_mobsf(mobsf_static_obj, mobsf_findings_obj):
    hits = []
    if isinstance(mobsf_findings_obj, dict):
        for key, value in mobsf_findings_obj.items():
            try:
                text = json.dumps(value).lower()
            except Exception:
                text = str(value).lower()
            if any(tok in text for tok in ["hardcoded", "api key", "apikey", "password", "secret", "credential"]):
                hits.append({
                    "source": "MobSF_FINDING",
                    "id": key,
                    "data": value,
                })

    ms_local = mobsf_static_obj or {}
    secrets_section = ms_local.get("secrets") or {}
    if isinstance(secrets_section, dict):
        for key, value in secrets_section.items():
            try:
                text = json.dumps(value).lower()
            except Exception:
                text = str(value).lower()
            if any(tok in text for tok in ["hardcoded", "api key", "apikey", "password", "secret", "credential"]):
                hits.append({
                    "source": "MobSF_SECRETS_SECTION",
                    "id": key,
                    "data": value,
                })

    return hits

hardcoded_secrets_hits = extract_hardcoded_secrets_from_mobsf(mobsf_static, mobsf_findings)

# ============================================================
# Code features
# ============================================================

OS_SETTINGS_API_PATTERNS = [
    r"\bsettings\.(system|secure|global)\.put",
    r"\bsettings\.(system|secure|global)\.putint",
    r"\bsettings\.(system|secure|global)\.putstring",
    r"\bdevicepolicymanager\b",
    r"\bdeviceadminreceiver\b",
    r"\bcontentresolver\.insert\(\s*settings\.",
    r"\bruntime\.getruntime\(\)\.exec\(",
    r"\bsettings\s+put\s+",
    r"\bsu\s+",
    r"\bsudo\s+",
]

OS_TIME_SOURCE_PATTERNS = [
    ("System.currentTimeMillis", r"\bSystem\.currentTimeMillis\s*\("),
    ("SystemClock.elapsedRealtime", r"\bSystemClock\.elapsedRealtime\s*\("),
    ("SystemClock.uptimeMillis", r"\bSystemClock\.uptimeMillis\s*\("),
    ("Instant.now", r"\bInstant\.now\s*\("),
    ("LocalDateTime.now", r"\bLocalDateTime\.now\s*\("),
    ("ZonedDateTime.now", r"\bZonedDateTime\.now\s*\("),
    ("Calendar.getInstance", r"\bCalendar\.getInstance\s*\("),
    ("new Date()", r"\bnew\s+Date\s*\("),
]

PREFERRED_TIME_EVIDENCE = [
    {
        "path_suffix": ".java",
        "rule_id": "System.currentTimeMillis",
        "regex": r"visit\.setstartdatetime\s*\(\s*dateutils\.converttime\s*\(\s*system\.currenttimemillis\s*\(",
        "note": "VisitRepository.startVisit uses System.currentTimeMillis() for timestamps"
    }
]

def detect_os_time_source_evidence(app_texts_obj, max_evidence=5):
    evidence = []
    hit_paths = []
    items = list((app_texts_obj or {}).items())

    # 1) priority: preferred evidence
    for path, txt in items:
        norm = path.replace("\\", "/").lower()
        for pref in PREFERRED_TIME_EVIDENCE:
            if norm.endswith(pref["path_suffix"]):
                low = (txt or "").lower()
                m = re.search(pref["regex"], low)
                if m:
                    excerpt = _extract_line_excerpt(txt, m.start())
                    evidence.append(ev(
                        "SOURCE_CODE_APP",
                        f"app.zip:{path}",
                        pref["rule_id"],
                        excerpt or pref["note"]
                    ))
                    hit_paths.append(path)
                    return {
                        "has_os_time_source": True,
                        "paths": sorted(set(hit_paths)),
                        "evidence": evidence
                    }

    # 2) fallback: scan VisitRepository.java then others
    preferred_paths = []
    for path, _ in items:
        norm = path.replace("\\", "/").lower()
        if norm.endswith("/visitrepository.java"):
            preferred_paths.append(path)
    scan_paths = preferred_paths + [p for p, _ in items if p not in preferred_paths]

    for path in scan_paths:
        txt = (app_texts_obj or {}).get(path) or ""
        for rule_id, pat in OS_TIME_SOURCE_PATTERNS:
            m = re.search(pat, txt)
            if not m:
                continue
            excerpt = _extract_line_excerpt(txt, m.start())
            evidence.append(ev(
                "SOURCE_CODE_APP",
                f"app.zip:{path}",
                rule_id,
                excerpt
            ))
            hit_paths.append(path)
            break
        if len(evidence) >= max_evidence:
            break

    return {
        "has_os_time_source": bool(evidence),
        "paths": sorted(set(hit_paths)),
        "evidence": evidence
    }

def detect_os_settings_modification_api_usage(code_text_lower):
    return any(re.search(pat, code_text_lower) for pat in OS_SETTINGS_API_PATTERNS)

has_os_settings_modification_api_usage = detect_os_settings_modification_api_usage(code_lower)

def detect_supports_runtime_permission_management(code_text_lower):
    patterns = [
        r"\brequestpermissions\s*\(",
        r"\bactivitycompat\.requestpermissions\s*\(",
        r"\bshouldshowrequestpermissionrationale\s*\(",
        r"\bonrequestpermissionsresult\s*\(",
        r"\bregisterforactivityresult\s*\(",
        r"\bactivityresultcontracts\.requestpermission\b",
        r"\bactivityresultcontracts\.requestmultiplepermissions\b",
    ]
    return any(re.search(p, code_text_lower) for p in patterns)

supports_runtime_permission_mgmt = detect_supports_runtime_permission_management(code_lower)

code_features = {
    "has_webview": "webview" in code_lower,
    "has_webview_js_enabled": bool(re.search(
        r'\.getsettings\(\)\.setjavascriptenabled\s*\(\s*true\s*\)', code_lower)),
    "has_bindservice": "bindservice(" in code_lower,
    "has_soap": any(x.lower() in code_lower for x in ["soapmessage", "javax.xml.soap", "ksoap2"]),
    "has_saml": "saml" in code_lower,
    "has_oauth2": "oauth2" in code_lower or "authorization: bearer" in code_lower,
    "has_jwt": "jwt" in code_lower or "jsonwebtoken" in code_lower,
    "has_hardcoded_password_literal": bool(re.search(
        r'password\s*=\s*"[^"]+"', combined_code, flags=re.IGNORECASE)),
    "has_dynamic_code_loading": any(tok in code_lower for tok in [
        "dexclassloader", "pathclassloader", "basedexclassloader",
        "inmemorydexclassloader", "loadclass(", "defineclass",
        "system.load(", "system.loadlibrary("
    ]),
    "has_os_settings_mod_api_usage": has_os_settings_modification_api_usage,
    "supports_runtime_permission_mgmt": supports_runtime_permission_mgmt,
}

has_default_credentials = (
    "demo username: admin" in readme_lower and
    "demo password: admin123" in readme_lower
)

# compute OS time source evidence now
os_time_source_evidence = detect_os_time_source_evidence(app_texts)

# ============================================================
# Password hashing (REFINED FLAGS)
# ============================================================

PASSWORD_HASHING_KDF_PATTERNS = [
    ("bcrypt", r"\bBCrypt\s*\.\s*hashpw\s*\("),
    ("bcrypt", r"\bBCrypt\s*\.\s*gensalt\s*\("),
    ("pbkdf2", r"PBKDF2WithHmacSHA\d+"),
    ("pbkdf2", r"\bSecretKeyFactory\s*\.\s*getInstance\s*\(\s*\"PBKDF2"),
    ("scrypt", r"\bscrypt\b"),
    ("argon2", r"\bargon2\b"),
]

PASSWORD_HASHING_SALT_PATTERNS = [
    ("bcrypt_salt", r"\bBCrypt\s*\.\s*gensalt\s*\("),
    ("salt_var", r"\bsalt\s*=\s*"),
]

def detect_password_hashing_features(app_texts_obj, max_evidence=8):
    evidence = []
    hit_paths = set()
    kdf_algs = set()
    salt_hits = False
    kdf_hits = False

    # priority path (user-provided evidence)
    preferred_suffix = ".java"
    preferred_paths = []
    for p in (app_texts_obj or {}).keys():
        if p.replace("\\", "/").lower().endswith(preferred_suffix):
            preferred_paths.append(p)

    scan_paths = preferred_paths + [p for p in (app_texts_obj or {}).keys() if p not in preferred_paths]

    for path in scan_paths:
        txt = (app_texts_obj or {}).get(path) or ""
        if not txt:
            continue

        # KDF patterns
        for alg, pat in PASSWORD_HASHING_KDF_PATTERNS:
            m = re.search(pat, txt, flags=re.IGNORECASE)
            if m:
                kdf_hits = True
                kdf_algs.add(alg)
                hit_paths.add(path)
                excerpt = _extract_line_excerpt(txt, m.start())
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{path}", f"password_kdf_{alg}", excerpt))
                break

        # Salt patterns
        for alg, pat in PASSWORD_HASHING_SALT_PATTERNS:
            m = re.search(pat, txt, flags=re.IGNORECASE)
            if m:
                salt_hits = True
                hit_paths.add(path)
                excerpt = _extract_line_excerpt(txt, m.start())
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{path}", f"password_salt_{alg}", excerpt))
                break

        if len(evidence) >= max_evidence:
            break

    # tighten: for bcrypt, require both gensalt and hashpw to claim "uses salts" strongly
    # but allow salt_var as secondary signal
    if "bcrypt" in kdf_algs:
        # already captured by patterns; no change
        pass

    return {
        "has_password_hashing_uses_kdf": bool(kdf_hits),
        "kdf_algorithms": sorted(kdf_algs),
        "has_password_hashing_uses_salts": bool(salt_hits),
        "paths": sorted(hit_paths),
        "evidence": evidence[:max_evidence],
    }

password_hashing_features = detect_password_hashing_features(app_texts)

# ============================================================
# Extra features: Gradle, WebView, vulnerabilities, Manifest
# ============================================================

def detect_keystore_env_paths(app_texts_obj):
    env_paths = []
    for path, txt in app_texts_obj.items():
        lower_path = path.lower()
        if not (lower_path.endswith("build.gradle") or lower_path.endswith(".gradle")):
            continue
        lower = txt.lower()
        if "signingconfigs" in lower and "system.getenv" in lower:
            if ("keystore_password" in lower or
                "keystore_alias_name" in lower or
                "keystore_alias_pass" in lower or
                "key_password" in lower or
                "store_password" in lower or
                "keyalias" in lower):
                env_paths.append(path)
    return sorted(set(env_paths))


def detect_signing_creds_hardcoded(app_texts_obj):
    for path, txt in app_texts_obj.items():
        lower_path = path.lower()
        if not (lower_path.endswith("build.gradle") or lower_path.endswith(".gradle")):
            continue
        low = txt.lower()
        if "signingconfigs" in low:
            if ('storepassword "' in low or "storepassword '" in low or
                'keypassword "' in low or "keypassword '" in low):
                return True
    return False


def detect_release_minify_disabled(app_texts_obj):
    for path, txt in app_texts_obj.items():
        if path.lower().endswith("build.gradle"):
            low = txt.lower()
            if "buildtypes" in low and "release" in low and "minifyenabled false" in low:
                return True
    return False

# -------------------------
# FIX: robust MobSF manifest_findings parsing
# -------------------------

def mobsf_manifest_findings_list(mobsf_static_obj):
    ma = (mobsf_static_obj or {}).get("manifest_analysis") or {}
    mf = ma.get("manifest_findings")
    if isinstance(mf, list):
        return [x for x in mf if isinstance(x, dict)]
    if isinstance(mf, dict):
        out = []
        for k, v in mf.items():
            if isinstance(v, dict):
                vv = dict(v)
                vv.setdefault("_key", str(k))
                out.append(vv)
        return out
    return []


def detect_manifest_finding_rule(mobsf_static_obj, rule_ids, keyword_fallback=None):
    findings = mobsf_manifest_findings_list(mobsf_static_obj)
    hits = []
    rule_ids = set(rule_ids or [])
    keyword_fallback = [k.lower() for k in (keyword_fallback or [])]

    for idx, f in enumerate(findings):
        rid = str(f.get("rule") or f.get("rule_id") or f.get("id") or "").strip()
        title = str(f.get("title") or f.get("name") or "").strip()
        desc = str(f.get("description") or "").strip()
        blob = (rid + " " + title + " " + desc).lower()

        ok = (rid in rule_ids) if rid else False
        if (not ok) and keyword_fallback:
            ok = any(k in blob for k in keyword_fallback)

        if ok:
            hits.append((idx, rid, title, desc))

    evidence = []
    for idx, rid, title, desc in hits:
        excerpt = title if title else (desc[:180] if desc else "manifest finding matched")
        evidence.append(ev(
            "MobSF_STATIC",
            f"mobsf_results.json:manifest_analysis.manifest_findings[{idx}]",
            rid or "manifest_finding",
            excerpt
        ))
    return (len(hits) > 0), evidence


def detect_source_manifest_attr(source_manifest_lower_text, attr_name):
    if not source_manifest_lower_text:
        return False
    pat = r'android\s*:\s*' + re.escape(attr_name.lower()) + r'\s*=\s*"\s*true\s*"'
    return re.search(pat, source_manifest_lower_text, flags=re.IGNORECASE) is not None


def detect_manifest_debuggable_true(source_manifest_text, mobsf_static_obj):
    src_true = detect_source_manifest_attr((source_manifest_text or "").lower(), "debuggable")
    src_ev = []
    if source_manifest_text and source_manifest_paths:
        src_ev.append(ev(
            "SOURCE_CODE_APP",
            f"app.zip:{source_manifest_paths[0]}",
            "android:debuggable",
            'android:debuggable="true"' if src_true else 'android:debuggable not true'
        ))

    mobsf_true, mobsf_ev = detect_manifest_finding_rule(
        mobsf_static_obj,
        rule_ids={"app_is_debuggable"},
        keyword_fallback=["android:debuggable=true", "debug enabled for app", "debuggable=true"]
    )

    return {
        "mobsf_true": mobsf_true,
        "source_true": src_true,
        "is_true": bool(mobsf_true or src_true),
        "evidence": mobsf_ev + src_ev,
        "mismatch": (mobsf_true != src_true) if (source_manifest_text is not None) else False
    }


def detect_manifest_allow_backup_true(source_manifest_text, mobsf_static_obj):
    src_true = detect_source_manifest_attr((source_manifest_text or "").lower(), "allowbackup")
    src_ev = []
    if source_manifest_text and source_manifest_paths:
        src_ev.append(ev(
            "SOURCE_CODE_APP",
            f"app.zip:{source_manifest_paths[0]}",
            "android:allowBackup",
            'android:allowBackup="true"' if src_true else 'android:allowBackup not true'
        ))

    mobsf_true, mobsf_ev = detect_manifest_finding_rule(
        mobsf_static_obj,
        rule_ids={"app_allowbackup"},
        keyword_fallback=["android:allowbackup=true", "application data can be backed up", "allowbackup=true"]
    )

    return {
        "mobsf_true": mobsf_true,
        "source_true": src_true,
        "is_true": bool(mobsf_true or src_true),
        "evidence": mobsf_ev + src_ev,
        "mismatch": (mobsf_true != src_true) if (source_manifest_text is not None) else False
    }


def detect_manifest_uses_cleartext_traffic_true(source_manifest_text, mobsf_static_obj):
    src_true = detect_source_manifest_attr((source_manifest_text or "").lower(), "usescleartexttraffic")
    src_ev = []
    if source_manifest_text and source_manifest_paths:
        src_ev.append(ev(
            "SOURCE_CODE_APP",
            f"app.zip:{source_manifest_paths[0]}",
            "usesCleartextTraffic",
            'usesCleartextTraffic="true"' if src_true else 'usesCleartextTraffic not true'
        ))

    mobsf_true, mobsf_ev = detect_manifest_finding_rule(
        mobsf_static_obj,
        rule_ids={"cleartext_traffic", "cleartexttraffic", "clear_text_traffic"},
        keyword_fallback=["usescleartexttraffic=true", "cleartext", "clear text traffic"]
    )

    return {
        "mobsf_true": mobsf_true,
        "source_true": src_true,
        "is_true": bool(mobsf_true or src_true),
        "evidence": mobsf_ev + src_ev,
        "mismatch": (mobsf_true != src_true) if (source_manifest_text is not None) else False
    }


def detect_manifest_insecure_exports_count(source_manifest_text):
    if not source_manifest_text:
        return {"count": 0, "evidence": [], "available": False}

    low = source_manifest_text.lower()
    count = 0
    evidence = []

    for i, line in enumerate(low.splitlines()):
        l = line.strip()
        if 'android:exported="true"' in l:
            if 'permission=' not in l and 'android:permission=' not in l:
                count += 1
                evidence.append(ev(
                    "SOURCE_CODE_APP",
                    f"app.zip:{source_manifest_paths[0]}:line{ i+1 }" if source_manifest_paths else "app.zip:AndroidManifest.xml",
                    "android:exported",
                    line.strip()[:200]
                ))
    return {"count": count, "evidence": evidence, "available": True}

def detect_manifest_custom_permissions(manifest_text: str) -> Dict[str, Any]:
    """Detect custom <permission ...> declarations in the PRIMARY AndroidManifest.xml."""
    if not manifest_text:
        return {"available": False, "count": 0, "evidence": []}

    # Match <permission .../> or <permission ...>
    tags = re.findall(r"<permission\b[^>]*(?:/>|>)", manifest_text, flags=re.IGNORECASE | re.DOTALL)
    count = len(tags)
    evidence = []
    for idx, tag in enumerate(tags[:8]):
        excerpt = re.sub(r"\s+", " ", tag.strip())
        if len(excerpt) > 200:
            excerpt = excerpt[:200] + "..."
        evidence.append(ev(
            "SOURCE_CODE_APP",
            f"app.zip:{source_manifest_paths[0]}:permission[{idx}]" if source_manifest_paths else "app.zip:AndroidManifest.xml",
            "manifest_custom_permission",
            excerpt
        ))
    return {"available": True, "count": count, "evidence": evidence}


def detect_manifest_signature_level_defined(manifest_text: str) -> Dict[str, Any]:
    """Detect whether any custom <permission> uses protectionLevel signature (or signature|privileged)."""
    if not manifest_text:
        return {"available": False, "is_true": False, "evidence": []}

    tags = re.findall(r"<permission\b[^>]*(?:/>|>)", manifest_text, flags=re.IGNORECASE | re.DOTALL)
    evidence = []
    is_true = False

    for idx, tag in enumerate(tags):
        low = tag.lower()
        if "protectionlevel" in low:
            m = re.search(r'android:protectionLevel\s*=\s*"([^"]+)"', tag, flags=re.IGNORECASE)
            if m:
                val = m.group(1).strip().lower()
                if "signature" in val:  # includes signature|privileged, signatureOrSystem, etc.
                    is_true = True
                    excerpt = re.sub(r"\s+", " ", tag.strip())
                    if len(excerpt) > 200:
                        excerpt = excerpt[:200] + "..."
                    evidence.append(ev(
                        "SOURCE_CODE_APP",
                        f"app.zip:{source_manifest_paths[0]}:permission[{idx}]" if source_manifest_paths else "app.zip:AndroidManifest.xml",
                        "manifest_permission_protectionLevel_signature",
                        f"protectionLevel={val} -> {excerpt}"
                    ))
                    if len(evidence) >= 8:
                        break

    if not is_true and tags:
        # Deterministic sample evidence for NO (first permission tag)
        excerpt = re.sub(r"\s+", " ", tags[0].strip())
        if len(excerpt) > 200:
            excerpt = excerpt[:200] + "..."
        evidence.append(ev(
            "SOURCE_CODE_APP",
            f"app.zip:{source_manifest_paths[0]}:permission[0]" if source_manifest_paths else "app.zip:AndroidManifest.xml",
            "manifest_permission_sample",
            excerpt
        ))

    return {"available": True, "is_true": is_true, "evidence": evidence}





def detect_exported_broadcast_receivers_without_permission(manifest_text: str, manifest_path: str) -> Dict[str, Any]:
    """
    Detect exported broadcast receivers that do NOT declare a permission.

    Deterministic policy (AndroidManifest.xml):
      - A receiver is considered *effectively exported* if:
          (a) android:exported="true", OR
          (b) android:exported is absent AND the receiver declares an <intent-filter>.
      - A receiver with android:exported="false" is NOT exported, even if it has an <intent-filter>.
      - A receiver is considered protected if it declares android:permission (or permission).

    Returns:
      {
        available: bool,
        manifest_path: str,
        total_receivers: int,
        exported_receivers_count: int,
        exported_receivers_without_permission_count: int,
        receiver_summaries: list[dict],
        evidence: list[dict]
      }

    Evidence schema matches ev(): {source, path, rule_id, excerpt}.
    """
    if not manifest_text or not isinstance(manifest_text, str):
        return {"available": False, "reason": "manifest_text unavailable", "manifest_path": manifest_path}

    receiver_blocks = list(re.finditer(
        r"<receiver\b[^>]*(?:/>|>.*?</receiver\s*>)",
        manifest_text,
        flags=re.IGNORECASE | re.DOTALL
    ))

    if not receiver_blocks:
        return {
            "available": True,
            "manifest_path": manifest_path,
            "total_receivers": 0,
            "exported_receivers_count": 0,
            "exported_receivers_without_permission_count": 0,
            "receiver_summaries": [],
            "evidence": [],
        }

    def _start_tag(block_text: str) -> str:
        if ">" in block_text:
            return block_text.split(">", 1)[0] + ">"
        return block_text

    summaries: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    exported_count = 0
    insecure_count = 0

    for idx, m in enumerate(receiver_blocks, start=1):
        block = m.group(0)
        start_tag = _start_tag(block)

        name_m = re.search(r'android:name\s*=\s*"([^"]+)"', start_tag, flags=re.IGNORECASE)
        rcv_name = name_m.group(1) if name_m else ""

        exported_m = re.search(r'android:exported\s*=\s*"([^"]+)"', start_tag, flags=re.IGNORECASE)
        exported_attr = exported_m.group(1).strip().lower() if exported_m else None

        has_intent_filter = bool(re.search(r"<intent-filter\b", block, flags=re.IGNORECASE))
        perm_m = re.search(r'(android:permission|permission)\s*=\s*"([^"]+)"', start_tag, flags=re.IGNORECASE)
        has_permission = bool(perm_m)

        # Effective export decision.
        if exported_attr == "true":
            exported_effective = True
        elif exported_attr == "false":
            exported_effective = False
        else:
            exported_effective = True if has_intent_filter else False

        if exported_effective:
            exported_count += 1

        insecure = bool(exported_effective and not has_permission)
        if insecure:
            insecure_count += 1
            excerpt = re.sub(r"\s+", " ", start_tag.strip())
            if len(excerpt) > 200:
                excerpt = excerpt[:200] + "..."
            evidence.append(ev(
                "SOURCE_CODE_APP",
                f"app.zip:{manifest_path}:receiver[{idx}]",
                "exported_broadcast_receiver_without_permission",
                f"{rcv_name or '(unnamed)'} -> {excerpt}"
            ))

        summaries.append({
            "index": idx,
            "name": rcv_name,
            "exported_attr": exported_attr,
            "exported_effective": exported_effective,
            "has_intent_filter": has_intent_filter,
            "has_permission": has_permission,
            "permission_value": perm_m.group(2) if perm_m else "",
        })

    # If there are no insecure receivers, include a deterministic sample secure receiver as evidence.
    if insecure_count == 0:
        sample = next((s for s in summaries if s.get("exported_attr") == "false"), None)
        if sample is None:
            sample = next((s for s in summaries if not s.get("exported_effective")), None) or summaries[0]

        sample_idx = int(sample.get("index", 1))
        sample_block = receiver_blocks[sample_idx - 1].group(0)
        sample_tag = _start_tag(sample_block)
        excerpt = re.sub(r"\s+", " ", sample_tag.strip())
        if len(excerpt) > 200:
            excerpt = excerpt[:200] + "..."
        evidence.append(ev(
            "SOURCE_CODE_APP",
            f"app.zip:{manifest_path}:receiver[{sample_idx}]",
            "broadcast_receiver_sample_secure",
            f"{sample.get('name') or '(unnamed)'} -> {excerpt}"
        ))

    return {
        "available": True,
        "manifest_path": manifest_path,
        "total_receivers": len(receiver_blocks),
        "exported_receivers_count": exported_count,
        "exported_receivers_without_permission_count": insecure_count,
        "receiver_summaries": summaries,
        "evidence": evidence,
    }


    summaries: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    exported_count = 0
    insecure_count = 0

    # Helper: extract the start tag for cleaner excerpts.
    def _start_tag(block_text: str) -> str:
        if ">" in block_text:
            return block_text.split(">", 1)[0] + ">"
        return block_text

    for idx, m in enumerate(receiver_blocks, start=1):
        block = m.group(0)
        start_tag = _start_tag(block)

        name_m = re.search(r'android:name\s*=\s*"([^"]+)"', start_tag, flags=re.IGNORECASE)
        rcv_name = name_m.group(1) if name_m else ""

        exported_m = re.search(r'android:exported\s*=\s*"([^"]+)"', start_tag, flags=re.IGNORECASE)
        exported_attr = exported_m.group(1).strip().lower() if exported_m else None

        has_intent_filter = bool(re.search(r"<intent-filter\b", block, flags=re.IGNORECASE))
        perm_m = re.search(r'(android:permission|permission)\s*=\s*"([^"]+)"', start_tag, flags=re.IGNORECASE)
        has_permission = bool(perm_m)

        # Effective export decision.
        if exported_attr == "true":
            exported_effective = True
        elif exported_attr == "false":
            exported_effective = False
        else:
            exported_effective = True if has_intent_filter else False

        if exported_effective:
            exported_count += 1

        insecure = bool(exported_effective and not has_permission)
        if insecure:
            insecure_count += 1
            evidence.append({
                "id": evidence_id("manifest_receiver_exported_without_permission", manifest_path, rcv_name or f"idx{idx}"),
                "rule_id": "exported_broadcast_receiver_without_permission",
                "excerpt": start_tag.strip(),
                "location": f"{manifest_path}:<receiver> {rcv_name or idx}",
                "confidence": "high",
            })

        summaries.append({
            "index": idx,
            "name": rcv_name,
            "exported_attr": exported_attr,
            "exported_effective": exported_effective,
            "has_intent_filter": has_intent_filter,
            "has_permission": has_permission,
            "permission_value": perm_m.group(2) if perm_m else "",
        })

    # If there are no insecure receivers, include a deterministic sample secure receiver as evidence.
    if insecure_count == 0:
        # Prefer an explicitly non-exported receiver to align with the user’s case.
        sample = next((s for s in summaries if s.get("exported_attr") == "false"), None)
        if sample is None:
            # Fallback: any receiver that is not effectively exported, else first receiver.
            sample = next((s for s in summaries if not s.get("exported_effective")), None) or summaries[0]

        # Re-find the corresponding start tag (deterministically by index).
        sample_idx = int(sample.get("index", 1))
        sample_block = receiver_blocks[sample_idx - 1].group(0)
        sample_tag = _start_tag(sample_block)

        evidence.append({
            "id": evidence_id("manifest_receiver_sample_secure", manifest_path, sample.get("name", "") or f"idx{sample_idx}"),
            "rule_id": "broadcast_receiver_export_sample",
            "excerpt": sample_tag.strip(),
            "location": f"{manifest_path}:<receiver> {sample.get('name') or sample_idx}",
            "confidence": "high",
        })

    return {
        "available": True,
        "manifest_path": manifest_path,
        "total_receivers": len(receiver_blocks),
        "exported_receivers_count": exported_count,
        "exported_receivers_without_permission_count": insecure_count,
        "receiver_summaries": summaries,
        "evidence": evidence,
    }


def detect_manifest_services_explicit_accessibility_attributes(source_manifest_text, source_manifest_paths_obj=None):
    """
    Deterministic check (PRIMARY manifest):
    - PASS: every <service ...> has android:exported explicitly.
    - FAIL: at least one <service ...> is missing android:exported.
    - NOT_APPLICABLE handled later if total_services==0.
    - UNKNOWN handled later if available==False.
    """
    if not source_manifest_text:
        return {"available": False, "total_services": 0, "missing_exported_count": 0, "evidence": []}

    manifest_path = "AndroidManifest.xml"
    if source_manifest_paths_obj and isinstance(source_manifest_paths_obj, list) and len(source_manifest_paths_obj) > 0:
        manifest_path = source_manifest_paths_obj[0]

    tags = re.findall(r"<service\b[^>]*>", source_manifest_text, flags=re.IGNORECASE | re.DOTALL)
    total = len(tags)
    missing = 0
    evidence = []

    for idx, tag in enumerate(tags):
        low = tag.lower()
        if "android:exported" not in low:
            missing += 1
            mname = re.search(r'android\s*:\s*name\s*=\s*"([^"]+)"', tag, flags=re.IGNORECASE)
            svc_name = mname.group(1) if mname else "(unknown_service)"
            excerpt = re.sub(r"\s+", " ", tag.strip())
            if len(excerpt) > 200:
                excerpt = excerpt[:200] + "..."
            evidence.append(ev(
                "SOURCE_CODE_APP",
                f"app.zip:{manifest_path}:service[{idx}]",
                "service_missing_android_exported",
                f"{svc_name} -> {excerpt}"
            ))
            if len(evidence) >= 8:
                break

    return {"available": True, "total_services": total, "missing_exported_count": missing, "evidence": evidence}

# ============================================================
# Keyword-based helpers
# ============================================================

def search_keywords_in_struct(obj, keywords):
    txt = flatten_to_text(obj, max_len=500000)
    return any(kw in txt for kw in keywords)

# ============================================================
# Logout/session/endpoints (minimal, deterministic)
# ============================================================

def detect_logout_and_session_features(app_texts_obj):
    features = {
        "has_mannual_logout": False,
        "has_clears_local_prefs_on_logout": False,
        "has_clears_cookies_on_logout": False,
        "has_session_cookie_based_auth": False,
        "has_logout_invalidates_server_session": False,
        "logout_paths": [],
        "cookie_clear_paths": [],
        "session_cookie_paths": [],
        "logout_endpoint_paths": [],
    }

    for path, txt in app_texts_obj.items():
        low = (txt or "").lower()
        norm = path.replace("\\", "/").lower()

        if norm.endswith("/acbaseactivity.java"):
            if "void logout(" in (txt or "") or "public void logout(" in (txt or ""):
                features["has_mannual_logout"] = True
                features["logout_paths"].append(path)
            if "clearuserpreferencesdata(" in low:
                features["has_clears_local_prefs_on_logout"] = True
            if "removeallcookies" in low or "clearcookies" in low:
                features["has_clears_cookies_on_logout"] = True
                features["cookie_clear_paths"].append(path)

        if any(tok in low for tok in [
            "cookiemanager.getinstance().setcookie",
            "cookiehandler.setdefault",
            "jsessionid",
            "sessionid"
        ]):
            features["has_session_cookie_based_auth"] = True
            features["session_cookie_paths"].append(path)

        if "removeallcookies" in low or "clearcookies" in low:
            features["has_clears_cookies_on_logout"] = True
            features["cookie_clear_paths"].append(path)

        if '"/logout"' in low or "'/logout'" in low:
            features["logout_endpoint_paths"].append(path)

    if features["has_mannual_logout"] and features["logout_endpoint_paths"]:
        features["has_logout_invalidates_server_session"] = True

    for k in ["logout_paths","cookie_clear_paths","session_cookie_paths","logout_endpoint_paths"]:
        features[k] = sorted(set(features[k]))

    return features

def detect_endpoint_auth_features(app_texts_obj):
    features = {
        "rest_service_builder_paths": [],
        "has_basic_auth_header_in_rest_service": False,
        "has_any_authorization_header_usage": False,
        "authorization_header_paths": [],
    }

    for path, txt in app_texts_obj.items():
        low = (txt or "").lower()
        norm = path.replace("\\", "/").lower()

        if norm.endswith("/restservicebuilder.java") or "restservicebuilder.java" in norm:
            features["rest_service_builder_paths"].append(path)
            if '.header("authorization", basic)' in low:
                features["has_basic_auth_header_in_rest_service"] = True

        if '"authorization"' in low:
            features["has_any_authorization_header_usage"] = True
            features["authorization_header_paths"].append(path)

    features["rest_service_builder_paths"] = sorted(set(features["rest_service_builder_paths"]))
    features["authorization_header_paths"] = sorted(set(features["authorization_header_paths"]))
    return features

logout_session_features = detect_logout_and_session_features(app_texts)
endpoint_auth_features = detect_endpoint_auth_features(app_texts)

# ============================================================
# WebView remote content (simple)
# ============================================================

def detect_webview_remote_content(app_texts_obj):
    paths = []
    pattern = re.compile(r'loadurl\s*\(\s*"(http|https)://', re.IGNORECASE)
    for path, txt in app_texts_obj.items():
        low = (txt or "").lower()
        if "webview" in low and pattern.search(low):
            paths.append(path)
    return sorted(set(paths))

webview_remote_paths = detect_webview_remote_content(app_texts)

# ============================================================
# Kill switch / safe mode keyword scan
# ============================================================

def detect_kill_switch_and_safe_mode():
    sources = {}

    def add_source(name, text):
        if not text:
            return
        sources[name] = text.lower()

    add_source("app_code", code_lower)
    add_source("readme_and_md", md_texts_joined)
    add_source("mobsf_static", flatten_to_text(mobsf_static))
    add_source("mobsf_dynamic", flatten_to_text(mobsf_dynamic))
    add_source("trivy", flatten_to_text(trivy))
    add_source("agent_payload", flatten_to_text(agent_payload))

    kill_kw = [
        "kill switch", "killswitch", "global kill",
        "emergency shutdown", "remote disable", "remote kill",
        "disable the application", "disable the application"
    ]
    safe_mode_kw = [
        "safe mode", "modo seguro",
        "degraded mode", "modo degradado",
        "read-only mode", "solo lectura",
        "limited functionality", "funcionalidad limitada"
    ]

    kill_sources = []
    safe_sources = []

    for name, text in sources.items():
        if any(kw in text for kw in kill_kw):
            kill_sources.append(name)
        if any(kw in text for kw in safe_mode_kw):
            safe_sources.append(name)

    return {
        "has_kill_switch_evidence": bool(kill_sources),
        "kill_switch_sources": sorted(set(kill_sources)),
        "has_safe_mode_evidence": bool(safe_sources),
        "safe_mode_sources": sorted(set(safe_sources)),
    }

kill_safe_features = detect_kill_switch_and_safe_mode()

# ============================================================
# Temp/cache compiled controls (heuristic)
# ============================================================

def detect_temp_compiled_data_controls(app_texts_obj):
    protection_paths = []
    secure_delete_paths = []

    for path, txt in app_texts_obj.items():
        low = (txt or "").lower()
        refers_temp = any(kw in low for kw in ["temp", "temporary", "cache", "compiled", "intermediate"])
        if refers_temp and any(kw in low for kw in ["encrypt", "encryption", "cipher", "secure", "protected"]):
            protection_paths.append(path)
        if refers_temp and any(kw in low for kw in ["delete", "remove", "cleanup", "clean up", "file.delete", "deletefile"]):
            secure_delete_paths.append(path)

    return {
        "protection_paths": sorted(set(protection_paths)),
        "secure_delete_paths": sorted(set(secure_delete_paths)),
    }

temp_compiled_features = detect_temp_compiled_data_controls(app_texts)

# ============================================================
# Derived vuln keywords (SAST+MobSF)
# ============================================================

has_buffer_overflow_evidence = search_keywords_in_struct(
    {"mobsf": mobsf_static, "sast": sast_merged},
    ["buffer overflow", "stack overflow", "out-of-bounds write", "out of bounds write"]
)

has_race_condition_evidence = search_keywords_in_struct(
    {"mobsf": mobsf_static, "sast": sast_merged},
    ["race condition", "data race"]
)

has_oob_evidence = search_keywords_in_struct(
    {"mobsf": mobsf_static, "sast": sast_merged},
    ["out-of-bounds read", "out of bounds read"]
)

has_memory_corruption_evidence = search_keywords_in_struct(
    {"mobsf": mobsf_static, "sast": sast_merged},
    ["memory corruption", "use-after-free"]
)

has_integer_vuln_evidence = search_keywords_in_struct(
    {"mobsf": mobsf_static, "sast": sast_merged},
    ["integer overflow", "integer underflow", "integer truncation"]
)

# ============================================================
# Manifest features (primary manifest)
# ============================================================

manifest_debuggable = detect_manifest_debuggable_true(source_manifest_text, mobsf_static)
manifest_allow_backup = detect_manifest_allow_backup_true(source_manifest_text, mobsf_static)
manifest_cleartext = detect_manifest_uses_cleartext_traffic_true(source_manifest_text, mobsf_static)
manifest_exports = detect_manifest_insecure_exports_count(source_manifest_text)
manifest_custom_permissions = detect_manifest_custom_permissions(source_manifest_text)
manifest_signature_level = detect_manifest_signature_level_defined(source_manifest_text)
manifest_services_explicit_accessibility = detect_manifest_services_explicit_accessibility_attributes(
    source_manifest_text, source_manifest_paths_obj=source_manifest_paths
)
exported_broadcast_receivers_without_permission = detect_exported_broadcast_receivers_without_permission(
    source_manifest_text or "",
    source_manifest_paths[0] if source_manifest_paths else "AndroidManifest.xml"
)

reverse_eng_features = {"has_minify_enabled_release": False, "paths": []}
for path, txt in app_texts.items():
    if path.lower().endswith("build.gradle"):
        low = (txt or "").lower()
        if "buildtypes" in low and "release" in low and "minifyenabled true" in low:
            reverse_eng_features["has_minify_enabled_release"] = True
            reverse_eng_features["paths"].append(path)

keystore_env_paths = detect_keystore_env_paths(app_texts)
has_signing_creds_hardcoded = detect_signing_creds_hardcoded(app_texts)
release_minify_disabled = detect_release_minify_disabled(app_texts)

# ============================================================
# Consolidation extra_features
# ============================================================

extra_features = {
    "keystore_env_paths": keystore_env_paths,
    "has_signing_creds_hardcoded": has_signing_creds_hardcoded,
    "release_minify_disabled": release_minify_disabled,
    "webview_remote_paths": webview_remote_paths,

    "has_buffer_overflow_evidence": has_buffer_overflow_evidence,
    "has_race_condition_evidence": has_race_condition_evidence,
    "has_oob_evidence": has_oob_evidence,
    "has_memory_corruption_evidence": has_memory_corruption_evidence,
    "has_integer_vuln_evidence": has_integer_vuln_evidence,

    "kill_safe_features": kill_safe_features,
    "temp_compiled_features": temp_compiled_features,

    "manifest_debuggable": manifest_debuggable,
    "manifest_allow_backup": manifest_allow_backup,
    "manifest_cleartext": manifest_cleartext,
    "manifest_exports": manifest_exports,
    "manifest_custom_permissions": manifest_custom_permissions,
    "manifest_signature_level": manifest_signature_level,
    "manifest_services_explicit_accessibility": manifest_services_explicit_accessibility,
    "exported_broadcast_receivers_without_permission": exported_broadcast_receivers_without_permission,

    "reverse_eng_features": reverse_eng_features,
    "logout_session_features": logout_session_features,
    "endpoint_auth_features": endpoint_auth_features,

    "permission_features": perm_features,
    "special_os_permissions_requested": special_os_permissions_requested,
    "risky_permissions_requested": risky_permissions_requested,
    "has_os_settings_modification_api_usage": has_os_settings_modification_api_usage,
    "supports_runtime_permission_mgmt": supports_runtime_permission_mgmt,

    "source_manifest_paths": source_manifest_paths,
    "os_time_source_evidence": os_time_source_evidence,

    "password_hashing_features": password_hashing_features,
}

# ============================================================
# GROUPS AND FLAGS (compressed payload)
# ============================================================

GROUPS_B64_ZLIB = "eJyNWsly5LgR/RWGDnOS3bYjfPDc1OpySxGtJbT0zMTEBANFoqrQIgkaAEuqdszHzAf0yZ+gH/PLBECCS6nnVBKZ2HJ5+TLBX/97osqTH09u7j6enJ445SpJ/5mtaNRX4ZRuRJX9kH3Ue2ka0RQSUqW0hVEtvYTsra5evzlVCHuaSete/2hKYaTNDllrdCGttpkO0xU8Hd4ZWfl/SrwtdJNZue2MKkXJw9Qeb/HPX7HYphJbe/Ljryc7YXNMlLe6UsUhl/ValqVqtnkpnMjdoaWtRSHRqhybaHVjpc1tsZO1SF4XlZKNy/0GLU3iZw0ipdyoRpZ5K6x91qZcfiuKQneYpdLF07KEpcl1kztVS925ZSGzFkVe61JW0/k7t9MmWGF5rCpxDOUOeaU2sjgUlTxyEKhUVXIr81o0YitrPv2SZKW3UJyjaY8t6kX2Sj5HBU4EnuQhN9q9sW+WkHtdBJnFaQppnNrAsdz3t21lgV3b78qRXxzfXnCtUhcdTeEltqK1ievQ70abWlS0KJwW2nfwe3Yio7dG1Im06Rq4H81U5NhadbDK5qrJC1WUU7EWS2KifC0xv6TJyq7gIJsJGqVLzNhvAH4K/dGe0606I4onO0hBBRQwNncaEaBtZ9KQMfI/nTIyyMu8gEtGO2NDOUKeorzCs0oKrDdRitsZKZz3ZB5Q6zV8DipvJ5Jr1QhzoAM6WcytMNFyK1yxO2pYEm40+Ql23llp8GgzHLlrgQ6jrRq5VdaRnChrWIJ2Ouixgs8tqLDQNaCEFt93VSONwMmgjdHE0WvsW6tDGfDF1shiwf2WBOhI4YCLwbI0Brutu6aXr0SzZOaNam2+F5WiPSLazKGFX3h1NBan20uG1qWxDVRIyxqkBR/Ng32W5EtdDuKF4FVcNfWgsAWa7gieMf6PQTmvJQU+ArBfbxoHKVAPMPwnBi7j93cGlgiZQtKiGN1nqwZHLmQa82OkReRQVLkcbpYfpDDfl9yQhUjUequJWk0UKrpSOQxttWF8Ek1JomTewvtRiUgfnbhrSXgYGiDID1UVAgcTpdbwQRwH0FYVYGzL/u8NCkhsd4Qc1eH4QKd1ZXkVmsIrL5GOfpqKJwtFRJys0QODslbndAoevBGqmpybfmFFs5UNrBVtFzXE+pU4xNgofr8eIheGy/3Endg7iKwUFXw4iegl9GPBaSbmjbRK5eO9AMdUrb7ioPSu0FUVcHWNZCat2jZHoJWZ1oH1RC6L0xTEmAZqNN2U923kDtvTqwXRWjfKacMyuoPf5/JlJzrbe5LHWY/A0zVUUzCtSRYAgvHJ56kkaKkgenrgqcGmnrp2yWK9N3jgp61EYOjRZtFmQVtz6fnJKVFUtMazcrucLFyTFCIH7vbb76eBbd+vzu9WD/cJ4773BAZU+xxBR0YXjI9jrv2RiMbr/5qslJmnPBqsu+ARhSJqfZqd3V5mgFAi4GR5hCv/O+PSO2FKyvEE/emK9C7SqUAFaLwjTiKbPULR9GJ+fp7Akn6HSYOEfGk1M/AgSTMR/wluQbQimihQM34Na1qfyRpndCTGtLptZUGRw+LJxkl0o1BE9EtHGgOmtZyhCkxQUoKlmRmqfC6bKgFBDXgp4AZdU07esUeEZzyTtkDnPRiQz/3IFcUOtY+tU/M/fEpNj/9g9mvpkNWesvtAHma2v+9LJBgfvKSxhNTyNIsnR80UXINm5PILCOsfbgyRy0xkV5cPVzNXQCrOrQUeqIatpODErKlBmXhLfPw7IvFtzzQtdMEIvdU6CiJKjVblaADIix0ssyRRSkoX/WqNV9fAtbwWJhPtnGtDLKa77z0uMJKQ8pqSs5IGgPYxbTn5B38NDwliJCM/kCnlsZP3DFDapkSXEwb5RQXAdsNW4hBFGNtW+oBd8bYpA6OgbgL27yIdo3mXuajVovW+ODCs4VnduQ5YRq8Gfzy/++X24SZxyfMhcc8d8dFqcjJ+QjKb128CXhirNSrp4XzCvP5RS0Sv7SVf/8B7PUciNg0hRDw0lx49uOBtjFgS3P+dXwnXcZHE5s6/iKZDulH2KRVN5yzlutumNWUqyKqxO5FOLaotqm+3q1PBl3/+7V8gSesvsGfvpjz1aIvEVrgs1zgAOFM9uNMAqTlhKiApjvQ9CYvk910yHldG9vTTAQ5KXecGDjWY9ezx4SIx6lnndoSWnnUAcs7SBsPMzHjrpRlBTjPRORb2gDKGF0IkDQee23a8/QRo2SjQR8wt8WTYk08D/LTkZOHPSLnlWQw1K4n+gwcMpwrvvjwTRaQNhQf8D6LMhr5Kj1k6RWj/kBsykbAzTWhjjkIxBjzzNqJpvk5MJDjK7VHpSRmAiG+1YqoTCiUu9xaPFEilP1X+LMUTZc+uQQSA+Dqxrqbw5M8cmPMcndJjJllRCTFUAfXG12p9/6jvetm3xAeFEAWLbD6lP/f3lzfXI/rDlVZ2lSbpt7gPSRPbAQ1HZQZ37FmZx6aBEc1ccrRlKuv0BkppymW9k3TQkl2ggIGhDCb3FaMqifzCmtHUfp/w5qGSie7hh/QowAUdSlVuMPnZOHTw6ycZS3LALAoMe6H+kIfCjQFKhIULrZ9UdJrBhkBSLB1mGmx2eX37+JDfPD7gJzHcZdN27t1N5/CTfU59bWw9/ypih0XAuR5LYDCMQqLAH9C/EaV4Z1l+nir8of3W7ezIfRqlXaWuP5zj083Hj5fXabP7k95uiSX/kF35usWn5fH+77htZDjzcZFAxJvLSW2Q/3CmUPTEU822zjbiUgIg70AoXXWI7lOlfhJ2H3UUmj4prfFCXwKnWKYBXJ+O4pahyeMucRrrRB3LKWkMNezgMIg+bFVZ6g9KrrBNA3cA+0LRbJfFgcmRJC8LcIpGPuua2NOWlDWpaSqOAybX+QbLjgl9tDEpYZxB/RC2DhRr6JIhBdC09vcVqBqly/eX12d3vySO8Z77lNkF8o5sgoeIKqSgsXusGuoTFCB15BpwkirjLqfSM2ZU+ylm/sEG05tNpQUVZVBXOLBVMvKHMDaQ4URzKcXcCtACqA7mlZRB5Qvm4QQRpSNo9cOYpdQAAOrLUg0LpylTwnHkbdhiRW2GSg7sfMSMtrQ0MJR+yv4gDSAUu0wknOnk9HWo5o8MFlWlnz0mYIcv7C4bKg6XpqJS1Likl2t7+tQ3jXph8kRFiI9RlSrgOD6JKY6yQy4cInjdDc3dfmTRwSlr6kjVKqC3v3voLcUOmlqKnhhLKgIOSd9hG9zyw+p2df1hdX1+uUqrxg+yRRRQkpPUNXjvoyK7Q2YkIrlwUTeMEAy1CG24JvukiaOU8L7rZ5v5aG/XQyNq6JmJOjnsUMlUag0/IXCeETjuU6vY2YxxHC9dkvNEiW6zARxQb2dDhl4GOtS9nIYR3UtoOCjy7ub94/3DNbhHosY7vYbBQCVIiVey1gj4e7GRCwW4F5VfueIG52IGwmxDAGsM5QCb1ug1zabmOSxSDmonHCvieOyBUaxr30B5boESZeRKRdI107Jg01WopTUDeooW8zpeUdpB5uR2ojCi5jSLbGFcF/MFoSgMDD3ROxoRgTUaBSyJ6uZtpddIH08Kq1uknmI3vnCJzb4+A9CUdIUEf0BpSUC46ZrC30PTgFE7kzoAvq1jeNroxq5vDzhhn/oagHomPg0OLUNC3XjwtqCrqTLEfvDaeCAwdIQ36QJoxw3XLo3y/gCRR0UNJECQdKASXnV7nt+u7q5SpzzzYZbhHbzydrTI2CchcZr5JTiQud+melrVY90CDU72Hh0ilmVDEcy9rCRrhNbwHkYzTCn2BP6+y5f2/AzNtTZAhkIwwhVSEcjx/HyV0q8+SRlGCuwCzkFN48A+xmn+Wa75UnIA8smLL2IvvJImL0RZDu84FDYEHmNyNZ8lH0S5beOzM3KM5Yszr5Y/M7rvhvb10ci5/9QGUPhNq+rJOAPscPLIvqgT7b+HkH28x/rauTaUyImKh5vE2HlSltpes9K+a2oEW+8FnfKP6WHS56I7OPogw0iM3mkECjnlONYCyccMdIWBNLE13Hodguan1fvPl6ufkpD5Sa4/Y8cIlzs+fnbeH3+xexXkQeLj5WrA8wPg3H+kQkx/CKeFzgZrLb2b7cE2va99w2IjOe5Btd26ory6E00jRz26x8v89u7y89l5ylAfL7N32b2PDvx16+9zssefZ8d+MFi2Z6eh3uJNES9E2ZVhrkMmqhpe1kRJLkPnJ6fEPrM/Mx0CzugA48a6r2hJklxsWcbuhOGvVSTyPnEYuyzH1ykHRF89gYawM7oFU3zzTYHz4sZvuWIOfZTjUvEqYvp6VKDHgyNGQORAR98SCi0ASn8+E1Kzp6/WSBJOuCMuDnaQ3F1NdbgsFbbNDRcsdgQ7YbMyCBGE7RTdoyOzH3rGm2q87exu7ODTezXfOPWRwNLBc6dyfVpsMY+vz/w9I2VpInez/BkFfduQU8qbIlyADCjVt2w8CPkLUh9odK/ELGFcV9pDU/C2qQYDD0+3H65UqQ4ituTMYUxjRteGMZPBBEZwT/owSbZpuuk/Z8A/bFavUlH18y1LPJWbtKN2c3ab359dfUp7anhG8ICn+FlRCmmxG3n8iumSL9QjEtL4dzz6kIWK0aPiwHJRFeIwIJ9LKEF3DnRL19nE/0RdhRxjrU6d6AUvet5hp29CDAz2BQmBTvPn5GubHZiDHO4mafnQgQhXcrNJFmRmW2CZULTZeOWD8o++C0pFkr4endE3X6nnEGqxtwXh4MocUjHvBtwnCt8vzlu5fv9EcadgrBrPbAcPuVidfXq4yFcXd4mLXEj42S77oGuAHHKnfzu5B6ArV8oWkv54/cZ3OOQGEIZn+ExSVK/fmsXLHeBBWckhWP0nixvFDUjUTdQG62voNpVjxmnpY62GZIaj3J49nF+Me3i39JEYYuM0e/TfXOEwn2KTdnaktJUM9IN26dtV39UbjkJur4qK8+V+qRnJHRtASeM/POEP4/aicWM4iJ+QsZwS4ZOueFOQ3NZcf7i7ufyQr35+uDtLjrYiGMliSfAuu9Lr+3//BZ4OY5ezo533gSp8ibr8vW04JNWsm6r7ojPhFV0sRnIE3KSb79tpA7GbgXJ/X7HQyYOvdiZi8/AVD39lGNTJFZopZ2khfBkQ8t8R6Tg/XJO6FOEzPP/Z42TAb7//9n/xb0RI"

def load_groups_from_embedded_b64():
    raw = zlib.decompress(base64.b64decode(GROUPS_B64_ZLIB.encode("ascii")))
    return json.loads(raw.decode("utf-8"))

groups = load_groups_from_embedded_b64()

# ============================================================
# Ensure new flag is present in groups (deterministic, local-only)
# ============================================================

def _ensure_flag_in_groups(groups_obj, flag_to_add, anchor_flags=None):
    if not isinstance(groups_obj, list):
        return
    anchor_flags = list(anchor_flags or [])
    # already present
    for g in groups_obj:
        fl = g.get("flags") or []
        if isinstance(fl, list) and flag_to_add in fl:
            return
    # try to attach to a related group
    for g in groups_obj:
        fl = g.get("flags") or []
        if not isinstance(fl, list):
            continue
        if any(a in fl for a in anchor_flags):
            fl.append(flag_to_add)
            g["flags"] = fl
            return
    # fallback: first group
    if groups_obj:
        groups_obj[0].setdefault("flags", [])
        if flag_to_add not in groups_obj[0]["flags"]:
            groups_obj[0]["flags"].append(flag_to_add)

_ensure_flag_in_groups(
    groups,
    "has_exported_broadcast_receivers_without_permission",
    anchor_flags=[
        "has_manifest_exports_components_insecurely",
        "has_manifest_services_explicit_accessibility_attributes",
        "has_manifest_backup_enabled",
        "has_manifest_debuggable_true",
    ],
)



# ============================================================
# ORG / POSITIVE / NEGATIVE classification
# ============================================================

ORG_FLAGS = set()
for g in groups:
    if g.get("id") == "ORG":
        ORG_FLAGS.update(g.get("flags", []))

POSITIVE_FLAGS = set()
NEGATIVE_FLAGS = set()

POSITIVE_FLAGS.update(ORG_FLAGS)

NEGATIVE_FLAGS.update({
    "has_hardcoded_credentials",
    "has_malware_detections",
    "has_log_injection_vulnerabilities",
    "has_android_debuggable_enabled",
    "has_manifest_debuggable_true",
    "has_release_minify_disabled",
    "has_dos_vulnerabilities",
    "has_buffer_overflow_vulnerabilities",
    "has_race_condition_vulnerabilities",
    "has_out_of_bounds_vulnerabilities",
    "has_memory_corruption_vulnerabilities",
    "has_integer_arithmetic_vulnerabilities",
    "has_displays_sensitive_data_unmasked",
    "has_stores_pii_in_plaintext",
    "has_stores_auth_tokens_in_plaintext",
    "has_stores_keys_in_plaintext",
    "has_stores_ephi_on_external_storage",
    "has_android_read_write_external_storage",
    "has_webview_remote_content",
    "has_webview_file_scheme",
    "has_insecure_http_based_webview_communication",
    "has_notification_leaks_sensitive_data",
    "has_notification_uses_public_channels",
    "has_android_extra_risky_permissions_present",
    "has_webview_addjavascriptinterface_present",
    "has_webview_javascript_interface_exposes_sensitive_functionality",
    "has_webview_javascript_interface_leaks_sensitive_data",
    "has_manifest_backup_enabled",
    "has_manifest_allow_clear_text_traffic_true",
    "has_manifest_exports_components_insecurely",
    "has_exported_broadcast_receivers_without_permission",
})

POSITIVE_FLAGS.update({
    "has_tls_ssl_pinning_implemented",
    "has_ssl_cert_pinning_implemented",
    "has_ssl_pinning_findings_severity_good",
    "has_android_ssl_pinning_present",
    "has_android_ssl_pinning_detected",
    "has_backend_input_validation",
    "has_secure_cicd_key_management",
    "has_secrets_secure_keystore_env_vars",
    "has_signing_creds_not_hardcoded",
    "has_protection_against_tampered_executables",
    "has_uses_encrypted_local_database",
    "has_uses_encrypted_shared_preferences",
    "has_uses_encrypted_filesystem_storage",
    "has_runtime_global_kill_switch_for_security_incidents",
    "has_safe_mode_degraded_functionality_design",
    "has_controls_protecting_temporary_compiled_data",
    "has_temporary_compiled_data_securely_deleted",
    "has_webview_javascript_interface_limited_to_trusted_content",
    "has_permissions_protected_with_signature_level",
    "has_requests_only_minimum_permissions",
    "has_supports_runtime_permission_management",
    "has_ipc_bindservice_secure",
    "has_os_time_source",
    "has_manifest_services_explicit_accessibility_attributes",
    "has_password_hashing_uses_salts",
    "has_password_hashing_uses_kdf",
})

# ============================================================
# ORG evidence (strict, deterministic)
# ============================================================

def find_org_evidence_for_flag(flag_id, org_text_index_obj):
    lower_id = flag_id.lower()
    anchor_terms = [
        " policy", " policies",
        " security policy", " security policies",
        " standard", " standards",
        " procedure", " procedures",
        " guideline", " guidelines",
        " sop ", "standard operating procedure",
        " mannual", " handbook"
    ]

    raw_tokens = re.split(r'[_\W]+', lower_id)
    stop_tokens = {
        "has", "org", "defined", "formal", "meets", "supports", "enforces", "requires",
        "policy", "policies", "standard", "standards", "process", "processes",
        "management", "controls", "control", "profile", "profiles", "stig",
        "minimizes", "minimize", "minimisation", "minimization",
        "collection", "collecting", "collect"
    }
    concept_tokens = [
        t for t in raw_tokens
        if t and t not in stop_tokens and len(t) > 3
    ]

    explicit_patterns_by_flag = {
        "data_classification_policy": [
            "data classification policy",
            "information classification policy"
        ],
        "data_retention_policy": [
            "data retention policy",
            "pii retention policy",
            "phi retention policy"
        ],
        "minimizes_pii_collection_by_design": [
            "data minimization policy",
            "policy on data minimization",
            "pii data minimization policy",
            "policy to minimize pii collection",
            "policy to minimise pii collection",
            "collect only the minimum necessary personal data",
            "collect only the minimum necessary pii",
            "minimize collection of personally identifiable information",
            "minimise collection of personally identifiable information",
            "data protection by design and by default",
            "privacy by design and by default"
        ],
        "password_policy": [
            "password policy",
            "password complexity policy",
            "password management policy"
        ],
        "account_lock_policy": [
            "account lockout policy",
            "account lock policy",
            "lockout threshold policy"
        ],
        "session_timeout_policy": [
            "session timeout policy",
            "session time-out policy",
            "inactive session timeout policy"
        ],
        "log_retention_policy": [
            "log retention policy",
            "logging retention policy",
            "audit log retention policy"
        ],
        "log_review_process": [
            "log review process",
            "audit log review process",
            "security log review procedure"
        ],
        "key_rotation_policy": [
            "key rotation policy",
            "cryptographic key rotation policy"
        ],
        "key_revocation_process": [
            "key revocation process",
            "certificate revocation process"
        ],
        "certificate_management_policy": [
            "certificate management policy",
            "tls certificate policy"
        ],
        "secrets_management_policy": [
            "secrets management policy",
            "secret management policy",
            "credentials management policy"
        ],
        "secure_coding_standard": [
            "secure coding standard",
            "secure coding guidelines",
            "secure development standard"
        ],
        "incident_response_plan": [
            "incident response plan",
            "security incident response plan",
            "csirt playbook"
        ],
        "app_deprecation_policy": [
            "app deprecation policy",
            "application deprecation policy",
            "mobile app deprecation policy",
            "sunset policy",
            "application end-of-life policy"
        ],
    }

    explicit_patterns = []
    for key, patterns in explicit_patterns_by_flag.items():
        if key in lower_id:
            explicit_patterns.extend(patterns)

    evidence_sources = set()

    for src_name, text in (org_text_index_obj or {}).items():
        if not text:
            continue
        t = text.lower()

        if any(phrase in t for phrase in explicit_patterns):
            evidence_sources.add(src_name)
            continue

        if concept_tokens:
            for token in concept_tokens:
                if token not in t:
                    continue
                pos = t.find(token)
                start = max(0, pos - 80)
                end = min(len(t), pos + 80)
                window = t[start:end]
                if any(anchor in window for anchor in anchor_terms):
                    evidence_sources.add(src_name)
                    break

    has_evidence = len(evidence_sources) > 0
    return has_evidence, sorted(evidence_sources)


# ============================================================
# STRICT ORG evidence: audit tool integrity periodically
# ============================================================

def detect_org_validates_audit_tool_integrity_periodically(app_texts_obj, max_evidence=6):
    """
    STRICT policy for has_org_validates_audit_tool_integrity_periodically:
    - Only returns True when an organizational artifact explicitly states that audit/security tools
      (e.g., SAST/DAST scanners, audit tooling, analysis toolchain) are periodically validated for integrity.
    - This is intentionally conservative to avoid false-positive compliance.
    - Evidence must include BOTH:
        (1) an integrity/verification signal (checksum/hash/signature/attestation/provenance), AND
        (2) a periodicity signal (periodic/regular/monthly/quarterly/annually/scheduled), AND
        (3) an explicit mention of tools/audit tooling/toolchain.
    """
    evidence = []
    hit_files = set()

    integrity_terms = [
        "integrity", "verify integrity", "validation of integrity", "validate integrity",
        "checksum", "sha256", "sha-256", "sha1", "sha-1", "hash", "digest",
        "signature verification", "verify signature", "signed", "gpg",
        "attestation", "provenance", "slsa", "sbom", "cosign", "sigstore",
        "tamper", "tampering", "supply chain",
    ]
    periodic_terms = [
        "periodic", "periodically", "regular", "regularly",
        "monthly", "quarterly", "annually", "weekly",
        "scheduled", "routine", "on a regular basis",
        "monthly", "quarterly", "annual", "weekly",
        "periodic", "periodically", "regularmente", "scheduled",
        "every month", "every quarter", "every year", "every week",
    ]
    tool_terms = [
        "audit tool", "audit tools", "audit tooling",
        "security tool", "security tools", "toolchain",
        "sast", "dast", "mobsf", "semgrep", "trivy",
        "scanner", "scanners", "analysis tool", "analysis tools",
        "audit tool", "audit tools",
        "security tool", "security tools",
    ]

    # Prefer docs/policy/procedure-like files; avoid using code as evidence.
    doc_suffixes = (".md", ".txt", ".yml", ".yaml")
    exclude_path_tokens = [
        "changelog", "release", "releasenote", "license", "third_party", "third-party",
        "privacy", "notice", "contributing",
    ]

    for fpath, content in (app_texts_obj or {}).items():
        if not isinstance(content, str) or not content:
            continue
        norm = fpath.replace("\\", "/").lower()

        if not norm.endswith(doc_suffixes):
            continue
        if any(tok in norm for tok in exclude_path_tokens):
            continue

        low = content.lower()

        # Must mention tools
        if not any(t in low for t in tool_terms):
            continue

        # Must include integrity + periodicity signals (can be anywhere in the document)
        has_integrity = any(t in low for t in integrity_terms)
        has_periodic = any(t in low for t in periodic_terms)

        if not (has_integrity and has_periodic):
            continue

        # Evidence: pick deterministic excerpts (first integrity hit + first periodic hit)
        # Keep at most max_evidence entries across all files.
        def _first_hit(term_list):
            for term in term_list:
                pos = low.find(term)
                if pos != -1:
                    return term, pos
            return None, -1

        iterm, ipos = _first_hit(integrity_terms)
        pterm, ppos = _first_hit(periodic_terms)
        tterm, tpos = _first_hit(tool_terms)

        # Prefer excerpt line containing tool mention if possible, else integrity hit line
        idx = tpos if tpos != -1 else (ipos if ipos != -1 else ppos)
        excerpt = _extract_line_excerpt(content, idx) if idx != -1 else content.strip()[:200]

        evidence.append(ev(
            "SOURCE_CODE_APP",
            f"app.zip:{fpath}",
            "org_audit_tool_integrity_periodic",
            excerpt
        ))
        hit_files.add(fpath)

        if len(evidence) >= max_evidence:
            break

    return {
        "has_evidence": bool(evidence),
        "hit_files": sorted(hit_files),
        "evidence": evidence,
    }

# ============================================================
# Flag verdict logic
# ============================================================

def compute_flag_verdict(
    flag_id,
    org_text_index_obj,
    mobsf_static_obj,
    malware_details_obj,
    has_malware_obj,
    tls_features_obj,
    certificate_info_obj,
    certificate_findings_obj,
    hardcoded_secrets_hits_obj,
    code_features_obj,
    has_default_credentials_obj,
    extra_features_obj,
):
    evidence = []

    # 1) ORG flags
    # STRICT: prevent false-positive compliance for audit-tool integrity periodic validation.
    if flag_id == "has_org_validates_audit_tool_integrity_periodically":
        strict = detect_org_validates_audit_tool_integrity_periodically(app_texts)
        if strict.get("has_evidence"):
            evidence.extend(strict.get("evidence") or [])
            notes = (
                "Explicit evidence was found that the organization periodically validates the integrity "
                "of audit/security tools (e.g., verification of checksums/signatures/attestation "
                "with a defined cadence). "
                f"files={', '.join(strict.get('hit_files') or [])}."
            )
            return {
                "state": "pass",
                "summary": f"{flag_id} = YES",
                "notes": notes,
                "evidence": evidence,
            }

        # Conservative default: NO unless explicitly proven.
        notes = (
            "No explicit evidence was found, within the analyzed artifacts, of an organizational process "
            "that periodically validates the integrity of audit/security tools. "
            "To mark PASS, explicit documentary evidence is required (policy, procedure, or SOP) "
            "that states what is validated (checksums/signatures/attestation/provenance) and at what cadence "
            "(monthly/quarterly/annual/scheduled)."
        )
        return {
            "state": "fail",
            "summary": f"{flag_id} = NO",
            "notes": notes,
            "evidence": [],
        }

    if flag_id in ORG_FLAGS or flag_id.startswith("has_org_") or flag_id.startswith("has_defined_"):
        has_evidence, evidence_sources = find_org_evidence_for_flag(flag_id, org_text_index_obj)
        if has_evidence:
            yn = "YES"
            state = "pass"
            notes = (
                "Explicit references to organizational policies, standards, or procedures were identified "
                f"en sources: {', '.join(evidence_sources)}."
            )
            for src in evidence_sources:
                evidence.append(ev("SOURCE_CODE_APP", f"ORG_INDEX:{src}", "org_policy_reference", "Evidence found via ORG index"))
        else:
            yn = "NO"
            state = "fail"
            notes = (
                "No explicit organizational references were found in the analyzed technical scope "
                "code, README, MD, MobSF, SAST, Trivy. Evidence may exist outside the analyzed scope."
            )
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # 2) Password hashing (REFINED)
    if flag_id in {"has_password_hashing_uses_salts", "has_password_hashing_uses_kdf"}:
        ph = (extra_features_obj.get("password_hashing_features") or {})
        uses_salts = bool(ph.get("has_password_hashing_uses_salts"))
        uses_kdf = bool(ph.get("has_password_hashing_uses_kdf"))
        evidence.extend(ph.get("evidence") or [])

        if flag_id == "has_password_hashing_uses_salts":
            has_feature = uses_salts
            yn = "YES" if has_feature else "NO"
            state = "pass" if has_feature else "fail"
            notes = (
                "Evidence of salt usage for password hashing was detected (e.g., BCrypt.gensalt or a salt variable associated with hashing)."
                f"paths={', '.join(ph.get('paths') or [])}."
                if has_feature else
                "No evidence of salt usage for password hashing was detected (e.g., BCrypt.gensalt or equivalent patterns) in the analyzed code."
            )
            return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

        if flag_id == "has_password_hashing_uses_kdf":
            has_feature = uses_kdf
            yn = "YES" if has_feature else "NO"
            state = "pass" if has_feature else "fail"
            algs = ph.get("kdf_algorithms") or []
            notes = (
                "Evidence of robust KDF / password hashing was detected (e.g., BCrypt.hashpw, PBKDF2, scrypt, Argon2). "
                f"algorithms={algs}; paths={', '.join(ph.get('paths') or [])}."
                if has_feature else
                "No evidence of robust KDF/password hashing usage (BCrypt/PBKDF2/scrypt/Argon2) was detected in the analyzed code."
            )
            return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # 3) Permission-driven rules
    pf = (extra_features_obj.get("permission_features") or {})
    dangerous = pf.get("dangerous_permissions") or []
    priv_like = pf.get("privileged_like_permissions") or []
    special_os = extra_features_obj.get("special_os_permissions_requested") or []

    if flag_id == "has_android_extra_risky_permissions_present":
        has_feature = bool(pf.get("has_dangerous")) or bool(pf.get("has_privileged_like")) or bool(special_os)
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        for p in (dangerous + priv_like + special_os):
            meta = (mobsf_permissions_table or {}).get(p) or {}
            st = meta.get("status", "unknown") if isinstance(meta, dict) else "unknown"
            evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "permission_status", f"status={st}"))
        notes = (
            "Based on MobSF permissions status and special permissions. "
            f"dangerous={dangerous}, privileged_like={priv_like}, special_os={special_os}."
        )
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_requests_only_minimum_permissions":
        has_feature = (not pf.get("has_dangerous")) and (not pf.get("has_privileged_like")) and (len(special_os) == 0)
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"

        if not has_feature:
            for p in dangerous:
                evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "dangerous_permission", "status=dangerous"))
            for p in priv_like:
                evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "privileged_like_permission", "status=privileged_or_signature"))
            for p in special_os:
                evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "special_os_permission", "special_os=true"))
        else:
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:permissions", "permission_summary", "No dangerous, no privileged-like, no special OS permissions"))

        notes = (
            "Conservative criterion: YES only if there are NO dangerous permissions, NO privileged/signature permissions, and NO special permissions: "
            "WRITE_SETTINGS, WRITE_SECURE_SETTINGS, SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES, MANAGE_EXTERNAL_STORAGE. "
            f"status_counts={pf.get('status_counts')}, special_os={special_os}."
        )
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_supports_runtime_permission_management":
        has_dangerous = bool(pf.get("has_dangerous"))
        supports = bool(extra_features_obj.get("supports_runtime_permission_mgmt"))
        if not has_dangerous:
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:permissions", "permission_summary", "No dangerous permissions detected"))
            return {
                "state": "not_applicable",
                "summary": f"{flag_id} = NOT_APPLICABLE",
                "notes": "No dangerous permissions detected in MobSF permissions; the runtime-permissions control does not strictly apply.",
                "evidence": evidence,
            }
        evidence.append(ev("MobSF_STATIC", "mobsf_results.json:permissions", "dangerous_permissions_present", f"dangerous_permissions={dangerous}"))
        if supports:
            evidence.append(ev("SOURCE_CODE_APP", "app.zip:code_scan", "runtime_permissions_api", "requestPermissions/ActivityCompat/etc detected"))
        yn = "YES" if supports else "NO"
        state = "pass" if supports else "fail"
        notes = (
            "Dangerous permissions were detected; therefore runtime-permission handling is required. "
            f"supports_runtime_permission_mgmt={supports}."
        )
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_android_read_write_external_storage":
        has_feature = any(p in requested_permissions for p in [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        ])
        if has_feature:
            for p in [
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
            ]:
                if p in requested_permissions:
                    meta = mobsf_permissions_table.get(p, {}) if isinstance(mobsf_permissions_table, dict) else {}
                    evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "permission_status", f"status={meta.get('status', 'unknown')}"))
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = (
            "Based on requested permissions from MobSF permissions and uses_permission_list. "
            f"external_storage_perms_present={has_feature}."
        )
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_permissions_protected_with_signature_level":
        msig = extra_features_obj.get("manifest_signature_level") or {}
        if not msig.get("available"):
            return {
                "state": "unknown",
                "summary": f"{flag_id} = UNKNOWN",
                "notes": "AndroidManifest.xml was not found in the source code; MobSF does not provide a conclusive signal for this flag.",
                "evidence": []
            }
        has_feature = bool(msig.get("is_true"))
        evidence.extend(msig.get("evidence") or [])
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        notes = (
            "Heuristic in the source-code AndroidManifest.xml: presence of protectionLevel=signature in custom permissions. "
            f"manifest_signature_level_defined={has_feature}."
        )
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # 4) Key flags
    if flag_id == "has_hardcoded_credentials":
        has_feature = bool(hardcoded_secrets_hits_obj) or code_features_obj.get("has_hardcoded_password_literal") or has_default_credentials_obj
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes_parts = []
        if hardcoded_secrets_hits_obj:
            notes_parts.append(f"MobSF identified {len(hardcoded_secrets_hits_obj)} secret/credential findings.")
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:secrets/findings", "hardcoded_secrets", f"hits={len(hardcoded_secrets_hits_obj)}"))
        if code_features_obj.get("has_hardcoded_password_literal"):
            notes_parts.append("Literal password assignments were observed in the code.")
            evidence.append(ev("SOURCE_CODE_APP", "app.zip:code_scan", "password_literal", 'password = "..." pattern'))
        if has_default_credentials_obj:
            notes_parts.append("The README documents demo credentials: admin / admin123.")
            evidence.append(ev("SOURCE_CODE_APP", "app.zip:README.md", "default_credentials", "demo username/password documented"))
        if not notes_parts:
            notes_parts.append("No evidence of hardcoded credentials was found in MobSF nor in code or README.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": " ".join(notes_parts), "evidence": evidence}

    if flag_id == "has_malware_detections":
        has_feature = bool(has_malware_obj)
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = "MobSF reports malware_permissions." if has_feature else "MobSF does not report evidence of malware_permissions."
        if malware_details_obj:
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:malware_permissions", "malware_permissions", f"items={len(malware_details_obj)}"))
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # TLS pinning flags
    if flag_id in {
        "has_tls_ssl_pinning_implemented",
        "has_ssl_cert_pinning_implemented",
        "has_ssl_pinning_findings_severity_good",
        "has_android_ssl_pinning_present",
        "has_android_ssl_pinning_detected",
    }:
        has_pinning = bool(tls_features_obj.get("has_android_ssl_pinning_block") or tls_features_obj.get("has_secure_ssl_pinning_message"))
        yn = "YES" if has_pinning else "NO"
        state = "pass" if has_pinning else "fail"
        meta = tls_features_obj.get("android_ssl_pinning_metadata", {})
        files = tls_features_obj.get("android_ssl_pinning_files", [])
        if tls_features_obj.get("has_android_ssl_pinning_block"):
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:code_analysis.findings.android_ssl_pinning", "android_ssl_pinning", f"files={len(files)}"))
        notes_parts = []
        if has_pinning:
            notes_parts.append("MobSF reports android_ssl_pinning or appsec.secure, indicating pinning.")
            if meta:
                notes_parts.append(f"metadata: severity={meta.get('severity')}, masvs={meta.get('masvs')}.")
            if files:
                notes_parts.append(f"files: {', '.join(files)}.")
        else:
            notes_parts.append("No evidence of SSL pinning found in MobSF.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": " ".join(notes_parts), "evidence": evidence}

    if flag_id == "has_os_time_source":
        ots = (extra_features_obj.get("os_time_source_evidence") or {})
        has_feature = bool(ots.get("has_os_time_source"))
        evidence.extend(ots.get("evidence") or [])

        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"

        if has_feature:
            paths = ots.get("paths") or []
            notes = (
                "Detected use of an operating-system-provided time source "
                "in the source code (e.g., System.currentTimeMillis/SystemClock/Instant.now), "
                "which indicates explicit reliance on the OS clock for timestamps."
            )
            if paths:
                notes += " Evidence in: " + ", ".join(paths) + "."
        else:
            notes = (
                "No calls to operating-system time sources were detected "
                "System.currentTimeMillis/SystemClock/Instant.now in the analyzed source code."
            )

        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # Insecure RNG (MobSF static finding: code_analysis.findings.android_insecure_random)
    if flag_id == "has_android_insecure_random_rng":
        ca = (mobsf_static_obj or {}).get("code_analysis") or {}
        findings = ca.get("findings") or {}
        air = findings.get("android_insecure_random") or {}
        if not isinstance(air, dict):
            air = {}

        files = air.get("files") or {}
        meta = air.get("metadata") or {}
        if not isinstance(files, dict):
            files = {}

        total_occ = 0
        file_summaries = []
        for p in sorted(files.keys()):
            v = files.get(p)
            try:
                c = int(str(v).strip())
            except Exception:
                c = 1
            total_occ += max(0, c)
            file_summaries.append(f"{p} ({c})")

            # Deterministic evidence expansion: one evidence entry per occurrence (bounded by total_occ)
            for i in range(max(0, c)):
                evidence.append(ev(
                    "MobSF_STATIC",
                    f"mobsf_results.json:code_analysis.findings.android_insecure_random.files.{p}",
                    "android_insecure_random",
                    f"{p} occurrence {i+1}/{c}"
                ))

        has_feature = total_occ > 0
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"

        cwe = str(meta.get("cwe") or "CWE-330").strip()
        masvs = str(meta.get("masvs") or "MSTG-CRYPTO-6").strip()
        cvss = meta.get("cvss")
        owasp = str(meta.get("owasp-mobile") or "").strip()

        if has_feature:
            notes = (
                f"MobSF finding android_insecure_random ({cwe}, MASVS/{masvs}). "
                f"Files: {', '.join(file_summaries)}. "
            )
            if cvss is not None:
                notes += f"CVSS {cvss}; "
            if owasp:
                notes += f"OWASP Mobile {owasp}."
            notes = notes.strip()
        else:
            notes = "MobSF does not report android_insecure_random in code_analysis.findings."

        return {
            "state": state,
            "summary": f"{flag_id} = {yn}",
            "notes": notes,
            "evidence": evidence,
            "evidence_count_override": int(total_occ),
        }

    
    # Certificate flags (MobSF certificate_analysis)
    if flag_id.startswith("has_cert_"):
        ca = (mobsf_static_obj or {}).get("certificate_analysis") or {}
        info_text = str(ca.get("certificate_info") or "")
        findings_raw = ca.get("certificate_findings") or []

        # Normalize findings into (severity, description, title) tuples (best-effort).
        findings_norm = []
        if isinstance(findings_raw, list):
            for item in findings_raw:
                if isinstance(item, (list, tuple)) and len(item) >= 3:
                    findings_norm.append((str(item[0]), str(item[1]), str(item[2])))
                elif isinstance(item, dict):
                    findings_norm.append((str(item.get("severity") or item.get("level") or ""), str(item.get("description") or ""), str(item.get("title") or item.get("name") or "")))
                else:
                    findings_norm.append(("", str(item), ""))
        elif isinstance(findings_raw, dict):
            # rare schema: dict keyed by id/title
            for k, v in findings_raw.items():
                findings_norm.append(("", str(v), str(k)))

        info_low = info_text.lower()
        findings_low = " ".join([(" ".join(t)).lower() for t in findings_norm])

        # Signals
        has_code_sign = ("signed application" in findings_low) or ("code signing certificate" in findings_low)
        has_janus = ("janus" in findings_low) or ("v1 signature scheme" in findings_low)
        has_debug_cert = (
            ("debug certificate" in findings_low) or
            ("application signed with debug certificate" in findings_low) or
            ("cn=android debug" in info_low) or
            ("x.509 subject: cn=android debug" in info_low)
        )
        has_sha1 = ("sha1withrsa" in info_low) or ("hash algorithm: sha1" in info_low) or ("sha1withrsa" in findings_low) or (" sha1 " in findings_low)
        has_android_debug_subject = ("x.509 subject: cn=android debug" in info_low) or ("issuer: cn=android debug" in info_low)

        # Long-term validity: parse Valid From/To if present; fallback heuristic year >= +10y
        has_long_term = False
        try:
            m_from = re.search(r"valid from:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", info_low)
            m_to = re.search(r"valid to:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", info_low)
            if m_from and m_to:
                d1 = datetime.fromisoformat(m_from.group(1))
                d2 = datetime.fromisoformat(m_to.group(1))
                has_long_term = (d2 - d1).days >= 3650  # >= 10 years
            else:
                has_long_term = ("valid to:" in info_low and any(y in info_low for y in ["203", "204", "205"]))
        except Exception:
            has_long_term = ("valid to:" in info_low and any(y in info_low for y in ["203", "204", "205"]))

        if not ca:
            return {
                "state": "unknown",
                "summary": f"{flag_id} = UNKNOWN",
                "notes": "certificate_analysis was not found in MobSF; cannot determine.",
                "evidence": []
            }

        # Map flags to features (negative unless stated otherwise)
        if flag_id == "has_cert_signed_with_code_signing_cert":
            has_feature = has_code_sign
            state = "pass" if has_feature else "fail"
        elif flag_id == "has_cert_v1_signature_present_janus_risk":
            has_feature = has_janus
            state = "fail" if has_feature else "pass"
        elif flag_id == "has_cert_signed_with_debug_certificate":
            has_feature = has_debug_cert
            state = "fail" if has_feature else "pass"
        elif flag_id == "has_cert_uses_sha1_signature_algorithm":
            has_feature = has_sha1
            state = "fail" if has_feature else "pass"
        elif flag_id == "has_cert_x509_subject_android_debug":
            has_feature = has_android_debug_subject
            state = "fail" if has_feature else "pass"
        elif flag_id == "has_cert_validity_long_term":
            has_feature = has_long_term
            state = "fail" if has_feature else "pass"
        else:
            # Unknown cert flag id
            has_feature = False
            state = "unknown"

        yn = "YES" if has_feature else "NO"

        # Evidence: add one key evidence item + up to 3 matching findings (deterministic)
        evidence.append(ev("MobSF_STATIC", "mobsf_results.json:certificate_analysis.certificate_info", "certificate_info", info_text[:200].replace("\n", " ")))
        if findings_norm:
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:certificate_analysis.certificate_findings", "certificate_findings_count", f"items={len(findings_norm)}"))

        # Deterministic finding excerpts by relevance
        match_terms = []
        if flag_id == "has_cert_signed_with_debug_certificate":
            match_terms = ["debug certificate", "android debug", "cn=android debug"]
        elif flag_id == "has_cert_v1_signature_present_janus_risk":
            match_terms = ["janus", "v1 signature scheme", "v1 signature"]
        elif flag_id == "has_cert_uses_sha1_signature_algorithm":
            match_terms = ["sha1withrsa", "sha1"]
        elif flag_id == "has_cert_signed_with_code_signing_cert":
            match_terms = ["signed application", "code signing certificate"]
        elif flag_id == "has_cert_validity_long_term":
            match_terms = ["valid to", "valid from"]
        elif flag_id == "has_cert_x509_subject_android_debug":
            match_terms = ["x.509 subject", "issuer", "android debug"]

        added = 0
        for sev, desc, title in findings_norm:
            blob = f"{sev} {desc} {title}".lower()
            if match_terms and not any(t in blob for t in match_terms):
                continue
            excerpt = (title + " — " + desc).strip(" —")
            excerpt = re.sub(r"\s+", " ", excerpt)
            if len(excerpt) > 200:
                excerpt = excerpt[:200] + "..."
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:certificate_analysis.certificate_findings", "certificate_finding_match", excerpt))
            added += 1
            if added >= 3:
                break

        notes = (
            "Based on MobSF certificate_analysis. Signals: "
            f"debug_cert={has_debug_cert}, janus_risk={has_janus}, sha1={has_sha1}, "
            f"x509_android_debug={has_android_debug_subject}, long_term_validity={has_long_term}."
        )

        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # Secrets / CI/CD keys
    if flag_id == "has_secrets_secure_keystore_env_vars":
        paths = extra_features_obj.get("keystore_env_paths") or []
        has_feature = bool(paths)
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        if paths:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "gradle_signing_env", "signingConfigs uses System.getenv"))
        notes = (f"Gradle uses System.getenv for signingConfigs en: {', '.join(paths)}." if has_feature else "No System.getenv detected for signingConfigs in Gradle.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_signing_creds_not_hardcoded":
        has_hardcoded = bool(extra_features_obj.get("has_signing_creds_hardcoded"))
        has_env_keystore = bool(extra_features_obj.get("keystore_env_paths"))
        has_feature = (not has_hardcoded) and has_env_keystore
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        notes_parts = []
        if has_env_keystore:
            notes_parts.append("Signing credentials are obtained via environment variables.")
        if has_hardcoded:
            notes_parts.append("Possible hardcoded credentials detected in Gradle.")
        if not notes_parts:
            notes_parts.append("Insufficient evidence regarding signing credential management.")
        if has_env_keystore:
            evidence.append(ev("SOURCE_CODE_APP", "app.zip:gradle", "signing_env", "System.getenv used for signing configs"))
        if has_hardcoded:
            evidence.append(ev("SOURCE_CODE_APP", "app.zip:gradle", "signing_hardcoded", "storePassword/keyPassword literal detected"))
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": " ".join(notes_parts), "evidence": evidence}

    if flag_id == "has_secure_cicd_key_management":
        env_paths = extra_features_obj.get("keystore_env_paths") or []
        has_signing_hardcoded = bool(extra_features_obj.get("has_signing_creds_hardcoded"))
        has_feature = bool(env_paths) and not has_signing_hardcoded
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        notes_parts = []
        if env_paths:
            notes_parts.append(f"Gradle obtiene secrets por System.getenv en: {', '.join(env_paths)}.")
            for p in env_paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "gradle_env", "System.getenv for signing configs"))
        else:
            notes_parts.append("No System.getenv observed for signing secrets in Gradle.")
        if has_signing_hardcoded:
            notes_parts.append("Possible hardcoded secrets detected in Gradle; rating downgraded.")
            evidence.append(ev("SOURCE_CODE_APP", "app.zip:gradle", "gradle_hardcoded_secret", "storePassword/keyPassword literal"))
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": " ".join(notes_parts), "evidence": evidence}

    if flag_id == "has_release_minify_disabled":
        has_feature = bool(extra_features_obj.get("release_minify_disabled"))
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        if has_feature:
            evidence.append(ev("SOURCE_CODE_APP", "app.zip:gradle", "minifyEnabled", "minifyEnabled false in release"))
        notes = ("minifyEnabled false was found in release." if has_feature else "minifyEnabled false was not found in release.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # Manifest flags
    if flag_id in {"has_manifest_debuggable_true", "has_android_debuggable_enabled"}:
        m = extra_features_obj.get("manifest_debuggable") or {}
        has_feature = bool(m.get("is_true"))
        evidence.extend(m.get("evidence") or [])
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = 'android:debuggable="true" detected in the MobSF APK manifest or in the primary source-code AndroidManifest.xml.' if has_feature else 'No android:debuggable="true" detected in the MobSF APK manifest nor in the primary source-code AndroidManifest.xml.'
        if m.get("mismatch"):
            notes += " Mismatch entre MobSF APK manifest y Primary AndroidManifest.xml; posible manifest-merging o build-variant."
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_manifest_backup_enabled":
        m = extra_features_obj.get("manifest_allow_backup") or {}
        has_feature = bool(m.get("is_true"))
        evidence.extend(m.get("evidence") or [])
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = 'android:allowBackup="true" detected in the MobSF APK manifest or in the primary source-code AndroidManifest.xml.' if has_feature else 'No android:allowBackup="true" detected in the MobSF APK manifest nor in the primary source-code AndroidManifest.xml.'
        if m.get("mismatch"):
            notes += " Mismatch entre MobSF APK manifest y Primary AndroidManifest.xml; posible manifest-merging o build-variant."
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_manifest_allow_clear_text_traffic_true":
        m = extra_features_obj.get("manifest_cleartext") or {}
        has_feature = bool(m.get("is_true"))
        evidence.extend(m.get("evidence") or [])
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = 'usesCleartextTraffic="true" detected in MobSF or in the primary source-code AndroidManifest.xml.' if has_feature else 'No usesCleartextTraffic="true" detected in MobSF nor in the primary source-code AndroidManifest.xml.'
        if m.get("mismatch"):
            notes += " Mismatch entre MobSF APK manifest y Primary AndroidManifest.xml; posible manifest-merging o build-variant."
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_manifest_exports_components_insecurely":
        me = extra_features_obj.get("manifest_exports") or {}
        if not me.get("available"):
            return {"state": "unknown", "summary": f"{flag_id} = UNKNOWN", "notes": "AndroidManifest.xml was not found in the source code; MobSF does not provide a conclusive signal for this flag.", "evidence": []}
        count = int(me.get("count") or 0)
        evidence.extend(me.get("evidence") or [])
        has_feature = count > 0
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = (f"Detected {count} exported components without explicit android:exported in the primary source-code AndroidManifest.xml (conservative heuristic)." if has_feature else "No insecure exports detected in the primary source-code AndroidManifest.xml (conservative heuristic).")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_manifest_services_explicit_accessibility_attributes":
        msrv = extra_features_obj.get("manifest_services_explicit_accessibility") or {}
        if not msrv.get("available"):
            return {
                "state": "unknown",
                "summary": f"{flag_id} = UNKNOWN",
                "notes": "AndroidManifest.xml was not found in the source code; MobSF does not provide a conclusive signal for this flag.",
                "evidence": []
            }

        total = int(msrv.get("total_services") or 0)
        missing = int(msrv.get("missing_exported_count") or 0)

        evidence.extend(msrv.get("evidence") or [])

        if total == 0:
            return {
                "state": "not_applicable",
                "summary": f"{flag_id} = NOT_APPLICABLE",
                "notes": "No <service> entries detected in the primary AndroidManifest.xml; control not applicable.",
                "evidence": evidence
            }

        has_feature = (missing == 0)
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"

        if has_feature:
            notes = (
                "All <service> entries in the primary AndroidManifest.xml explicitly declare android:exported. "
                "This control makes the service IPC exposure explicit and reduces export ambiguity."
            )
        else:
            notes = (
                f"Detected {missing} of {total} <service> without explicit android:exported in the primary AndroidManifest.xml. "
                "Deterministic heuristic based on <service ...> start-tags."
            )

        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    
    if flag_id == "has_exported_broadcast_receivers_without_permission":
        rcv = (extra_features_obj.get("exported_broadcast_receivers_without_permission") or {})

        if not rcv.get("available", False):
            return {
                "state": "unknown",
                "summary": f"{flag_id} = UNKNOWN",
                "notes": "Unable to evaluate broadcast receiver export (AndroidManifest.xml not available).",
                "evidence": []
            }

        total = int(rcv.get("total_receivers", 0))
        insecure = int(rcv.get("exported_receivers_without_permission_count", 0))
        exported_effective = int(rcv.get("exported_receivers_count", 0))

        evidence.extend(rcv.get("evidence", []) or [])

        if total == 0:
            return {
                "state": "not_applicable",
                "summary": f"{flag_id} = NOT_APPLICABLE",
                "notes": "No <receiver> entries detected in the primary AndroidManifest.xml; control not applicable.",
                "evidence": evidence,
            }

        # NEGATIVE condition: presence implies FAIL
        has_feature = insecure > 0
        yn = "YES" if has_feature else "NO"

        # Sample receiver for explanatory notes (prefer exported=false)
        sample = None
        summaries = rcv.get("receiver_summaries", []) or []
        for s in summaries:
            if str(s.get("exported_attr", "")).lower() == "false":
                sample = s
                break
        if sample is None and summaries:
            sample = summaries[0]

        notes = (
            f"Receivers total={total}; exported_effective={exported_effective}; exported_without_permission={insecure}. "
            "Export logic: android:exported='false' is treated as NOT exported even if an <intent-filter> exists. "
            "If android:exported is absent, an <intent-filter> implies effective export."
        )
        if sample:
            notes += f" Deterministic example: {sample.get('name') or '(unnamed)'} exported={sample.get('exported_attr') or '(absent)'}."

        return {
            "state": "fail" if has_feature else "pass",
            "summary": f"{flag_id} = {yn}",
            "notes": notes,
            "evidence": evidence,
        }



    if flag_id == "has_manifest_custom_permission_defined":
        mp = extra_features_obj.get("manifest_custom_permissions") or {}
        if not mp.get("available"):
            return {"state": "unknown", "summary": f"{flag_id} = UNKNOWN", "notes": "AndroidManifest.xml was not found in the source code; MobSF does not provide a conclusive signal for this flag.", "evidence": []}
        count = int(mp.get("count") or 0)
        evidence.extend(mp.get("evidence") or [])
        has_feature = count > 0
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        notes = ("Custom <permission> detected in the primary manifest." if has_feature else "No custom <permission> detected in the primary manifest.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_prevention_against_reverse_engineering":
        rev = extra_features_obj.get("reverse_eng_features") or {}
        has_minify = bool(rev.get("has_minify_enabled_release"))
        paths = rev.get("paths") or []
        yn = "YES" if has_minify else "NO"
        state = "pass" if has_minify else "fail"
        if has_minify:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "minifyEnabled", "minifyEnabled true in release"))
        notes = ("minifyEnabled true en release." if has_minify else "No minifyEnabled true detected in release.")
        if paths:
            notes += " Paths: " + ", ".join(sorted(set(paths)))
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_webview_remote_content":
        paths = extra_features_obj.get("webview_remote_paths") or []
        has_feature = bool(paths)
        if has_feature:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "WebView.loadUrl", "loadUrl(http/https) detected"))
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = (f"WebView.loadUrl http(s) en: {', '.join(paths)}." if has_feature else "No WebView.loadUrl to http(s) detected.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # Robustness indicators
    if flag_id == "has_buffer_overflow_vulnerabilities":
        has_feature = bool(extra_features_obj.get("has_buffer_overflow_evidence"))
        if has_feature:
            evidence.append(ev("SAST_MERGED", "sast-findings.zip:merged.sarif", "keyword_match", "buffer overflow keyword detected"))
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = ("References to buffer overflow were observed in SAST or MobSF." if has_feature else "No references to buffer overflow were observed.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_race_condition_vulnerabilities":
        has_feature = bool(extra_features_obj.get("has_race_condition_evidence"))
        if has_feature:
            evidence.append(ev("SAST_MERGED", "sast-findings.zip:merged.sarif", "keyword_match", "race condition keyword detected"))
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = ("References to race condition were observed in SAST or MobSF." if has_feature else "No references to race condition were observed.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_out_of_bounds_vulnerabilities":
        has_feature = bool(extra_features_obj.get("has_oob_evidence"))
        if has_feature:
            evidence.append(ev("SAST_MERGED", "sast-findings.zip:merged.sarif", "keyword_match", "out-of-bounds keyword detected"))
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = ("References to out-of-bounds were observed in SAST or MobSF." if has_feature else "No references to out-of-bounds were observed.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_memory_corruption_vulnerabilities":
        has_feature = bool(extra_features_obj.get("has_memory_corruption_evidence"))
        if has_feature:
            evidence.append(ev("SAST_MERGED", "sast-findings.zip:merged.sarif", "keyword_match", "memory corruption keyword detected"))
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = ("References to memory corruption or use-after-free were observed." if has_feature else "No references to memory corruption were observed.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_integer_arithmetic_vulnerabilities":
        has_feature = bool(extra_features_obj.get("has_integer_vuln_evidence"))
        if has_feature:
            evidence.append(ev("SAST_MERGED", "sast-findings.zip:merged.sarif", "keyword_match", "integer overflow/underflow keyword detected"))
        yn = "YES" if has_feature else "NO"
        state = "fail" if has_feature else "pass"
        notes = ("References to integer overflow/underflow were observed." if has_feature else "No references to integer arithmetic vulnerabilities were observed.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # Kill switch / safe mode
    if flag_id == "has_runtime_global_kill_switch_for_security_incidents":
        kill_safe = extra_features_obj.get("kill_safe_features") or {}
        has_feature = bool(kill_safe.get("has_kill_switch_evidence"))
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        sources = kill_safe.get("kill_switch_sources") or []
        if has_feature:
            for s in sources:
                evidence.append(ev("SOURCE_CODE_APP", f"ORG_INDEX:{s}", "kill_switch_keyword", "kill switch keyword detected"))
        notes = (f"Kill-switch evidence in: {', '.join(sources)}." if has_feature else "No evidence of a kill switch.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_safe_mode_degraded_functionality_design":
        kill_safe = extra_features_obj.get("kill_safe_features") or {}
        has_feature = bool(kill_safe.get("has_safe_mode_evidence"))
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        sources = kill_safe.get("safe_mode_sources") or []
        if has_feature:
            for s in sources:
                evidence.append(ev("SOURCE_CODE_APP", f"ORG_INDEX:{s}", "safe_mode_keyword", "safe mode keyword detected"))
        notes = (f"Safe/degraded mode evidence in: {', '.join(sources)}." if has_feature else "No evidence of safe/degraded mode.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_controls_protecting_temporary_compiled_data":
        tmp = extra_features_obj.get("temp_compiled_features") or {}
        paths = tmp.get("protection_paths") or []
        has_feature = bool(paths)
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        if has_feature:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "temp_protection", "temp/cache encrypted/protected keywords"))
        notes = (f"Heuristic: protection of temporary files in: {', '.join(paths)}." if has_feature else "No clear evidence of temporary-file protection.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_temporary_compiled_data_securely_deleted":
        tmp = extra_features_obj.get("temp_compiled_features") or {}
        paths = tmp.get("secure_delete_paths") or []
        has_feature = bool(paths)
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        if has_feature:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "temp_cleanup", "cleanup/delete keywords"))
        notes = (f"Heuristic: cleanup/deletion of temporary files in: {', '.join(paths)}." if has_feature else "No clear evidence of temporary-file deletion.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # Logout/session/endpoints
    if flag_id == "has_supports_manual_logout":
        lf = extra_features_obj.get("logout_session_features") or {}
        paths = lf.get("logout_paths") or []
        has_feature = bool(lf.get("has_manual_logout"))
        if has_feature:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "logout()", "logout() method detected"))
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        notes = (f"logout() detectado en: {', '.join(paths)}." if has_feature else "No se detectó logout() manual.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_clears_local_session_data_on_logout":
        lf = extra_features_obj.get("logout_session_features") or {}
        paths = lf.get("logout_paths") or []
        has_feature = bool(lf.get("has_clears_local_prefs_on_logout"))
        if has_feature:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "clearUserPreferencesData", "clears local prefs on logout"))
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        notes = ("Logout limpia preferencias/datos locales." if has_feature else "No clear evidence of local-session cleanup in logout().")
        if paths:
            notes += f" Paths: {', '.join(paths)}."
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_clears_cookies_on_logout":
        lf = extra_features_obj.get("logout_session_features") or {}
        paths = lf.get("cookie_clear_paths") or []
        has_feature = bool(lf.get("has_clears_cookies_on_logout"))
        if has_feature:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "cookie_clear", "removeAllCookies/clearCookies detected"))
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        notes = ("Cookie cleanup detected on logout." if has_feature else "No cookie-cleanup patterns detected on logout.")
        if paths:
            notes += f" Paths: {', '.join(paths)}."
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_session_id_assigned_from_server_cookie":
        lf = extra_features_obj.get("logout_session_features") or {}
        paths = lf.get("session_cookie_paths") or []
        has_feature = bool(lf.get("has_session_cookie_based_auth"))
        if has_feature:
            for p in paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "cookie_session", "CookieManager/JSESSIONID usage detected"))
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        notes = ("Indicators of a cookie-based session via JSESSIONID or CookieManager." if has_feature else "No clear evidence of a cookie-based session.")
        if paths:
            notes += f" Paths: {', '.join(paths)}."
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_logout_invalidates_server_session":
        lf = extra_features_obj.get("logout_session_features") or {}
        has_feature = bool(lf.get("has_logout_invalidates_server_session"))
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        if has_feature:
            evidence.append(ev("SOURCE_CODE_APP", "app.zip:code_scan", "/logout", "logout endpoint referenced"))
        notes = ("Logout appears to invalidate the server session; /logout detected." if has_feature else "No evidence of server-side session invalidation.")
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    if flag_id == "has_endpoint_requires_user_authentication":
        ea = extra_features_obj.get("endpoint_auth_features") or {}
        has_basic_auth = bool(ea.get("has_basic_auth_header_in_rest_service"))
        rest_paths = ea.get("rest_service_builder_paths") or []
        auth_paths = ea.get("authorization_header_paths") or []
        has_feature = has_basic_auth
        if has_basic_auth:
            for p in rest_paths:
                evidence.append(ev("SOURCE_CODE_APP", f"app.zip:{p}", "Authorization: Basic", "RestServiceBuilder adds Authorization header"))
        yn = "YES" if has_feature else "NO"
        state = "pass" if has_feature else "fail"
        if has_feature:
            notes = "RestServiceBuilder adds Authorization: Basic when credentials are present."
        else:
            notes = "No conclusive evidence that endpoints require user authentication via an Authorization: Basic pattern."
        if rest_paths:
            notes += f" RestServiceBuilder: {', '.join(rest_paths)}."
        if (not has_feature) and auth_paths:
            notes += f" Authorization usado en: {', '.join(auth_paths)}."
        return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": evidence}

    # ========================================================
    # Fallback
    # ========================================================
    has_feature = False
    if "vulnerab" in flag_id or "hardcoded" in flag_id or "malware" in flag_id or "debuggable" in flag_id:
        NEGATIVE_FLAGS.add(flag_id)
    elif flag_id.startswith("has_org_") or flag_id.startswith("has_defined_") or "encrypted" in flag_id or "tls" in flag_id or "pinning" in flag_id or "secure" in flag_id or "protection" in flag_id:
        POSITIVE_FLAGS.add(flag_id)

    yn = "YES" if has_feature else "NO"
    if yn == "YES":
        state = "fail" if flag_id in NEGATIVE_FLAGS else "pass"
    else:
        state = "pass" if flag_id in NEGATIVE_FLAGS else "fail"

    notes = (
        "Fallback verdict: no specific rule for this flag is implemented in the generator; "
        "absence of explicit evidence is assumed in the analyzed technical artifacts."
    )
    return {"state": state, "summary": f"{flag_id} = {yn}", "notes": notes, "evidence": []}

# ============================================================
# Build vision360_fingerprint.json and vision360_output.json
# ============================================================

vision360_fingerprint = {
  "schema_version": 1,
  "project": {
    "name": "Android app",
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "sources": [
      "MobSF_STATIC",
      "MobSF_DYNAMIC",
      "SAST_MERGED",
      "SAST_SEMGREP",
      "TRIVY",
      "AGENT_PAYLOAD",
      "SOURCE_CODE_APP"
    ]
  },
  "groups": groups,
  "flags": []
}

def id_to_title(flag_id):
    if flag_id.startswith("has_"):
        s = flag_id.replace("has_", "")
        prefix = "Has "
    elif flag_id.startswith("uses_"):
        s = flag_id.replace("uses_", "")
        prefix = "Uses "
    else:
        s = flag_id
        prefix = ""
    parts = s.split("_")
    return prefix + " ".join(p.capitalize() for p in parts)

# ============================================================
# Overrides (stable schema + curated wording for specific flags)
# ============================================================

TITLE_OVERRIDES = {
    "has_android_insecure_random_rng": "Uses Insecure Random Number Generator (android_insecure_random)",
    "has_exported_broadcast_receivers_without_permission": "Exported Broadcast Receivers Without Permission",
}

DESCRIPTION_OVERRIDES = {
    "has_android_insecure_random_rng": "Detects insecure random number generator usage (CWE-330), as reported by MobSF (MSTG-CRYPTO-6).",
    "has_exported_broadcast_receivers_without_permission": "Detects any <receiver> in AndroidManifest.xml with android:exported=\"true\" and no android:permission attribute, which may allow untrusted broadcasts to reach privileged app code.",
}

RATIONALE_OVERRIDES = {
    "has_android_insecure_random_rng": "Weak RNG undermines key/nonce/token unpredictability and can break cryptographic guarantees.",
    "has_exported_broadcast_receivers_without_permission": "Exported receivers without permission can be invoked by other apps, enabling intent spoofing and unauthorized triggering of receiver logic. Secure apps constrain receivers via permissions, non-export, or explicit intent scoping.",
}

PRIMARY_SOURCES_OVERRIDES = {
    "has_android_insecure_random_rng": ["MobSF_STATIC"],
    "has_exported_broadcast_receivers_without_permission": ["SOURCE_CODE_APP"],
}

def infer_severity(flag_id):
    low = flag_id.lower()
    if "os_time_source" in low:
        return "medium"
    if "manifest_services_explicit_accessibility" in low:
        return "medium"
    if "exported_broadcast_receivers_without_permission" in low:
        return "high"
    if any(x in low for x in ["hardcoded", "malware", "debuggable", "vulnerab", "ephi", "auth_tokens_in_plaintext", "keys_in_plaintext"]):
        return "high"
    if any(x in low for x in ["tls", "pinning", "encrypted", "keystore", "signing", "secure_cicd"]):
        return "high"
    if "endpoint_requires_user_authentication" in low:
        return "high"
    if "insecure_random" in low:
        return "high"
    if "password_hashing" in low:
        return "high"
    if "org_" in low:
        return "medium"
    return "low"

vision360_output_flags = {}

# raw app scan hashes (deterministic)
app_code_scan = {"files": {}}
for path, content in app_texts.items():
    safe_content = content if isinstance(content, str) else str(content)
    h = hashlib.sha256(safe_content.encode("utf-8", errors="ignore")).hexdigest()
    app_code_scan["files"][path] = {
        "length": len(safe_content),
        "sha256": h,
        "snippet_start": safe_content[:400],
        "snippet_end": safe_content[-400:] if len(safe_content) > 800 else ""
    }

for group in groups:
    gid = group.get("id")
    for flag_id in group.get("flags", []):
        flag_verdict = compute_flag_verdict(
            flag_id,
            org_text_index,
            mobsf_static,
            malware_details,
            has_malware,
            tls_features,
            certificate_info,
            certificate_findings,
            hardcoded_secrets_hits,
            code_features,
            has_default_credentials,
            extra_features,
        )

        description = (
            f"Evaluates whether the condition '{flag_id}' is met in the application or in the "
            f"configurations/source-code/processes associated within group {gid}."
        )

        severity = infer_severity(flag_id)
        evidence = flag_verdict.get("evidence") or []

        evidence_count_override = flag_verdict.get("evidence_count_override")
        evidence_count = int(evidence_count_override) if evidence_count_override is not None else len(evidence)

        title = TITLE_OVERRIDES.get(flag_id, id_to_title(flag_id))
        description_final = DESCRIPTION_OVERRIDES.get(flag_id, description)
        rationale_final = RATIONALE_OVERRIDES.get(
            flag_id,
            "Verdict based on structured evidence from MobSF, SAST, and source code, combined with deterministic/heuristic rules."
        )
        primary_sources = PRIMARY_SOURCES_OVERRIDES.get(flag_id, ["MobSF_STATIC", "SOURCE_CODE_APP"])

        flag_obj = {
          "id": flag_id,
          "group": gid,
          "title": title,
          "description": description_final,
          "severity": severity,
          "expected_state": "good",
          "rationale": rationale_final,
          "primary_sources": primary_sources,
          "app_verdict": {
            "state": flag_verdict["state"],
            "summary": flag_verdict["summary"],
            "notes": flag_verdict["notes"],
            "evidence": evidence,
            "evidence_count": evidence_count,
          }
        }
        vision360_fingerprint["flags"].append(flag_obj)

        vision360_output_flags[flag_id] = {
            "summary": flag_verdict["summary"],
            "state": flag_verdict["state"],
            "notes": flag_verdict["notes"],
            "evidence": evidence,
            "evidence_count": evidence_count,
        }

vision360_output = {
  "schema_version": 1,
  "project": {
    "name": "Android app",
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "source_artifacts": {
      "mobsf_static": "mobsf-report.zip/mobsf_results.json",
      "mobsf_dynamic": "mobsf-dynamic-report.zip/mobsf_dynamic_results.json",
      "sast_merged": "sast-findings.zip/merged.sarif",
      "sast_semgrep": "sast-findings.zip/semgrep.sarif",
      "trivy": "trivy-payload.zip/trivy.json",
      "agent_payload": "trivy-payload.zip/agent_payload.json",
      "app_source": "app.zip"
    }
  },
  "flags": vision360_output_flags,
  "raw": {}
}

# include raw for audit traceability
vision360_output["raw"]["mobsf_static_full"] = mobsf_static
vision360_output["raw"]["mobsf_dynamic_full"] = mobsf_dynamic
vision360_output["raw"]["sast_merged_full"] = sast_merged
vision360_output["raw"]["sast_semgrep_full"] = sast_semgrep
vision360_output["raw"]["trivy_full"] = trivy
vision360_output["raw"]["agent_payload_full"] = agent_payload
vision360_output["raw"]["app_code_scan"] = app_code_scan

vision360_output["raw"]["permission_features"] = {
    "requested_permissions": perm_features["requested_permissions"],
    "status_counts": perm_features["status_counts"],
    "dangerous_permissions": perm_features["dangerous_permissions"],
    "signature_permissions": perm_features["signature_permissions"],
    "privileged_permissions": perm_features["privileged_permissions"],
    "privileged_like_permissions": perm_features["privileged_like_permissions"],
    "special_os_permissions_requested": special_os_permissions_requested,
    "risky_permissions_requested": risky_permissions_requested,
}

vision360_output["raw"]["manifest_evidence"] = {
    "source_manifest_paths": source_manifest_paths,
    "debuggable": manifest_debuggable,
    "allow_backup": manifest_allow_backup,
    "cleartext": manifest_cleartext,
    "exports": manifest_exports,
    "custom_permissions": manifest_custom_permissions,
    "signature_level": manifest_signature_level,
    "services_explicit_accessibility": manifest_services_explicit_accessibility,
    "exported_receivers_without_permission": exported_broadcast_receivers_without_permission,
}

vision360_output["raw"]["os_settings_evidence"] = {
    "has_os_settings_modification_api_usage": has_os_settings_modification_api_usage,
    "patterns": OS_SETTINGS_API_PATTERNS,
}

vision360_output["raw"]["os_time_source_evidence"] = os_time_source_evidence
vision360_output["raw"]["password_hashing_features"] = password_hashing_features

vision360_output["raw"]["requirement_os_privileged_access_summary"] = {
    "interpretation": "The requirement is mainly grounded in least-privilege and surface-area reduction (exports/IPC/dynamic code loading).",
    "signals": {
        "special_os_permissions_requested": special_os_permissions_requested,
        "privileged_like_permissions": perm_features["privileged_like_permissions"],
        "has_os_settings_modification_api_usage": has_os_settings_modification_api_usage,
        "manifest_insecure_exports_count": int(manifest_exports.get("count") or 0),
        "dynamic_code_loading_indicator": bool(code_features.get("has_dynamic_code_loading")),
    }
}

# ============================================================
# Write outputs
# ============================================================

with open("/mnt/data/vision360_fingerprint.json", "w", encoding="utf-8") as f:
    json.dump(vision360_fingerprint, f, ensure_ascii=False, indent=2)

with open("/mnt/data/vision360_output.json", "w", encoding="utf-8") as f:
    json.dump(vision360_output, f, ensure_ascii=False)

# ============================================================
# Summary prints
# ============================================================

size_fingerprint = os.path.getsize("/mnt/data/vision360_fingerprint.json")
size_output = os.path.getsize("/mnt/data/vision360_output.json")

total_flags = len(vision360_fingerprint["flags"])
counts = {"pass": 0, "fail": 0, "not_applicable": 0, "unknown": 0}
for flag in vision360_fingerprint["flags"]:
    st = (flag.get("app_verdict") or {}).get("state")
    if st in counts:
        counts[st] += 1

print("vision360_fingerprint.json size (bytes):", size_fingerprint)
print("vision360_output.json size (bytes):", size_output)
print("total_flags:", total_flags)
print("flags_pass:", counts["pass"])
print("flags_fail:", counts["fail"])
print("flags_not_applicable:", counts["not_applicable"])
print("flags_unknown:", counts["unknown"])
print("permission_status_counts:", perm_features.get("status_counts"))
print("dangerous_permissions:", perm_features.get("dangerous_permissions"))
print("privileged_like_permissions:", perm_features.get("privileged_like_permissions"))
print("special_os_permissions_requested:", special_os_permissions_requested)
print("primary_source_manifest_paths:", source_manifest_paths)
print("primary_manifest_debuggable_is_true:", manifest_debuggable.get("is_true"), "mismatch:", manifest_debuggable.get("mismatch"))
print("primary_manifest_allow_backup_is_true:", manifest_allow_backup.get("is_true"), "mismatch:", manifest_allow_backup.get("mismatch"))
print("supports_runtime_permission_mgmt:", supports_runtime_permission_mgmt)
print("has_os_time_source:", os_time_source_evidence.get("has_os_time_source"), "paths:", os_time_source_evidence.get("paths"))
print("primary_manifest_services_total:", manifest_services_explicit_accessibility.get("total_services"), "missing_exported:", manifest_services_explicit_accessibility.get("missing_exported_count"))
print(
    "has_password_hashing_uses_salts:", password_hashing_features.get("has_password_hashing_uses_salts"),
    "has_password_hashing_uses_kdf:", password_hashing_features.get("has_password_hashing_uses_kdf"),
    "algs:", password_hashing_features.get("kdf_algorithms")
)

