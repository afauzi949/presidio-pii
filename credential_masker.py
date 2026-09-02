"""
Port Python dari n8n Code Node "Mask Retrieved Credentials".

Modul ini SENGAJA tidak lewat Presidio AnalyzerEngine/RecognizerRegistry.
Deteksinya deterministik berbasis regex + nama key JSON (bukan
confidence-score/context seperti PatternRecognizer di costumregex.py),
karena kebocoran credential adalah security incident yang tidak boleh
bergantung ke threshold probabilistik.

Entry point publik:
- mask_text(text: str) -> str            : jalankan semua rule di atas satu string
- mask_credentials(data: Any) -> Any     : traversal rekursif utk dict/list/str (setara maskRecursive di JS)
"""

import re
from typing import Any

REDACTED = "[REDACTED]"
MASKED_IP_PART = "***"

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def mask_ip(match: "re.Match") -> str:
    """10.100.226.32 -> 10.***.***.32"""
    parts = match.group(0).split(".")
    if len(parts) != 4:
        return match.group(0)
    return f"{parts[0]}.{MASKED_IP_PART}.{MASKED_IP_PART}.{parts[3]}"


def mask_username(_value: str = "") -> str:
    """Username adalah credential identifier - jangan sisakan prefix/suffix."""
    return REDACTED


_SECRET_TRIM_RE = re.compile(r'^["\'\`]+|["\'\.,;:]+$')
_SECRET_IGNORE_RE = re.compile(
    r"^(?:\[?REDACTED\]?|\*+|x+|password|passwd|secret|unknown|null|none)$",
    re.IGNORECASE,
)
_SECRET_URL_RE = re.compile(r"^(?:https?|ftp|file)://", re.IGNORECASE)


def is_likely_secret(value: Any) -> bool:
    """Mendeteksi token yang sangat mungkin merupakan password."""
    if not isinstance(value, str):
        return False

    token = _SECRET_TRIM_RE.sub("", value.strip())

    if len(token) < 8 or len(token) > 256:
        return False

    if _SECRET_IGNORE_RE.match(token):
        return False

    if _SECRET_URL_RE.match(token) or "://" in token:
        return False

    has_lower = bool(re.search(r"[a-z]", token))
    has_upper = bool(re.search(r"[A-Z]", token))
    has_digit = bool(re.search(r"\d", token))
    # Simbol selain titik, atau titik jika disertai digit/simbol lain
    has_symbol = bool(re.search(r"[^A-Za-z0-9.]", token)) or (bool(re.search(r"\.", token)) and has_digit)

    character_classes = sum([has_lower, has_upper, has_digit, has_symbol])

    # Password kompleks biasa.
    if character_classes >= 3:
        return True

    # Password random panjang yang hanya berisi uppercase/lowercase.
    # Contoh: LBaOdcvEzMzIiHMG
    if len(token) >= 14 and has_lower and has_upper and not re.search(r"\s", token):
        return True

    return False


_STANDALONE_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z0-9@#$%^&*()_+\-=\[\]{};:'\",.<>/?\\|!~]{8,256})(?![A-Za-z0-9])"
)
_COMMON_FILE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|csv|json|xml|yaml|yml|log)$", re.IGNORECASE
)


def mask_likely_standalone_secrets(text: str) -> str:
    """Safety net setelah rule berbasis label."""

    def _repl(m: "re.Match") -> str:
        token = m.group(1)
        if not is_likely_secret(token):
            return m.group(0)
        # Hindari masking nama file umum.
        if _COMMON_FILE_EXT_RE.search(token):
            return m.group(0)
        return REDACTED

    return _STANDALONE_SECRET_RE.sub(_repl, text)


# --------------------------------------------------------------------------
# Rule-rule mask_text, urutan HARUS sama seperti versi n8n (rule belakangan
# mengasumsikan rule sebelumnya sudah jalan, mis. cek "(?!\[REDACTED\])").
# --------------------------------------------------------------------------

_RULE_1_AUTH_HEADER = re.compile(
    r"(\bauthorization\b\s*[:=]\s*)(?:bearer|basic|token)?\s*[^\s\r\n|,;]+",
    re.IGNORECASE,
)

_RULE_2_MD_LINK = re.compile(
    r"\[([^\]\r\n]{1,256})\]\((?:mailto:)?([^) \r\n]{1,512})\)", re.IGNORECASE
)

_RULE_3_HTML_MAILTO = re.compile(
    r'<a\b[^>]*href=["\']mailto:([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

_RULE_4_PASSWORD_WITH_SEP = re.compile(
    r"((?:\*{0,2}|_{0,2})\b(?:password|passwd|passphrase|pwd|pin)\b(?:\*{0,2}|_{0,2})"
    r"[^:=\r\n|,;]{0,120}[:=][ \t\u00A0]*)(?!\[REDACTED\])(?:`[^`\r\n]+`|\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\r\n|,;]+)",
    re.IGNORECASE,
)

_RULE_5_PASSWORD_NO_SEP = re.compile(
    r"((?:\*{0,2}|_{0,2})\b(?:password|passwd|passphrase|pwd|pin)\b(?:\*{0,2}|_{0,2})"
    r"[ \t\u00A0]+)(?!\[REDACTED\])(?:`[^`\r\n]+`|\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s\r\n|,;]+)",
    re.IGNORECASE,
)

_RULE_6_STRUCTURED_QUOTED = re.compile(
    r"([\"']?\b(?:password|passwd|passphrase|pwd|pin|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|private[_-]?key)\b[\"']?\s*[:=]\s*)([\"'`])[^\"'`\r\n]*\2",
    re.IGNORECASE,
)

_RULE_7_STRUCTURED_UNQUOTED = re.compile(
    r"(\b(?:secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"private[_-]?key)\b\s*[:=]\s*)(?!\[REDACTED\])[^\s\r\n|,;]+",
    re.IGNORECASE,
)

_RULE_8_CONN_STRING = re.compile(
    r"\b([a-z][a-z0-9+.-]*://)([^:\s/@]+):([^@\s/]+)@", re.IGNORECASE
)

_RULE_9_JDBC_USER = re.compile(r"(\b(?:user(?:name)?|uid)\s*=\s*)[^;\s\r\n|,]+", re.IGNORECASE)
_RULE_9_JDBC_PASS = re.compile(r"(\b(?:password|passwd|pwd)\s*=\s*)[^;\s\r\n|,]+", re.IGNORECASE)

_RULE_10_LABELED_USERNAME = re.compile(
    r"(\b(?:username|user[\s_-]?name|user[\s_-]?id|userid|login\s+as|login|db[\s_-]?user)\b"
    r"(?:\*{0,2})\s*(?::|=)?\s*)(`?)([A-Za-z0-9][A-Za-z0-9._@-]*)(`?)",
    re.IGNORECASE,
)
_LABELED_USERNAME_COMMON_WORDS = {
    "yang", "untuk", "dapat", "bisa", "harus", "akan", "telah", "sudah",
    "masuk", "akses", "login", "menggunakan",
}

_RULE_11_PSQL_USER = re.compile(
    r"(\bpsql\b[^\r\n]*?(?:\s-U\s+|\s--username(?:=|\s+)))([\"\']?)([^\s\"'`\\,;]+)([\"\']?)",
    re.IGNORECASE,
)

_RULE_12_WINDOWS_RDP_USER = re.compile(
    r"\b([A-Za-z0-9._-]+\\)(?!n\b)([A-Za-z0-9._@*-]+)"
)

_RULE_13_OPERATIONAL_ACCOUNT = re.compile(
    r"\b(?:adm|admin|opr|operator|svc|service|usr|user)\d{0,4}(?:\.[A-Za-z0-9][A-Za-z0-9._-]*)?\b",
    re.IGNORECASE,
)

_RULE_14_PARTIALLY_MASKED = re.compile(
    r"\b[A-Za-z0-9]{1,12}\*{3,}[A-Za-z0-9._-]{1,30}\b"
)


def mask_text(value: Any) -> Any:
    """Terapkan semua rule masking credential ke satu string."""
    if not isinstance(value, str):
        return value

    text = value

    # 1. Authorization header.
    text = _RULE_1_AUTH_HEADER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)

    # 2. Markdown link yang berisi credential.
    def _md_link_repl(m: "re.Match") -> str:
        label, target = m.group(1), m.group(2)
        if is_likely_secret(label) or is_likely_secret(target):
            return REDACTED
        return m.group(0)

    text = _RULE_2_MD_LINK.sub(_md_link_repl, text)

    # 3. HTML link mailto yang berisi credential.
    def _html_mailto_repl(m: "re.Match") -> str:
        target, label = m.group(1), m.group(2)
        if is_likely_secret(target) or is_likely_secret(label):
            return REDACTED
        return m.group(0)

    text = _RULE_3_HTML_MAILTO.sub(_html_mailto_repl, text)

    # 4. Password dengan separator.
    text = _RULE_4_PASSWORD_WITH_SEP.sub(lambda m: f"{m.group(1)}{REDACTED}", text)

    # 5. Password tanpa separator.
    text = _RULE_5_PASSWORD_NO_SEP.sub(lambda m: f"{m.group(1)}{REDACTED}", text)

    # 6. Credential terstruktur (quoted).
    text = _RULE_6_STRUCTURED_QUOTED.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(2)}", text
    )

    # 7. Credential terstruktur tanpa quote.
    text = _RULE_7_STRUCTURED_UNQUOTED.sub(lambda m: f"{m.group(1)}{REDACTED}", text)

    # 8. Connection string.
    text = _RULE_8_CONN_STRING.sub(
        lambda m: f"{m.group(1)}{REDACTED}:{REDACTED}@", text
    )

    # 9. JDBC-like connection string.
    text = _RULE_9_JDBC_USER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _RULE_9_JDBC_PASS.sub(lambda m: f"{m.group(1)}{REDACTED}", text)

    # 10. Username dengan label.
    def _labeled_username_repl(m: "re.Match") -> str:
        prefix, opening, username, closing = m.groups()
        if username.lower() in _LABELED_USERNAME_COMMON_WORDS:
            return m.group(0)
        return f"{prefix}{opening}{mask_username()}{closing}"

    text = _RULE_10_LABELED_USERNAME.sub(_labeled_username_repl, text)

    # 11. PostgreSQL CLI username.
    text = _RULE_11_PSQL_USER.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{mask_username(m.group(3))}{m.group(4)}", text
    )

    # 12. Username Windows/RDP (domain dipertahankan).
    text = _RULE_12_WINDOWS_RDP_USER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)

    # 13. Username standalone dengan pola akun operasional.
    text = _RULE_13_OPERATIONAL_ACCOUNT.sub(REDACTED, text)

    # 14. Username yang sudah dimasking sebagian oleh sumber.
    text = _RULE_14_PARTIALLY_MASKED.sub(REDACTED, text)

    # 15. IPv4.
    text = _IPV4_RE.sub(mask_ip, text)

    # 16. Safety net untuk password standalone.
    text = mask_likely_standalone_secrets(text)

    return text


def normalize_key(key: Any) -> str:
    key_str = str(key).strip()
    key_str = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key_str)
    key_str = re.sub(r"[\s.\-]+", "_", key_str)
    return key_str.lower()


_PASSWORD_KEY_RE = re.compile(
    r"^(?:password|passwd|passphrase|pwd|pin|secret|api_key|apikey|access_token|"
    r"accesstoken|refresh_token|refreshtoken|client_secret|clientsecret|private_key|"
    r"authorization|auth_token|token)$"
)
_USERNAME_KEY_RE = re.compile(
    r"^(?:username|user_name|userid|user_id|login|login_as|db_user|db_username|"
    r"database_user|rdp_user|ssh_user)$"
)
_IP_KEY_RE = re.compile(
    r"^(?:ip|ip_address|ipaddress|host_ip|server_ip|database_ip|db_ip|source_ip|destination_ip)$"
)


def mask_credentials(value: Any, key: str = "") -> Any:
    """
    Traversal rekursif setara `maskRecursive` di script n8n.
    Dipanggil langsung ke payload JSON (dict/list/str/dst).
    """
    normalized_key = normalize_key(key) if key else ""

    if normalized_key and _PASSWORD_KEY_RE.match(normalized_key):
        return REDACTED

    if normalized_key and _USERNAME_KEY_RE.match(normalized_key):
        return value if value is None else REDACTED

    if normalized_key and _IP_KEY_RE.match(normalized_key):
        return _IPV4_RE.sub(mask_ip, value) if isinstance(value, str) else value

    if isinstance(value, str):
        return mask_text(value)

    if isinstance(value, list):
        return [mask_credentials(item) for item in value]

    if isinstance(value, dict):
        return {k: mask_credentials(v, key=k) for k, v in value.items()}

    return value
