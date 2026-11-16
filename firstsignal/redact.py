"""Secret redaction. Applied to everything that leaves the process: reports and AI prompts.

Three layers:
1. Known shapes: credentials in URLs, Authorization headers, key=value secrets, JWTs, vendor keys.
2. Whole private-key blocks, including when they span several log lines.
3. An entropy backstop for long random-looking tokens that match no known shape.
"""

from __future__ import annotations

import math
import re
from collections import Counter

_RULES = [
    # scheme://user:password@host
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+(@)", re.IGNORECASE), r"\1<REDACTED>\2"),
    # Authorization headers: the whole credential, at any length
    (re.compile(r"(\b(?:proxy-)?authorization\b[\"']?\s*[:=]\s*[\"']?(?:(?:bearer|basic|digest|token)\s+)?)"
                r"[^\s\"',;]+", re.IGNORECASE), r"\1<REDACTED>"),
    # Bearer and Basic credentials in free text. The lookahead skips prose such as "basic authentication".
    (re.compile(r"\b(bearer|basic)\s+(?=[A-Za-z0-9._~+/=-]*[0-9+/=])[A-Za-z0-9._~+/=-]{6,}", re.IGNORECASE),
     r"\1 <REDACTED>"),
    # key=value / "key": "value" secrets
    (re.compile(
        r"(\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
        r"|client[_-]?secret|session[_-]?id|cookie)\b[\"']?\s*[:=]\s*[\"']?)[^\s\"',;&}]+",
        re.IGNORECASE), r"\1<REDACTED>"),
    # JSON Web Tokens
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "<REDACTED_JWT>"),
    # Cloud and vendor key shapes
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<REDACTED_AWS_KEY>"),
    (re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}\b"), "<REDACTED_TOKEN>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "<REDACTED_TOKEN>"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "<REDACTED_TOKEN>"),
    # A private-key marker on its own: the block was cut off, or arrived one line at a time
    (re.compile(r"-----(?:BEGIN|END) [A-Z ]*PRIVATE KEY-----"), "<REDACTED_PRIVATE_KEY>"),
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<EMAIL>"),
]
# A whole PEM private-key block, header to footer, across lines
_KEY_BLOCK = re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----.*?-----END \1PRIVATE KEY-----", re.DOTALL)

# Entropy backstop. A candidate is a run of token characters not glued to a path, host or file name.
_TOKEN = re.compile(r"(?<![\w./+-])[A-Za-z0-9+/_-]{20,}={0,2}(?![\w./+=-])")
_WORD = re.compile(r"^(?:[a-z]{3,}|[A-Z][a-z]{2,})$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
MIN_HEX_SECRET = 32          # shorter hex is usually a request id or short commit hash
MIN_ENTROPY = 3.5            # bits per character for mixed tokens

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


class Redactor:
    """Masks secrets in text. Disabled instances return text unchanged."""

    def __init__(self, enabled: bool = True, redact_ips: bool = False, extra=()):
        self.enabled = enabled
        self.rules = list(_RULES)
        if redact_ips:
            self.rules.append((_IPV4, "<IP>"))
        for rx in extra:
            self.rules.append((rx if hasattr(rx, "sub") else re.compile(rx), "<REDACTED>"))

    def __call__(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        text = self.mask_blocks(text)
        for rx, repl in self.rules:
            text = rx.sub(repl, text)
        return _TOKEN.sub(lambda m: "<REDACTED>" if looks_like_secret(m.group(0)) else m.group(0), text)

    def mask_blocks(self, text: str) -> str:
        """Replace whole private-key blocks. Call on the full text before splitting it into lines."""
        if not self.enabled or not text or "PRIVATE KEY-----" not in text:
            return text
        return _KEY_BLOCK.sub("<REDACTED_PRIVATE_KEY>", text)


def _entropy(token: str) -> float:
    """Shannon entropy in bits per character."""
    counts = Counter(token)
    n = len(token)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_like_secret(token: str) -> bool:
    """True for long random-looking tokens: API keys, session secrets, key material.

    Leaves alone UUIDs, short hex ids, paths, words, key=value labels and dashed resource names.
    Hex of 32+ characters is masked, so long hashes and container ids are masked too.
    """
    core = token.rstrip("=")
    if len(core) < 20 or _UUID.match(core):
        return False
    if "/" in core and ("" in core.split("/")):
        return False  # a path: leading, trailing or doubled slash
    if _HEX.match(core):
        return len(core) >= MIN_HEX_SECRET
    if not (any(c.isdigit() for c in core) and any(c.isalpha() for c in core)):
        return False
    segments = re.split(r"[-_]", core)
    if len(segments) > 1 and max(map(len, segments)) < 16 and any(_WORD.match(s) for s in segments):
        return False  # a resource name such as payments-worker-6b8d9c7f5d-x2k4p
    return _entropy(core) >= MIN_ENTROPY
