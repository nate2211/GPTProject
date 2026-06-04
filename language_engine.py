from __future__ import annotations

"""
PromptChat language_engine.py

Fast local English/response helper engine for PromptChat.

Goals:
- Improve GPT replies before they are shown to the user.
- Clean rough user text into readable English.
- Produce quick tool-ready prompts, APIDoc queries, search queries, and final answers.
- Run fast with stdlib only, while using optional packages when installed.
- Preserve code blocks, markdown structure, URLs, file paths, and citations.

Optional dependencies used when present:
    pip install ftfy language-tool-python rapidfuzz beautifulsoup4 markdown textstat

This file intentionally does not require network access, does not call external LLMs,
and does not read private app/browser state. It is a text transformation engine only.
"""

import html
import json
import math
import os
import re
import sqlite3
import textwrap
import time
import unicodedata
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher, unified_diff
from functools import lru_cache
from hashlib import blake2b
from pathlib import Path
from string import punctuation
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


# =============================================================================
# Optional dependency loading
# =============================================================================

try:
    import ftfy as _ftfy  # type: ignore
except Exception:
    _ftfy = None

try:
    import language_tool_python as _language_tool_python  # type: ignore
except Exception:
    _language_tool_python = None

try:
    from rapidfuzz import fuzz as _rapidfuzz_fuzz  # type: ignore
    from rapidfuzz import process as _rapidfuzz_process  # type: ignore
except Exception:
    _rapidfuzz_fuzz = None
    _rapidfuzz_process = None

try:
    from bs4 import BeautifulSoup as _BeautifulSoup  # type: ignore
except Exception:
    _BeautifulSoup = None

try:
    import markdown as _markdown  # type: ignore
except Exception:
    _markdown = None

try:
    import textstat as _textstat  # type: ignore
except Exception:
    _textstat = None


# =============================================================================
# Constants
# =============================================================================

ENGINE_VERSION = "2026.06.04-language-engine-v1"

DEFAULT_MAX_CHARS = 12000
DEFAULT_MAX_SENTENCES = 8
DEFAULT_MAX_QUERIES = 12
DEFAULT_CACHE_PATH = "data/language_engine/cache.sqlite3"

LANGUAGE_ENGINE_ACTIONS = [
    "status",
    "normalize_text",
    "fix_spacing",
    "fix_typos",
    "grammar_check",
    "rewrite",
    "rewrite_plain_english",
    "rewrite_technical",
    "rewrite_fast_answer",
    "summarize",
    "summarize_tool_output",
    "extract_intent",
    "extract_constraints",
    "make_search_queries",
    "make_apidoc_queries",
    "make_tool_prompt",
    "make_final_answer",
    "score_clarity",
    "score_readability",
    "rank_rewrites",
    "diff_rewrites",
    "cache_get",
    "cache_put",
    "help",
]

STYLE_PRESETS = [
    "auto",
    "concise",
    "direct",
    "friendly",
    "technical",
    "plain_english",
    "debug",
    "apidoc",
    "tool_prompt",
    "final_answer",
    "code_review",
    "step_by_step",
]

STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "being", "but", "by",
    "can", "could", "did", "do", "does", "doing", "for", "from", "had", "has",
    "have", "he", "her", "here", "him", "his", "how", "i", "if", "in", "into",
    "is", "it", "its", "just", "me", "my", "of", "on", "or", "our", "out",
    "over", "she", "so", "that", "the", "their", "them", "then", "there",
    "these", "they", "this", "to", "too", "up", "use", "using", "was", "we",
    "were", "what", "when", "where", "which", "who", "why", "will", "with",
    "would", "you", "your",
}

# Common typo fixes from the project/user's actual phrasing style.
COMMON_TYPO_FIXES = {
    "lanaguge": "language",
    "lanagauage": "language",
    "langauge": "language",
    "intelginently": "intelligently",
    "inteligent": "intelligent",
    "inteligently": "intelligently",
    "intellgient": "intelligent",
    "reseponding": "responding",
    "reponding": "responding",
    "ues": "use",
    "useing": "using",
    "geting": "getting",
    "gpt": "GPT",
    "rewrtie": "rewrite",
    "rewrit": "rewrite",
    "rewriteing": "rewriting",
    "interative": "interactive",
    "itnerative": "interactive",
    "iterative": "interactive",
    "torbrowsersession": "Tor browser session",
    "aite": "wait",
    "apidos": "APIDocs",
    "apidocs": "APIDocs",
    "api docs": "APIDocs",
    "singauter": "signature",
    "singature": "signature",
    "siganture": "signature",
    "comptiable": "compatible",
    "incomtiable": "incompatible",
    "animatmion": "animation",
    "naimton": "animation",
    "tursting": "thrusting",
    "thusting": "thrusting",
    "repertly": "repeatedly",
    "reperatly": "repeatedly",
    "repreratlly": "repeatedly",
    "pronatic": "problematic",
    "promatic": "problematic",
    "recieve": "receive",
    "seperate": "separate",
    "defualt": "default",
    "proy": "proxy",
    "javascirpt": "JavaScript",
    "comamnd": "command",
    "retrunre": "return",
    "incresae": "increase",
    "mointors": "monitors",
    "engin": "engine",
    "enigne": "engine",
    "eninge": "engine",
}

ACTION_HINT_WORDS = {
    "rewrite": {"rewrite", "full", "patch", "fix", "clean", "refactor", "replace"},
    "debug": {"error", "traceback", "crash", "failed", "bug", "exception", "issue"},
    "apidoc": {"apidoc", "api", "docs", "documentation", "queries", "reference"},
    "code": {"code", "script", "file", "class", "function", "method", "compile"},
    "search": {"search", "find", "latest", "look", "browse", "source"},
    "summarize": {"summarize", "summary", "recap", "extract", "explain"},
    "tool": {"tool", "schema", "json", "params", "action", "signature"},
}

CODE_FENCE_RE = re.compile(r"(?s)(```.*?```)")
INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
URL_RE = re.compile(r"\b(?:https?://|socks5h?://|file://|www\.)[^\s<>)]+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_'\-]*")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])")
HEADING_RE = re.compile(r"^(#{1,6})\s*(.+?)\s*$", re.M)


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class LanguageEngineConfig:
    default_style: str = "direct"
    max_chars: int = DEFAULT_MAX_CHARS
    max_sentences: int = DEFAULT_MAX_SENTENCES
    max_queries: int = DEFAULT_MAX_QUERIES
    cache_path: str = DEFAULT_CACHE_PATH
    preserve_markdown: bool = True
    preserve_code: bool = True
    use_optional_dependencies: bool = True
    language_tool_lang: str = "en-US"
    language_tool_mode: str = "lazy"  # off, lazy
    min_sentence_score: float = 0.0
    allow_cache: bool = True
    cache_ttl_sec: int = 7 * 24 * 3600


@dataclass
class ProtectedText:
    text: str
    placeholders: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScoredText:
    text: str
    clarity_score: float
    readability_score: float
    length_score: float
    repetition_penalty: float
    total_score: float
    notes: List[str] = field(default_factory=list)


@dataclass
class GrammarMatch:
    rule_id: str
    message: str
    offset: int
    error_length: int
    replacements: List[str]
    context: str = ""
    category: str = ""


# =============================================================================
# Utility helpers
# =============================================================================

def _now() -> int:
    return int(time.time())


def _safe_int(value: Any, default: int, minimum: int = 0, maximum: int = 10**9) -> int:
    try:
        out = int(value)
    except Exception:
        out = default
    return max(minimum, min(maximum, out))


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "y", "on", "enable", "enabled"}:
        return True
    if s in {"0", "false", "no", "n", "off", "disable", "disabled"}:
        return False
    return default


def _truncate(text: str, max_chars: int) -> Tuple[str, bool]:
    if max_chars <= 0:
        return text, False
    if len(text) <= max_chars:
        return text, False
    cut = max(0, max_chars)
    clipped = text[:cut]
    last_break = max(clipped.rfind("\n\n"), clipped.rfind("\n"), clipped.rfind(". "), clipped.rfind(" "))
    if last_break > int(cut * 0.65):
        clipped = clipped[:last_break].rstrip()
    return clipped.rstrip() + "\n\n[truncated]", True


def _hash_key(*parts: Any) -> str:
    h = blake2b(digest_size=16)
    for p in parts:
        h.update(str(p).encode("utf-8", errors="replace"))
        h.update(b"\0")
    return h.hexdigest()


def _split_lines_keepends(text: str) -> List[str]:
    return text.splitlines(keepends=True)


def _is_probably_code_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    code_markers = (
        "def ", "class ", "import ", "from ", "return ", "try:", "except", "finally:",
        "if ", "else:", "elif ", "for ", "while ", "using ", "namespace ", "public ",
        "private ", "protected ", "{", "}", "#include", "var ", "let ", "const ",
        "function ", "=>", "::", ";", "</", "<div", "<span", "```",
    )
    if stripped.startswith(code_markers):
        return True
    if re.search(r"[{};=<>]\s*$", stripped) and len(stripped.split()) <= 12:
        return True
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(.*\)", stripped) and (";" in stripped or "{" in stripped):
        return True
    return False


def _protect_segments(text: str, preserve_code: bool = True) -> ProtectedText:
    """
    Replace code fences, inline code, URLs, and emails with placeholders so
    rewriting does not damage them.
    """
    if not text:
        return ProtectedText(text="")

    placeholders: Dict[str, str] = {}
    protected = text

    def repl(prefix: str) -> Callable[[re.Match[str]], str]:
        def _inner(match: re.Match[str]) -> str:
            key = f"⟦{prefix}_{len(placeholders)}⟧"
            placeholders[key] = match.group(0)
            return key
        return _inner

    if preserve_code:
        protected = CODE_FENCE_RE.sub(repl("CODEBLOCK"), protected)
        protected = INLINE_CODE_RE.sub(repl("INLINECODE"), protected)

    protected = URL_RE.sub(repl("URL"), protected)
    protected = EMAIL_RE.sub(repl("EMAIL"), protected)
    return ProtectedText(text=protected, placeholders=placeholders)


def _restore_segments(protected: ProtectedText | str, placeholders: Optional[Dict[str, str]] = None) -> str:
    if isinstance(protected, ProtectedText):
        text = protected.text
        mapping = protected.placeholders
    else:
        text = protected
        mapping = placeholders or {}

    # Longest first so similar placeholders do not collide.
    for key in sorted(mapping.keys(), key=len, reverse=True):
        text = text.replace(key, mapping[key])
    return text


def _normalize_unicode(text: str, use_ftfy: bool = True) -> str:
    s = str(text or "")
    if use_ftfy and _ftfy is not None:
        try:
            s = _ftfy.fix_text(s)
        except Exception:
            pass
    s = unicodedata.normalize("NFKC", s)
    return s


def _strip_html(text: str) -> str:
    raw = text or ""
    if "<" not in raw or ">" not in raw:
        return raw
    if _BeautifulSoup is not None:
        try:
            soup = _BeautifulSoup(raw, "html.parser")
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            return soup.get_text(separator="\n")
        except Exception:
            pass
    raw = re.sub(r"(?is)<script.*?>.*?</script>", " ", raw)
    raw = re.sub(r"(?is)<style.*?>.*?</style>", " ", raw)
    raw = re.sub(r"(?i)<br\s*/?>", "\n", raw)
    raw = re.sub(r"(?i)</p\s*>", "\n\n", raw)
    raw = re.sub(r"(?s)<.*?>", " ", raw)
    return html.unescape(raw)


def _normalize_whitespace(text: str, preserve_paragraphs: bool = True) -> str:
    s = text.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[\t\f\v]+", " ", s)
    s = re.sub(r"[ \u00A0]{2,}", " ", s)
    s = re.sub(r" *\n *", "\n", s)
    if preserve_paragraphs:
        s = re.sub(r"\n{3,}", "\n\n", s)
    else:
        s = re.sub(r"\s+", " ", s)
    return s.strip()


def _fix_basic_spacing(text: str) -> str:
    s = text or ""

    # Add space after punctuation when obvious.
    s = re.sub(r"([.!?,;:])([A-Za-z0-9])", r"\1 \2", s)

    # Add spaces around markdown heading marker accidents: "###text".
    s = re.sub(r"(?m)^(#{1,6})([^\s#])", r"\1 \2", s)

    # Add space after list markers.
    s = re.sub(r"(?m)^(\s*[-*+])([^\s])", r"\1 \2", s)
    s = re.sub(r"(?m)^(\s*\d+\.)([^\s])", r"\1 \2", s)

    # Split obvious glued phrases created by missing whitespace in natural text.
    # Keep code-ish tokens safe by not splitting around underscores/digits.
    s = re.sub(r"([a-z])([A-Z][a-z])", r"\1 \2", s)
    s = re.sub(r"([a-zA-Z])(\d)([a-zA-Z])", r"\1 \2 \3", s)

    # Fix common run-together technical words.
    run_together = {
        "Torbrowsersession": "Tor browser session",
        "torbrowsersession": "Tor browser session",
        "browserwindow": "browser window",
        "toolcall": "tool call",
        "toolcalls": "tool calls",
        "searchquery": "search query",
        "searchqueries": "search queries",
        "sourcecode": "source code",
        "fullcode": "full code",
        "errormessage": "error message",
        "webpage": "web page",
        "webpages": "web pages",
        "plaintext": "plain text",
        "englishresponse": "English response",
        "languageengine": "language engine",
    }
    for old, new in run_together.items():
        s = re.sub(rf"\b{re.escape(old)}\b", new, s)

    return _normalize_whitespace(s, preserve_paragraphs=True)


def _fix_common_typos(text: str) -> str:
    s = text or ""

    def replace_word(match: re.Match[str]) -> str:
        original = match.group(0)
        lower = original.lower()
        replacement = COMMON_TYPO_FIXES.get(lower)
        if not replacement:
            return original
        if original.isupper():
            return replacement.upper()
        if original[:1].isupper() and replacement:
            return replacement[:1].upper() + replacement[1:]
        return replacement

    return re.sub(r"\b[A-Za-z][A-Za-z0-9_'\-]*\b", replace_word, s)


def _sentence_split(text: str) -> List[str]:
    clean = _normalize_whitespace(text, preserve_paragraphs=False)
    if not clean:
        return []
    parts = SENTENCE_RE.split(clean)
    out: List[str] = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        # Further split very long semicolon-heavy runs.
        if len(p) > 420 and "; " in p:
            out.extend(x.strip() for x in p.split("; ") if x.strip())
        else:
            out.append(p)
    return out


def _word_tokens(text: str) -> List[str]:
    return [m.group(0).lower().strip("'") for m in WORD_RE.finditer(text or "")]


def _content_words(text: str) -> List[str]:
    return [w for w in _word_tokens(text) if len(w) > 2 and w not in STOPWORDS]


def _capitalize_sentence(s: str) -> str:
    stripped = s.strip()
    if not stripped:
        return stripped
    # Do not damage code-ish starts or markdown headings.
    if stripped.startswith(("#", "-", "*", "`")) or _is_probably_code_line(stripped):
        return stripped
    if stripped[:1].islower():
        stripped = stripped[:1].upper() + stripped[1:]
    return stripped


def _ensure_terminal_punctuation(s: str) -> str:
    stripped = s.rstrip()
    if not stripped:
        return stripped
    if stripped[-1] in ".!?;:>`)\"']}" or stripped.startswith(("#", "-", "*", "`")):
        return stripped
    if _is_probably_code_line(stripped):
        return stripped
    return stripped + "."


def _format_paragraphs(text: str, width: int = 100, preserve_markdown: bool = True) -> str:
    if not text:
        return ""
    paragraphs = re.split(r"\n\s*\n", text.strip())
    out: List[str] = []
    in_code = False
    for para in paragraphs:
        if "```" in para:
            out.append(para.strip())
            continue
        lines = para.splitlines()
        if preserve_markdown and any(
            line.lstrip().startswith(("#", "-", "*", ">", "|")) or re.match(r"\s*\d+\.", line)
            for line in lines
        ):
            out.append("\n".join(line.rstrip() for line in lines).strip())
            continue
        joined = " ".join(line.strip() for line in lines if line.strip())
        if not joined:
            continue
        out.append(textwrap.fill(joined, width=width, break_long_words=False, break_on_hyphens=False))
    return "\n\n".join(out).strip()


def _extract_json_object(text: str) -> Optional[Any]:
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        pass

    # Try first balanced object/array block.
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = raw.find(start_char)
        end = raw.rfind(end_char)
        if start >= 0 and end > start:
            try:
                return json.loads(raw[start:end + 1])
            except Exception:
                pass
    return None


def _keywords(text: str, limit: int = 18) -> List[str]:
    words = _content_words(text)
    counts = Counter(words)

    # Boost code/API-ish tokens from raw text.
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?", text or ""):
        t = token.lower()
        if len(t) > 2 and t not in STOPWORDS:
            counts[t] += 1

    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [w for w, _ in ranked[:max(1, limit)]]


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for item in items:
        clean = str(item or "").strip()
        if not clean:
            continue
        key = clean.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(clean)
    return out


def _similarity(a: str, b: str) -> float:
    if _rapidfuzz_fuzz is not None:
        try:
            return float(_rapidfuzz_fuzz.ratio(a, b)) / 100.0
        except Exception:
            pass
    return SequenceMatcher(None, a, b).ratio()


def _simple_readability_score(text: str) -> float:
    """
    Returns 0..100 where higher is easier to read. Uses textstat when available,
    otherwise a rough sentence/word length heuristic.
    """
    clean = _normalize_whitespace(text, preserve_paragraphs=False)
    if not clean:
        return 0.0
    if _textstat is not None:
        try:
            score = float(_textstat.flesch_reading_ease(clean))
            return max(0.0, min(100.0, score))
        except Exception:
            pass

    sentences = _sentence_split(clean) or [clean]
    words = _word_tokens(clean)
    if not words:
        return 0.0
    avg_sentence = len(words) / max(1, len(sentences))
    avg_word_len = sum(len(w) for w in words) / max(1, len(words))
    score = 100.0
    score -= max(0.0, avg_sentence - 14.0) * 1.8
    score -= max(0.0, avg_word_len - 5.0) * 8.0
    score -= clean.count(";") * 1.5
    return max(0.0, min(100.0, score))


def _clarity_score(text: str) -> Tuple[float, List[str]]:
    notes: List[str] = []
    clean = _normalize_whitespace(text, preserve_paragraphs=True)
    if not clean:
        return 0.0, ["empty text"]

    score = 100.0
    sentences = _sentence_split(clean)
    words = _word_tokens(clean)

    if len(clean) > 4000:
        score -= 6
        notes.append("long response")
    if any(len(s) > 260 for s in sentences):
        score -= 10
        notes.append("very long sentence")
    if clean.count("  ") > 0:
        score -= 4
        notes.append("extra spaces")
    if re.search(r"[a-z][.!?][A-Za-z]", clean):
        score -= 8
        notes.append("missing punctuation spacing")
    if len(words) >= 20:
        counts = Counter(words)
        repeated = sum(1 for _, c in counts.items() if c >= 5)
        if repeated:
            score -= min(12, repeated * 2)
            notes.append("repetition")
    if re.search(r"\b(?:maybe|probably|sort of|kind of)\b", clean, re.I):
        score -= 3
        notes.append("hedging")
    if re.search(r"\b(?:thing|stuff|something)\b", clean, re.I):
        score -= 3
        notes.append("vague wording")

    return max(0.0, min(100.0, score)), notes


# =============================================================================
# Cache
# =============================================================================

class LanguageCache:
    def __init__(self, path: str = DEFAULT_CACHE_PATH, ttl_sec: int = 7 * 24 * 3600) -> None:
        self.path = path
        self.ttl_sec = int(ttl_sec)

    def _connect(self) -> sqlite3.Connection:
        db_path = Path(self.path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(str(db_path))
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
            """
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires_at ON cache(expires_at)")
        return con

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        now = _now()
        try:
            with self._connect() as con:
                row = con.execute(
                    "SELECT value, expires_at FROM cache WHERE key = ?",
                    (key,),
                ).fetchone()
                if not row:
                    return None
                value, expires_at = row
                if int(expires_at) < now:
                    con.execute("DELETE FROM cache WHERE key = ?", (key,))
                    return None
                return json.loads(value)
        except Exception:
            return None

    def put(self, key: str, value: Dict[str, Any], ttl_sec: Optional[int] = None) -> bool:
        now = _now()
        ttl = self.ttl_sec if ttl_sec is None else int(ttl_sec)
        try:
            with self._connect() as con:
                con.execute(
                    """
                    INSERT OR REPLACE INTO cache(key, value, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (key, json.dumps(value, ensure_ascii=False), now, now + max(1, ttl)),
                )
            return True
        except Exception:
            return False

    def purge_expired(self) -> int:
        now = _now()
        try:
            with self._connect() as con:
                cur = con.execute("DELETE FROM cache WHERE expires_at < ?", (now,))
                return int(cur.rowcount or 0)
        except Exception:
            return 0


# =============================================================================
# Main engine
# =============================================================================

class LanguageEngine:
    def __init__(self, config: Optional[LanguageEngineConfig] = None) -> None:
        self.config = config or LanguageEngineConfig()
        self._language_tool: Any = None
        self.cache = LanguageCache(self.config.cache_path, self.config.cache_ttl_sec)

    # ---------------------------------------------------------------------
    # Status/help
    # ---------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "engine": "language_engine",
            "version": ENGINE_VERSION,
            "actions": LANGUAGE_ENGINE_ACTIONS,
            "styles": STYLE_PRESETS,
            "config": asdict(self.config),
            "optional_dependencies": {
                "ftfy": _ftfy is not None,
                "language_tool_python": _language_tool_python is not None,
                "rapidfuzz": _rapidfuzz_fuzz is not None,
                "beautifulsoup4": _BeautifulSoup is not None,
                "markdown": _markdown is not None,
                "textstat": _textstat is not None,
            },
        }

    def help(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "engine": "language_engine",
            "summary": (
                "Fast English helper for GPT responses. Use normalize_text/fix_spacing/fix_typos "
                "on rough text, grammar_check for issues, rewrite for user-facing answers, "
                "summarize_tool_output for tool JSON, make_search_queries/make_apidoc_queries "
                "for research, and make_final_answer before showing a response."
            ),
            "actions": LANGUAGE_ENGINE_ACTIONS,
            "examples": [
                {
                    "action": "rewrite",
                    "text": "rough answer here",
                    "style": "direct",
                },
                {
                    "action": "make_apidoc_queries",
                    "text": "Need Bannerlord APIs for Agent animations and MissionLogic",
                    "max_queries": 20,
                },
                {
                    "action": "make_final_answer",
                    "text": "tool output summary",
                    "context": "user asked to fix spacing",
                },
            ],
        }

    # ---------------------------------------------------------------------
    # Core cleanup
    # ---------------------------------------------------------------------

    def normalize_text(
        self,
        text: str,
        *,
        max_chars: int = DEFAULT_MAX_CHARS,
        preserve_markdown: bool = True,
        preserve_code: bool = True,
        strip_html: bool = False,
        use_optional: bool = True,
    ) -> Dict[str, Any]:
        original = text or ""
        clipped, was_truncated = _truncate(original, max_chars)

        protected = _protect_segments(clipped, preserve_code=preserve_code)
        s = protected.text
        s = _normalize_unicode(s, use_ftfy=use_optional and self.config.use_optional_dependencies)
        s = html.unescape(s)
        if strip_html:
            s = _strip_html(s)
        s = s.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
        s = s.replace("—", "-").replace("–", "-")
        s = _normalize_whitespace(s, preserve_paragraphs=preserve_markdown)
        s = _restore_segments(s, protected.placeholders)

        return {
            "ok": True,
            "action": "normalize_text",
            "text": s,
            "changed": s != original,
            "truncated": was_truncated,
            "char_count": len(s),
        }

    def fix_spacing(
        self,
        text: str,
        *,
        max_chars: int = DEFAULT_MAX_CHARS,
        preserve_markdown: bool = True,
        preserve_code: bool = True,
    ) -> Dict[str, Any]:
        original = text or ""
        clipped, was_truncated = _truncate(original, max_chars)
        protected = _protect_segments(clipped, preserve_code=preserve_code)
        s = protected.text

        # Keep code-ish lines intact. Process natural language lines.
        lines = _split_lines_keepends(s)
        fixed_lines: List[str] = []
        for line in lines:
            if preserve_code and _is_probably_code_line(line):
                fixed_lines.append(line.rstrip())
            else:
                fixed_lines.append(_fix_basic_spacing(line))
        s = "\n".join(fixed_lines)
        s = re.sub(r"\n{3,}", "\n\n", s)
        s = _restore_segments(s, protected.placeholders)

        if preserve_markdown:
            s = _format_paragraphs(s, width=110, preserve_markdown=True)

        return {
            "ok": True,
            "action": "fix_spacing",
            "text": s,
            "changed": s != original,
            "truncated": was_truncated,
            "char_count": len(s),
        }

    def fix_typos(
        self,
        text: str,
        *,
        max_chars: int = DEFAULT_MAX_CHARS,
        preserve_code: bool = True,
    ) -> Dict[str, Any]:
        original = text or ""
        clipped, was_truncated = _truncate(original, max_chars)
        protected = _protect_segments(clipped, preserve_code=preserve_code)
        s = _fix_common_typos(protected.text)
        s = _restore_segments(s, protected.placeholders)
        return {
            "ok": True,
            "action": "fix_typos",
            "text": s,
            "changed": s != original,
            "truncated": was_truncated,
            "char_count": len(s),
        }

    # ---------------------------------------------------------------------
    # Grammar
    # ---------------------------------------------------------------------

    def _get_language_tool(self) -> Any:
        if self.config.language_tool_mode == "off":
            return None
        if _language_tool_python is None:
            return None
        if self._language_tool is not None:
            return self._language_tool
        try:
            self._language_tool = _language_tool_python.LanguageTool(self.config.language_tool_lang)
        except Exception:
            self._language_tool = None
        return self._language_tool

    def grammar_check(
        self,
        text: str,
        *,
        max_chars: int = DEFAULT_MAX_CHARS,
        auto_correct: bool = False,
        use_optional: bool = True,
    ) -> Dict[str, Any]:
        original = text or ""
        clipped, was_truncated = _truncate(original, max_chars)
        matches: List[GrammarMatch] = []
        corrected = clipped

        if use_optional and self.config.use_optional_dependencies:
            tool = self._get_language_tool()
            if tool is not None:
                try:
                    raw_matches = tool.check(clipped)
                    for m in raw_matches:
                        matches.append(
                            GrammarMatch(
                                rule_id=str(getattr(m, "ruleId", "")),
                                message=str(getattr(m, "message", "")),
                                offset=int(getattr(m, "offset", 0)),
                                error_length=int(getattr(m, "errorLength", 0)),
                                replacements=list(getattr(m, "replacements", []) or [])[:8],
                                context=str(getattr(m, "context", "")),
                                category=str(getattr(m, "category", "")),
                            )
                        )
                    if auto_correct:
                        try:
                            corrected = tool.correct(clipped)
                        except Exception:
                            corrected = clipped
                except Exception as exc:
                    return {
                        "ok": False,
                        "action": "grammar_check",
                        "error": str(exc),
                        "language_tool_available": _language_tool_python is not None,
                        "matches": [],
                        "text": clipped,
                    }

        # Fallback heuristic warnings.
        if not matches:
            if re.search(r"[a-z][.!?][A-Z]", clipped):
                matches.append(GrammarMatch("SPACING", "Missing space after punctuation.", 0, 0, ["Add a space."]))
            if re.search(r"\b(?:teh|recieve|seperate|definately)\b", clipped, re.I):
                matches.append(GrammarMatch("COMMON_TYPO", "Common typo detected.", 0, 0, []))
            if any(len(s) > 280 for s in _sentence_split(clipped)):
                matches.append(GrammarMatch("LONG_SENTENCE", "A sentence is very long and may be hard to read.", 0, 0, []))

        return {
            "ok": True,
            "action": "grammar_check",
            "text": corrected,
            "changed": corrected != original,
            "truncated": was_truncated,
            "language_tool_available": _language_tool_python is not None,
            "match_count": len(matches),
            "matches": [asdict(m) for m in matches],
        }

    # ---------------------------------------------------------------------
    # Rewrite
    # ---------------------------------------------------------------------

    def _rewrite_sentence(self, sentence: str, style: str = "direct") -> str:
        s = sentence.strip()
        if not s:
            return s
        if _is_probably_code_line(s):
            return s

        # Remove filler without changing meaning.
        filler_patterns = [
            (r"\b(?:basically|actually|literally|just|kind of|sort of)\b\s*", ""),
            (r"\b(?:I think that|I believe that)\b\s*", ""),
            (r"\b(?:in order to)\b", "to"),
            (r"\b(?:due to the fact that)\b", "because"),
            (r"\b(?:at this point in time)\b", "now"),
        ]
        for pat, repl in filler_patterns:
            s = re.sub(pat, repl, s, flags=re.I)

        if style in {"plain_english", "friendly"}:
            replacements = {
                "utilize": "use",
                "approximately": "about",
                "subsequently": "then",
                "prior to": "before",
                "commence": "start",
                "terminate": "stop",
                "implement": "add",
                "functionality": "feature",
            }
            for old, new in replacements.items():
                s = re.sub(rf"\b{re.escape(old)}\b", new, s, flags=re.I)

        if style in {"technical", "debug", "code_review"}:
            # Keep technical style compact and precise.
            s = re.sub(r"\bthing\b", "component", s, flags=re.I)
            s = re.sub(r"\bstuff\b", "data", s, flags=re.I)

        s = _fix_basic_spacing(s)
        s = _capitalize_sentence(s)
        s = _ensure_terminal_punctuation(s)
        return s

    def rewrite(
        self,
        text: str,
        *,
        context: str = "",
        style: str = "auto",
        mode: str = "auto",
        max_chars: int = DEFAULT_MAX_CHARS,
        max_sentences: int = DEFAULT_MAX_SENTENCES,
        preserve_markdown: bool = True,
        preserve_code: bool = True,
        fast: bool = True,
        use_optional: bool = True,
    ) -> Dict[str, Any]:
        original = text or ""
        if not original.strip():
            return {"ok": False, "action": "rewrite", "error": "text is required", "text": ""}

        if style == "auto":
            style = self._guess_style(original, context=context, mode=mode)

        cache_key = _hash_key("rewrite", original, context, style, mode, max_chars, max_sentences, preserve_markdown)
        if self.config.allow_cache:
            cached = self.cache.get(cache_key)
            if cached:
                cached = dict(cached)
                cached["cache_hit"] = True
                return cached

        clipped, was_truncated = _truncate(original, max_chars)
        protected = _protect_segments(clipped, preserve_code=preserve_code)

        s = protected.text
        s = _normalize_unicode(s, use_ftfy=use_optional and self.config.use_optional_dependencies)
        s = html.unescape(s)
        s = _fix_common_typos(s)
        s = _fix_basic_spacing(s)

        if preserve_markdown and ("\n" in s or "#" in s or "-" in s):
            s = self._rewrite_markdownish(s, style=style, max_sentences=max_sentences)
        else:
            sentences = _sentence_split(s)
            if max_sentences > 0 and len(sentences) > max_sentences and style in {"concise", "direct", "fast_answer", "final_answer"}:
                sentences = sentences[:max_sentences]
            rewritten = [self._rewrite_sentence(x, style=style) for x in sentences] or [self._rewrite_sentence(s, style=style)]
            s = " ".join(x for x in rewritten if x)

        s = _restore_segments(s, protected.placeholders)
        s = self._apply_style_wrapper(s, style=style, context=context)
        s = _normalize_whitespace(s, preserve_paragraphs=True)

        clarity, clarity_notes = _clarity_score(s)
        readability = _simple_readability_score(s)

        result = {
            "ok": True,
            "action": "rewrite",
            "style": style,
            "mode": mode,
            "text": s,
            "changed": s != original,
            "truncated": was_truncated,
            "char_count": len(s),
            "clarity_score": round(clarity, 2),
            "readability_score": round(readability, 2),
            "notes": clarity_notes,
            "cache_hit": False,
        }
        if self.config.allow_cache:
            self.cache.put(cache_key, result)
        return result

    def _rewrite_markdownish(self, text: str, style: str, max_sentences: int) -> str:
        lines = text.splitlines()
        out: List[str] = []
        paragraph: List[str] = []

        def flush_para() -> None:
            nonlocal paragraph
            if not paragraph:
                return
            joined = " ".join(x.strip() for x in paragraph if x.strip())
            if joined:
                sentences = _sentence_split(joined)
                if style in {"concise", "direct", "final_answer"} and max_sentences > 0:
                    sentences = sentences[:max_sentences]
                out.append(" ".join(self._rewrite_sentence(x, style=style) for x in sentences if x))
            paragraph = []

        for line in lines:
            raw = line.rstrip()
            stripped = raw.strip()

            if not stripped:
                flush_para()
                out.append("")
                continue

            if stripped.startswith("#"):
                flush_para()
                m = re.match(r"^(#{1,6})\s*(.+)$", stripped)
                if m:
                    out.append(f"{m.group(1)} {_capitalize_sentence(_fix_basic_spacing(m.group(2))).rstrip('.')}")
                else:
                    out.append(stripped)
                continue

            if stripped.startswith(("-", "*", ">")) or re.match(r"^\d+\.", stripped):
                flush_para()
                marker_match = re.match(r"^(\s*(?:[-*]>?|\d+\.|>))\s*(.*)$", raw)
                if marker_match:
                    marker, content = marker_match.group(1), marker_match.group(2)
                    out.append(f"{marker} {self._rewrite_sentence(content, style=style)}")
                else:
                    out.append(self._rewrite_sentence(raw, style=style))
                continue

            if _is_probably_code_line(raw):
                flush_para()
                out.append(raw)
                continue

            paragraph.append(raw)

        flush_para()
        return "\n".join(out).strip()

    def _apply_style_wrapper(self, text: str, style: str, context: str = "") -> str:
        s = text.strip()

        if style in {"concise", "direct", "fast_answer"}:
            # Reduce repeated paragraphs/sentences.
            sentences = _sentence_split(s)
            deduped: List[str] = []
            for sent in sentences:
                if not any(_similarity(sent.lower(), old.lower()) > 0.92 for old in deduped):
                    deduped.append(sent)
            if deduped and len("\n".join(deduped)) < len(s) * 0.95:
                s = " ".join(deduped)

        if style == "tool_prompt":
            s = self._tool_prompt_from_text(s, context=context)

        if style == "final_answer":
            s = self._final_answer_from_text(s, context=context).get("text", s)

        return s

    def _guess_style(self, text: str, context: str = "", mode: str = "auto") -> str:
        hay = f"{text} {context} {mode}".lower()
        if any(w in hay for w in ("traceback", "error", "crash", "bug", "fix")):
            return "debug"
        if any(w in hay for w in ("apidoc", "api doc", "documentation queries")):
            return "apidoc"
        if any(w in hay for w in ("tool", "schema", "json arguments", "params")):
            return "tool_prompt"
        if any(w in hay for w in ("explain simple", "plain english", "non technical")):
            return "plain_english"
        if any(w in hay for w in ("code", "function", "class", "compile", ".py", ".cs", ".cpp")):
            return "technical"
        return self.config.default_style or "direct"

    # ---------------------------------------------------------------------
    # Summarization
    # ---------------------------------------------------------------------

    def summarize(
        self,
        text: str,
        *,
        context: str = "",
        max_chars: int = DEFAULT_MAX_CHARS,
        max_sentences: int = DEFAULT_MAX_SENTENCES,
        style: str = "direct",
    ) -> Dict[str, Any]:
        original = text or ""
        if not original.strip():
            return {"ok": False, "action": "summarize", "error": "text is required", "summary": ""}

        clipped, was_truncated = _truncate(original, max_chars)
        clean = self.normalize_text(clipped, max_chars=max_chars).get("text", clipped)
        sentences = _sentence_split(clean)
        if not sentences:
            return {"ok": True, "action": "summarize", "summary": clean, "sentences": [clean], "truncated": was_truncated}

        words = _content_words(clean)
        freq = Counter(words)
        if not freq:
            selected = sentences[:max_sentences]
        else:
            max_freq = max(freq.values()) or 1
            scored: List[Tuple[float, int, str]] = []
            context_words = set(_content_words(context))
            for idx, sent in enumerate(sentences):
                sw = _content_words(sent)
                if not sw:
                    continue
                score = sum(freq[w] / max_freq for w in sw) / max(1, len(sw))
                score += 0.10 if idx == 0 else 0.0
                score += 0.08 if idx == len(sentences) - 1 else 0.0
                if context_words:
                    overlap = len(set(sw) & context_words)
                    score += min(0.25, overlap * 0.04)
                if len(sent) > 280:
                    score -= 0.10
                scored.append((score, idx, sent))
            scored.sort(key=lambda x: (-x[0], x[1]))
            chosen = sorted(scored[:max(1, max_sentences)], key=lambda x: x[1])
            selected = [s for _, _, s in chosen]

        summary = " ".join(self._rewrite_sentence(s, style=style) for s in selected)
        return {
            "ok": True,
            "action": "summarize",
            "summary": summary,
            "text": summary,
            "sentence_count": len(selected),
            "truncated": was_truncated,
            "keywords": _keywords(clean, limit=18),
        }

    def summarize_tool_output(
        self,
        text: str,
        *,
        context: str = "",
        max_chars: int = DEFAULT_MAX_CHARS,
        max_sentences: int = 10,
    ) -> Dict[str, Any]:
        data = _extract_json_object(text)
        if data is None:
            return self.summarize(text, context=context, max_chars=max_chars, max_sentences=max_sentences)

        summary_parts: List[str] = []
        evidence: List[Any] = []

        def walk(obj: Any, path: str = "") -> None:
            if len(evidence) >= 80:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key = str(k)
                    lower = key.lower()
                    if lower in {"error", "errors", "warning", "warnings", "status", "ok", "count", "title", "url", "final_url", "snippet", "summary", "message"}:
                        evidence.append({path + key: v})
                    elif isinstance(v, (dict, list)):
                        walk(v, path + key + ".")
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:20]):
                    walk(item, path + f"{i}.")

        walk(data)

        if isinstance(data, dict):
            if data.get("ok") is False:
                summary_parts.append(f"The tool returned an error: {data.get('error', 'unknown error')}.")
            elif "error" in data:
                summary_parts.append(f"The tool reported: {data.get('error')}.")
            elif "summary" in data:
                summary_parts.append(str(data.get("summary")))
            elif "count" in data:
                summary_parts.append(f"The tool returned {data.get('count')} item(s).")
            else:
                summary_parts.append("The tool returned structured data.")
        elif isinstance(data, list):
            summary_parts.append(f"The tool returned a list with {len(data)} item(s).")

        # Add compact top-level highlights.
        if isinstance(data, dict):
            for key in ("title", "url", "final_url", "status", "status_code", "mode", "action", "tool"):
                if key in data and data.get(key) not in ("", None):
                    summary_parts.append(f"{key}: {data.get(key)}")

            for collection_key in ("results", "items", "links", "errors", "matches", "alerts"):
                value = data.get(collection_key)
                if isinstance(value, list) and value:
                    summary_parts.append(f"{collection_key}: {len(value)} item(s)")
                    for row in value[:5]:
                        if isinstance(row, dict):
                            title = row.get("title") or row.get("name") or row.get("url") or row.get("message") or row.get("text")
                            if title:
                                summary_parts.append(f"- {str(title)[:240]}")
                        else:
                            summary_parts.append(f"- {str(row)[:240]}")

        out = "\n".join(_dedupe_preserve_order(summary_parts))
        out = self.rewrite(out, context=context, style="direct", max_chars=max_chars, max_sentences=max_sentences).get("text", out)
        return {
            "ok": True,
            "action": "summarize_tool_output",
            "text": out,
            "summary": out,
            "parsed_json": True,
            "evidence": evidence[:40],
        }

    # ---------------------------------------------------------------------
    # Intent / constraints
    # ---------------------------------------------------------------------

    def extract_intent(self, text: str, *, context: str = "") -> Dict[str, Any]:
        clean = self.normalize_text(text, max_chars=DEFAULT_MAX_CHARS).get("text", text)
        words = set(_content_words(clean))
        scores: Dict[str, int] = {}
        for intent, hints in ACTION_HINT_WORDS.items():
            scores[intent] = sum(1 for h in hints if h in clean.lower() or h in words)

        best = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
        primary = best[0][0] if best and best[0][1] > 0 else "answer"

        asks_full_code = bool(re.search(r"\b(?:rewrite|write|create|generate)\b.*\b(?:full|whole|entire)\b", clean, re.I))
        wants_no_changes_to_signature = bool(re.search(r"\bexact\s+(?:old\s+)?signature\b|\bsame signature\b", clean, re.I))
        wants_apidocs = "apidoc" in clean.lower() or "api docs" in clean.lower() or "documentation" in clean.lower()

        return {
            "ok": True,
            "action": "extract_intent",
            "primary_intent": primary,
            "scores": scores,
            "flags": {
                "asks_full_code": asks_full_code,
                "wants_no_signature_changes": wants_no_changes_to_signature,
                "wants_apidocs": wants_apidocs,
                "mentions_error": "error" in words or "traceback" in clean.lower(),
                "mentions_tor": "tor" in words or ".onion" in clean.lower(),
                "mentions_bannerlord": "bannerlord" in clean.lower() or "taleworlds" in clean.lower(),
            },
            "keywords": _keywords(clean, limit=24),
            "cleaned_request": clean,
        }

    def extract_constraints(self, text: str, *, context: str = "") -> Dict[str, Any]:
        clean = self.normalize_text(text, max_chars=DEFAULT_MAX_CHARS).get("text", text)
        constraints: List[str] = []

        patterns = [
            (r"\bexact\s+(?:old\s+)?signature\b|\bsame signature\b", "preserve exact signatures"),
            (r"\bfull\s+(?:file|code|script|rewrite)\b|\bwhole\s+(?:file|code|script)\b", "write the full file"),
            (r"\bdon'?t\s+change\b|\bwithout changing\b", "avoid unrelated changes"),
            (r"\bno\s+external\s+scripts\b", "do not depend on external scripts"),
            (r"\buse\s+tor\b|\b9150\b", "use Tor SOCKS 9150 when applicable"),
            (r"\bcopy\s+and\s+paste\b", "make output copy-paste ready"),
            (r"\bfast\b|\bquick\b", "optimize for fast response"),
            (r"\bsafe\b|\bconsent\b", "keep consent/safety boundaries"),
            (r"\bAPIDocs?\b|\bapi docs\b", "ground with API documentation"),
        ]

        for pat, label in patterns:
            if re.search(pat, clean, re.I):
                constraints.append(label)

        quoted = re.findall(r"['\"]([^'\"]{2,120})['\"]", clean)
        file_paths = re.findall(r"\b[\w./\\-]+\.(?:py|cs|cpp|hpp|h|js|ts|tsx|jsx|json|md|txt)\b", clean, re.I)

        return {
            "ok": True,
            "action": "extract_constraints",
            "constraints": _dedupe_preserve_order(constraints),
            "quoted_terms": quoted[:20],
            "file_paths": file_paths[:20],
            "keywords": _keywords(clean, limit=24),
        }

    # ---------------------------------------------------------------------
    # Query generation
    # ---------------------------------------------------------------------

    def make_search_queries(
        self,
        text: str,
        *,
        context: str = "",
        max_queries: int = DEFAULT_MAX_QUERIES,
        style: str = "web",
    ) -> Dict[str, Any]:
        clean = self.normalize_text(text, max_chars=DEFAULT_MAX_CHARS).get("text", text)
        keys = _keywords(f"{clean} {context}", limit=28)

        queries: List[str] = []

        # Preserve exact error/API-like phrases.
        quoted = re.findall(r"['\"]([^'\"]{4,160})['\"]", clean)
        queries.extend(quoted[:4])

        # Common direct query forms.
        if keys:
            queries.append(" ".join(keys[:8]))
            queries.append(" ".join(keys[:5]) + " documentation")
            queries.append(" ".join(keys[:5]) + " examples")

        # Error-specific.
        error_lines = [
            line.strip()
            for line in clean.splitlines()
            if "error" in line.lower() or "exception" in line.lower() or "traceback" in line.lower()
        ]
        queries.extend(error_lines[:3])

        # Product/framework hints.
        lower = clean.lower()
        if "bannerlord" in lower or "taleworlds" in lower:
            queries.append("TaleWorlds Bannerlord " + " ".join(keys[:6]))
        if "python" in lower or ".py" in lower:
            queries.append("Python " + " ".join(keys[:7]))
        if "c#" in lower or ".cs" in lower or "cs" in lower:
            queries.append("C# " + " ".join(keys[:7]))

        queries = _dedupe_preserve_order(queries)
        return {
            "ok": True,
            "action": "make_search_queries",
            "queries": queries[:max(1, max_queries)],
            "keywords": keys,
            "count": min(len(queries), max(1, max_queries)),
        }

    def make_apidoc_queries(
        self,
        text: str,
        *,
        context: str = "",
        max_queries: int = DEFAULT_MAX_QUERIES,
    ) -> Dict[str, Any]:
        clean = self.normalize_text(text, max_chars=DEFAULT_MAX_CHARS).get("text", text)
        lower = clean.lower()
        keys = _keywords(f"{clean} {context}", limit=30)
        queries: List[str] = []

        # Language/framework detection.
        if "python" in lower or ".py" in lower or "language_engine" in lower:
            topics = [
                "str methods split strip replace casefold",
                "re compile search findall sub flags",
                "textwrap wrap fill shorten dedent indent",
                "difflib SequenceMatcher unified_diff",
                "unicodedata normalize category",
                "json dumps loads JSONEncoder ensure_ascii",
                "dataclasses dataclass field asdict",
                "sqlite3 connect execute row_factory",
                "functools lru_cache cached_property",
                "typing TypedDict Protocol Literal",
            ]
            queries.extend([f"python: {t}" for t in topics])

        if "grammar" in lower or "languagetool" in lower or "english" in lower:
            queries.extend([
                "LanguageTool HTTP API check text matches replacements rules categories",
                "language_tool_python LanguageTool check correct Match ruleId offset replacements",
                "textstat Flesch reading ease sentence count word count",
            ])

        if "spacy" in lower or "token" in lower or "sentence" in lower:
            queries.extend([
                "spaCy API Language tokenizer add_pipe disable_pipes",
                "spaCy API Doc Token Span Sent sentence segmentation",
                "spaCy API Sentencizer component",
            ])

        if "nltk" in lower or "wordnet" in lower:
            queries.extend([
                "NLTK word_tokenize sent_tokenize documentation",
                "NLTK wordnet synsets lemmas documentation",
                "NLTK pos_tag documentation",
            ])

        if "markdown" in lower or "html" in lower:
            queries.extend([
                "beautifulsoup4 get_text strip separator documentation",
                "markdown python markdown to html extensions documentation",
                "html official Python escape unescape",
            ])

        if "fast" in lower or "cache" in lower:
            queries.extend([
                "python functools lru_cache cache cached_property documentation",
                "sqlite3 Python connect execute transactions documentation",
                "rapidfuzz fuzz ratio process extract documentation",
            ])

        # Generic keyword docs.
        if keys:
            queries.append(" ".join(keys[:8]) + " API documentation")
            queries.append(" ".join(keys[:8]) + " official docs")
            queries.append(" ".join(keys[:8]) + " examples")

        # APIDoc engine prefers clean direct strings, not code-like list syntax.
        queries = [q.strip(" ,\"'") for q in queries if q.strip(" ,\"'")]
        queries = _dedupe_preserve_order(queries)
        return {
            "ok": True,
            "action": "make_apidoc_queries",
            "queries": queries[:max(1, max_queries)],
            "keywords": keys,
            "count": min(len(queries), max(1, max_queries)),
        }

    # ---------------------------------------------------------------------
    # Tool prompt/final answer
    # ---------------------------------------------------------------------

    def _tool_prompt_from_text(self, text: str, *, context: str = "") -> str:
        intent = self.extract_intent(text, context=context)
        constraints = self.extract_constraints(text, context=context)
        clean = self.normalize_text(text, max_chars=DEFAULT_MAX_CHARS).get("text", text)

        parts = [
            "Task:",
            clean,
            "",
            "Detected intent:",
            str(intent.get("primary_intent", "answer")),
        ]
        if constraints.get("constraints"):
            parts.extend(["", "Constraints:"])
            parts.extend(f"- {c}" for c in constraints["constraints"])
        if context.strip():
            parts.extend(["", "Context:", context.strip()])
        return "\n".join(parts).strip()

    def make_tool_prompt(
        self,
        text: str,
        *,
        context: str = "",
        tool_name: str = "",
        max_chars: int = DEFAULT_MAX_CHARS,
    ) -> Dict[str, Any]:
        clean = self.normalize_text(text, max_chars=max_chars).get("text", text)
        prompt = self._tool_prompt_from_text(clean, context=context)
        if tool_name:
            prompt = f"Use tool: {tool_name}\n\n{prompt}"
        return {
            "ok": True,
            "action": "make_tool_prompt",
            "tool_name": tool_name,
            "prompt": prompt,
            "text": prompt,
            "char_count": len(prompt),
        }

    def _final_answer_from_text(self, text: str, *, context: str = "") -> Dict[str, Any]:
        clean = self.normalize_text(text, max_chars=DEFAULT_MAX_CHARS).get("text", text)
        clean = _fix_common_typos(clean)
        clean = _fix_basic_spacing(clean)

        # Avoid overly meta phrasing.
        clean = re.sub(r"\bShort answer:\s*", "", clean, flags=re.I)
        clean = re.sub(r"\bShort version:\s*", "", clean, flags=re.I)
        clean = re.sub(r"\bIf you want,?\s*", "", clean, flags=re.I)

        # Make markdown/code-friendly and direct.
        if "```" not in clean and len(clean) < 1800:
            sentences = _sentence_split(clean)
            clean = " ".join(self._rewrite_sentence(s, style="direct") for s in sentences) if sentences else clean
        clean = _normalize_whitespace(clean, preserve_paragraphs=True)

        return {
            "ok": True,
            "action": "make_final_answer",
            "text": clean,
            "char_count": len(clean),
            "clarity_score": round(_clarity_score(clean)[0], 2),
            "readability_score": round(_simple_readability_score(clean), 2),
        }

    def make_final_answer(
        self,
        text: str,
        *,
        context: str = "",
        max_chars: int = DEFAULT_MAX_CHARS,
        style: str = "direct",
    ) -> Dict[str, Any]:
        rewritten = self.rewrite(
            text,
            context=context,
            style="final_answer" if style in {"auto", "direct", "final_answer"} else style,
            max_chars=max_chars,
            max_sentences=DEFAULT_MAX_SENTENCES,
            preserve_markdown=True,
            preserve_code=True,
        )
        if rewritten.get("ok"):
            return {
                "ok": True,
                "action": "make_final_answer",
                "text": rewritten.get("text", ""),
                "char_count": rewritten.get("char_count", 0),
                "clarity_score": rewritten.get("clarity_score", 0),
                "readability_score": rewritten.get("readability_score", 0),
            }
        return self._final_answer_from_text(text, context=context)

    # ---------------------------------------------------------------------
    # Scoring/ranking
    # ---------------------------------------------------------------------

    def score_clarity(self, text: str, *, max_chars: int = DEFAULT_MAX_CHARS) -> Dict[str, Any]:
        clipped, was_truncated = _truncate(text or "", max_chars)
        clarity, notes = _clarity_score(clipped)
        return {
            "ok": True,
            "action": "score_clarity",
            "clarity_score": round(clarity, 2),
            "notes": notes,
            "truncated": was_truncated,
        }

    def score_readability(self, text: str, *, max_chars: int = DEFAULT_MAX_CHARS) -> Dict[str, Any]:
        clipped, was_truncated = _truncate(text or "", max_chars)
        return {
            "ok": True,
            "action": "score_readability",
            "readability_score": round(_simple_readability_score(clipped), 2),
            "truncated": was_truncated,
        }

    def _score_candidate(self, text: str) -> ScoredText:
        clarity, notes = _clarity_score(text)
        readability = _simple_readability_score(text)
        length = len(text)
        if length == 0:
            length_score = 0.0
        elif length < 250:
            length_score = 85.0
        elif length < 1200:
            length_score = 100.0
        elif length < 3500:
            length_score = 88.0
        else:
            length_score = 72.0

        words = _word_tokens(text)
        repetition_penalty = 0.0
        if words:
            counts = Counter(words)
            repetition_penalty = min(25.0, sum(max(0, c - 3) for c in counts.values()) * 1.2)

        total = (clarity * 0.50) + (readability * 0.30) + (length_score * 0.20) - repetition_penalty
        return ScoredText(
            text=text,
            clarity_score=round(clarity, 2),
            readability_score=round(readability, 2),
            length_score=round(length_score, 2),
            repetition_penalty=round(repetition_penalty, 2),
            total_score=round(max(0.0, min(100.0, total)), 2),
            notes=notes,
        )

    def rank_rewrites(
        self,
        text: str,
        *,
        context: str = "",
        candidates: Optional[List[str]] = None,
        styles: Optional[List[str]] = None,
        max_chars: int = DEFAULT_MAX_CHARS,
    ) -> Dict[str, Any]:
        rows: List[ScoredText] = []

        if candidates:
            for c in candidates:
                rows.append(self._score_candidate(c))
        else:
            styles_to_try = styles or ["direct", "concise", "plain_english", "technical"]
            for style in styles_to_try:
                result = self.rewrite(text, context=context, style=style, max_chars=max_chars)
                if result.get("ok"):
                    rows.append(self._score_candidate(str(result.get("text", ""))))

        rows.sort(key=lambda x: x.total_score, reverse=True)
        return {
            "ok": True,
            "action": "rank_rewrites",
            "count": len(rows),
            "best": asdict(rows[0]) if rows else None,
            "ranked": [asdict(r) for r in rows],
        }

    def diff_rewrites(
        self,
        original: str,
        revised: str = "",
        *,
        context: str = "",
        style: str = "direct",
        max_chars: int = DEFAULT_MAX_CHARS,
    ) -> Dict[str, Any]:
        if not revised:
            revised = self.rewrite(original, context=context, style=style, max_chars=max_chars).get("text", "")
        diff = "\n".join(
            unified_diff(
                original.splitlines(),
                revised.splitlines(),
                fromfile="original",
                tofile="revised",
                lineterm="",
            )
        )
        return {
            "ok": True,
            "action": "diff_rewrites",
            "original": original,
            "revised": revised,
            "diff": diff,
            "similarity": round(_similarity(original, revised), 4),
        }

    # ---------------------------------------------------------------------
    # Cache tool surface
    # ---------------------------------------------------------------------

    def cache_get(self, key: str) -> Dict[str, Any]:
        value = self.cache.get(key)
        return {"ok": value is not None, "action": "cache_get", "key": key, "value": value}

    def cache_put(self, key: str, value: Any, ttl_sec: Optional[int] = None) -> Dict[str, Any]:
        if isinstance(value, dict):
            payload = value
        else:
            payload = {"value": value}
        ok = self.cache.put(key, payload, ttl_sec=ttl_sec)
        return {"ok": ok, "action": "cache_put", "key": key}

    # ---------------------------------------------------------------------
    # Dispatch
    # ---------------------------------------------------------------------

    def run(
        self,
        action: str = "rewrite",
        text: str = "",
        context: str = "",
        style: str = "auto",
        mode: str = "auto",
        max_chars: int = DEFAULT_MAX_CHARS,
        max_sentences: int = DEFAULT_MAX_SENTENCES,
        max_queries: int = DEFAULT_MAX_QUERIES,
        preserve_markdown: bool = True,
        preserve_code: bool = True,
        fast: bool = True,
        use_optional: bool = True,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        params = dict(params or {})
        action = (action or "rewrite").strip().lower()

        # Params override loose direct args when passed from generic tool calls.
        style = str(params.get("style", style))
        mode = str(params.get("mode", mode))
        max_chars = _safe_int(params.get("max_chars", max_chars), DEFAULT_MAX_CHARS, 1, 2_000_000)
        max_sentences = _safe_int(params.get("max_sentences", max_sentences), DEFAULT_MAX_SENTENCES, 1, 1000)
        max_queries = _safe_int(params.get("max_queries", max_queries), DEFAULT_MAX_QUERIES, 1, 1000)
        preserve_markdown = _safe_bool(params.get("preserve_markdown", preserve_markdown), True)
        preserve_code = _safe_bool(params.get("preserve_code", preserve_code), True)
        fast = _safe_bool(params.get("fast", fast), True)
        use_optional = _safe_bool(params.get("use_optional", use_optional), True)

        try:
            if action in {"status", "capabilities"}:
                return self.status()
            if action == "help":
                return self.help()
            if action == "normalize_text":
                return self.normalize_text(
                    text,
                    max_chars=max_chars,
                    preserve_markdown=preserve_markdown,
                    preserve_code=preserve_code,
                    strip_html=_safe_bool(params.get("strip_html", False), False),
                    use_optional=use_optional,
                )
            if action == "fix_spacing":
                return self.fix_spacing(text, max_chars=max_chars, preserve_markdown=preserve_markdown, preserve_code=preserve_code)
            if action == "fix_typos":
                return self.fix_typos(text, max_chars=max_chars, preserve_code=preserve_code)
            if action == "grammar_check":
                return self.grammar_check(
                    text,
                    max_chars=max_chars,
                    auto_correct=_safe_bool(params.get("auto_correct", False), False),
                    use_optional=use_optional,
                )
            if action in {"rewrite", "rewrite_plain_english", "rewrite_technical", "rewrite_fast_answer"}:
                mapped_style = {
                    "rewrite_plain_english": "plain_english",
                    "rewrite_technical": "technical",
                    "rewrite_fast_answer": "direct",
                }.get(action, style)
                return self.rewrite(
                    text,
                    context=context,
                    style=mapped_style,
                    mode=mode,
                    max_chars=max_chars,
                    max_sentences=max_sentences,
                    preserve_markdown=preserve_markdown,
                    preserve_code=preserve_code,
                    fast=fast,
                    use_optional=use_optional,
                )
            if action == "summarize":
                return self.summarize(text, context=context, max_chars=max_chars, max_sentences=max_sentences, style=style)
            if action == "summarize_tool_output":
                return self.summarize_tool_output(text, context=context, max_chars=max_chars, max_sentences=max_sentences)
            if action == "extract_intent":
                return self.extract_intent(text, context=context)
            if action == "extract_constraints":
                return self.extract_constraints(text, context=context)
            if action == "make_search_queries":
                return self.make_search_queries(text, context=context, max_queries=max_queries, style=style)
            if action == "make_apidoc_queries":
                return self.make_apidoc_queries(text, context=context, max_queries=max_queries)
            if action == "make_tool_prompt":
                return self.make_tool_prompt(
                    text,
                    context=context,
                    tool_name=str(params.get("tool_name", "")),
                    max_chars=max_chars,
                )
            if action == "make_final_answer":
                return self.make_final_answer(text, context=context, max_chars=max_chars, style=style)
            if action == "score_clarity":
                return self.score_clarity(text, max_chars=max_chars)
            if action == "score_readability":
                return self.score_readability(text, max_chars=max_chars)
            if action == "rank_rewrites":
                candidates = params.get("candidates")
                styles = params.get("styles")
                return self.rank_rewrites(
                    text,
                    context=context,
                    candidates=candidates if isinstance(candidates, list) else None,
                    styles=styles if isinstance(styles, list) else None,
                    max_chars=max_chars,
                )
            if action == "diff_rewrites":
                return self.diff_rewrites(
                    original=text,
                    revised=str(params.get("revised", "")),
                    context=context,
                    style=style,
                    max_chars=max_chars,
                )
            if action == "cache_get":
                return self.cache_get(str(params.get("key", text)))
            if action == "cache_put":
                return self.cache_put(
                    str(params.get("key", _hash_key(text))),
                    params.get("value", {"text": text, "context": context}),
                    ttl_sec=params.get("ttl_sec"),
                )

            return {
                "ok": False,
                "action": action,
                "error": f"Unknown language_engine action: {action}",
                "available_actions": LANGUAGE_ENGINE_ACTIONS,
            }
        except Exception as exc:
            return {
                "ok": False,
                "action": action,
                "error": str(exc),
                "error_type": type(exc).__name__,
            }


# =============================================================================
# Module-level singleton and tool functions
# =============================================================================

_DEFAULT_ENGINE: Optional[LanguageEngine] = None


def get_language_engine(config: Optional[LanguageEngineConfig] = None) -> LanguageEngine:
    global _DEFAULT_ENGINE
    if config is not None:
        return LanguageEngine(config)
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = LanguageEngine()
    return _DEFAULT_ENGINE


def language_engine(
    action: str = "rewrite",
    text: str = "",
    context: str = "",
    style: str = "auto",
    mode: str = "auto",
    max_chars: int = DEFAULT_MAX_CHARS,
    max_sentences: int = DEFAULT_MAX_SENTENCES,
    max_queries: int = DEFAULT_MAX_QUERIES,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
    fast: bool = True,
    use_optional: bool = True,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Main GPT-facing language engine call.

    Keep this signature stable for tools.py:
      action: operation name
      text: primary text/request/tool output
      context: optional user/task context
      style/mode: rewrite style hints
      params: optional extra config/action-specific fields
    """
    engine = get_language_engine()
    return engine.run(
        action=action,
        text=text,
        context=context,
        style=style,
        mode=mode,
        max_chars=max_chars,
        max_sentences=max_sentences,
        max_queries=max_queries,
        preserve_markdown=preserve_markdown,
        preserve_code=preserve_code,
        fast=fast,
        use_optional=use_optional,
        params=params,
    )


def language_engine_tool_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": LANGUAGE_ENGINE_ACTIONS,
                "default": "rewrite",
                "description": "Language engine operation.",
            },
            "text": {
                "type": "string",
                "default": "",
                "description": "Primary text, user request, draft answer, code-adjacent prose, or tool output.",
            },
            "context": {
                "type": "string",
                "default": "",
                "description": "Optional extra context, user goal, prior tool output, or constraints.",
            },
            "style": {
                "type": "string",
                "enum": STYLE_PRESETS,
                "default": "auto",
                "description": "Rewrite/answer style.",
            },
            "mode": {
                "type": "string",
                "default": "auto",
                "description": "Optional task mode hint such as debug, apidoc, code, final_answer.",
            },
            "max_chars": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2000000,
                "default": DEFAULT_MAX_CHARS,
            },
            "max_sentences": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000,
                "default": DEFAULT_MAX_SENTENCES,
            },
            "max_queries": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000,
                "default": DEFAULT_MAX_QUERIES,
            },
            "preserve_markdown": {"type": "boolean", "default": True},
            "preserve_code": {"type": "boolean", "default": True},
            "fast": {"type": "boolean", "default": True},
            "use_optional": {
                "type": "boolean",
                "default": True,
                "description": "Use optional local dependencies when installed.",
            },
            "params": {
                "type": "object",
                "default": {},
                "additionalProperties": True,
                "description": (
                    "Action-specific params, e.g. auto_correct, strip_html, tool_name, "
                    "candidates, styles, revised, key, value, ttl_sec."
                ),
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    }


def make_language_engine_tool_function() -> Callable[..., Dict[str, Any]]:
    def _tool(
        action: str = "rewrite",
        text: str = "",
        context: str = "",
        style: str = "auto",
        mode: str = "auto",
        max_chars: int = DEFAULT_MAX_CHARS,
        max_sentences: int = DEFAULT_MAX_SENTENCES,
        max_queries: int = DEFAULT_MAX_QUERIES,
        preserve_markdown: bool = True,
        preserve_code: bool = True,
        fast: bool = True,
        use_optional: bool = True,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return language_engine(
            action=action,
            text=text,
            context=context,
            style=style,
            mode=mode,
            max_chars=max_chars,
            max_sentences=max_sentences,
            max_queries=max_queries,
            preserve_markdown=preserve_markdown,
            preserve_code=preserve_code,
            fast=fast,
            use_optional=use_optional,
            params=params,
        )

    return _tool


def register_language_engine_tool(tools: Any) -> bool:
    """
    Optional registry helper. Works with your ToolRegistry/ToolSpec style if those
    classes are already defined by tools.py.

    Usage in tools.py:
        from language_engine import (
            language_engine,
            language_engine_tool_schema,
            make_language_engine_tool_function,
            register_language_engine_tool,
        )

        register_language_engine_tool(tools)
    """
    try:
        ToolSpec = globals().get("ToolSpec")
        if ToolSpec is None:
            # In tools.py, call this after injecting ToolSpec or register manually.
            return False
        tools.register(
            ToolSpec(
                name="language_engine",
                description=(
                    "Fast local English/response helper. Cleans spacing/typos, checks grammar, rewrites drafts, "
                    "summarizes tool output, extracts intent/constraints, generates search/APIDoc queries, "
                    "and builds final user-facing answers while preserving markdown/code."
                ),
                parameters=language_engine_tool_schema(),
                fn=language_engine,
            )
        )
        return True
    except Exception:
        return False


# =============================================================================
# CLI for quick local tests
# =============================================================================

def _main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="PromptChat language_engine")
    parser.add_argument("action", nargs="?", default="rewrite", choices=LANGUAGE_ENGINE_ACTIONS)
    parser.add_argument("text", nargs="*", help="Text to process. If omitted, stdin is used.")
    parser.add_argument("--context", default="")
    parser.add_argument("--style", default="auto")
    parser.add_argument("--mode", default="auto")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    parser.add_argument("--max-sentences", type=int, default=DEFAULT_MAX_SENTENCES)
    parser.add_argument("--max-queries", type=int, default=DEFAULT_MAX_QUERIES)
    parser.add_argument("--json", action="store_true", help="Print full JSON result.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    text = " ".join(args.text).strip()
    if not text and args.action not in {"status", "help"}:
        try:
            import sys
            text = sys.stdin.read()
        except Exception:
            text = ""

    result = language_engine(
        action=args.action,
        text=text,
        context=args.context,
        style=args.style,
        mode=args.mode,
        max_chars=args.max_chars,
        max_sentences=args.max_sentences,
        max_queries=args.max_queries,
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result.get("text") or result.get("summary") or json.dumps(result, ensure_ascii=False, indent=2))

    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(_main())
