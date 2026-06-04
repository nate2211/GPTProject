# intelligence_engine.py
# ---------------------------------------------------------------------------
# PromptChat / local GPT intelligence engine
#
# A meta-tool for your GPT runtime:
#   user question -> subqueries -> tool calls -> evidence ranking -> uncertainty
#   -> compact intelligence packet the GPT can use to answer smarter.
#
# This file is intentionally standalone. It can integrate with your existing
# ToolRegistry by receiving an object that has:
#   - names() -> list[str]
#   - call(name: str, arguments: dict | str) -> str
#
# It does not require NumPy/SciPy, but will use them if installed for stronger
# numeric/vector scoring.
# ---------------------------------------------------------------------------

from __future__ import annotations

import json
import math
import re
import time
import traceback
from dataclasses import dataclass, asdict, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


try:
    import numpy as _np  # type: ignore
except Exception:
    _np = None

try:
    from scipy import stats as _scipy_stats  # type: ignore
except Exception:
    _scipy_stats = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_TOOL_ROUNDS = 6
DEFAULT_MAX_EVIDENCE = 16
DEFAULT_MAX_EXCERPT_CHARS = 1600
DEFAULT_MAX_TOOL_RESULT_CHARS = 12000


STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "if", "to", "for", "of", "in", "on",
    "at", "by", "with", "from", "as", "is", "are", "was", "were", "be", "been",
    "being", "do", "does", "did", "how", "what", "when", "where", "why", "can",
    "could", "should", "would", "using", "use", "make", "build", "create",
    "write", "rewrite", "full", "new", "old", "our", "us", "your", "their",
    "this", "that", "these", "those", "into", "onto", "about", "over", "under",
    "after", "before", "then", "than", "also", "just", "like", "need", "needs",
}


CODE_HINTS = {
    "code", "class", "function", "method", "signature", "compile", "compiler",
    "exception", "traceback", "error", "crash", "bug", "fix", "rewrite",
    "api", "docs", "documentation", "import", "module", "file", "project",
}


FRESH_HINTS = {
    "latest", "current", "today", "recent", "newest", "now", "version",
    "release", "updated", "2025", "2026",
}


MATH_HINTS = {
    "rank", "score", "confidence", "probability", "optimize", "matrix",
    "vector", "distance", "similarity", "statistics", "mean", "variance",
    "outlier", "cluster", "correlation", "linear", "regression", "uncertainty",
}


SAFE_RESULT_KEYS = {
    "ok", "error", "query", "url", "final_url", "title", "path", "file",
    "source", "source_key", "display_name", "kind", "text", "content",
    "excerpt", "snippet", "summary", "results", "matches", "items",
    "evidence", "pages", "docs", "count", "score", "elapsed_ms",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    source: str
    title: str
    locator: str
    excerpt: str
    score: float = 0.0
    confidence: float = 0.0
    kind: str = "unknown"
    tool: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolTraceItem:
    tool: str
    arguments: Dict[str, Any]
    ok: bool
    elapsed_ms: int
    result_excerpt: str = ""
    error: str = ""


@dataclass
class IntelligenceReport:
    ok: bool
    query: str
    mode: str
    answer_strategy: str
    summary: str
    evidence: List[Dict[str, Any]]
    contradictions: List[str]
    missing_information: List[str]
    suggested_answer: str
    tool_trace: List[Dict[str, Any]]
    capabilities: Dict[str, Any]
    elapsed_ms: int


@dataclass
class IntelligenceConfig:
    max_tool_rounds: int = DEFAULT_MAX_TOOL_ROUNDS
    max_evidence: int = DEFAULT_MAX_EVIDENCE
    max_excerpt_chars: int = DEFAULT_MAX_EXCERPT_CHARS
    max_tool_result_chars: int = DEFAULT_MAX_TOOL_RESULT_CHARS
    allow_web: bool = True
    allow_project: bool = True
    allow_local: bool = True
    allow_apidoc: bool = True
    allow_math: bool = True
    include_tool_trace: bool = True
    strict_no_guessing: bool = True


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _now_ms(start: float) -> int:
    return int((time.time() - start) * 1000)


def _safe_json_loads(text: Any) -> Any:
    if isinstance(text, (dict, list)):
        return text
    if text is None:
        return None
    s = str(text)
    try:
        return json.loads(s)
    except Exception:
        return {"ok": False, "raw_text": s}


def _safe_json_dumps(obj: Any, limit: int = DEFAULT_MAX_TOOL_RESULT_CHARS) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        text = str(obj)
    if len(text) > limit:
        return text[:limit] + "\n...[truncated]"
    return text


def _clip(text: Any, limit: int = DEFAULT_MAX_EXCERPT_CHARS) -> str:
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(s) <= limit:
        return s
    return s[:limit].rstrip() + " ...[truncated]"


def _flatten_text(obj: Any, limit: int = 24000) -> str:
    """Extract readable text from arbitrary nested tool output."""
    parts: List[str] = []

    def walk(x: Any, depth: int = 0) -> None:
        if len(" ".join(parts)) > limit:
            return
        if depth > 5:
            return
        if x is None:
            return
        if isinstance(x, str):
            if x.strip():
                parts.append(x.strip())
            return
        if isinstance(x, (int, float, bool)):
            parts.append(str(x))
            return
        if isinstance(x, dict):
            for k, v in x.items():
                if str(k) in {"html", "raw", "body_bytes", "content_bytes"}:
                    continue
                if str(k) in SAFE_RESULT_KEYS or isinstance(v, (str, int, float, bool, list, dict)):
                    parts.append(str(k))
                    walk(v, depth + 1)
            return
        if isinstance(x, (list, tuple)):
            for item in x[:80]:
                walk(item, depth + 1)
            return
        parts.append(str(x))

    walk(obj)
    out = re.sub(r"\s+", " ", " ".join(parts)).strip()
    return out[:limit]


def _keywords(text: str, limit: int = 32) -> List[str]:
    words = re.findall(r"[A-Za-z0-9_#.+:-]{3,}", text or "")
    out: List[str] = []
    seen = set()

    for w in words:
        lw = w.lower().strip(".,:;()[]{}")
        if lw in STOPWORDS or lw in seen:
            continue
        seen.add(lw)
        out.append(w.strip(".,:;()[]{}"))
        if len(out) >= limit:
            break

    return out


def _token_set(text: str) -> set[str]:
    return {w.lower() for w in _keywords(text, limit=256)}


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / max(1, len(sa | sb))


def _cosine_bow(a: str, b: str) -> float:
    """Tiny bag-of-words cosine without requiring sklearn."""
    ta = _token_set(a)
    tb = _token_set(b)
    if not ta or not tb:
        return 0.0

    if _np is not None:
        vocab = sorted(ta | tb)
        va = _np.array([1.0 if t in ta else 0.0 for t in vocab], dtype=float)
        vb = _np.array([1.0 if t in tb else 0.0 for t in vocab], dtype=float)
        denom = float(_np.linalg.norm(va) * _np.linalg.norm(vb))
        return float(_np.dot(va, vb) / denom) if denom else 0.0

    inter = len(ta & tb)
    return inter / math.sqrt(max(1, len(ta) * len(tb)))


def _score_evidence(query: str, item_text: str, source: str = "", kind: str = "") -> Tuple[float, float]:
    qtokens = _token_set(query)
    itokens = _token_set(item_text)
    overlap = _jaccard(qtokens, itokens)
    cosine = _cosine_bow(query, item_text)

    source_bonus = 0.0
    sl = source.lower()
    kl = kind.lower()

    if "project" in sl or "local" in sl:
        source_bonus += 0.20
    if "apidoc" in sl or "docs" in sl or "numpy" in sl or "scipy" in sl:
        source_bonus += 0.18
    if "web" in sl or "search" in sl:
        source_bonus += 0.08
    if "official" in sl or "direct" in sl:
        source_bonus += 0.12
    if "error" in kl:
        source_bonus -= 0.12

    exact_bonus = 0.15 if query.lower()[:80] in item_text.lower() else 0.0

    score = max(0.0, min(1.0, (0.52 * cosine) + (0.35 * overlap) + source_bonus + exact_bonus))
    confidence = max(0.0, min(1.0, score * 0.92 + (0.08 if len(item_text) > 200 else 0.0)))
    return round(score, 4), round(confidence, 4)


def _mode_from_query(query: str, explicit: str = "auto") -> str:
    explicit = (explicit or "auto").lower().strip()
    if explicit and explicit != "auto":
        return explicit

    low = query.lower()
    tokens = set(_keywords(low, limit=64))

    if tokens & MATH_HINTS:
        return "math"
    if tokens & CODE_HINTS:
        return "code"
    if tokens & FRESH_HINTS:
        return "research"
    if "api" in low or "docs" in low or "documentation" in low:
        return "docs"
    return "general"


def _subqueries(query: str, context: str = "", mode: str = "auto", limit: int = 8) -> List[str]:
    base = re.sub(r"\s+", " ", (query or "").strip())
    ctx = re.sub(r"\s+", " ", (context or "").strip())
    keys = _keywords(base + " " + ctx, limit=24)

    items: List[str] = []
    if base:
        items.append(base)

    if keys:
        items.append(" ".join(keys[:10]))

    low = base.lower()
    mode = _mode_from_query(base, mode)

    if mode in {"code", "debug"} or any(x in low for x in ("error", "crash", "exception", "traceback", "bug")):
        items.extend([
            base + " root cause",
            base + " exact error",
            base + " fix implementation",
        ])

    if mode in {"docs", "code"} or any(x in low for x in ("api", "docs", "signature", "method", "class")):
        items.extend([
            base + " official API docs",
            base + " method signature parameters return type",
        ])

    if mode in {"math", "analysis"}:
        items.extend([
            base + " numeric scoring uncertainty ranking",
            base + " mathematical model",
        ])

    if mode == "research" or any(x in low for x in FRESH_HINTS):
        items.append(base + " latest documentation current")

    # Deduplicate while preserving order.
    out: List[str] = []
    seen = set()
    for q in items:
        q = re.sub(r"\s+", " ", q).strip()
        if q and q.lower() not in seen:
            out.append(q)
            seen.add(q.lower())
        if len(out) >= limit:
            break

    return out


def _detect_contradictions(evidence: List[EvidenceItem]) -> List[str]:
    text = "\n".join(e.excerpt.lower() for e in evidence)
    contradictions: List[str] = []

    pairs = [
        ("supported", "unsupported"),
        ("enabled", "disabled"),
        ("available", "not available"),
        ("works", "fails"),
        ("success", "failed"),
        ("recommended", "deprecated"),
        ("safe", "unsafe"),
        ("true", "false"),
        ("official", "unofficial"),
    ]

    for a, b in pairs:
        if a in text and b in text:
            contradictions.append(f"Evidence contains both '{a}' and '{b}'. Verify before relying on this conclusion.")

    # Look for version conflicts.
    versions = sorted(set(re.findall(r"\b(?:v|version\s*)?(\d+\.\d+(?:\.\d+)?)\b", text)))
    if len(versions) >= 4:
        contradictions.append(f"Multiple versions appear in evidence: {', '.join(versions[:8])}. Check version-specific behavior.")

    return contradictions[:12]


def _missing_information(query: str, evidence: List[EvidenceItem], tool_errors: List[str]) -> List[str]:
    missing: List[str] = []

    if not evidence:
        missing.append("No usable evidence was collected from available tools.")

    if tool_errors:
        missing.append("Some tools failed: " + "; ".join(tool_errors[:4]))

    qlow = query.lower()
    joined = " ".join(e.excerpt.lower() for e in evidence[:8])

    if any(x in qlow for x in ("error", "crash", "exception", "traceback")) and "traceback" not in joined and "exception" not in joined:
        missing.append("Exact traceback/log context may be missing.")

    if any(x in qlow for x in ("api", "docs", "signature")) and "parameter" not in joined and "signature" not in joined:
        missing.append("Official signature/parameter details may be missing.")

    if any(x in qlow for x in FRESH_HINTS) and not any(x in joined for x in ("2025", "2026", "latest", "release", "version")):
        missing.append("Freshness/version evidence is weak.")

    return missing[:12]


def _suggested_answer(query: str, evidence: List[EvidenceItem], contradictions: List[str], missing: List[str]) -> str:
    if not evidence:
        return (
            "I do not have enough evidence to answer confidently. The GPT should ask for the relevant file/logs "
            "or run project/local/API-doc search before making claims."
        )

    lines: List[str] = []
    lines.append("Use this answer strategy:")
    lines.append("1. State the likely answer directly.")
    lines.append("2. Ground it in the highest-scoring evidence.")
    lines.append("3. Mention uncertainty if contradictions or missing information exist.")
    lines.append("")
    lines.append("Highest-value evidence:")

    for i, item in enumerate(evidence[:5], start=1):
        loc = f" ({item.locator})" if item.locator else ""
        lines.append(f"{i}. [{item.source}] {item.title}{loc}: {_clip(item.excerpt, 420)}")

    if contradictions:
        lines.append("")
        lines.append("Contradictions to handle:")
        for c in contradictions[:4]:
            lines.append(f"- {c}")

    if missing:
        lines.append("")
        lines.append("Missing/weak evidence:")
        for m in missing[:4]:
            lines.append(f"- {m}")

    lines.append("")
    lines.append("Final response should not invent tool results. If evidence is weak, say exactly what is weak.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool adapter
# ---------------------------------------------------------------------------

class ToolCaller:
    """
    Small adapter around your PromptChat ToolRegistry.

    Expected registry API:
        registry.names() -> list[str]
        registry.call(name, arguments) -> JSON string

    You can also pass a simple dict[str, callable].
    """

    def __init__(self, tools: Any = None) -> None:
        self.tools = tools

    def names(self) -> List[str]:
        if self.tools is None:
            return []
        try:
            if hasattr(self.tools, "names"):
                return list(self.tools.names())
            if isinstance(self.tools, dict):
                return sorted(str(k) for k in self.tools.keys())
        except Exception:
            return []
        return []

    def has(self, name: str) -> bool:
        return name in set(self.names())

    def call(self, name: str, arguments: Dict[str, Any]) -> Tuple[bool, Any, str]:
        if self.tools is None:
            return False, None, "No tool registry was provided."

        try:
            if hasattr(self.tools, "call"):
                raw = self.tools.call(name, arguments)
                data = _safe_json_loads(raw)
                ok = bool(isinstance(data, dict) and data.get("ok", True))
                if isinstance(data, dict) and data.get("error"):
                    ok = False
                return ok, data, ""

            if isinstance(self.tools, dict) and name in self.tools:
                result = self.tools[name](**arguments)
                ok = bool(not isinstance(result, dict) or result.get("ok", True))
                return ok, result, ""

            return False, None, f"Tool is unavailable: {name}"
        except Exception as exc:
            return False, None, f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Evidence normalization
# ---------------------------------------------------------------------------

def _item_from_mapping(
    *,
    tool: str,
    source: str,
    query: str,
    row: Dict[str, Any],
    fallback_kind: str = "result",
) -> EvidenceItem:
    title = (
        row.get("title")
        or row.get("name")
        or row.get("heading")
        or row.get("subject")
        or row.get("file")
        or row.get("path")
        or row.get("url")
        or source
    )

    locator = (
        row.get("url")
        or row.get("final_url")
        or row.get("href")
        or row.get("path")
        or row.get("file")
        or row.get("saved_text")
        or row.get("source")
        or ""
    )

    excerpt = (
        row.get("excerpt")
        or row.get("snippet")
        or row.get("summary")
        or row.get("description")
        or row.get("text")
        or row.get("content")
        or _flatten_text(row, limit=2000)
    )

    kind = str(row.get("kind") or row.get("type") or fallback_kind)
    score_value, confidence = _score_evidence(query, str(title) + " " + str(excerpt), source=source, kind=kind)

    raw_small = {str(k): v for k, v in row.items() if str(k) in SAFE_RESULT_KEYS}

    return EvidenceItem(
        source=source,
        title=_clip(title, 220),
        locator=_clip(locator, 360),
        excerpt=_clip(excerpt, DEFAULT_MAX_EXCERPT_CHARS),
        score=score_value,
        confidence=confidence,
        kind=kind,
        tool=tool,
        raw=raw_small,
    )


def _normalize_tool_result(tool: str, query: str, result: Any) -> List[EvidenceItem]:
    rows: List[EvidenceItem] = []

    data = result
    if isinstance(data, str):
        data = _safe_json_loads(data)

    if not isinstance(data, (dict, list)):
        return [
            EvidenceItem(
                source=tool,
                title=tool,
                locator="",
                excerpt=_clip(data),
                score=_score_evidence(query, str(data), source=tool)[0],
                confidence=_score_evidence(query, str(data), source=tool)[1],
                kind="raw",
                tool=tool,
            )
        ]

    if isinstance(data, list):
        for item in data[:50]:
            if isinstance(item, dict):
                rows.append(_item_from_mapping(tool=tool, source=tool, query=query, row=item))
            else:
                text = _clip(item)
                score_value, confidence = _score_evidence(query, text, source=tool)
                rows.append(EvidenceItem(tool, tool, "", text, score_value, confidence, "list_item", tool))
        return rows

    source = (
        str(data.get("source") or data.get("source_key") or data.get("display_name") or tool)
        if isinstance(data, dict)
        else tool
    )

    # Common result buckets used by your tools.py/APIDoc/project tools.
    buckets = [
        "evidence", "results", "matches", "items", "pages", "docs",
        "sniffed_pages", "urls", "links", "files",
    ]

    found_bucket = False
    for bucket in buckets:
        value = data.get(bucket)
        if not value:
            continue
        found_bucket = True

        if isinstance(value, dict):
            value = list(value.values())

        if isinstance(value, list):
            for row in value[:80]:
                if isinstance(row, dict):
                    # Handle search_and_sniff format.
                    if "search_result" in row and isinstance(row["search_result"], dict):
                        rows.append(_item_from_mapping(
                            tool=tool,
                            source=source,
                            query=query,
                            row=row["search_result"],
                            fallback_kind=bucket,
                        ))
                    else:
                        rows.append(_item_from_mapping(
                            tool=tool,
                            source=source,
                            query=query,
                            row=row,
                            fallback_kind=bucket,
                        ))
                else:
                    text = _clip(row)
                    score_value, confidence = _score_evidence(query, text, source=source, kind=bucket)
                    rows.append(EvidenceItem(source, bucket, "", text, score_value, confidence, bucket, tool))

    if not found_bucket:
        text = _flatten_text(data, limit=4000)
        title = str(data.get("title") or data.get("query") or tool)
        locator = str(data.get("url") or data.get("path") or data.get("final_url") or "")
        score_value, confidence = _score_evidence(query, title + " " + text, source=source)
        rows.append(EvidenceItem(source, _clip(title, 220), _clip(locator, 360), _clip(text), score_value, confidence, "summary", tool))

    return rows


def _dedupe_evidence(items: Sequence[EvidenceItem]) -> List[EvidenceItem]:
    out: List[EvidenceItem] = []
    seen = set()

    for item in items:
        key = (
            item.source.lower(),
            item.locator.lower()[:300],
            item.title.lower()[:120],
            item.excerpt.lower()[:180],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)

    return out


# ---------------------------------------------------------------------------
# Intelligence engine
# ---------------------------------------------------------------------------

class IntelligenceEngine:
    def __init__(
        self,
        tools: Any = None,
        *,
        config: Optional[IntelligenceConfig] = None,
    ) -> None:
        self.toolcaller = ToolCaller(tools)
        self.config = config or IntelligenceConfig()

    def capabilities(self) -> Dict[str, Any]:
        names = self.toolcaller.names()
        name_set = set(names)

        groups = {
            "local": [n for n in names if n in {"search_local_knowledge", "list_notes", "read_note"}],
            "project": [n for n in names if n.startswith("project_") or n in {"search_project", "read_project_file", "project_tree", "project_status"}],
            "web": [n for n in names if n in {"search_web", "browse_web", "search_and_sniff", "sniff_url"}],
            "apidoc": [n for n in names if "apidoc" in n.lower() or n in {"api_docs", "search_api_docs"}],
            "math": [n for n in names if n.startswith("math_")],
            "forensic": [n for n in names if "forensic" in n.lower() or "cdn" in n.lower() or "archive" in n.lower()],
        }

        return {
            "tool_count": len(names),
            "available_tools": names,
            "groups": groups,
            "has_numpy": _np is not None,
            "has_scipy_stats": _scipy_stats is not None,
            "recommended_core_tools_present": {
                "search_local_knowledge": "search_local_knowledge" in name_set,
                "search_web": "search_web" in name_set,
                "search_project": "search_project" in name_set,
                "project_status": "project_status" in name_set,
                "apidoc": any("apidoc" in n.lower() for n in names),
            },
        }

    def _call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        trace: List[ToolTraceItem],
    ) -> Tuple[bool, Any]:
        start = time.time()
        ok, data, err = self.toolcaller.call(tool_name, arguments)
        elapsed = _now_ms(start)

        trace.append(
            ToolTraceItem(
                tool=tool_name,
                arguments=arguments,
                ok=ok,
                elapsed_ms=elapsed,
                result_excerpt=_clip(_safe_json_dumps(data, limit=1400), 900) if data is not None else "",
                error=err,
            )
        )

        return ok, data

    def _tool_candidates(self, mode: str) -> Dict[str, List[str]]:
        names = set(self.toolcaller.names())

        def available(candidates: Sequence[str]) -> List[str]:
            return [x for x in candidates if x in names]

        apidoc_names = [n for n in names if "apidoc" in n.lower()]
        math_names = [n for n in names if n.startswith("math_")]

        return {
            "local": available(["search_local_knowledge"]),
            "project": available(["search_project", "project_status", "project_tree"]),
            "web": available(["search_web", "search_and_sniff", "browse_web"]),
            "apidoc": sorted(apidoc_names),
            "math": sorted(math_names),
        }

    def _run_local_phase(self, query: str, subqueries: List[str], trace: List[ToolTraceItem]) -> List[EvidenceItem]:
        if not self.config.allow_local or not self.toolcaller.has("search_local_knowledge"):
            return []

        evidence: List[EvidenceItem] = []

        for sq in subqueries[:3]:
            ok, data = self._call_tool(
                "search_local_knowledge",
                {
                    "query": sq,
                    "limit": 6,
                    "per_file_limit": 2,
                    "excerpt_chars": self.config.max_excerpt_chars,
                },
                trace,
            )
            if ok:
                evidence.extend(_normalize_tool_result("search_local_knowledge", query, data))

        return evidence

    def _run_project_phase(self, query: str, subqueries: List[str], trace: List[ToolTraceItem]) -> List[EvidenceItem]:
        if not self.config.allow_project:
            return []

        evidence: List[EvidenceItem] = []

        if self.toolcaller.has("project_status"):
            ok, data = self._call_tool("project_status", {}, trace)
            if ok:
                evidence.extend(_normalize_tool_result("project_status", query, data))

        search_name = "search_project" if self.toolcaller.has("search_project") else ""
        if not search_name:
            return evidence

        for sq in subqueries[:4]:
            # Different project tool versions use different parameter names.
            # Try the richer form first; ToolRegistry will return an error if invalid.
            ok, data = self._call_tool(
                search_name,
                {"query": sq, "max_results": 8, "context_chars": 1200},
                trace,
            )
            if not ok:
                ok, data = self._call_tool(
                    search_name,
                    {"query": sq, "limit": 8},
                    trace,
                )
            if ok:
                evidence.extend(_normalize_tool_result(search_name, query, data))

        return evidence

    def _run_web_phase(self, query: str, subqueries: List[str], trace: List[ToolTraceItem]) -> List[EvidenceItem]:
        if not self.config.allow_web:
            return []

        evidence: List[EvidenceItem] = []

        web_tool = ""
        for candidate in ("search_and_sniff", "search_web"):
            if self.toolcaller.has(candidate):
                web_tool = candidate
                break

        if not web_tool:
            return evidence

        for sq in subqueries[:2]:
            if web_tool == "search_and_sniff":
                args = {"query": sq, "max_results": 5, "sniff_top_n": 2, "timeout_sec": 20}
            else:
                args = {"query": sq, "max_results": 6, "timeout_sec": 20}

            ok, data = self._call_tool(web_tool, args, trace)
            if ok:
                evidence.extend(_normalize_tool_result(web_tool, query, data))

        return evidence

    def _run_apidoc_phase(self, query: str, subqueries: List[str], trace: List[ToolTraceItem]) -> List[EvidenceItem]:
        if not self.config.allow_apidoc:
            return []

        names = self.toolcaller.names()
        apidoc_tools = [n for n in names if n.lower() in {"apidoc", "api_docs", "search_api_docs", "apidoc_discover"}]
        apidoc_tools += [n for n in names if "apidoc" in n.lower() and n not in apidoc_tools]
        apidoc_tools = apidoc_tools[:2]

        if not apidoc_tools:
            return []

        evidence: List[EvidenceItem] = []

        for tool in apidoc_tools:
            for sq in subqueries[:3]:
                possible_args = [
                    {"query": sq},
                    {"queries": [sq]},
                    {"payload": sq},
                ]
                for args in possible_args:
                    ok, data = self._call_tool(tool, args, trace)
                    if ok:
                        evidence.extend(_normalize_tool_result(tool, query, data))
                        break

        return evidence

    def _run_math_phase(self, query: str, evidence: List[EvidenceItem], trace: List[ToolTraceItem]) -> List[EvidenceItem]:
        """
        Optional second-pass math/tool ranking.

        If your GPT registry later exposes math_rank_evidence or similar, this
        engine will use it. Otherwise it already has built-in NumPy/SciPy-light
        scoring.
        """
        if not self.config.allow_math or not evidence:
            return evidence

        if not self.toolcaller.has("math_rank_evidence"):
            return evidence

        candidates = [
            {
                "source": e.source,
                "title": e.title,
                "locator": e.locator,
                "excerpt": e.excerpt,
                "score": e.score,
            }
            for e in evidence[:30]
        ]

        ok, data = self._call_tool(
            "math_rank_evidence",
            {"query": query, "candidates": candidates, "max_results": self.config.max_evidence},
            trace,
        )

        if not ok:
            return evidence

        # If the math tool returns ranked rows, merge scores back by locator/title.
        ranked = data.get("results") if isinstance(data, dict) else None
        if not isinstance(ranked, list):
            return evidence

        bonus: Dict[Tuple[str, str], float] = {}
        for idx, row in enumerate(ranked):
            if not isinstance(row, dict):
                continue
            key = (str(row.get("locator") or row.get("url") or ""), str(row.get("title") or ""))
            bonus[key] = max(0.0, 0.12 - idx * 0.01)

        for e in evidence:
            key = (e.locator, e.title)
            if key in bonus:
                e.score = round(min(1.0, e.score + bonus[key]), 4)
                e.confidence = round(min(1.0, e.confidence + bonus[key]), 4)

        return evidence

    def investigate(
        self,
        query: str,
        *,
        context: str = "",
        mode: str = "auto",
        max_evidence: Optional[int] = None,
        allow_web: Optional[bool] = None,
        allow_project: Optional[bool] = None,
        allow_local: Optional[bool] = None,
        allow_apidoc: Optional[bool] = None,
        allow_math: Optional[bool] = None,
    ) -> Dict[str, Any]:
        started = time.time()
        query = re.sub(r"\s+", " ", str(query or "")).strip()
        context = str(context or "").strip()
        resolved_mode = _mode_from_query(query + " " + context, mode)

        if not query:
            report = IntelligenceReport(
                ok=False,
                query=query,
                mode=resolved_mode,
                answer_strategy="no_query",
                summary="No query was provided.",
                evidence=[],
                contradictions=[],
                missing_information=["query"],
                suggested_answer="Ask the user for a concrete question or task.",
                tool_trace=[],
                capabilities=self.capabilities(),
                elapsed_ms=_now_ms(started),
            )
            return asdict(report)

        # Per-call override without permanently mutating config.
        old_flags = (
            self.config.allow_web,
            self.config.allow_project,
            self.config.allow_local,
            self.config.allow_apidoc,
            self.config.allow_math,
        )
        if allow_web is not None:
            self.config.allow_web = bool(allow_web)
        if allow_project is not None:
            self.config.allow_project = bool(allow_project)
        if allow_local is not None:
            self.config.allow_local = bool(allow_local)
        if allow_apidoc is not None:
            self.config.allow_apidoc = bool(allow_apidoc)
        if allow_math is not None:
            self.config.allow_math = bool(allow_math)

        try:
            max_ev = max(1, int(max_evidence or self.config.max_evidence))
            subqs = _subqueries(query, context, resolved_mode)
            trace: List[ToolTraceItem] = []
            evidence: List[EvidenceItem] = []

            # Choose phases based on mode but still opportunistically use available tools.
            if resolved_mode in {"code", "debug", "docs", "general", "math"}:
                evidence.extend(self._run_local_phase(query, subqs, trace))

            if resolved_mode in {"code", "debug", "docs"}:
                evidence.extend(self._run_project_phase(query, subqs, trace))
                evidence.extend(self._run_apidoc_phase(query, subqs, trace))

            if resolved_mode == "math":
                evidence.extend(self._run_local_phase(query, subqs, trace))
                evidence.extend(self._run_apidoc_phase(query, subqs, trace))

            if resolved_mode in {"research", "general", "docs"}:
                evidence.extend(self._run_web_phase(query, subqs, trace))

            # If no evidence, broaden one step.
            if not evidence:
                evidence.extend(self._run_project_phase(query, subqs, trace))
                evidence.extend(self._run_apidoc_phase(query, subqs, trace))
                evidence.extend(self._run_web_phase(query, subqs, trace))

            evidence = _dedupe_evidence(evidence)

            # Recompute scores against the original query/context.
            scoring_query = query + " " + context
            for item in evidence:
                s, c = _score_evidence(scoring_query, item.title + " " + item.excerpt, item.source, item.kind)
                item.score = s
                item.confidence = c

            evidence = self._run_math_phase(scoring_query, evidence, trace)
            evidence.sort(key=lambda e: (e.score, e.confidence), reverse=True)
            evidence = evidence[:max_ev]

            tool_errors = [t.error or t.result_excerpt for t in trace if not t.ok]
            contradictions = _detect_contradictions(evidence)
            missing = _missing_information(query, evidence, tool_errors)

            strong_count = len([e for e in evidence if e.score >= 0.50])
            summary = (
                f"Collected {len(evidence)} evidence item(s), {strong_count} strong, "
                f"using mode '{resolved_mode}'."
            )

            if not evidence:
                answer_strategy = "ask_or_search_more"
            elif contradictions:
                answer_strategy = "answer_with_conflict_warning"
            elif missing:
                answer_strategy = "answer_with_uncertainty"
            else:
                answer_strategy = "answer_directly_from_evidence"

            report = IntelligenceReport(
                ok=True,
                query=query,
                mode=resolved_mode,
                answer_strategy=answer_strategy,
                summary=summary,
                evidence=[asdict(e) for e in evidence],
                contradictions=contradictions,
                missing_information=missing,
                suggested_answer=_suggested_answer(query, evidence, contradictions, missing),
                tool_trace=[asdict(t) for t in trace] if self.config.include_tool_trace else [],
                capabilities=self.capabilities(),
                elapsed_ms=_now_ms(started),
            )
            return asdict(report)

        except Exception as exc:
            report = IntelligenceReport(
                ok=False,
                query=query,
                mode=resolved_mode,
                answer_strategy="engine_error",
                summary=f"IntelligenceEngine failed: {type(exc).__name__}: {exc}",
                evidence=[],
                contradictions=[],
                missing_information=["engine_exception"],
                suggested_answer="The GPT should continue with available context and clearly state the engine failed.",
                tool_trace=[],
                capabilities=self.capabilities(),
                elapsed_ms=_now_ms(started),
            )
            out = asdict(report)
            out["traceback"] = traceback.format_exc()
            return out
        finally:
            (
                self.config.allow_web,
                self.config.allow_project,
                self.config.allow_local,
                self.config.allow_apidoc,
                self.config.allow_math,
            ) = old_flags


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

_DEFAULT_ENGINE: Optional[IntelligenceEngine] = None


def get_default_intelligence_engine(tools: Any = None) -> IntelligenceEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None or tools is not None:
        _DEFAULT_ENGINE = IntelligenceEngine(tools=tools)
    return _DEFAULT_ENGINE


def intelligence_engine(
    query: str,
    context: str = "",
    mode: str = "auto",
    max_evidence: int = DEFAULT_MAX_EVIDENCE,
    allow_web: bool = True,
    allow_project: bool = True,
    allow_local: bool = True,
    allow_apidoc: bool = True,
    allow_math: bool = True,
    tools: Any = None,
) -> Dict[str, Any]:
    """
    Direct callable version.

    In PromptChat, usually you will not pass tools here manually. Instead,
    register a wrapper from tools.py that closes over your ToolRegistry.
    """
    engine = get_default_intelligence_engine(tools)
    return engine.investigate(
        query=query,
        context=context,
        mode=mode,
        max_evidence=max_evidence,
        allow_web=allow_web,
        allow_project=allow_project,
        allow_local=allow_local,
        allow_apidoc=allow_apidoc,
        allow_math=allow_math,
    )


# ---------------------------------------------------------------------------
# Optional registration helper for your tools.py
# ---------------------------------------------------------------------------

def intelligence_tool_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The user's question or task to investigate.",
            },
            "context": {
                "type": "string",
                "description": "Optional extra context, pasted error, code summary, or user constraints.",
                "default": "",
            },
            "mode": {
                "type": "string",
                "enum": ["auto", "general", "code", "debug", "docs", "research", "math"],
                "default": "auto",
            },
            "max_evidence": {
                "type": "integer",
                "minimum": 1,
                "maximum": 40,
                "default": DEFAULT_MAX_EVIDENCE,
            },
            "allow_web": {"type": "boolean", "default": True},
            "allow_project": {"type": "boolean", "default": True},
            "allow_local": {"type": "boolean", "default": True},
            "allow_apidoc": {"type": "boolean", "default": True},
            "allow_math": {"type": "boolean", "default": True},
        },
        "required": ["query"],
    }


def make_intelligence_tool_function(tool_registry: Any) -> Callable[..., Dict[str, Any]]:
    """
    Use inside tools.py:

        from intelligence_engine import make_intelligence_tool_function, intelligence_tool_schema

        registry.register(ToolSpec(
            name="intelligence_engine",
            description="Meta-research engine...",
            parameters=intelligence_tool_schema(),
            fn=make_intelligence_tool_function(registry),
        ))

    Important:
    The wrapper closes over the same registry that the model uses, so the engine
    can call search_project, search_local_knowledge, apidoc, search_web, etc.
    """

    def _tool(
        query: str,
        context: str = "",
        mode: str = "auto",
        max_evidence: int = DEFAULT_MAX_EVIDENCE,
        allow_web: bool = True,
        allow_project: bool = True,
        allow_local: bool = True,
        allow_apidoc: bool = True,
        allow_math: bool = True,
    ) -> Dict[str, Any]:
        engine = IntelligenceEngine(tools=tool_registry)
        return engine.investigate(
            query=query,
            context=context,
            mode=mode,
            max_evidence=max_evidence,
            allow_web=allow_web,
            allow_project=allow_project,
            allow_local=allow_local,
            allow_apidoc=allow_apidoc,
            allow_math=allow_math,
        )

    return _tool


def register_intelligence_tool(registry: Any, ToolSpec: Any = None) -> bool:
    """
    Optional helper if you want registration in one line.

    Works when your tools.py exposes ToolSpec with fields:
        name, description, parameters, fn

    Returns True if registered.
    """
    if registry is None or ToolSpec is None:
        return False

    registry.register(
        ToolSpec(
            name="intelligence_engine",
            description=(
                "Meta-research and verification engine for the local GPT. "
                "Use before answering hard questions, code/debug questions, API-doc questions, "
                "math/ranking questions, or anything that needs evidence from tools."
            ),
            parameters=intelligence_tool_schema(),
            fn=make_intelligence_tool_function(registry),
        )
    )
    return True


# ---------------------------------------------------------------------------
# Local smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    class DemoTools:
        def names(self) -> List[str]:
            return ["search_local_knowledge", "search_web"]

        def call(self, name: str, arguments: Any) -> str:
            if name == "search_local_knowledge":
                return json.dumps({
                    "ok": True,
                    "results": [
                        {
                            "title": "Local GPT Tool Registry",
                            "path": "tools.py",
                            "excerpt": "ToolRegistry registers callable ToolSpec objects and calls tools by name with JSON arguments.",
                        }
                    ],
                })
            if name == "search_web":
                return json.dumps({
                    "ok": True,
                    "results": [
                        {
                            "title": "Official documentation result",
                            "url": "https://example.com/docs",
                            "snippet": "Official docs explain parameters, return values, and examples.",
                        }
                    ],
                })
            return json.dumps({"ok": False, "error": "unknown tool"})

    engine = IntelligenceEngine(DemoTools())
    print(json.dumps(engine.investigate("How should our GPT use tools for smarter answers?"), indent=2))
