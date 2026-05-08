from __future__ import annotations

import html
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote_plus, unquote, urljoin, urlparse

import requests

try:
    from retrieval import SimpleFileRetrieval
except Exception:
    SimpleFileRetrieval = None

try:
    from project_tools import LocalPythonProjectTools
except Exception:
    LocalPythonProjectTools = None


DEFAULT_WEB_TIMEOUT_SEC = 20
DEFAULT_MAX_PAGE_CHARS = 12000
DEFAULT_TOR_SOCKS_URL = "socks5h://127.0.0.1:9150"


STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "but",
    "if",
    "to",
    "for",
    "of",
    "in",
    "on",
    "at",
    "by",
    "with",
    "from",
    "as",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "do",
    "does",
    "did",
    "how",
    "what",
    "when",
    "where",
    "why",
    "can",
    "could",
    "should",
    "would",
    "using",
    "use",
    "our",
    "us",
    "make",
    "try",
    "find",
    "look",
    "search",
    "browser",
    "tool",
    "tools",
    "latest",
    "new",
}


BAD_RESULT_DOMAINS = {
    "duckduckgo.com",
    "www.duckduckgo.com",
    "google.com",
    "www.google.com",
    "bing.com",
    "www.bing.com",
    "search.yahoo.com",
    "yahoo.com",
    "www.yahoo.com",
}


GOOD_BONUS_DOMAINS = {
    "docs.python-requests.org",
    "developer.mozilla.org",
    "docs.python.org",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "readthedocs.io",
    "pypi.org",
    "learn.microsoft.com",
    "ollama.com",
    "docs.ollama.com",
}


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: Dict[str, Any]
    fn: Callable[..., Any]

    def as_ollama_tool(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        self._tools[tool.name] = tool

    def names(self) -> List[str]:
        return sorted(self._tools.keys())

    def schemas(self) -> List[Dict[str, Any]]:
        return [tool.as_ollama_tool() for tool in self._tools.values()]

    def call(self, name: str, arguments: Any) -> str:
        if name not in self._tools:
            return json.dumps(
                {
                    "ok": False,
                    "error": f"Unknown tool: {name}",
                    "available_tools": self.names(),
                },
                ensure_ascii=False,
            )

        if isinstance(arguments, str):
            try:
                args = json.loads(arguments or "{}")
            except json.JSONDecodeError as exc:
                return json.dumps(
                    {"ok": False, "error": f"Invalid JSON tool arguments: {exc}"},
                    ensure_ascii=False,
                )
        elif isinstance(arguments, dict):
            args = arguments
        else:
            return json.dumps(
                {"ok": False, "error": "Tool arguments must be a JSON object or JSON string."},
                ensure_ascii=False,
            )

        if not isinstance(args, dict):
            return json.dumps(
                {"ok": False, "error": "Tool arguments must decode to a JSON object."},
                ensure_ascii=False,
            )

        try:
            result = self._tools[name].fn(**args)
            return json.dumps(result, ensure_ascii=False)
        except TypeError as exc:
            return json.dumps(
                {"ok": False, "error": f"Invalid tool arguments for {name}: {exc}"},
                ensure_ascii=False,
            )
        except Exception as exc:
            return json.dumps(
                {"ok": False, "error": f"Tool {name} failed: {exc}"},
                ensure_ascii=False,
            )


def get_time() -> Dict[str, str]:
    return {"ok": True, "unix_time": str(int(time.time()))}


def save_note(title: str, body: str) -> Dict[str, Any]:
    notes_dir = Path("data/notes")
    notes_dir.mkdir(parents=True, exist_ok=True)

    safe_title = "".join(c for c in title if c.isalnum() or c in (" ", "-", "_")).strip() or "note"
    note_path = notes_dir / f"{safe_title}.txt"
    note_path.write_text(body, encoding="utf-8")

    return {"ok": True, "saved_to": str(note_path)}


def list_notes() -> Dict[str, Any]:
    notes_dir = Path("data/notes")
    notes_dir.mkdir(parents=True, exist_ok=True)
    notes = sorted(p.name for p in notes_dir.glob("*.txt"))
    return {"ok": True, "notes": notes}


def read_note(title: str) -> Dict[str, Any]:
    notes_dir = Path("data/notes")
    note_path = notes_dir / f"{title}.txt"

    if not note_path.exists():
        return {"ok": False, "error": f"Note not found: {title}.txt"}

    return {
        "ok": True,
        "title": title,
        "content": note_path.read_text(encoding="utf-8"),
    }


def search_local_knowledge(
    query: str,
    limit: int = 5,
    per_file_limit: int = 2,
    excerpt_chars: int = 800,
) -> Dict[str, Any]:
    if SimpleFileRetrieval is None:
        return {
            "ok": False,
            "error": "SimpleFileRetrieval is not available. Check retrieval.py.",
        }

    retriever = SimpleFileRetrieval()
    results = retriever.search(
        query=query,
        limit=limit,
        per_file_limit=per_file_limit,
        excerpt_chars=excerpt_chars,
    )

    return {
        "ok": True,
        "query": query,
        "count": len(results),
        "results": results,
    }


def _normalize_url(url: str) -> str:
    raw = (url or "").strip()

    if not raw:
        raise ValueError("URL is required.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        first_part = raw.split("/", 1)[0].lower()
        if first_part.endswith(".onion"):
            raw = "http://" + raw
        else:
            raw = "https://" + raw

    parsed = urlparse(raw)

    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")

    return raw


def _make_session(
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: Optional[str] = None,
) -> tuple[requests.Session, int]:
    session = requests.Session()

    adapter = requests.adapters.HTTPAdapter(
        pool_connections=8,
        pool_maxsize=16,
        max_retries=0,
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36 GPTProject/1.0"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
    )

    if tor_socks_url:
        session.proxies = {
            "http": tor_socks_url,
            "https": tor_socks_url,
        }

    return session, int(timeout_sec)


def _clean_html_to_text(html_text: str) -> str:
    text = html_text or ""
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?is)<noscript.*?>.*?</noscript>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</div\s*>", "\n", text)
    text = re.sub(r"(?i)</li\s*>", "\n", text)
    text = re.sub(r"(?i)</tr\s*>", "\n", text)
    text = re.sub(r"(?i)</h[1-6]\s*>", "\n\n", text)
    text = re.sub(r"(?s)<.*?>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_title(html_text: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_text or "")
    if not match:
        return ""
    return _clean_html_to_text(match.group(1))[:300]


def _extract_meta_description(html_text: str) -> str:
    patterns = [
        r'(?is)<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
        r'(?is)<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']description["\']',
        r'(?is)<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']',
        r'(?is)<meta[^>]+content=["\'](.*?)["\'][^>]+property=["\']og:description["\']',
    ]

    for pattern in patterns:
        m = re.search(pattern, html_text or "")
        if m:
            return html.unescape(m.group(1)).strip()[:500]

    return ""


def _extract_links_from_html(base_url: str, html_text: str, max_links: int = 50) -> List[Dict[str, str]]:
    links: List[Dict[str, str]] = []
    seen: set[str] = set()

    for href, label in re.findall(
        r'(?is)<a\b[^>]*href=["\'](.*?)["\'][^>]*>(.*?)</a>',
        html_text or "",
    ):
        href = html.unescape(href).strip()

        if not href:
            continue

        lower_href = href.lower()

        if href.startswith("#") or lower_href.startswith("javascript:") or lower_href.startswith("mailto:"):
            continue

        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)

        if parsed.scheme not in {"http", "https"}:
            continue

        if absolute in seen:
            continue

        seen.add(absolute)

        links.append(
            {
                "url": absolute,
                "text": _clean_html_to_text(label)[:200],
                "domain": parsed.netloc,
            }
        )

        if len(links) >= max_links:
            break

    return links


def _request_failed_result(
    *,
    mode: str,
    url: str,
    error: Exception,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ok": False,
        "mode": mode,
        "url": url,
        "error": f"Request failed: {error}",
    }

    if tor_socks_url:
        result["tor_socks_url"] = tor_socks_url
        result["hint"] = (
            "Make sure Tor Browser or the Tor daemon is running, "
            "and that requests[socks] is installed."
        )

    return result


def _fetch_url(
    url: str,
    *,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_url = _normalize_url(url)
    session, timeout_value = _make_session(
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url,
    )

    mode = "tor" if tor_socks_url else "web"

    try:
        response = session.get(
            normalized_url,
            timeout=timeout_value,
            allow_redirects=True,
        )
        response.raise_for_status()
        body = response.text or ""
    except requests.RequestException as exc:
        return _request_failed_result(
            mode=mode,
            url=normalized_url,
            error=exc,
            tor_socks_url=tor_socks_url,
        )
    finally:
        session.close()

    content_type = response.headers.get("Content-Type", "")
    title = _extract_title(body)
    meta_description = _extract_meta_description(body)
    text = _clean_html_to_text(body)

    truncated = False
    if len(text) > max_chars:
        text = text[:max_chars]
        truncated = True

    return {
        "ok": True,
        "mode": mode,
        "url": normalized_url,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": content_type,
        "title": title,
        "description": meta_description,
        "text": text,
        "truncated": truncated,
        "char_count": len(text),
        "tor_socks_url": tor_socks_url or "",
    }


def browse_web(
    url: str,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
) -> Dict[str, Any]:
    return _fetch_url(
        url,
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        tor_socks_url=None,
    )


def browse_tor(
    url: str,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
) -> Dict[str, Any]:
    return _fetch_url(
        url,
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
    )


def extract_links(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_links: int = 25,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_url = _normalize_url(url)
    session, timeout_value = _make_session(
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url,
    )

    mode = "tor" if tor_socks_url else "web"

    try:
        response = session.get(
            normalized_url,
            timeout=timeout_value,
            allow_redirects=True,
        )
        response.raise_for_status()
        body = response.text or ""
    except requests.RequestException as exc:
        return _request_failed_result(
            mode=mode,
            url=normalized_url,
            error=exc,
            tor_socks_url=tor_socks_url,
        )
    finally:
        session.close()

    links = _extract_links_from_html(response.url, body, max_links=max_links)

    return {
        "ok": True,
        "mode": mode,
        "url": normalized_url,
        "final_url": response.url,
        "count": len(links),
        "links": links,
        "tor_socks_url": tor_socks_url or "",
    }


def extract_links_tor(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_links: int = 25,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
) -> Dict[str, Any]:
    return extract_links(
        url=url,
        timeout_sec=timeout_sec,
        max_links=max_links,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
    )


def check_tor_proxy(
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    timeout_sec: int = 8,
) -> Dict[str, Any]:
    session, timeout_value = _make_session(
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
    )

    try:
        response = session.get(
            "https://check.torproject.org/api/ip",
            timeout=timeout_value,
        )
        response.raise_for_status()
        data = response.json()
        return {
            "ok": True,
            "tor_socks_url": tor_socks_url,
            "is_tor": bool(data.get("IsTor")),
            "ip": data.get("IP", ""),
            "raw": data,
        }
    except Exception as exc:
        return {
            "ok": False,
            "tor_socks_url": tor_socks_url,
            "error": str(exc),
            "hint": "Start Tor Browser or Tor daemon and install requests[socks] if needed.",
        }
    finally:
        session.close()


def _rewrite_query(query: str) -> List[str]:
    raw = (query or "").strip()

    if not raw:
        return []

    terms = []
    for token in re.findall(r"[A-Za-z0-9_'\-]+", raw):
        t = token.lower().strip("'")
        if len(t) >= 3 and t not in STOPWORDS:
            terms.append(token)

    compact = " ".join(terms[:12]).strip()
    rewrites = [raw]

    if compact and compact != raw:
        rewrites.append(compact)

    return list(dict.fromkeys(rewrites))


def _extract_duckduckgo_results(body: str, max_results: int = 20) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for match in re.finditer(
        r'(?is)<a[^>]+class=["\'][^"\']*result__a[^"\']*["\'][^>]+href=["\'](.*?)["\'][^>]*>(.*?)</a>',
        body or "",
    ):
        url = html.unescape(match.group(1))
        title = _clean_html_to_text(match.group(2))

        if "uddg=" in url:
            m = re.search(r"[?&]uddg=([^&]+)", url)
            if m:
                url = unquote(m.group(1))

        out.append({"title": title, "url": url, "snippet": ""})

        if len(out) >= max_results:
            break

    if out:
        return out

    for match in re.finditer(
        r'(?is)<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
        body or "",
    ):
        url = html.unescape(match.group(1))
        title = _clean_html_to_text(match.group(2))
        host = urlparse(url).netloc.lower()

        if title and host not in BAD_RESULT_DOMAINS:
            out.append({"title": title[:300], "url": url, "snippet": ""})

        if len(out) >= max_results:
            break

    return out


def _extract_generic_results(body: str, max_results: int = 20) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for match in re.finditer(r"https?://[^\s\"'<>]+", body or ""):
        url = html.unescape(match.group(0)).rstrip(").,;")
        host = urlparse(url).netloc.lower()

        if host in BAD_RESULT_DOMAINS or url in seen:
            continue

        seen.add(url)
        out.append({"title": url, "url": url, "snippet": ""})

        if len(out) >= max_results:
            break

    return out


def _score_result(item: Dict[str, Any], query: str) -> float:
    hay = f"{item.get('title', '')} {item.get('snippet', '')} {item.get('url', '')}".lower()

    terms = [
        t.lower()
        for t in re.findall(r"[A-Za-z0-9_'\-]+", query or "")
        if len(t) > 2 and t.lower() not in STOPWORDS
    ]

    score = sum(1.0 for t in terms if t in hay)

    host = urlparse(item.get("url", "")).netloc.lower()
    for good in GOOD_BONUS_DOMAINS:
        if host == good or host.endswith("." + good):
            score += 1.5
            break

    return score


def search_web(
    query: str,
    max_results: int = 5,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    raw_query = (query or "").strip()
    rewrites = _rewrite_query(raw_query)

    if not rewrites:
        return {"ok": False, "error": "Could not generate search queries."}

    all_results: List[Dict[str, Any]] = []
    seen_urls: set[str] = set()

    session, timeout_value = _make_session(
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url,
    )

    mode = "tor" if tor_socks_url else "web"

    try:
        for rewritten in rewrites:
            candidate_urls = [
                f"https://html.duckduckgo.com/html/?q={quote_plus(rewritten)}",
                f"https://lite.duckduckgo.com/lite/?q={quote_plus(rewritten)}",
            ]

            parsed_any: List[Dict[str, Any]] = []

            for search_url in candidate_urls:
                try:
                    response = session.get(search_url, timeout=timeout_value, allow_redirects=True)
                    response.raise_for_status()
                    body = response.text or ""
                except requests.RequestException:
                    continue

                parsed = _extract_duckduckgo_results(body, max_results=max_results * 3)

                if not parsed:
                    parsed = _extract_generic_results(body, max_results=max_results * 3)

                if parsed:
                    parsed_any = parsed
                    break

            for item in parsed_any:
                url = item.get("url", "")

                if not url or url in seen_urls:
                    continue

                seen_urls.add(url)
                item["matched_query"] = rewritten
                item["score"] = _score_result(item, raw_query)
                all_results.append(item)

    finally:
        session.close()

    all_results.sort(key=lambda x: x.get("score", 0.0), reverse=True)
    final_results = all_results[:max_results]

    return {
        "ok": True,
        "mode": mode,
        "query": raw_query,
        "rewritten_queries": rewrites,
        "count": len(final_results),
        "results": final_results,
        "tor_socks_url": tor_socks_url or "",
    }


def search_tor(
    query: str,
    max_results: int = 5,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
) -> Dict[str, Any]:
    return search_web(
        query=query,
        max_results=max_results,
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
    )


def _register_project_tools(tools: ToolRegistry, app_config: Any = None) -> None:
    if app_config is None:
        return

    if not bool(getattr(app_config, "project_tools_enabled", True)):
        return

    if LocalPythonProjectTools is None:
        return

    project = LocalPythonProjectTools.from_app_config(app_config)

    if project is None:
        return

    tools.register(
        ToolSpec(
            name="project_status",
            description=(
                "Return the configured local Python project root and enabled capabilities. "
                "Use this first before project scanning or running."
            ),
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            fn=lambda: project.project_status(),
        )
    )

    tools.register(
        ToolSpec(
            name="project_tree",
            description=(
                "List files in the configured local Python project. "
                "Use this before reading files."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "max_files": {"type": "integer", "minimum": 1, "maximum": 3000},
                    "suffix": {"type": "string", "description": "Optional suffix filter, such as .py"},
                    "include_hidden": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            fn=lambda max_files=350, suffix="", include_hidden=False: project.project_tree(
                max_files=max_files,
                suffix=suffix,
                include_hidden=include_hidden,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="read_project_file",
            description=(
                "Read a text/code file from the configured local project root. "
                "Path must stay inside the project root."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 100, "maximum": 300000},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
            fn=lambda path, max_chars=None: project.read_project_file(
                path=path,
                max_chars=max_chars,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="search_project",
            description=(
                "Search the configured local Python project for code/text and return ranked excerpts. "
                "Use this to locate classes, methods, errors, configs, and imports."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 100},
                    "context_chars": {"type": "integer", "minimum": 80, "maximum": 4000},
                    "suffix": {"type": "string"},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            fn=lambda query, max_results=25, context_chars=700, suffix="": project.search_project(
                query=query,
                max_results=max_results,
                context_chars=context_chars,
                suffix=suffix,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="summarize_project",
            description=(
                "Build a structural summary of the configured Python project: files, packages, "
                "classes, functions, and imports."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "max_files": {"type": "integer", "minimum": 50, "maximum": 5000},
                },
                "additionalProperties": False,
            },
            fn=lambda max_files=1000: project.summarize_project(max_files=max_files),
        )
    )

    tools.register(
        ToolSpec(
            name="run_project_command",
            description=(
                "Run an allowlisted command in the configured local project without shell=True. "
                "Use for tests, linting, py_compile, or safe diagnostics."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}},
                        ]
                    },
                    "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 300},
                    "cwd": {"type": "string"},
                },
                "required": ["command"],
                "additionalProperties": False,
            },
            fn=lambda command, timeout_sec=None, cwd=".": project.run_project_command(
                command=command,
                timeout_sec=timeout_sec,
                cwd=cwd,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="run_python_file",
            description="Run a Python file inside the configured local project root.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 300},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
            fn=lambda path, args=None, timeout_sec=None: project.run_python_file(
                path=path,
                args=args,
                timeout_sec=timeout_sec,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="compile_python_file",
            description="Run python -m py_compile on a Python file inside the configured project.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 300},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
            fn=lambda path, timeout_sec=None: project.compile_python_file(
                path=path,
                timeout_sec=timeout_sec,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="run_pytest",
            description="Run pytest -q against the configured local Python project and return stdout/stderr.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 300},
                    "extra_args": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": False,
            },
            fn=lambda target="", timeout_sec=None, extra_args=None: project.run_pytest(
                target=target,
                timeout_sec=timeout_sec,
                extra_args=extra_args,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="run_ruff",
            description=(
                "Run ruff check against the configured project. "
                "fix=true only works when project_write_enabled is true."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "fix": {"type": "boolean"},
                    "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 300},
                },
                "additionalProperties": False,
            },
            fn=lambda target=".", fix=False, timeout_sec=None: project.run_ruff(
                target=target,
                fix=fix,
                timeout_sec=timeout_sec,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="write_project_file",
            description=(
                "Write a text/code file inside the configured project. "
                "Disabled unless project_write_enabled=true."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "create_dirs": {"type": "boolean"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
            fn=lambda path, content, create_dirs=True: project.write_project_file(
                path=path,
                content=content,
                create_dirs=create_dirs,
            ),
        )
    )


def build_default_tool_registry(
    *,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    prefer_tor_for_web: bool = False,
    app_config: Any = None,
) -> ToolRegistry:
    tools = ToolRegistry()
    tor_socks_url_config = tor_socks_url or DEFAULT_TOR_SOCKS_URL

    def effective_tor_url(user_value: str = "") -> str:
        return (user_value or tor_socks_url_config or DEFAULT_TOR_SOCKS_URL).strip()

    tools.register(
        ToolSpec(
            name="get_time",
            description="Get the current Unix time.",
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            fn=lambda: get_time(),
        )
    )

    tools.register(
        ToolSpec(
            name="save_note",
            description="Save a note to local disk.",
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["title", "body"],
                "additionalProperties": False,
            },
            fn=save_note,
        )
    )

    tools.register(
        ToolSpec(
            name="list_notes",
            description="List saved note filenames.",
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            fn=lambda: list_notes(),
        )
    )

    tools.register(
        ToolSpec(
            name="read_note",
            description="Read one saved note by title without .txt.",
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                },
                "required": ["title"],
                "additionalProperties": False,
            },
            fn=read_note,
        )
    )

    tools.register(
        ToolSpec(
            name="search_local_knowledge",
            description="Search local text/code files in data/knowledge.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    "per_file_limit": {"type": "integer", "minimum": 1, "maximum": 5},
                    "excerpt_chars": {"type": "integer", "minimum": 150, "maximum": 2000},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            fn=search_local_knowledge,
        )
    )

    tools.register(
        ToolSpec(
            name="browse_web",
            description="Fetch a normal web page and return readable text.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 500, "maximum": 50000},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 120},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            fn=browse_web,
        )
    )

    tools.register(
        ToolSpec(
            name="browse_tor",
            description="Fetch a web page through Tor SOCKS proxy.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 500, "maximum": 50000},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "tor_socks_url": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            fn=lambda url, max_chars=DEFAULT_MAX_PAGE_CHARS, timeout_sec=DEFAULT_WEB_TIMEOUT_SEC, tor_socks_url="": browse_tor(
                url=url,
                max_chars=max_chars,
                timeout_sec=timeout_sec,
                tor_socks_url=effective_tor_url(tor_socks_url),
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="extract_links",
            description="Fetch a normal page and return outgoing links.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 120},
                    "max_links": {"type": "integer", "minimum": 1, "maximum": 100},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            fn=extract_links,
        )
    )

    tools.register(
        ToolSpec(
            name="extract_links_tor",
            description="Fetch a page through Tor and return outgoing links.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_links": {"type": "integer", "minimum": 1, "maximum": 100},
                    "tor_socks_url": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            fn=lambda url, timeout_sec=DEFAULT_WEB_TIMEOUT_SEC, max_links=25, tor_socks_url="": extract_links_tor(
                url=url,
                timeout_sec=timeout_sec,
                max_links=max_links,
                tor_socks_url=effective_tor_url(tor_socks_url),
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="check_tor_proxy",
            description="Check whether the configured Tor SOCKS proxy works.",
            parameters={
                "type": "object",
                "properties": {
                    "tor_socks_url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 30},
                },
                "additionalProperties": False,
            },
            fn=lambda tor_socks_url="", timeout_sec=8: check_tor_proxy(
                tor_socks_url=effective_tor_url(tor_socks_url),
                timeout_sec=timeout_sec,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="search_web",
            description=(
                "Search the web and return ranked results. "
                "If config prefer_tor_for_web is true, route through Tor."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 20},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 120},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            fn=lambda query, max_results=5, timeout_sec=DEFAULT_WEB_TIMEOUT_SEC: search_tor(
                query=query,
                max_results=max_results,
                timeout_sec=timeout_sec,
                tor_socks_url=tor_socks_url_config,
            )
            if prefer_tor_for_web
            else search_web(
                query=query,
                max_results=max_results,
                timeout_sec=timeout_sec,
                tor_socks_url=None,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="search_tor",
            description="Search the web through configured Tor SOCKS proxy.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 20},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "tor_socks_url": {"type": "string"},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            fn=lambda query, max_results=5, timeout_sec=DEFAULT_WEB_TIMEOUT_SEC, tor_socks_url="": search_tor(
                query=query,
                max_results=max_results,
                timeout_sec=timeout_sec,
                tor_socks_url=effective_tor_url(tor_socks_url),
            ),
        )
    )

    _register_project_tools(tools, app_config)
    return tools