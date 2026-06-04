from __future__ import annotations

"""
forensic_engine.py

Standalone, safe internet-forensics and lost-content discovery engine for PromptChat/GPT toolbeds.

Scope
-----
This engine is designed for public or authorized content discovery only. It does not bypass
logins, paywalls, access controls, robots policy, rate limits, or technical restrictions.
It focuses on evidence preservation, URL/source provenance, metadata extraction, public
archive lookup, sitemap/feed discovery, redirect graphs, TLS/DNS context, and asset clues.

Drop-in usage
-------------
    from forensic_engine import ForensicEngine, ForensicConfig

    engine = ForensicEngine(ForensicConfig())
    report = engine.investigate_url("https://example.com", include_archives=True)
    print(report.to_json())

CLI
---
    python forensic_engine.py url https://example.com --archives --depth 1 --out report.json
    python forensic_engine.py file ./some_image.jpg --out file_report.json
"""

import argparse
import base64
import csv
import datetime as _dt
import gzip
import hashlib
import html
import json
import mimetypes
import os
import re
import socket
import sqlite3
import ssl
import sys
import tempfile
import time
import traceback
import urllib.robotparser
import zlib
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urldefrag, urljoin, urlparse, urlunparse

try:
    import requests
except Exception as exc:  # pragma: no cover
    raise RuntimeError("forensic_engine.py requires requests. Install with: pip install requests") from exc

try:  # optional, better HTML parsing
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None

try:  # optional DNS detail
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None  # type: ignore

try:  # optional image metadata
    from PIL import Image  # type: ignore
except Exception:  # pragma: no cover
    Image = None  # type: ignore


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 PromptChatForensics/1.0"
)

TRACKING_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "gclid", "dclid", "gbraid", "wbraid", "fbclid", "msclkid", "ttclid", "twclid",
    "yclid", "mc_cid", "mc_eid", "ref", "referrer", "spm",
}

SECRET_QUERY_HINTS = {
    "token", "auth", "authorization", "sig", "signature", "expires", "expire", "exp",
    "policy", "key-pair-id", "x-amz-", "x-goog-", "x-ms-", "hdnts", "hmac", "session",
    "sess", "psid", "key", "password", "passwd", "secret", "jwt", "bearer",
}

MEDIA_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".avif", ".heic", ".heif", ".tiff",
    ".mp4", ".webm", ".mkv", ".mov", ".avi", ".m4v", ".m3u8", ".mpd", ".m4s", ".ts",
    ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wav", ".weba",
}

DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".json", ".xml", ".rss", ".atom", ".md"}
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"}

URL_RE = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>`\\]+", re.I)
SCHEMELESS_RE = re.compile(r"(?<!:)//[^\s\"'<>`\\]+", re.I)
CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", re.I)
SRCSET_PART_RE = re.compile(r"\s*,\s*")


# ---------------------------------------------------------------------------
# Core records
# ---------------------------------------------------------------------------
@dataclass
class ForensicConfig:
    timeout_sec: float = 20.0
    max_body_bytes: int = 2_000_000
    max_text_chars: int = 200_000
    max_evidence_items: int = 2_000
    max_links_per_page: int = 500
    max_archive_results: int = 50
    max_sitemap_urls: int = 1_000
    max_depth: int = 1
    max_pages: int = 25
    rate_limit_delay_sec: float = 0.2
    user_agent: str = DEFAULT_USER_AGENT
    follow_redirects: bool = True
    verify_tls: bool = True
    respect_robots: bool = True
    include_archive_search: bool = True
    include_commoncrawl_search: bool = True
    include_wayback_search: bool = True
    include_dns: bool = True
    include_tls: bool = True
    include_sitemaps: bool = True
    include_feeds: bool = True
    include_oembed: bool = True
    include_url_variants: bool = True
    include_head_probe: bool = True
    include_range_probe: bool = True
    include_binary_magic: bool = True
    allow_cross_host_crawl: bool = False
    keep_original_url: bool = False
    keep_secret_query_values: bool = False
    sqlite_path: str = ""
    artifact_dir: str = "data/forensics/artifacts"
    host_allow_substrings: Set[str] = field(default_factory=set)
    host_deny_substrings: Set[str] = field(default_factory=set)


@dataclass
class EvidenceItem:
    evidence_id: str
    evidence_type: str
    source: str
    url: str = ""
    final_url: str = ""
    original_url_sha256: str = ""
    title: str = ""
    status_code: int = 0
    content_type: str = ""
    content_length: str = ""
    sha256: str = ""
    md5: str = ""
    collected_at: str = ""
    collector: str = ""
    confidence: float = 0.0
    parent_id: str = ""
    relation: str = ""
    tags: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    text_excerpt: str = ""
    artifact_path: str = ""

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in ("", None, [], {})}


@dataclass
class ForensicReport:
    ok: bool
    target: str
    started_at: str
    finished_at: str = ""
    elapsed_ms: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)
    evidence: List[EvidenceItem] = field(default_factory=list)
    edges: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_ms": self.elapsed_ms,
            "summary": self.summary,
            "evidence_count": len(self.evidence),
            "edge_count": len(self.edges),
            "evidence": [x.as_dict() for x in self.evidence],
            "edges": self.edges,
            "errors": self.errors,
            "warnings": self.warnings,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_markdown(self) -> str:
        lines = [
            f"# Forensic Report",
            "",
            f"- Target: `{self.target}`",
            f"- OK: `{self.ok}`",
            f"- Evidence items: `{len(self.evidence)}`",
            f"- Edges: `{len(self.edges)}`",
            f"- Started: `{self.started_at}`",
            f"- Finished: `{self.finished_at}`",
            "",
            "## Summary",
            "",
        ]
        for k, v in self.summary.items():
            lines.append(f"- **{k}**: `{v}`")
        if self.errors:
            lines.extend(["", "## Errors", ""])
            lines.extend(f"- {e}" for e in self.errors[:50])
        lines.extend(["", "## Top Evidence", ""])
        for item in self.evidence[:100]:
            lines.append(f"- `{item.evidence_type}` `{item.status_code or ''}` {item.url or item.source} ({item.collector})")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Evidence store
# ---------------------------------------------------------------------------
class EvidenceStore:
    def __init__(self, sqlite_path: str) -> None:
        self.sqlite_path = sqlite_path
        self.conn: Optional[sqlite3.Connection] = None
        if sqlite_path:
            self.open()

    def open(self) -> None:
        Path(self.sqlite_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.sqlite_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                evidence_type TEXT,
                source TEXT,
                url TEXT,
                final_url TEXT,
                original_url_sha256 TEXT,
                title TEXT,
                status_code INTEGER,
                content_type TEXT,
                content_length TEXT,
                sha256 TEXT,
                md5 TEXT,
                collected_at TEXT,
                collector TEXT,
                confidence REAL,
                parent_id TEXT,
                relation TEXT,
                tags_json TEXT,
                headers_json TEXT,
                metadata_json TEXT,
                text_excerpt TEXT,
                artifact_path TEXT
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS edges (
                src TEXT,
                dst TEXT,
                relation TEXT,
                evidence TEXT,
                created_at TEXT
            )
            """
        )
        self.conn.commit()

    def add(self, item: EvidenceItem) -> None:
        if not self.conn:
            return
        self.conn.execute(
            """
            INSERT OR REPLACE INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item.evidence_id,
                item.evidence_type,
                item.source,
                item.url,
                item.final_url,
                item.original_url_sha256,
                item.title,
                item.status_code,
                item.content_type,
                item.content_length,
                item.sha256,
                item.md5,
                item.collected_at,
                item.collector,
                item.confidence,
                item.parent_id,
                item.relation,
                json.dumps(item.tags, ensure_ascii=False),
                json.dumps(item.headers, ensure_ascii=False),
                json.dumps(item.metadata, ensure_ascii=False),
                item.text_excerpt,
                item.artifact_path,
            ),
        )
        self.conn.commit()

    def add_edge(self, src: str, dst: str, relation: str, evidence: str = "") -> None:
        if not self.conn:
            return
        self.conn.execute(
            "INSERT INTO edges VALUES (?,?,?,?,?)",
            (src, dst, relation, evidence, now_iso()),
        )
        self.conn.commit()

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None


# ---------------------------------------------------------------------------
# Simple HTML URL collector fallback
# ---------------------------------------------------------------------------
class LinkHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[Tuple[str, str, str]] = []  # raw_url, tag, attr
        self.meta: List[Dict[str, str]] = []
        self._current_a_href = ""
        self._current_a_text: List[str] = []
        self.anchors: List[Tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        amap = {k.lower(): (v or "") for k, v in attrs}
        tag_l = tag.lower()
        for attr in ("href", "src", "poster", "data-src", "data-original", "data-url", "content", "action"):
            val = amap.get(attr)
            if val:
                self.links.append((html.unescape(val), tag_l, attr))
        if tag_l == "source" and amap.get("srcset"):
            self.links.append((html.unescape(amap["srcset"]), tag_l, "srcset"))
        if tag_l == "img" and amap.get("srcset"):
            self.links.append((html.unescape(amap["srcset"]), tag_l, "srcset"))
        if tag_l == "meta":
            self.meta.append(amap)
        if tag_l == "a" and amap.get("href"):
            self._current_a_href = amap["href"]
            self._current_a_text = []

    def handle_data(self, data: str) -> None:
        if self._current_a_href:
            self._current_a_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_a_href:
            self.anchors.append((self._current_a_href, " ".join(self._current_a_text).strip()))
            self._current_a_href = ""
            self._current_a_text = []


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class ForensicEngine:
    def __init__(self, config: Optional[ForensicConfig] = None) -> None:
        self.cfg = config or ForensicConfig()
        self.session = self._make_session()
        self.store = EvidenceStore(self.cfg.sqlite_path) if self.cfg.sqlite_path else EvidenceStore("")
        self._seen_evidence_ids: Set[str] = set()
        self._robots_cache: Dict[str, urllib.robotparser.RobotFileParser] = {}

    # ---------------------------- public API ----------------------------
    def investigate_url(
        self,
        url: str,
        *,
        include_archives: Optional[bool] = None,
        depth: Optional[int] = None,
        max_pages: Optional[int] = None,
    ) -> ForensicReport:
        started = time.time()
        target = self.normalize_url(url)
        report = ForensicReport(ok=False, target=self.redact_url(target), started_at=now_iso())
        if not self._host_allowed(target):
            report.errors.append("Target blocked by host allow/deny policy.")
            return self._finish(report, started)

        max_depth = self.cfg.max_depth if depth is None else max(0, int(depth))
        max_pages_eff = self.cfg.max_pages if max_pages is None else max(1, int(max_pages))
        do_archives = self.cfg.include_archive_search if include_archives is None else bool(include_archives)

        try:
            if self.cfg.include_dns:
                for item in self.collect_dns(target):
                    self._add(report, item)
            if self.cfg.include_tls and urlparse(target).scheme == "https":
                for item in self.collect_tls(target):
                    self._add(report, item)

            frontier: List[Tuple[str, int, str]] = [(target, 0, "root")]
            visited: Set[str] = set()
            root_host = urlparse(target).netloc.lower()

            while frontier and len(visited) < max_pages_eff and len(report.evidence) < self.cfg.max_evidence_items:
                current, cur_depth, relation = frontier.pop(0)
                canon = self.canonicalize_url(current)
                if canon in visited:
                    continue
                visited.add(canon)

                if self.cfg.respect_robots and not self._robots_allowed(current):
                    self._add(report, self._make_item(
                        evidence_type="robots_blocked",
                        source="robots",
                        url=current,
                        collector="robots",
                        confidence=0.9,
                        metadata={"reason": "robots.txt disallows fetch for configured user-agent"},
                    ))
                    continue

                page_item, body_text, body_bytes = self.fetch_page(current, relation=relation)
                self._add(report, page_item)

                if body_text:
                    for item in self.extract_page_evidence(current, body_text, page_item.evidence_id):
                        self._add(report, item)
                        if item.url:
                            report.edges.append({
                                "src": page_item.evidence_id,
                                "dst": item.evidence_id,
                                "relation": item.relation or "mentions",
                            })
                            self.store.add_edge(page_item.evidence_id, item.evidence_id, item.relation or "mentions")

                    if cur_depth < max_depth:
                        for link in self.extract_links(current, body_text):
                            p = urlparse(link)
                            if not p.scheme.startswith("http"):
                                continue
                            if not self.cfg.allow_cross_host_crawl and p.netloc.lower() != root_host:
                                continue
                            if self.canonicalize_url(link) not in visited and len(frontier) + len(visited) < max_pages_eff:
                                frontier.append((link, cur_depth + 1, "crawl_link"))

                time.sleep(max(0.0, self.cfg.rate_limit_delay_sec))

            if self.cfg.include_sitemaps:
                for item in self.discover_sitemaps(target):
                    self._add(report, item)

            if self.cfg.include_feeds:
                for item in self.discover_feed_candidates(target):
                    self._add(report, item)

            if self.cfg.include_url_variants:
                for item in self.generate_url_variant_evidence(target):
                    self._add(report, item)

            if do_archives:
                for item in self.discover_archives(target):
                    self._add(report, item)

            report.ok = len(report.evidence) > 0 and not any(e.startswith("fatal") for e in report.errors)
            report.summary = self._summarize(report)
            return self._finish(report, started)
        except Exception as exc:
            report.errors.append(f"fatal: {exc}")
            report.errors.append(traceback.format_exc(limit=4))
            return self._finish(report, started)

    def analyze_file(self, path: str) -> ForensicReport:
        started = time.time()
        p = Path(path)
        report = ForensicReport(ok=False, target=str(p), started_at=now_iso())
        try:
            if not p.exists() or not p.is_file():
                report.errors.append(f"File not found: {path}")
                return self._finish(report, started)
            data = p.read_bytes()
            sha256, md5 = hash_bytes(data)
            ctype = guess_mime_from_bytes(data, str(p))
            item = self._make_item(
                evidence_type="file",
                source="file",
                url=str(p),
                collector="file_analyzer",
                confidence=1.0,
                content_type=ctype,
                content_length=str(len(data)),
                sha256=sha256,
                md5=md5,
                metadata={
                    "name": p.name,
                    "suffix": p.suffix,
                    "size_bytes": len(data),
                    "mtime": _dt.datetime.fromtimestamp(p.stat().st_mtime, tz=_dt.timezone.utc).isoformat(),
                    "magic": magic_label(data),
                },
            )
            self._add(report, item)
            for extra in self.extract_file_metadata(p, data, item.evidence_id):
                self._add(report, extra)
            report.ok = True
            report.summary = self._summarize(report)
            return self._finish(report, started)
        except Exception as exc:
            report.errors.append(f"fatal: {exc}")
            return self._finish(report, started)

    def close(self) -> None:
        self.store.close()
        self.session.close()

    # ---------------------------- collection ----------------------------
    def fetch_page(self, url: str, *, relation: str = "fetch") -> Tuple[EvidenceItem, str, bytes]:
        headers = {"User-Agent": self.cfg.user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        body = b""
        text = ""
        final_url = url
        status = 0
        resp_headers: Dict[str, str] = {}
        error = ""
        try:
            resp = self.session.get(
                url,
                headers=headers,
                timeout=self.cfg.timeout_sec,
                allow_redirects=self.cfg.follow_redirects,
                verify=self.cfg.verify_tls,
                stream=True,
            )
            status = int(resp.status_code)
            final_url = resp.url
            resp_headers = self._safe_headers(resp.headers)
            body = resp.raw.read(self.cfg.max_body_bytes, decode_content=True) or b""
            enc = resp.encoding or "utf-8"
            text = body.decode(enc, errors="replace")
        except Exception as exc:
            error = str(exc)

        sha256, md5 = hash_bytes(body)
        artifact_path = self._save_artifact(body, sha256, suffix=suffix_for_url(final_url)) if body else ""
        item = self._make_item(
            evidence_type="http_response",
            source="network",
            url=url,
            final_url=final_url,
            status_code=status,
            content_type=resp_headers.get("content-type", ""),
            content_length=resp_headers.get("content-length", str(len(body)) if body else ""),
            sha256=sha256,
            md5=md5,
            collector="fetch_page",
            confidence=0.95 if status else 0.2,
            relation=relation,
            headers=resp_headers,
            metadata={
                "redirects": self._redirect_history(url, final_url),
                "error": error,
                "magic": magic_label(body),
            },
            text_excerpt=clean_text(text)[:2000],
            artifact_path=artifact_path,
        )

        if self.cfg.include_head_probe:
            # HEAD probe is stored as metadata on the fetched item to avoid duplicate noise.
            item.metadata["head_probe"] = self.head_probe(url)
        if self.cfg.include_range_probe:
            item.metadata["range_probe"] = self.range_probe(url)
        return item, text[: self.cfg.max_text_chars], body

    def extract_page_evidence(self, base_url: str, text: str, parent_id: str = "") -> List[EvidenceItem]:
        out: List[EvidenceItem] = []
        title = extract_title(text)
        metadata = extract_metadata(base_url, text)
        if title or metadata:
            out.append(self._make_item(
                evidence_type="page_metadata",
                source="html",
                url=base_url,
                title=title,
                collector="metadata_extractor",
                confidence=0.85,
                parent_id=parent_id,
                relation="metadata",
                metadata=metadata,
            ))

        for raw, tag, attr in self.extract_tag_urls(base_url, text):
            kind = classify_url(raw)
            out.append(self._make_item(
                evidence_type=kind,
                source="html",
                url=raw,
                collector="html_url_extractor",
                confidence=0.75,
                parent_id=parent_id,
                relation=f"{tag}.{attr}",
                tags=[tag, attr, kind],
                metadata={"tag": tag, "attribute": attr},
            ))

        for found in extract_urls_from_text(text, base_url):
            out.append(self._make_item(
                evidence_type=classify_url(found),
                source="text_regex",
                url=found,
                collector="url_regex",
                confidence=0.45,
                parent_id=parent_id,
                relation="text_mention",
            ))

        for hit in extract_jsonish_urls(base_url, text):
            out.append(self._make_item(
                evidence_type=classify_url(hit.get("url", "")),
                source="json_or_script",
                url=hit.get("url", ""),
                collector="json_url_miner",
                confidence=float(hit.get("confidence", 0.55)),
                parent_id=parent_id,
                relation=hit.get("path", "json_url"),
                metadata=hit,
            ))

        for srcmap in extract_sourcemap_hints(base_url, text):
            out.append(self._make_item(
                evidence_type="source_map",
                source="script",
                url=srcmap,
                collector="sourcemap_hints",
                confidence=0.6,
                parent_id=parent_id,
                relation="sourceMappingURL",
            ))
        return out

    def extract_links(self, base_url: str, text: str) -> List[str]:
        links: List[str] = []
        seen: Set[str] = set()
        for raw, _tag, _attr in self.extract_tag_urls(base_url, text):
            if raw and raw not in seen:
                seen.add(raw)
                links.append(raw)
            if len(links) >= self.cfg.max_links_per_page:
                break
        return links

    def extract_tag_urls(self, base_url: str, text: str) -> List[Tuple[str, str, str]]:
        rows: List[Tuple[str, str, str]] = []
        seen: Set[str] = set()

        def add(raw: str, tag: str, attr: str) -> None:
            if not raw:
                return
            for part in split_srcset(raw) if attr == "srcset" else [raw]:
                u = self.absolutize_url(part, base_url)
                if not u or u.startswith("javascript:") or u.startswith("mailto:") or u.startswith("tel:"):
                    continue
                u = self.canonicalize_url(u)
                if u not in seen and self._host_allowed(u):
                    seen.add(u)
                    rows.append((u, tag, attr))

        if BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(text, "html.parser")
                for tag in soup.find_all(True):
                    name = str(tag.name).lower()
                    for attr in ("href", "src", "poster", "data-src", "data-original", "data-url", "action", "content", "srcset"):
                        val = tag.get(attr)
                        if isinstance(val, list):
                            val = " ".join(map(str, val))
                        if val:
                            add(str(val), name, attr)
                # CSS urls inside style tags/attrs
                for style in soup.find_all("style"):
                    for m in CSS_URL_RE.finditer(style.get_text("\n")):
                        add(m.group(1), "style", "url")
                for tag in soup.find_all(style=True):
                    for m in CSS_URL_RE.finditer(str(tag.get("style") or "")):
                        add(m.group(1), str(tag.name).lower(), "style.url")
                return rows
            except Exception:
                pass

        parser = LinkHTMLParser()
        try:
            parser.feed(text)
        except Exception:
            pass
        for raw, tag, attr in parser.links:
            add(raw, tag, attr)
        for m in CSS_URL_RE.finditer(text):
            add(m.group(1), "css", "url")
        return rows

    def discover_sitemaps(self, target_url: str) -> List[EvidenceItem]:
        out: List[EvidenceItem] = []
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        candidates = [urljoin(origin, "/robots.txt"), urljoin(origin, "/sitemap.xml"), urljoin(origin, "/sitemap_index.xml")]
        seen: Set[str] = set()

        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                resp = self.session.get(candidate, timeout=self.cfg.timeout_sec, headers={"User-Agent": self.cfg.user_agent})
                if resp.status_code >= 400:
                    continue
                body = resp.text or ""
                item = self._make_item(
                    evidence_type="sitemap_or_robots",
                    source="discovery",
                    url=candidate,
                    final_url=resp.url,
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    collector="sitemap_discovery",
                    confidence=0.8,
                    headers=self._safe_headers(resp.headers),
                    text_excerpt=body[:2000],
                )
                out.append(item)
                if candidate.endswith("robots.txt"):
                    for line in body.splitlines():
                        if line.lower().startswith("sitemap:"):
                            sm = line.split(":", 1)[1].strip()
                            if sm and sm not in seen:
                                seen.add(sm)
                                out.extend(self._parse_sitemap_url(sm, parent_id=item.evidence_id))
                else:
                    out.extend(self._parse_sitemap_text(candidate, body, parent_id=item.evidence_id))
            except Exception:
                continue
        return out[: self.cfg.max_sitemap_urls]

    def _parse_sitemap_url(self, sitemap_url: str, parent_id: str = "") -> List[EvidenceItem]:
        try:
            resp = self.session.get(sitemap_url, timeout=self.cfg.timeout_sec, headers={"User-Agent": self.cfg.user_agent})
            if resp.status_code >= 400:
                return []
            return self._parse_sitemap_text(resp.url, resp.text or "", parent_id=parent_id)
        except Exception:
            return []

    def _parse_sitemap_text(self, sitemap_url: str, xml_text: str, parent_id: str = "") -> List[EvidenceItem]:
        out: List[EvidenceItem] = []
        for loc in re.findall(r"(?is)<loc>\s*(.*?)\s*</loc>", xml_text or ""):
            u = html.unescape(loc.strip())
            if not u:
                continue
            out.append(self._make_item(
                evidence_type="sitemap_url",
                source="sitemap",
                url=self.canonicalize_url(u),
                collector="sitemap_parser",
                confidence=0.85,
                parent_id=parent_id,
                relation="sitemap_loc",
                metadata={"sitemap": sitemap_url},
            ))
            if len(out) >= self.cfg.max_sitemap_urls:
                break
        return out

    def discover_feed_candidates(self, target_url: str) -> List[EvidenceItem]:
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        candidates = [
            urljoin(origin, "/feed"), urljoin(origin, "/rss"), urljoin(origin, "/rss.xml"),
            urljoin(origin, "/atom.xml"), urljoin(origin, "/feed.xml"), urljoin(origin, "/opensearch.xml"),
        ]
        out: List[EvidenceItem] = []
        for u in candidates:
            try:
                resp = self.session.get(u, timeout=self.cfg.timeout_sec, headers={"User-Agent": self.cfg.user_agent})
                ctype = resp.headers.get("content-type", "")
                if resp.status_code < 400 and ("xml" in ctype.lower() or "rss" in (resp.text[:200].lower())):
                    out.append(self._make_item(
                        evidence_type="feed_candidate",
                        source="feed_discovery",
                        url=u,
                        final_url=resp.url,
                        status_code=resp.status_code,
                        content_type=ctype,
                        collector="feed_discovery",
                        confidence=0.65,
                        text_excerpt=(resp.text or "")[:2000],
                    ))
                    for found in extract_urls_from_text(resp.text or "", resp.url):
                        out.append(self._make_item(
                            evidence_type=classify_url(found),
                            source="feed",
                            url=found,
                            collector="feed_url_miner",
                            confidence=0.7,
                            relation="feed_url",
                        ))
            except Exception:
                continue
        return out

    def generate_url_variant_evidence(self, target_url: str) -> List[EvidenceItem]:
        variants = generate_url_variants(target_url)
        return [
            self._make_item(
                evidence_type="url_variant",
                source="variant_generator",
                url=v,
                collector="url_variant_generator",
                confidence=0.35,
                metadata={"reason": "possible moved/deleted/canonical variant"},
            )
            for v in variants
        ]

    def discover_archives(self, target_url: str) -> List[EvidenceItem]:
        out: List[EvidenceItem] = []
        if self.cfg.include_wayback_search:
            out.extend(self.query_wayback_cdx(target_url))
        if self.cfg.include_commoncrawl_search:
            out.extend(self.query_commoncrawl_index(target_url))
        return out[: self.cfg.max_archive_results]

    def query_wayback_cdx(self, target_url: str) -> List[EvidenceItem]:
        api = "https://web.archive.org/cdx"
        params = {
            "url": target_url,
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype,digest",
            "filter": "statuscode:200",
            "collapse": "digest",
            "limit": str(self.cfg.max_archive_results),
        }
        out: List[EvidenceItem] = []
        try:
            resp = self.session.get(api, params=params, timeout=self.cfg.timeout_sec, headers={"User-Agent": self.cfg.user_agent})
            data = resp.json()
            rows = data[1:] if isinstance(data, list) and data and isinstance(data[0], list) else []
            for row in rows:
                ts, original, status, mimetype, digest = (row + [""] * 5)[:5]
                memento = f"https://web.archive.org/web/{ts}/{original}"
                out.append(self._make_item(
                    evidence_type="archive_snapshot",
                    source="wayback_cdx",
                    url=memento,
                    final_url=original,
                    status_code=int(status or 0) if str(status).isdigit() else 0,
                    content_type=mimetype,
                    collector="wayback_cdx",
                    confidence=0.9,
                    metadata={"timestamp": ts, "original": original, "digest": digest, "api": resp.url},
                ))
        except Exception as exc:
            out.append(self._make_item(
                evidence_type="archive_error",
                source="wayback_cdx",
                url=target_url,
                collector="wayback_cdx",
                confidence=0.1,
                metadata={"error": str(exc)},
            ))
        return out

    def query_commoncrawl_index(self, target_url: str) -> List[EvidenceItem]:
        out: List[EvidenceItem] = []
        try:
            idx = self.session.get("https://index.commoncrawl.org/collinfo.json", timeout=self.cfg.timeout_sec).json()
            if not isinstance(idx, list) or not idx:
                return out
            api = idx[0].get("cdx-api") or idx[0].get("cdx-api-url")
            if not api:
                return out
            resp = self.session.get(api, params={"url": target_url, "output": "json", "limit": self.cfg.max_archive_results}, timeout=self.cfg.timeout_sec)
            for line in (resp.text or "").splitlines():
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                out.append(self._make_item(
                    evidence_type="commoncrawl_record",
                    source="commoncrawl",
                    url=row.get("url", target_url),
                    status_code=int(row.get("status", 0) or 0),
                    content_type=row.get("mime", ""),
                    collector="commoncrawl_index",
                    confidence=0.85,
                    metadata=row,
                ))
        except Exception as exc:
            out.append(self._make_item(
                evidence_type="archive_error",
                source="commoncrawl",
                url=target_url,
                collector="commoncrawl_index",
                confidence=0.1,
                metadata={"error": str(exc)},
            ))
        return out

    def collect_dns(self, target_url: str) -> List[EvidenceItem]:
        host = urlparse(target_url).hostname or ""
        if not host:
            return []
        out: List[EvidenceItem] = []
        metadata: Dict[str, Any] = {"host": host}
        try:
            infos = socket.getaddrinfo(host, None)
            metadata["addresses"] = sorted({x[4][0] for x in infos if x and x[4]})
        except Exception as exc:
            metadata["socket_error"] = str(exc)
        if dns is not None:
            for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
                try:
                    answers = dns.resolver.resolve(host, rtype, lifetime=self.cfg.timeout_sec)  # type: ignore[attr-defined]
                    metadata[rtype] = [str(a).strip() for a in answers]
                except Exception:
                    pass
        out.append(self._make_item(
            evidence_type="dns_context",
            source="dns",
            url=target_url,
            collector="dns_context",
            confidence=0.75,
            metadata=metadata,
        ))
        return out

    def collect_tls(self, target_url: str) -> List[EvidenceItem]:
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        if not host:
            return []
        metadata: Dict[str, Any] = {"host": host, "port": port}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.cfg.timeout_sec) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    der = ssock.getpeercert(binary_form=True) or b""
                    metadata.update({
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "serialNumber": cert.get("serialNumber"),
                        "subjectAltName": cert.get("subjectAltName"),
                        "sha256_fingerprint": hashlib.sha256(der).hexdigest() if der else "",
                        "cipher": ssock.cipher(),
                        "version": ssock.version(),
                    })
        except Exception as exc:
            metadata["error"] = str(exc)
        return [self._make_item(
            evidence_type="tls_certificate",
            source="tls",
            url=target_url,
            collector="tls_certificate",
            confidence=0.75 if "error" not in metadata else 0.25,
            metadata=metadata,
        )]

    def head_probe(self, url: str) -> Dict[str, Any]:
        try:
            resp = self.session.head(url, timeout=self.cfg.timeout_sec, allow_redirects=True, headers={"User-Agent": self.cfg.user_agent})
            return {
                "ok": True,
                "status_code": resp.status_code,
                "final_url": self.redact_url(resp.url),
                "headers": self._safe_headers(resp.headers),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def range_probe(self, url: str) -> Dict[str, Any]:
        try:
            resp = self.session.get(
                url,
                timeout=self.cfg.timeout_sec,
                allow_redirects=True,
                headers={"User-Agent": self.cfg.user_agent, "Range": "bytes=0-4095"},
                stream=True,
            )
            data = resp.raw.read(4096, decode_content=True) or b""
            sha256, _md5 = hash_bytes(data)
            return {
                "ok": True,
                "status_code": resp.status_code,
                "final_url": self.redact_url(resp.url),
                "content_type": resp.headers.get("content-type", ""),
                "content_range": resp.headers.get("content-range", ""),
                "accept_ranges": resp.headers.get("accept-ranges", ""),
                "prefix_sha256": sha256,
                "prefix_magic": magic_label(data),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def extract_file_metadata(self, path: Path, data: bytes, parent_id: str = "") -> List[EvidenceItem]:
        out: List[EvidenceItem] = []
        suffix = path.suffix.lower()
        if Image is not None and suffix in {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp", ".gif"}:
            try:
                with Image.open(path) as im:  # type: ignore[union-attr]
                    meta = {
                        "format": im.format,
                        "mode": im.mode,
                        "size": im.size,
                        "info_keys": sorted(list(im.info.keys())),
                    }
                    exif = None
                    try:
                        exif = im.getexif()
                    except Exception:
                        pass
                    if exif:
                        meta["exif_tags_count"] = len(exif)
                        meta["exif_tag_ids"] = [str(k) for k in list(exif.keys())[:200]]
                    out.append(self._make_item(
                        evidence_type="image_metadata",
                        source="file",
                        url=str(path),
                        collector="image_metadata",
                        confidence=0.8,
                        parent_id=parent_id,
                        relation="file_metadata",
                        metadata=meta,
                    ))
            except Exception as exc:
                out.append(self._make_item(
                    evidence_type="metadata_error",
                    source="file",
                    url=str(path),
                    collector="image_metadata",
                    confidence=0.1,
                    parent_id=parent_id,
                    metadata={"error": str(exc)},
                ))
        # URLs embedded in text-like files.
        if suffix in {".txt", ".md", ".html", ".htm", ".json", ".xml", ".csv", ".js", ".css"}:
            try:
                txt = data.decode("utf-8", errors="replace")
                for u in extract_urls_from_text(txt, ""):
                    out.append(self._make_item(
                        evidence_type=classify_url(u),
                        source="file_text",
                        url=u,
                        collector="file_url_miner",
                        confidence=0.55,
                        parent_id=parent_id,
                        relation="embedded_url",
                    ))
            except Exception:
                pass
        return out

    # ---------------------------- helpers ----------------------------
    def _make_session(self) -> requests.Session:
        sess = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=0)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        sess.headers.update({"User-Agent": self.cfg.user_agent})
        return sess

    def _make_item(self, *, evidence_type: str, source: str, collector: str, url: str = "", final_url: str = "", **kw: Any) -> EvidenceItem:
        safe_url = self.redact_url(url)
        safe_final = self.redact_url(final_url) if final_url else ""
        original_hash = hashlib.sha256(url.encode("utf-8", "ignore")).hexdigest() if url else ""
        base = f"{evidence_type}|{source}|{collector}|{safe_url}|{safe_final}|{kw.get('sha256','')}|{kw.get('relation','')}"
        eid = hashlib.sha256(base.encode("utf-8", "ignore")).hexdigest()[:24]
        return EvidenceItem(
            evidence_id=eid,
            evidence_type=evidence_type,
            source=source,
            url=url if self.cfg.keep_original_url else safe_url,
            final_url=final_url if self.cfg.keep_original_url else safe_final,
            original_url_sha256=original_hash,
            collector=collector,
            collected_at=now_iso(),
            **kw,
        )

    def _add(self, report: ForensicReport, item: EvidenceItem) -> None:
        if item.evidence_id in self._seen_evidence_ids:
            return
        if len(report.evidence) >= self.cfg.max_evidence_items:
            return
        self._seen_evidence_ids.add(item.evidence_id)
        report.evidence.append(item)
        self.store.add(item)

    def _finish(self, report: ForensicReport, started: float) -> ForensicReport:
        report.finished_at = now_iso()
        report.elapsed_ms = int((time.time() - started) * 1000)
        if not report.summary:
            report.summary = self._summarize(report)
        return report

    def _summarize(self, report: ForensicReport) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        collectors: Dict[str, int] = {}
        for item in report.evidence:
            counts[item.evidence_type] = counts.get(item.evidence_type, 0) + 1
            collectors[item.collector] = collectors.get(item.collector, 0) + 1
        return {
            "evidence_types": counts,
            "collectors": collectors,
            "unique_urls": len({x.url for x in report.evidence if x.url}),
            "errors": len(report.errors),
            "warnings": len(report.warnings),
        }

    def _save_artifact(self, body: bytes, sha256: str, *, suffix: str = "") -> str:
        if not body or not sha256:
            return ""
        root = Path(self.cfg.artifact_dir)
        root.mkdir(parents=True, exist_ok=True)
        safe_suffix = suffix if suffix and len(suffix) <= 12 and re.fullmatch(r"\.[A-Za-z0-9]+", suffix) else ".bin"
        dest = root / sha256[:2] / f"{sha256}{safe_suffix}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            tmp = dest.with_suffix(dest.suffix + ".tmp")
            tmp.write_bytes(body)
            os.replace(tmp, dest)
        return str(dest)

    def _redirect_history(self, start: str, final: str) -> List[Dict[str, str]]:
        if start == final:
            return []
        return [{"from": self.redact_url(start), "to": self.redact_url(final), "type": "requests_history_summary"}]

    def _safe_headers(self, headers: Mapping[str, Any]) -> Dict[str, str]:
        allowed = {
            "content-type", "content-length", "content-range", "accept-ranges", "etag", "last-modified",
            "cache-control", "expires", "server", "via", "x-cache", "cf-cache-status", "age", "location",
            "content-disposition", "link", "vary", "date", "strict-transport-security", "content-security-policy",
            "referrer-policy", "x-content-type-options", "server-timing",
        }
        out: Dict[str, str] = {}
        for k, v in headers.items():
            lk = str(k).lower()
            if lk in allowed:
                out[lk] = str(v)[:2000]
        return out

    def normalize_url(self, url: str) -> str:
        raw = (url or "").strip()
        if not raw:
            raise ValueError("URL is required")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw = "https://" + raw
        p = urlparse(raw)
        if not p.scheme or not p.netloc:
            raise ValueError(f"Invalid URL: {url}")
        return raw

    def canonicalize_url(self, url: str) -> str:
        try:
            clean, _frag = urldefrag(url)
            p = urlparse(clean)
            scheme = p.scheme.lower() or "https"
            netloc = p.netloc.lower()
            path = re.sub(r"/{2,}", "/", p.path or "/")
            pairs = []
            for k, v in parse_qsl(p.query, keep_blank_values=True):
                lk = k.lower()
                if lk in TRACKING_KEYS:
                    continue
                if is_secret_query_key(lk) and not self.cfg.keep_secret_query_values:
                    pairs.append((k, "[redacted]"))
                else:
                    pairs.append((k, v))
            query = urlencode(pairs, doseq=True)
            return urlunparse((scheme, netloc, path, "", query, ""))
        except Exception:
            return url

    def redact_url(self, url: str) -> str:
        if not url:
            return ""
        try:
            p = urlparse(url)
            pairs = []
            for k, v in parse_qsl(p.query, keep_blank_values=True):
                lk = k.lower()
                if is_secret_query_key(lk) and not self.cfg.keep_secret_query_values:
                    pairs.append((k, "[redacted]"))
                elif lk in TRACKING_KEYS:
                    continue
                else:
                    pairs.append((k, v))
            return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(pairs, doseq=True), ""))
        except Exception:
            return url

    def absolutize_url(self, raw: str, base_url: str) -> str:
        raw = html.unescape((raw or "").strip())
        if not raw:
            return ""
        if raw.startswith("//"):
            scheme = urlparse(base_url).scheme or "https"
            raw = f"{scheme}:{raw}"
        if raw.startswith("data:"):
            return ""
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw):
            raw = urljoin(base_url, raw)
        return raw

    def _host_allowed(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        if not host:
            return True
        if self.cfg.host_allow_substrings and not any(x.lower() in host for x in self.cfg.host_allow_substrings):
            return False
        if self.cfg.host_deny_substrings and any(x.lower() in host for x in self.cfg.host_deny_substrings):
            return False
        return True

    def _robots_allowed(self, url: str) -> bool:
        try:
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
            if origin not in self._robots_cache:
                rp = urllib.robotparser.RobotFileParser()
                rp.set_url(urljoin(origin, "/robots.txt"))
                try:
                    rp.read()
                except Exception:
                    pass
                self._robots_cache[origin] = rp
            return self._robots_cache[origin].can_fetch(self.cfg.user_agent, url)
        except Exception:
            return True


# ---------------------------------------------------------------------------
# Standalone helper functions
# ---------------------------------------------------------------------------
def now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def hash_bytes(data: bytes) -> Tuple[str, str]:
    if not data:
        return "", ""
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


def clean_text(text: str) -> str:
    text = text or ""
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?s)<.*?>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_title(text: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text or "")
    return clean_text(m.group(1))[:300] if m else ""


def extract_metadata(base_url: str, text: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    if not text:
        return metadata
    meta_pairs: Dict[str, str] = {}
    for m in re.finditer(r"(?is)<meta\b([^>]+)>", text):
        attrs = dict(re.findall(r"([a-zA-Z_:.-]+)\s*=\s*['\"]([^'\"]*)['\"]", m.group(1)))
        key = attrs.get("property") or attrs.get("name") or attrs.get("itemprop")
        val = attrs.get("content")
        if key and val:
            meta_pairs[key] = html.unescape(val)
    if meta_pairs:
        metadata["meta"] = meta_pairs
    links: List[Dict[str, str]] = []
    for m in re.finditer(r"(?is)<link\b([^>]+)>", text):
        attrs = dict(re.findall(r"([a-zA-Z_:.-]+)\s*=\s*['\"]([^'\"]*)['\"]", m.group(1)))
        href = attrs.get("href")
        if href:
            links.append({"rel": attrs.get("rel", ""), "href": urljoin(base_url, html.unescape(href)), "type": attrs.get("type", "")})
    if links:
        metadata["links"] = links[:200]
    jsonld: List[Any] = []
    for m in re.finditer(r"(?is)<script[^>]+type=['\"]application/ld\+json['\"][^>]*>(.*?)</script>", text):
        raw = html.unescape(m.group(1).strip())
        try:
            jsonld.append(json.loads(raw))
        except Exception:
            jsonld.append({"raw_excerpt": raw[:1000]})
    if jsonld:
        metadata["jsonld"] = jsonld[:50]
    return metadata


def extract_urls_from_text(text: str, base_url: str = "") -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()

    def add(u: str) -> None:
        u = html.unescape((u or "").strip().rstrip("),.;'\"}]"))
        if not u:
            return
        if u.startswith("//"):
            scheme = urlparse(base_url).scheme or "https"
            u = f"{scheme}:{u}"
        if base_url and u.startswith(("/", "./", "../")):
            u = urljoin(base_url, u)
        if not re.match(r"^https?://", u, re.I):
            return
        if u not in seen:
            seen.add(u)
            out.append(u)

    for rx in (URL_RE, SCHEMELESS_RE):
        for m in rx.finditer(text or ""):
            add(m.group(0))
    for m in CSS_URL_RE.finditer(text or ""):
        add(m.group(1))
    return out


def split_srcset(raw: str) -> List[str]:
    vals: List[str] = []
    for part in SRCSET_PART_RE.split(raw or ""):
        first = part.strip().split()[0] if part.strip() else ""
        if first:
            vals.append(first)
    return vals


def extract_jsonish_urls(base_url: str, text: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    # Direct JSON-LD and JS config blobs are often not valid standalone JSON, so URL mining is deliberately conservative.
    for m in re.finditer(r"(?is)<script[^>]*>(.*?)</script>", text or ""):
        body = m.group(1)
        if not body or len(body) > 2_000_000:
            continue
        for u in extract_urls_from_text(body, base_url):
            hits.append({"url": u, "path": "script_url", "confidence": 0.55})
        for key, val in re.findall(r"['\"]([A-Za-z0-9_.:-]*(?:url|Url|URL|src|href|image|video|audio|thumbnail)[A-Za-z0-9_.:-]*)['\"]\s*:\s*['\"]([^'\"]+)['\"]", body):
            if val.startswith(("http://", "https://", "//", "/")):
                hits.append({"url": urljoin(base_url, val), "path": f"script_key:{key}", "confidence": 0.65})
    return hits[:1000]


def extract_sourcemap_hints(base_url: str, text: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(r"sourceMappingURL\s*=\s*([^\s*]+)", text or ""):
        u = html.unescape(m.group(1).strip())
        if u and not u.startswith("data:"):
            out.append(urljoin(base_url, u))
    return out


def classify_url(url: str) -> str:
    path = urlparse(url).path.lower()
    ext = Path(path).suffix.lower()
    if ext in MEDIA_EXTS:
        if ext in {".mp4", ".webm", ".mkv", ".mov", ".avi", ".m4v", ".m3u8", ".mpd", ".m4s", ".ts"}:
            return "video_or_manifest"
        if ext in {".mp3", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wav", ".weba"}:
            return "audio"
        return "image"
    if ext in DOC_EXTS:
        return "document"
    if ext in ARCHIVE_EXTS:
        return "archive"
    if ext in {".js", ".mjs"}:
        return "script"
    if ext in {".css"}:
        return "stylesheet"
    return "url"


def generate_url_variants(url: str) -> List[str]:
    p = urlparse(url)
    base = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    path = p.path or "/"
    stem = path.rstrip("/")
    variants = {
        base,
        urlunparse((p.scheme, p.netloc, stem + "/", "", "", "")),
        urlunparse((p.scheme, p.netloc, stem + ".html", "", "", "")),
        urlunparse((p.scheme, p.netloc, stem + ".htm", "", "", "")),
        urlunparse((p.scheme, p.netloc, stem + ".json", "", "", "")),
        urlunparse((p.scheme, p.netloc, stem + ".xml", "", "", "")),
        urlunparse((p.scheme, p.netloc, "/" + Path(stem).name, "", "", "")),
    }
    if p.scheme == "https":
        variants.add(urlunparse(("http", p.netloc, p.path, "", p.query, "")))
    elif p.scheme == "http":
        variants.add(urlunparse(("https", p.netloc, p.path, "", p.query, "")))
    return [v for v in sorted(variants) if v and v != url]


def is_secret_query_key(key: str) -> bool:
    lk = key.lower()
    return any(h in lk for h in SECRET_QUERY_HINTS)


def suffix_for_url(url: str) -> str:
    ext = Path(urlparse(url).path).suffix.lower()
    if ext and len(ext) <= 12:
        return ext
    return ".bin"


def guess_mime_from_bytes(data: bytes, filename: str = "") -> str:
    magic = magic_label(data)
    if magic != "unknown":
        return magic
    guessed, _enc = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def magic_label(data: bytes) -> str:
    if not data:
        return "unknown"
    sigs = [
        (b"%PDF", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b", "application/gzip"),
        (b"BZh", "application/x-bzip2"),
        (b"\x7fELF", "application/x-elf"),
        (b"MZ", "application/x-msdownload"),
    ]
    for sig, label in sigs:
        if data.startswith(sig):
            return label
    if len(data) > 12 and data[4:8] == b"ftyp":
        return "video/mp4"
    stripped = data[:200].lstrip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return "application/json"
    if stripped.startswith(b"<"):
        return "text/html-or-xml"
    return "unknown"


# ---------------------------------------------------------------------------
# Convenience functions for tools.py integration
# ---------------------------------------------------------------------------
def investigate_url(url: str, **kwargs: Any) -> Dict[str, Any]:
    cfg = ForensicConfig()
    for key, value in kwargs.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
    engine = ForensicEngine(cfg)
    try:
        return engine.investigate_url(url).to_dict()
    finally:
        engine.close()


def analyze_file(path: str, **kwargs: Any) -> Dict[str, Any]:
    cfg = ForensicConfig()
    for key, value in kwargs.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
    engine = ForensicEngine(cfg)
    try:
        return engine.analyze_file(path).to_dict()
    finally:
        engine.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="forensic_engine", description="PromptChat standalone internet forensic engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    u = sub.add_parser("url", help="Investigate a public or authorized URL")
    u.add_argument("url")
    u.add_argument("--archives", action="store_true", help="Query public archive indexes")
    u.add_argument("--no-archives", action="store_true", help="Disable archive lookups")
    u.add_argument("--depth", type=int, default=1)
    u.add_argument("--max-pages", type=int, default=25)
    u.add_argument("--sqlite", default="")
    u.add_argument("--out", default="")
    u.add_argument("--markdown", action="store_true")
    u.add_argument("--allow-cross-host", action="store_true")
    u.add_argument("--ignore-robots", action="store_true")

    f = sub.add_parser("file", help="Analyze a local file")
    f.add_argument("path")
    f.add_argument("--sqlite", default="")
    f.add_argument("--out", default="")
    f.add_argument("--markdown", action="store_true")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = ForensicConfig()
    cfg.sqlite_path = getattr(args, "sqlite", "") or ""
    if args.cmd == "url":
        cfg.max_depth = max(0, args.depth)
        cfg.max_pages = max(1, args.max_pages)
        cfg.include_archive_search = bool(args.archives) and not bool(args.no_archives)
        cfg.allow_cross_host_crawl = bool(args.allow_cross_host)
        cfg.respect_robots = not bool(args.ignore_robots)
        engine = ForensicEngine(cfg)
        try:
            report = engine.investigate_url(args.url, include_archives=cfg.include_archive_search, depth=cfg.max_depth, max_pages=cfg.max_pages)
        finally:
            engine.close()
    else:
        engine = ForensicEngine(cfg)
        try:
            report = engine.analyze_file(args.path)
        finally:
            engine.close()

    output = report.to_markdown() if getattr(args, "markdown", False) else report.to_json()
    if getattr(args, "out", ""):
        Path(args.out).parent.mkdir(parents=True, exist_ok=True) if Path(args.out).parent != Path(".") else None
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0 if report.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
