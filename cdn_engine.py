from __future__ import annotations

"""
cdn_engine.py

Standalone public/authorized CDN discovery and evidence engine for PromptChat.

Purpose
-------
This module helps find public CDN-hosted links and related assets that are hard to
notice from normal page text: JavaScript chunks, CSS url() assets, source-map hints,
HTML preload/prefetch links, manifest files, media playlists, cache/header metadata,
redirects, sitemap references, and CDN provider fingerprints.

Safety boundaries
-----------------
- Designed for public or explicitly authorized URLs only.
- Does not bypass authentication, paywalls, signed URLs, ACLs, robots policy, or rate limits.
- Does not brute-force private buckets or enumerate secret token values.
- Redacts sensitive/signed query values by default while preserving query key names.
- Blocks localhost/private IP URLs by default unless allow_private_hosts=True.

Drop this file beside tools.py.  It has no required dependency beyond requests.
Optional packages improve output when installed: tldextract, dnspython, cryptography,
Pillow, brotli.
"""

import argparse
import base64
import dataclasses
import email.utils
import gzip
import hashlib
import html
import ipaddress
import json
import mimetypes
import os
import re
import socket
import sqlite3
import ssl
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urldefrag, urljoin, urlparse, urlunparse

import requests

try:  # optional
    import brotli  # type: ignore
except Exception:  # pragma: no cover
    brotli = None


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 PromptChatCDNEngine/1.0"
)

VOLATILE_QUERY_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "gclid", "dclid", "gbraid", "wbraid", "fbclid", "msclkid", "ttclid", "twclid",
    "yclid", "mc_cid", "mc_eid", "ref", "referrer", "spm", "igshid", "si",
}

SIGNED_QUERY_HINTS = {
    "token", "auth", "authorization", "sig", "signature", "expires", "expire", "exp",
    "policy", "key-pair-id", "x-amz-", "x-goog-", "x-ms-", "hdnts", "hmac", "session",
    "sess", "psid", "key", "jwt", "bearer", "access_token", "download_token",
}

ASSET_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".json", ".webmanifest", ".xml", ".txt",
    ".html", ".htm", ".wasm", ".data", ".mem", ".symbols.json",
}

MEDIA_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp",
    ".mp4", ".webm", ".mov", ".m4v", ".m3u8", ".mpd", ".ts", ".m4s",
    ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac",
    ".vtt", ".srt", ".ttml",
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".tar",
    ".gz", ".bz2", ".xz", ".7z", ".rar", ".csv", ".tsv", ".parquet",
}

CDN_HOST_HINTS = {
    "cloudfront.net": "Amazon CloudFront",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "akamaihd.net": "Akamai",
    "akamaized.net": "Akamai",
    "edgesuite.net": "Akamai",
    "edgekey.net": "Akamai",
    "cloudflare.com": "Cloudflare",
    "cloudflare.net": "Cloudflare",
    "azureedge.net": "Azure CDN",
    "trafficmanager.net": "Azure",
    "googleusercontent.com": "Google CDN",
    "gstatic.com": "Google Static",
    "ggpht.com": "Google Images CDN",
    "fbcdn.net": "Meta/Facebook CDN",
    "cdninstagram.com": "Instagram CDN",
    "twimg.com": "X/Twitter CDN",
    "tiktokcdn.com": "TikTok CDN",
    "vimeocdn.com": "Vimeo CDN",
    "ytimg.com": "YouTube Images CDN",
    "googlevideo.com": "YouTube/Google Video CDN",
    "cloudinary.com": "Cloudinary",
    "imgix.net": "Imgix",
    "shopifycdn.net": "Shopify CDN",
    "cdn.shopify.com": "Shopify CDN",
    "jsdelivr.net": "jsDelivr",
    "unpkg.com": "unpkg",
    "esm.sh": "esm.sh",
    "skypack.dev": "Skypack",
    "vercel.app": "Vercel",
    "vercel-storage.com": "Vercel Storage",
    "netlify.app": "Netlify",
    "githubusercontent.com": "GitHub Raw/User Content",
    "raw.githubusercontent.com": "GitHub Raw",
}

MAGIC_SIGNATURES: List[Tuple[bytes, str, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png", "image"),
    (b"\xff\xd8\xff", "image/jpeg", "image"),
    (b"GIF87a", "image/gif", "image"),
    (b"GIF89a", "image/gif", "image"),
    (b"RIFF", "application/riff", "media"),
    (b"%PDF-", "application/pdf", "document"),
    (b"PK\x03\x04", "application/zip", "archive"),
    (b"\x1f\x8b", "application/gzip", "archive"),
    (b"\x00\x00\x00", "application/mp4", "media"),
    (b"#EXTM3U", "application/vnd.apple.mpegurl", "manifest"),
]


@dataclass
class CDNConfig:
    timeout_sec: float = 20.0
    max_page_bytes: int = 768_000
    max_asset_bytes: int = 1_500_000
    max_probe_bytes: int = 4096
    max_items: int = 800
    max_depth: int = 1
    max_pages: int = 25
    max_assets_to_fetch: int = 80
    max_variants: int = 120
    min_delay_sec: float = 0.0
    user_agent: str = DEFAULT_USER_AGENT
    follow_redirects: bool = True
    verify_tls: bool = True
    allow_private_hosts: bool = False
    same_registered_domain_only: bool = False
    respect_robots: bool = True
    keep_signed_query_values: bool = False
    keep_tracking_query_values: bool = False
    fetch_js_css: bool = True
    fetch_source_maps: bool = True
    fetch_manifests: bool = True
    fetch_sitemaps: bool = True
    probe_candidates: bool = True
    include_archives: bool = False
    resolve_domain_context: bool = True
    max_domain_contexts: int = 15
    sqlite_path: str = ""
    artifact_dir: str = "data/cdn_engine/artifacts"


@dataclass
class CDNItem:
    url: str
    kind: str = "link"
    source: str = "unknown"
    evidence: str = ""
    referer: str = ""
    text: str = ""
    final_url: str = ""
    status_code: int = 0
    content_type: str = ""
    content_length: str = ""
    cache_status: str = ""
    cdn_provider: str = ""
    etag: str = ""
    last_modified: str = ""
    sha256: str = ""
    score: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        out = dataclasses.asdict(self)
        return {k: v for k, v in out.items() if v not in ("", 0, None, [], {})}


@dataclass
class CDNDomainContext:
    host: str
    registered_domain: str = ""
    likely_cdn_provider: str = ""
    addresses: List[str] = field(default_factory=list)
    cname_chain: List[str] = field(default_factory=list)
    certificate: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        out = dataclasses.asdict(self)
        return {k: v for k, v in out.items() if v not in ("", 0, None, [], {})}


@dataclass
class CDNReport:
    ok: bool
    url: str = ""
    final_url: str = ""
    title: str = ""
    mode: str = "cdn-static"
    started_at: float = 0.0
    elapsed_ms: int = 0
    domains: Dict[str, CDNDomainContext] = field(default_factory=dict)
    items: List[CDNItem] = field(default_factory=list)
    pages_crawled: List[str] = field(default_factory=list)
    redirects: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    variants: List[str] = field(default_factory=list)
    archive_refs: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    log: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        by_kind: Dict[str, List[Dict[str, Any]]] = {}
        for item in self.items:
            by_kind.setdefault(item.kind, []).append(item.as_dict())
        return {
            "ok": self.ok,
            "mode": self.mode,
            "url": self.url,
            "final_url": self.final_url,
            "title": self.title,
            "elapsed_ms": self.elapsed_ms,
            "count": len(self.items),
            "pages_crawled_count": len(self.pages_crawled),
            "domains_count": len(self.domains),
            "items": [x.as_dict() for x in self.items],
            "by_kind": by_kind,
            "cdn_assets": [x.as_dict() for x in self.items if x.cdn_provider],
            "scripts": by_kind.get("script", []),
            "styles": by_kind.get("style", []),
            "images": by_kind.get("image", []),
            "videos": by_kind.get("video", []) + by_kind.get("manifest", []),
            "audio": by_kind.get("audio", []),
            "documents": by_kind.get("document", []),
            "source_maps": by_kind.get("source_map", []),
            "manifests": by_kind.get("manifest", []),
            "variants": self.variants,
            "domains": {k: v.as_dict() for k, v in self.domains.items()},
            "redirects": self.redirects,
            "headers": self.headers,
            "archive_refs": self.archive_refs,
            "errors": self.errors,
            "log": self.log,
        }

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=kwargs.pop("indent", 2), **kwargs)

    def to_markdown(self) -> str:
        data = self.as_dict()
        lines = [f"# CDN Investigation Report", ""]
        lines.append(f"- URL: `{self.url}`")
        lines.append(f"- Final URL: `{self.final_url}`")
        lines.append(f"- Items: `{len(self.items)}`")
        lines.append(f"- Domains: `{len(self.domains)}`")
        lines.append(f"- Elapsed: `{self.elapsed_ms} ms`")
        if self.errors:
            lines.append(f"- Errors: `{len(self.errors)}`")
        lines.append("")
        if self.domains:
            lines.append("## Domains")
            lines.append("| Host | Provider | Addresses |")
            lines.append("| --- | --- | --- |")
            for host, ctx in self.domains.items():
                lines.append(f"| `{host}` | {ctx.likely_cdn_provider or ''} | {', '.join(ctx.addresses[:4])} |")
            lines.append("")
        lines.append("## Top Items")
        lines.append("| Kind | Provider | Source | Status | URL |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in sorted(self.items, key=lambda x: x.score, reverse=True)[:80]:
            lines.append(
                f"| {item.kind} | {item.cdn_provider or ''} | {item.source} | {item.status_code or ''} | `{item.url}` |"
            )
        return "\n".join(lines)


class CDNEvidenceStore:
    def __init__(self, sqlite_path: str) -> None:
        self.path = sqlite_path
        self.conn: Optional[sqlite3.Connection] = None
        if sqlite_path:
            Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(sqlite_path)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cdn_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    url TEXT NOT NULL,
                    kind TEXT,
                    source TEXT,
                    evidence TEXT,
                    referer TEXT,
                    final_url TEXT,
                    status_code INTEGER,
                    content_type TEXT,
                    content_length TEXT,
                    cdn_provider TEXT,
                    sha256 TEXT,
                    score REAL,
                    extra_json TEXT
                )
                """
            )
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cdn_items_url ON cdn_items(url)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cdn_items_kind ON cdn_items(kind)")
            self.conn.commit()

    def add_item(self, item: CDNItem) -> None:
        if not self.conn:
            return
        self.conn.execute(
            """
            INSERT INTO cdn_items
            (created_at, url, kind, source, evidence, referer, final_url, status_code,
             content_type, content_length, cdn_provider, sha256, score, extra_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(), item.url, item.kind, item.source, item.evidence, item.referer,
                item.final_url, item.status_code, item.content_type, item.content_length,
                item.cdn_provider, item.sha256, item.score, json.dumps(item.extra, ensure_ascii=False),
            ),
        )
        self.conn.commit()

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None


class CDNEngine:
    def __init__(self, config: Optional[CDNConfig] = None, *, session: Optional[requests.Session] = None) -> None:
        self.cfg = config or CDNConfig()
        self.session = session or self._make_session()
        self.store = CDNEvidenceStore(self.cfg.sqlite_path) if self.cfg.sqlite_path else None
        Path(self.cfg.artifact_dir).mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self.store:
            self.store.close()
        try:
            self.session.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def investigate_url(
        self,
        url: str,
        *,
        max_depth: Optional[int] = None,
        max_pages: Optional[int] = None,
        include_archives: Optional[bool] = None,
    ) -> CDNReport:
        started = time.time()
        root = self._normalize_url(url)
        report = CDNReport(ok=True, url=root, started_at=started)
        depth_limit = self.cfg.max_depth if max_depth is None else int(max_depth)
        page_limit = self.cfg.max_pages if max_pages is None else int(max_pages)
        include_arch = self.cfg.include_archives if include_archives is None else bool(include_archives)

        try:
            if not self._url_allowed(root):
                return CDNReport(ok=False, url=root, errors=["URL blocked by safety policy or unsupported scheme"])
        except Exception as exc:
            return CDNReport(ok=False, url=root, errors=[str(exc)])

        frontier: List[Tuple[str, int]] = [(root, 0)]
        seen_pages: Set[str] = set()
        all_items: List[CDNItem] = []
        root_registered = self._registered_domain(urlparse(root).netloc)

        while frontier and len(seen_pages) < max(1, page_limit):
            current, depth = frontier.pop(0)
            if current in seen_pages or depth > depth_limit:
                continue
            if not self._url_allowed(current):
                continue
            if self.cfg.same_registered_domain_only:
                if self._registered_domain(urlparse(current).netloc) != root_registered:
                    continue

            page_items, page_meta = self._collect_page(current, report)
            seen_pages.add(current)
            report.pages_crawled.append(current)
            all_items.extend(page_items)
            if not report.final_url and page_meta.get("final_url"):
                report.final_url = page_meta.get("final_url", "")
            if not report.title and page_meta.get("title"):
                report.title = page_meta.get("title", "")

            if depth < depth_limit:
                next_links = [x.url for x in page_items if x.kind in {"page", "link"}]
                for link in next_links:
                    if len(frontier) + len(seen_pages) >= page_limit:
                        break
                    if link not in seen_pages and self._registered_domain(urlparse(link).netloc) == root_registered:
                        frontier.append((link, depth + 1))

            if self.cfg.min_delay_sec > 0:
                time.sleep(self.cfg.min_delay_sec)

        # Fetch/probe likely JS/CSS/maps/manifests discovered from pages.
        extra = self._expand_assets(all_items, report)
        all_items.extend(extra)

        # Safe URL variants are generated but not aggressively probed unless enabled.
        variants = self.generate_url_variants(root)
        report.variants = variants[: self.cfg.max_variants]
        if self.cfg.probe_candidates:
            variant_items = []
            for v in report.variants[: min(len(report.variants), 30)]:
                if v == root or not self._url_allowed(v):
                    continue
                item = self._probe_candidate(v, source="variant_probe", evidence="safe-url-variant", referer=root)
                if item.status_code and item.status_code < 500:
                    variant_items.append(item)
            all_items.extend(variant_items)

        if include_arch:
            report.archive_refs = self._archive_refs(root, report)

        report.items = self._rank_dedupe(all_items)[: self.cfg.max_items]
        self._populate_domain_context(report)
        report.elapsed_ms = int((time.time() - started) * 1000)
        for item in report.items:
            if self.store:
                self.store.add_item(item)
        return report

    def analyze_asset(self, url: str) -> CDNReport:
        started = time.time()
        root = self._normalize_url(url)
        report = CDNReport(ok=True, url=root, final_url=root, started_at=started)
        if not self._url_allowed(root):
            report.ok = False
            report.errors.append("URL blocked by safety policy or unsupported scheme")
            return report
        item = self._probe_candidate(root, source="asset_probe", evidence="direct-asset-analysis", referer="")
        report.items.append(item)
        expanded = self._expand_assets([item], report)
        report.items.extend(expanded)
        report.items = self._rank_dedupe(report.items)[: self.cfg.max_items]
        report.variants = self.generate_url_variants(root)
        self._populate_domain_context(report)
        report.elapsed_ms = int((time.time() - started) * 1000)
        return report

    def extract_from_text(self, text: str, *, base_url: str = "") -> CDNReport:
        started = time.time()
        report = CDNReport(ok=True, url=base_url or "", final_url=base_url or "", started_at=started, mode="cdn-text")
        items: List[CDNItem] = []
        self._collect_urls_from_text(text or "", base_url=base_url or "", items=items, source="text", evidence="pasted-text")
        self._collect_html_assets(text or "", base_url=base_url or "", items=items, source="text_html")
        report.items = self._rank_dedupe(items)[: self.cfg.max_items]
        self._populate_domain_context(report)
        report.elapsed_ms = int((time.time() - started) * 1000)
        return report

    def generate_url_variants(self, url: str) -> List[str]:
        """Generate conservative public URL variants based on one observed URL.

        This is not brute force. It only creates variants derived from the provided URL:
        stripped query, source maps for JS/CSS, common image-size normalization, and
        CDN image-transform cleanup. Probing remains controlled by config.
        """
        out: List[str] = []
        seen: Set[str] = set()
        raw = self._canonicalize_url(self._normalize_url(url))
        parsed = urlparse(raw)

        def add(u: str) -> None:
            if not u or u in seen:
                return
            seen.add(u)
            out.append(u)

        add(raw)
        no_frag = urlunparse(parsed._replace(fragment=""))
        add(no_frag)
        no_query = urlunparse(parsed._replace(query="", fragment=""))
        add(no_query)

        path = parsed.path or "/"
        suffix = Path(path).suffix.lower()
        if suffix in {".js", ".mjs", ".css"}:
            add(urlunparse(parsed._replace(path=path + ".map", query="", fragment="")))
            if path.endswith(".min" + suffix):
                add(urlunparse(parsed._replace(path=path.replace(".min" + suffix, suffix), query="", fragment="")))

        if suffix in {".jpg", ".jpeg", ".png", ".webp", ".avif", ".gif"}:
            # Remove common dimensions from filenames: image-800x600.jpg, image_800x600.jpg, image@2x.jpg
            stem = path[: -len(suffix)] if suffix else path
            candidates = {
                re.sub(r"[-_]\d{2,5}x\d{2,5}$", "", stem) + suffix,
                re.sub(r"@\d+x$", "", stem) + suffix,
                re.sub(r"[-_](small|medium|large|thumb|thumbnail|preview)$", "", stem, flags=re.I) + suffix,
            }
            for p in candidates:
                if p != path:
                    add(urlunparse(parsed._replace(path=p, query="", fragment="")))

            # Remove image transform query keys but preserve non-transform keys redacted/canonicalized.
            transform_keys = {"w", "h", "width", "height", "fit", "crop", "format", "fm", "q", "quality", "dpr", "auto"}
            kept = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() not in transform_keys]
            if kept != parse_qsl(parsed.query, keep_blank_values=True):
                add(urlunparse(parsed._replace(query=urlencode(kept), fragment="")))

        # Directory-level public manifests only from existing origin/path.
        base_path = path.rsplit("/", 1)[0] or "/"
        manifest_names = ["asset-manifest.json", "manifest.json", "site.webmanifest", "robots.txt", "sitemap.xml"]
        for name in manifest_names:
            add(urlunparse(parsed._replace(path=(base_path.rstrip("/") + "/" + name), query="", fragment="")))
        add(urlunparse(parsed._replace(path="/robots.txt", query="", fragment="")))
        add(urlunparse(parsed._replace(path="/sitemap.xml", query="", fragment="")))

        return out[: self.cfg.max_variants]

    def domain_context(self, host_or_url: str) -> CDNDomainContext:
        host = urlparse(host_or_url).netloc or host_or_url
        host = host.split("@")[-1].split(":")[0].strip("[]").lower()
        ctx = CDNDomainContext(host=host, registered_domain=self._registered_domain(host))
        ctx.likely_cdn_provider = self._detect_cdn_from_host(host)
        try:
            infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            addresses = sorted({x[4][0] for x in infos})
            ctx.addresses = addresses[:16]
        except Exception as exc:
            ctx.errors.append(f"dns/getaddrinfo failed: {exc}")

        # Optional dnspython CNAME chain.
        try:
            import dns.resolver  # type: ignore
            resolver = dns.resolver.Resolver()
            resolver.lifetime = min(float(self.cfg.timeout_sec), 5.0)
            current = host
            chain: List[str] = []
            for _ in range(8):
                ans = resolver.resolve(current, "CNAME")
                if not ans:
                    break
                target = str(ans[0].target).rstrip(".")
                chain.append(target)
                current = target
            ctx.cname_chain = chain
            for node in chain:
                provider = self._detect_cdn_from_host(node)
                if provider and not ctx.likely_cdn_provider:
                    ctx.likely_cdn_provider = provider
        except Exception:
            pass

        # TLS cert summary.
        try:
            ctx.certificate = self._tls_certificate_summary(host)
        except Exception as exc:
            ctx.errors.append(f"tls failed: {exc}")
        return ctx

    # ------------------------------------------------------------------
    # Page/asset collection
    # ------------------------------------------------------------------
    def _collect_page(self, url: str, report: CDNReport) -> Tuple[List[CDNItem], Dict[str, Any]]:
        items: List[CDNItem] = []
        meta: Dict[str, Any] = {}
        try:
            resp = self.session.get(
                url,
                timeout=float(self.cfg.timeout_sec),
                allow_redirects=bool(self.cfg.follow_redirects),
                verify=bool(self.cfg.verify_tls),
                stream=True,
            )
            raw = resp.raw.read(int(self.cfg.max_page_bytes), decode_content=False)
            body = self._decode_response_body(raw, resp.headers)
            final_url = self._canonicalize_url(resp.url)
            meta["final_url"] = final_url
            meta["title"] = self._extract_title(body)
            report.headers = self._headers_dict(resp.headers)
            report.redirects.extend(self._redirect_history(resp))
            provider = self._detect_cdn(resp.url, resp.headers)
            page_item = CDNItem(
                url=self._canonicalize_url(url),
                kind="page",
                source="http_get",
                evidence="fetched-page",
                final_url=final_url,
                status_code=int(resp.status_code),
                content_type=resp.headers.get("content-type", ""),
                content_length=resp.headers.get("content-length", ""),
                cache_status=self._cache_status(resp.headers),
                cdn_provider=provider,
                etag=resp.headers.get("etag", ""),
                last_modified=resp.headers.get("last-modified", ""),
            )
            page_item.score = self._score_item(page_item)
            items.append(page_item)

            self._collect_urls_from_text(body, base_url=final_url, items=items, source="page_text", evidence="regex-url")
            self._collect_html_assets(body, base_url=final_url, items=items, source="html")
            self._collect_link_headers(resp.headers, base_url=final_url, items=items)
            self._collect_meta_refresh(body, base_url=final_url, items=items)
            if self.cfg.fetch_sitemaps:
                items.extend(self._discover_robots_and_sitemaps(final_url, report))
        except Exception as exc:
            report.errors.append(f"fetch page failed {url}: {exc}")
        return items, meta

    def _expand_assets(self, seed_items: Sequence[CDNItem], report: CDNReport) -> List[CDNItem]:
        out: List[CDNItem] = []
        fetched = 0
        seen = {x.url for x in seed_items}
        candidates = sorted(seed_items, key=lambda x: x.score, reverse=True)
        for item in candidates:
            if fetched >= self.cfg.max_assets_to_fetch:
                break
            if not item.url or not self._url_allowed(item.url):
                continue
            kind = item.kind
            suffix = Path(urlparse(item.url).path).suffix.lower()
            should_fetch = False
            if self.cfg.fetch_js_css and kind in {"script", "style"}:
                should_fetch = True
            if self.cfg.fetch_source_maps and (kind == "source_map" or suffix == ".map"):
                should_fetch = True
            if self.cfg.fetch_manifests and kind in {"manifest", "feed", "sitemap"}:
                should_fetch = True
            if suffix in {".json", ".webmanifest", ".xml", ".m3u8", ".mpd"}:
                should_fetch = True
            if not should_fetch:
                continue
            fetched += 1
            try:
                asset_items = self._fetch_and_mine_asset(item.url, referer=item.referer or report.final_url or report.url)
                for ai in asset_items:
                    if ai.url not in seen:
                        seen.add(ai.url)
                        out.append(ai)
            except Exception as exc:
                report.log.append(f"asset expand failed {item.url}: {exc}")
        return out

    def _fetch_and_mine_asset(self, url: str, *, referer: str = "") -> List[CDNItem]:
        items: List[CDNItem] = []
        resp = self.session.get(
            url,
            timeout=float(self.cfg.timeout_sec),
            allow_redirects=bool(self.cfg.follow_redirects),
            verify=bool(self.cfg.verify_tls),
            headers={"Referer": referer} if referer else None,
            stream=True,
        )
        raw = resp.raw.read(int(self.cfg.max_asset_bytes), decode_content=False)
        body = self._decode_response_body(raw, resp.headers)
        final_url = self._canonicalize_url(resp.url)
        content_type = resp.headers.get("content-type", "")
        provider = self._detect_cdn(resp.url, resp.headers)
        parent = CDNItem(
            url=self._canonicalize_url(url),
            kind=self._classify_url(url, content_type=content_type),
            source="asset_get",
            evidence="fetched-asset",
            referer=referer,
            final_url=final_url,
            status_code=int(resp.status_code),
            content_type=content_type,
            content_length=resp.headers.get("content-length", ""),
            cache_status=self._cache_status(resp.headers),
            cdn_provider=provider,
            etag=resp.headers.get("etag", ""),
            last_modified=resp.headers.get("last-modified", ""),
            sha256=hashlib.sha256(raw).hexdigest() if raw else "",
        )
        parent.score = self._score_item(parent)
        items.append(parent)

        source = "asset_body"
        self._collect_urls_from_text(body, base_url=final_url, items=items, source=source, evidence="asset-regex-url")
        suffix = Path(urlparse(final_url).path).suffix.lower()
        low_ct = content_type.lower()
        if suffix in {".css"} or "text/css" in low_ct:
            self._collect_css_assets(body, base_url=final_url, items=items, source="css")
        if suffix in {".js", ".mjs"} or "javascript" in low_ct:
            self._collect_js_assets(body, base_url=final_url, items=items)
        if suffix in {".map"} or final_url.endswith(".map"):
            self._collect_source_map(body, base_url=final_url, items=items)
        if suffix in {".json", ".webmanifest"} or "json" in low_ct:
            self._collect_json_urls(body, base_url=final_url, items=items, source="json")
        if suffix in {".xml"} or "xml" in low_ct:
            self._collect_xml_like(body, base_url=final_url, items=items)
        if suffix == ".m3u8" or "mpegurl" in low_ct:
            self._collect_hls(body, base_url=final_url, items=items)
        if suffix == ".mpd" or "dash+xml" in low_ct:
            self._collect_mpd(body, base_url=final_url, items=items)
        return items

    # ------------------------------------------------------------------
    # Extractors
    # ------------------------------------------------------------------
    def _collect_html_assets(self, text: str, *, base_url: str, items: List[CDNItem], source: str) -> None:
        html_text = text or ""
        patterns = [
            (r'(?is)<script\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "script", "script-src"),
            (r'(?is)<link\b[^>]*?\bhref\s*=\s*["\']([^"\']+)["\'][^>]*>', "style", "link-href"),
            (r'(?is)<img\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "image", "img-src"),
            (r'(?is)<source\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "link", "source-src"),
            (r'(?is)<video\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "video", "video-src"),
            (r'(?is)<audio\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "audio", "audio-src"),
            (r'(?is)<video\b[^>]*?\bposter\s*=\s*["\']([^"\']+)["\'][^>]*>', "image", "video-poster"),
            (r'(?is)<iframe\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "iframe", "iframe-src"),
            (r'(?is)<embed\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "embed", "embed-src"),
            (r'(?is)<object\b[^>]*?\bdata\s*=\s*["\']([^"\']+)["\'][^>]*>', "embed", "object-data"),
            (r'(?is)<track\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "subtitle", "track-src"),
            (r'(?is)<meta\b[^>]*?\bcontent\s*=\s*["\']([^"\']+)["\'][^>]*>', "link", "meta-content"),
        ]
        for rx, kind_hint, evidence in patterns:
            for m in re.finditer(rx, html_text):
                raw = html.unescape((m.group(1) or "").strip())
                self._add_url_item(items, raw, base_url=base_url, kind_hint=kind_hint, source=source, evidence=evidence, referer=base_url)

        # srcset, data-src, data-original, preload-like attrs.
        for m in re.finditer(r'(?is)\b(?:srcset|data-srcset)\s*=\s*["\']([^"\']+)["\']', html_text):
            for part in self._parse_srcset(m.group(1)):
                self._add_url_item(items, part, base_url=base_url, kind_hint="image", source=source, evidence="srcset", referer=base_url)
        for m in re.finditer(r'(?is)\b(?:data-src|data-original|data-url|data-href|poster|content)\s*=\s*["\']([^"\']+)["\']', html_text):
            raw = html.unescape((m.group(1) or "").strip())
            self._add_url_item(items, raw, base_url=base_url, kind_hint="", source=source, evidence="data-attr", referer=base_url)

        # Inline JSON-LD/importmap/speculationrules.
        for m in re.finditer(r'(?is)<script\b[^>]*type\s*=\s*["\'](?:application/ld\+json|application/json|importmap|speculationrules)["\'][^>]*>(.*?)</script>', html_text):
            self._collect_json_urls(html.unescape(m.group(1) or ""), base_url=base_url, items=items, source="inline_json")

        self._collect_css_assets(html_text, base_url=base_url, items=items, source="inline_css")
        self._collect_js_assets(html_text, base_url=base_url, items=items, inline_only=True)

    def _collect_urls_from_text(self, text: str, *, base_url: str, items: List[CDNItem], source: str, evidence: str) -> None:
        if not text:
            return
        for m in re.finditer(r'(?i)\bhttps?://[^\s"\'<>\\)\]]+', text):
            raw = html.unescape(m.group(0)).rstrip('.,;:)]}"')
            self._add_url_item(items, raw, base_url=base_url, kind_hint="", source=source, evidence=evidence, referer=base_url)
        # Protocol-relative URLs.
        for m in re.finditer(r'(?i)(?<!:)//[a-z0-9][a-z0-9.-]+\.[a-z]{2,}[^\s"\'<>\\)\]]*', text):
            raw = "https:" + html.unescape(m.group(0)).rstrip('.,;:)]}"')
            self._add_url_item(items, raw, base_url=base_url, kind_hint="", source=source, evidence="protocol-relative-url", referer=base_url)

    def _collect_css_assets(self, text: str, *, base_url: str, items: List[CDNItem], source: str) -> None:
        for m in re.finditer(r'(?is)url\(\s*["\']?([^"\')]+)["\']?\s*\)', text or ""):
            self._add_url_item(items, html.unescape(m.group(1).strip()), base_url=base_url, kind_hint="", source=source, evidence="css-url", referer=base_url)
        for m in re.finditer(r'(?is)@import\s+(?:url\()?\s*["\']?([^"\')\s;]+)', text or ""):
            self._add_url_item(items, html.unescape(m.group(1).strip()), base_url=base_url, kind_hint="style", source=source, evidence="css-import", referer=base_url)
        for m in re.finditer(r'(?is)image-set\((.*?)\)', text or ""):
            for u in re.findall(r'["\']([^"\']+)["\']', m.group(1)):
                self._add_url_item(items, html.unescape(u.strip()), base_url=base_url, kind_hint="image", source=source, evidence="css-image-set", referer=base_url)

    def _collect_js_assets(self, text: str, *, base_url: str, items: List[CDNItem], inline_only: bool = False) -> None:
        js = text or ""
        # sourceMappingURL comment.
        for m in re.finditer(r'(?im)//[#@]\s*sourceMappingURL\s*=\s*(\S+)|/\*[#@]\s*sourceMappingURL\s*=\s*([^*]+)\*/', js):
            raw = (m.group(1) or m.group(2) or "").strip()
            self._add_url_item(items, raw, base_url=base_url, kind_hint="source_map", source="javascript", evidence="sourceMappingURL", referer=base_url)

        # Dynamic imports and bundler chunks.
        patterns = [
            (r'import\(\s*["\']([^"\']+)["\']\s*\)', "script", "dynamic-import"),
            (r'new\s+URL\(\s*["\']([^"\']+)["\']\s*,\s*import\.meta\.url\s*\)', "link", "import-meta-url"),
            (r'__webpack_require__\.u\s*=|webpackChunk', "script", "webpack-hint"),
        ]
        for rx, kind, evidence in patterns[:2]:
            for m in re.finditer(rx, js):
                self._add_url_item(items, html.unescape(m.group(1).strip()), base_url=base_url, kind_hint=kind, source="javascript", evidence=evidence, referer=base_url)

        # Quoted asset-like paths in JS bundles.
        for m in re.finditer(r'["\']([^"\']+\.(?:js|mjs|css|map|json|webmanifest|png|jpg|jpeg|webp|gif|svg|avif|mp4|webm|m3u8|mpd|vtt|pdf)(?:\?[^"\']*)?)["\']', js, re.I):
            raw = html.unescape(m.group(1).strip())
            self._add_url_item(items, raw, base_url=base_url, kind_hint="", source="javascript", evidence="quoted-asset-path", referer=base_url)

        # Next/Nuxt/Vite public asset hints.
        for m in re.finditer(r'["\'](/_next/static/[^"\']+)["\']|["\'](/assets/[^"\']+)["\']|["\'](/build/assets/[^"\']+)["\']', js, re.I):
            raw = next((g for g in m.groups() if g), "")
            self._add_url_item(items, raw, base_url=base_url, kind_hint="", source="javascript", evidence="framework-asset-path", referer=base_url)

    def _collect_source_map(self, text: str, *, base_url: str, items: List[CDNItem]) -> None:
        try:
            data = json.loads(text or "{}")
        except Exception:
            self._collect_urls_from_text(text, base_url=base_url, items=items, source="source_map", evidence="sourcemap-regex-url")
            return
        source_root = data.get("sourceRoot") or ""
        for key in ("file", "sourceRoot"):
            val = data.get(key)
            if isinstance(val, str):
                self._add_url_item(items, val, base_url=base_url, kind_hint="", source="source_map", evidence=f"sourcemap-{key}", referer=base_url)
        for src in data.get("sources") or []:
            if not isinstance(src, str):
                continue
            candidate = urljoin(base_url, urljoin(source_root, src))
            item = CDNItem(
                url=self._canonicalize_url(candidate),
                kind="source_ref",
                source="source_map",
                evidence="sourcemap-sources",
                referer=base_url,
                text=src[:240],
            )
            item.score = self._score_item(item)
            items.append(item)
        # We intentionally do not emit sourcesContent raw text. Only URL-like values inside it.
        for src_text in data.get("sourcesContent") or []:
            if isinstance(src_text, str):
                self._collect_urls_from_text(src_text[:200_000], base_url=base_url, items=items, source="source_map_sourcesContent", evidence="url-in-sourcesContent")

    def _collect_json_urls(self, text: str, *, base_url: str, items: List[CDNItem], source: str) -> None:
        try:
            data = json.loads(text or "null")
            self._walk_json(data, base_url=base_url, items=items, source=source)
        except Exception:
            self._collect_urls_from_text(text, base_url=base_url, items=items, source=source, evidence="jsonish-regex-url")

    def _walk_json(self, obj: Any, *, base_url: str, items: List[CDNItem], source: str, path: str = "$") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = str(k)
                next_path = f"{path}.{key}"
                if isinstance(v, str):
                    hint = self._kind_hint_from_key(key)
                    self._add_url_item(items, v, base_url=base_url, kind_hint=hint, source=source, evidence=f"json:{next_path}", referer=base_url)
                else:
                    self._walk_json(v, base_url=base_url, items=items, source=source, path=next_path)
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:5000]):
                self._walk_json(v, base_url=base_url, items=items, source=source, path=f"{path}[{i}]")
        elif isinstance(obj, str):
            self._add_url_item(items, obj, base_url=base_url, kind_hint="", source=source, evidence=f"json:{path}", referer=base_url)

    def _collect_xml_like(self, text: str, *, base_url: str, items: List[CDNItem]) -> None:
        # Regex extractor handles malformed XML better and avoids namespace complexity.
        for tag in ("loc", "url", "link", "guid", "media:content", "media:thumbnail", "enclosure"):
            for m in re.finditer(fr'(?is)<{re.escape(tag)}\b[^>]*(?:url=["\']([^"\']+)["\'])?[^>]*>(.*?)</{re.escape(tag)}>', text or ""):
                raw = m.group(1) or m.group(2) or ""
                self._add_url_item(items, html.unescape(raw.strip()), base_url=base_url, kind_hint="", source="xml", evidence=f"xml-{tag}", referer=base_url)
        for m in re.finditer(r'(?is)\b(?:href|src|url)\s*=\s*["\']([^"\']+)["\']', text or ""):
            self._add_url_item(items, html.unescape(m.group(1).strip()), base_url=base_url, kind_hint="", source="xml", evidence="xml-attr-url", referer=base_url)

    def _collect_hls(self, text: str, *, base_url: str, items: List[CDNItem]) -> None:
        for line in (text or "").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                if s.startswith("#EXT-X-MAP") or "URI=" in s:
                    for uri in re.findall(r'URI=["\']?([^",\']+)', s):
                        self._add_url_item(items, uri, base_url=base_url, kind_hint="video", source="hls", evidence="hls-uri", referer=base_url)
                continue
            self._add_url_item(items, s, base_url=base_url, kind_hint="video", source="hls", evidence="hls-line", referer=base_url)

    def _collect_mpd(self, text: str, *, base_url: str, items: List[CDNItem]) -> None:
        for m in re.finditer(r'(?is)<BaseURL>(.*?)</BaseURL>|(?:media|initialization|sourceURL)=["\']([^"\']+)["\']', text or ""):
            raw = html.unescape((m.group(1) or m.group(2) or "").strip())
            self._add_url_item(items, raw, base_url=base_url, kind_hint="video", source="dash_mpd", evidence="mpd-url", referer=base_url)

    def _collect_link_headers(self, headers: Mapping[str, str], *, base_url: str, items: List[CDNItem]) -> None:
        link = ""
        for k, v in headers.items():
            if k.lower() == "link":
                link += "," + v
        for m in re.finditer(r'<([^>]+)>\s*;?\s*([^,]*)', link):
            raw = m.group(1)
            attrs = m.group(2) or ""
            kind = "link"
            if "preload" in attrs or "modulepreload" in attrs:
                kind = "preload"
            if "stylesheet" in attrs:
                kind = "style"
            self._add_url_item(items, raw, base_url=base_url, kind_hint=kind, source="headers", evidence="link-header", referer=base_url)

    def _collect_meta_refresh(self, body: str, *, base_url: str, items: List[CDNItem]) -> None:
        for m in re.finditer(r'(?is)<meta\b[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url\s*=\s*([^"\'>]+)', body or ""):
            self._add_url_item(items, html.unescape(m.group(1).strip()), base_url=base_url, kind_hint="page", source="html", evidence="meta-refresh", referer=base_url)

    def _discover_robots_and_sitemaps(self, base_url: str, report: CDNReport) -> List[CDNItem]:
        items: List[CDNItem] = []
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        robots = root + "/robots.txt"
        sitemap = root + "/sitemap.xml"
        for u, kind, evidence in [(robots, "robots", "well-known-robots"), (sitemap, "sitemap", "well-known-sitemap")]:
            if not self._url_allowed(u):
                continue
            item = self._probe_candidate(u, source="well_known", evidence=evidence, referer=base_url)
            if item.status_code and item.status_code < 500:
                items.append(item)
        # Read robots for Sitemap lines only; do not use Disallow for bypass.
        try:
            resp = self.session.get(robots, timeout=min(self.cfg.timeout_sec, 8), allow_redirects=True, verify=self.cfg.verify_tls)
            if resp.status_code < 400:
                for m in re.finditer(r'(?im)^\s*Sitemap\s*:\s*(\S+)', resp.text or ""):
                    self._add_url_item(items, m.group(1).strip(), base_url=root, kind_hint="sitemap", source="robots", evidence="robots-sitemap", referer=robots)
        except Exception as exc:
            report.log.append(f"robots read failed: {exc}")
        return items

    # ------------------------------------------------------------------
    # Probes, variants, archives
    # ------------------------------------------------------------------
    def _probe_candidate(self, url: str, *, source: str, evidence: str, referer: str = "") -> CDNItem:
        clean = self._canonicalize_url(url)
        item = CDNItem(url=clean, kind=self._classify_url(clean), source=source, evidence=evidence, referer=referer)
        headers: Mapping[str, str] = {}
        try:
            resp = self.session.head(clean, timeout=float(self.cfg.timeout_sec), allow_redirects=True, verify=bool(self.cfg.verify_tls), headers={"Referer": referer} if referer else None)
            if resp.status_code in {405, 403, 400}:
                raise RuntimeError(f"HEAD returned {resp.status_code}")
            headers = resp.headers
            item.final_url = self._canonicalize_url(resp.url)
            item.status_code = int(resp.status_code)
            item.content_type = resp.headers.get("content-type", "")
            item.content_length = resp.headers.get("content-length", "")
            item.cache_status = self._cache_status(resp.headers)
            item.cdn_provider = self._detect_cdn(resp.url, resp.headers)
            item.etag = resp.headers.get("etag", "")
            item.last_modified = resp.headers.get("last-modified", "")
        except Exception:
            try:
                resp = self.session.get(clean, timeout=float(self.cfg.timeout_sec), allow_redirects=True, verify=bool(self.cfg.verify_tls), headers={"Range": f"bytes=0-{max(0, self.cfg.max_probe_bytes - 1)}", **({"Referer": referer} if referer else {})}, stream=True)
                raw = resp.raw.read(int(self.cfg.max_probe_bytes), decode_content=False)
                headers = resp.headers
                item.final_url = self._canonicalize_url(resp.url)
                item.status_code = int(resp.status_code)
                item.content_type = resp.headers.get("content-type", "")
                item.content_length = resp.headers.get("content-length", "")
                item.cache_status = self._cache_status(resp.headers)
                item.cdn_provider = self._detect_cdn(resp.url, resp.headers)
                item.etag = resp.headers.get("etag", "")
                item.last_modified = resp.headers.get("last-modified", "")
                item.sha256 = hashlib.sha256(raw).hexdigest() if raw else ""
                magic = self._magic_type(raw)
                if magic:
                    item.extra["magic_mime"] = magic[0]
                    if item.kind == "link":
                        item.kind = magic[1]
            except Exception as exc:
                item.extra["probe_error"] = str(exc)
        if headers:
            item.extra["headers_subset"] = self._interesting_headers(headers)
        item.kind = self._classify_url(item.final_url or item.url, content_type=item.content_type) or item.kind
        item.score = self._score_item(item)
        return item

    def _archive_refs(self, url: str, report: CDNReport) -> List[Dict[str, Any]]:
        refs: List[Dict[str, Any]] = []
        # Conservative public archive lookups; failures are logged, not fatal.
        try:
            api = "https://web.archive.org/cdx"
            params = {
                "url": url,
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype,digest",
                "filter": "statuscode:200",
                "collapse": "digest",
                "limit": "20",
            }
            resp = self.session.get(api, params=params, timeout=min(self.cfg.timeout_sec, 12), allow_redirects=True)
            if resp.status_code < 400:
                rows = resp.json()
                if isinstance(rows, list) and rows:
                    header = rows[0]
                    for row in rows[1:]:
                        if isinstance(row, list):
                            refs.append({"source": "wayback_cdx", **dict(zip(header, row))})
        except Exception as exc:
            report.log.append(f"wayback lookup failed: {exc}")
        return refs

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _make_session(self) -> requests.Session:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=0)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({
            "User-Agent": self.cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,text/css;q=0.7,*/*;q=0.5",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        })
        return s

    def _normalize_url(self, url: str) -> str:
        raw = (url or "").strip()
        if not raw:
            raise ValueError("URL is required")
        if raw.startswith("//"):
            raw = "https:" + raw
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw = "https://" + raw
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Unsupported or invalid URL: {url}")
        return raw

    def _url_allowed(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return False
            host = parsed.hostname or ""
            if not self.cfg.allow_private_hosts and self._is_private_host(host):
                return False
            return True
        except Exception:
            return False

    def _is_private_host(self, host: str) -> bool:
        h = (host or "").strip().strip("[]").lower()
        if h in {"localhost", "localhost.localdomain"}:
            return True
        try:
            ip = ipaddress.ip_address(h)
            return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
        except Exception:
            return False

    def _canonicalize_url(self, url: str) -> str:
        if not url:
            return ""
        try:
            url, _frag = urldefrag(url.strip())
            parsed = urlparse(url)
            scheme = parsed.scheme.lower() or "https"
            netloc = parsed.netloc.lower()
            path = quote(unquote(parsed.path or "/"), safe="/%:@!$&'()*+,;=-._~")
            pairs = []
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                lk = k.lower()
                if not self.cfg.keep_tracking_query_values and lk in VOLATILE_QUERY_KEYS:
                    continue
                if not self.cfg.keep_signed_query_values and self._looks_signed_key(lk):
                    pairs.append((k, "<redacted>"))
                else:
                    pairs.append((k, v))
            query = urlencode(pairs, doseq=True)
            return urlunparse((scheme, netloc, path, "", query, ""))
        except Exception:
            return url

    def _absolutize(self, raw: str, base_url: str) -> str:
        s = html.unescape((raw or "").strip())
        if not s or s.startswith(("data:", "javascript:", "mailto:", "tel:", "blob:")):
            return ""
        if s.startswith("//"):
            return "https:" + s
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
            return s
        if base_url:
            return urljoin(base_url, s)
        return ""

    def _add_url_item(
        self,
        items: List[CDNItem],
        raw_url: str,
        *,
        base_url: str,
        kind_hint: str,
        source: str,
        evidence: str,
        referer: str = "",
        text: str = "",
    ) -> None:
        u = self._absolutize(raw_url, base_url)
        if not u or not self._url_allowed(u):
            return
        clean = self._canonicalize_url(u)
        kind = kind_hint or self._classify_url(clean)
        provider = self._detect_cdn_from_host(urlparse(clean).netloc)
        item = CDNItem(
            url=clean,
            kind=kind or "link",
            source=source,
            evidence=evidence,
            referer=referer or base_url,
            text=(text or raw_url or "")[:240],
            cdn_provider=provider,
        )
        item.score = self._score_item(item)
        items.append(item)

    def _parse_srcset(self, srcset: str) -> List[str]:
        out: List[str] = []
        for part in (srcset or "").split(","):
            url = part.strip().split(" ", 1)[0].strip()
            if url:
                out.append(url)
        return out

    def _classify_url(self, url: str, *, content_type: str = "") -> str:
        ct = (content_type or "").split(";", 1)[0].lower().strip()
        if ct.startswith("image/"):
            return "image"
        if ct.startswith("video/"):
            return "video"
        if ct.startswith("audio/"):
            return "audio"
        if "mpegurl" in ct or "dash+xml" in ct:
            return "manifest"
        if "javascript" in ct:
            return "script"
        if ct == "text/css":
            return "style"
        if "json" in ct:
            return "manifest" if "manifest" in url.lower() else "json"
        if ct in {"application/pdf"}:
            return "document"

        path = urlparse(url).path.lower()
        suffix = Path(path).suffix.lower()
        if suffix in {".js", ".mjs"}:
            return "script"
        if suffix == ".css":
            return "style"
        if suffix == ".map":
            return "source_map"
        if suffix in {".json", ".webmanifest"}:
            return "manifest" if "manifest" in path else "json"
        if suffix in {".xml"}:
            return "sitemap" if "sitemap" in path else "feed"
        if suffix in {".m3u8", ".mpd"}:
            return "manifest"
        if suffix in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp"}:
            return "image"
        if suffix in {".mp4", ".webm", ".mov", ".m4v", ".ts", ".m4s"}:
            return "video"
        if suffix in {".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac"}:
            return "audio"
        if suffix in {".vtt", ".srt", ".ttml"}:
            return "subtitle"
        if suffix in DOCUMENT_EXTENSIONS:
            return "document"
        if path.endswith("/robots.txt"):
            return "robots"
        return "link"

    def _kind_hint_from_key(self, key: str) -> str:
        k = key.lower()
        if "image" in k or "thumbnail" in k or "poster" in k or "icon" in k:
            return "image"
        if "video" in k or "stream" in k or "hls" in k or "dash" in k:
            return "video"
        if "audio" in k:
            return "audio"
        if "script" in k or "chunk" in k:
            return "script"
        if "style" in k or "css" in k:
            return "style"
        if "manifest" in k:
            return "manifest"
        if "map" in k and "source" in k:
            return "source_map"
        return ""

    def _decode_response_body(self, raw: bytes, headers: Mapping[str, str]) -> str:
        data = raw or b""
        enc = (headers.get("content-encoding") or "").lower()
        try:
            if "br" in enc and brotli is not None:
                data = brotli.decompress(data)
            elif "gzip" in enc:
                data = gzip.decompress(data)
            elif "deflate" in enc:
                data = zlib.decompress(data)
        except Exception:
            pass
        encoding = "utf-8"
        ctype = headers.get("content-type", "")
        m = re.search(r"charset=([^;\s]+)", ctype, re.I)
        if m:
            encoding = m.group(1).strip('"')
        return data.decode(encoding, errors="replace")

    def _headers_dict(self, headers: Mapping[str, str]) -> Dict[str, str]:
        return {str(k).lower(): str(v) for k, v in headers.items()}

    def _interesting_headers(self, headers: Mapping[str, str]) -> Dict[str, str]:
        wanted = {
            "server", "via", "x-cache", "cf-cache-status", "cf-ray", "x-amz-cf-id",
            "x-amz-cf-pop", "x-served-by", "x-cache-hits", "x-timer", "x-akamai-transformed",
            "akamai-cache-status", "x-azure-ref", "x-vercel-cache", "x-vercel-id",
            "x-nf-request-id", "age", "etag", "last-modified", "cache-control",
            "content-type", "content-length", "content-range", "accept-ranges",
            "content-disposition", "link", "location", "strict-transport-security",
        }
        return {str(k).lower(): str(v) for k, v in headers.items() if str(k).lower() in wanted}

    def _redirect_history(self, resp: requests.Response) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for r in list(resp.history or []) + [resp]:
            rows.append({
                "url": self._canonicalize_url(r.url),
                "status_code": int(r.status_code),
                "location": r.headers.get("location", ""),
                "cdn_provider": self._detect_cdn(r.url, r.headers),
                "cache_status": self._cache_status(r.headers),
            })
        return rows

    def _cache_status(self, headers: Mapping[str, str]) -> str:
        keys = ["cf-cache-status", "x-cache", "x-cache-hits", "akamai-cache-status", "x-vercel-cache", "age"]
        vals = []
        lower = {str(k).lower(): str(v) for k, v in headers.items()}
        for k in keys:
            if k in lower:
                vals.append(f"{k}={lower[k]}")
        return "; ".join(vals)

    def _detect_cdn(self, url: str, headers: Mapping[str, str]) -> str:
        lower = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        host_provider = self._detect_cdn_from_host(urlparse(url).netloc)
        if host_provider:
            return host_provider
        if "cf-ray" in lower or lower.get("server") == "cloudflare" or "cf-cache-status" in lower:
            return "Cloudflare"
        if "x-amz-cf-id" in lower or "x-amz-cf-pop" in lower or "cloudfront" in lower.get("via", "") or "cloudfront" in lower.get("x-cache", ""):
            return "Amazon CloudFront"
        if "x-served-by" in lower or "x-timer" in lower or "fastly" in lower.get("via", ""):
            return "Fastly"
        if any("akamai" in k for k in lower) or "akamaighost" in lower.get("server", ""):
            return "Akamai"
        if "x-azure-ref" in lower or "azure" in lower.get("x-cache", ""):
            return "Azure CDN"
        if "x-vercel-id" in lower or "x-vercel-cache" in lower or "vercel" in lower.get("server", ""):
            return "Vercel"
        if "x-nf-request-id" in lower or "netlify" in lower.get("server", ""):
            return "Netlify"
        if any(k.startswith("x-goog-") for k in lower):
            return "Google CDN/Storage"
        return ""

    def _detect_cdn_from_host(self, host: str) -> str:
        h = (host or "").lower().split(":", 1)[0]
        for suffix, provider in CDN_HOST_HINTS.items():
            if h == suffix or h.endswith("." + suffix):
                return provider
        return ""

    def _populate_domain_context(self, report: CDNReport) -> None:
        if not self.cfg.resolve_domain_context:
            return
        hosts = []
        for u in [report.final_url, report.url] + [x.url for x in report.items[:200]]:
            if not u:
                continue
            host = urlparse(u).netloc.lower().split("@")[-1].split(":")[0].strip("[]")
            if host and host not in hosts:
                hosts.append(host)
        for host in hosts[: max(0, int(self.cfg.max_domain_contexts))]:
            report.domains[host] = self.domain_context(host)

    def _registered_domain(self, host: str) -> str:
        h = (host or "").split(":", 1)[0].strip("[]").lower()
        if not h:
            return ""
        try:
            import tldextract  # type: ignore
            ex = tldextract.extract(h)
            if ex.domain and ex.suffix:
                return f"{ex.domain}.{ex.suffix}"
        except Exception:
            pass
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h

    def _tls_certificate_summary(self, host: str) -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=min(float(self.cfg.timeout_sec), 6.0)) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                der = ssock.getpeercert(binary_form=True)
        out: Dict[str, Any] = {
            "subject": cert.get("subject", []),
            "issuer": cert.get("issuer", []),
            "notBefore": cert.get("notBefore", ""),
            "notAfter": cert.get("notAfter", ""),
            "sha256": hashlib.sha256(der or b"").hexdigest() if der else "",
        }
        sans = []
        for typ, val in cert.get("subjectAltName", []) or []:
            if typ.lower() == "dns":
                sans.append(val)
        out["san_dns"] = sans[:80]
        return out

    def _looks_signed_key(self, key: str) -> bool:
        lk = key.lower()
        return any(lk == h or lk.startswith(h) or h in lk for h in SIGNED_QUERY_HINTS)

    def _magic_type(self, raw: bytes) -> Optional[Tuple[str, str]]:
        if not raw:
            return None
        for sig, mime, kind in MAGIC_SIGNATURES:
            if raw.startswith(sig):
                if sig == b"\x00\x00\x00" and b"ftyp" not in raw[:16]:
                    continue
                return mime, kind
        return None

    def _extract_title(self, html_text: str) -> str:
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_text or "")
        if not m:
            return ""
        title = re.sub(r"(?s)<.*?>", " ", m.group(1))
        title = html.unescape(re.sub(r"\s+", " ", title)).strip()
        return title[:300]

    def _score_item(self, item: CDNItem) -> float:
        score = 1.0
        if item.cdn_provider:
            score += 4.0
        if item.kind in {"script", "source_map", "manifest", "json"}:
            score += 3.0
        if item.kind in {"image", "video", "audio", "document"}:
            score += 2.0
        if item.source in {"javascript", "source_map", "headers", "hls", "dash_mpd"}:
            score += 2.0
        if item.status_code and item.status_code < 400:
            score += 2.0
        if item.cache_status:
            score += 1.0
        if item.content_length:
            try:
                size = int(re.sub(r"\D", "", item.content_length) or "0")
                if size > 0:
                    score += min(2.0, size / 5_000_000.0)
            except Exception:
                pass
        return round(score, 4)

    def _rank_dedupe(self, items: Sequence[CDNItem]) -> List[CDNItem]:
        best: Dict[str, CDNItem] = {}
        for item in items:
            if not item.url:
                continue
            key = item.url
            if key not in best or item.score > best[key].score:
                best[key] = item
        out = list(best.values())
        out.sort(key=lambda x: (x.score, bool(x.cdn_provider), x.kind), reverse=True)
        return out


def cdn_investigate_url(
    url: str,
    *,
    timeout_sec: float = 20.0,
    max_depth: int = 1,
    max_pages: int = 25,
    max_items: int = 800,
    include_archives: bool = False,
    probe_candidates: bool = True,
    sqlite_path: str = "",
) -> Dict[str, Any]:
    cfg = CDNConfig(
        timeout_sec=timeout_sec,
        max_depth=max_depth,
        max_pages=max_pages,
        max_items=max_items,
        include_archives=include_archives,
        probe_candidates=probe_candidates,
        sqlite_path=sqlite_path,
    )
    engine = CDNEngine(cfg)
    try:
        return engine.investigate_url(url, include_archives=include_archives).as_dict()
    finally:
        engine.close()


def cdn_analyze_asset(url: str, *, timeout_sec: float = 20.0, probe_candidates: bool = True) -> Dict[str, Any]:
    engine = CDNEngine(CDNConfig(timeout_sec=timeout_sec, probe_candidates=probe_candidates))
    try:
        return engine.analyze_asset(url).as_dict()
    finally:
        engine.close()


def cdn_extract_from_text(text: str, *, base_url: str = "", max_items: int = 800) -> Dict[str, Any]:
    engine = CDNEngine(CDNConfig(max_items=max_items, probe_candidates=False, resolve_domain_context=False))
    try:
        return engine.extract_from_text(text, base_url=base_url).as_dict()
    finally:
        engine.close()


def cdn_url_variants(url: str, *, max_variants: int = 120) -> Dict[str, Any]:
    engine = CDNEngine(CDNConfig(max_variants=max_variants, probe_candidates=False, resolve_domain_context=False))
    try:
        variants = engine.generate_url_variants(url)
        return {"ok": True, "url": url, "count": len(variants), "variants": variants}
    finally:
        engine.close()


def cdn_domain_context(host_or_url: str, *, timeout_sec: float = 10.0) -> Dict[str, Any]:
    engine = CDNEngine(CDNConfig(timeout_sec=timeout_sec, probe_candidates=False))
    try:
        return {"ok": True, "context": engine.domain_context(host_or_url).as_dict()}
    finally:
        engine.close()


def _main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Public/authorized CDN link and asset discovery engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_url = sub.add_parser("url", help="Investigate a URL/page for CDN-hosted and hidden asset links")
    p_url.add_argument("url")
    p_url.add_argument("--depth", type=int, default=1)
    p_url.add_argument("--max-pages", type=int, default=25)
    p_url.add_argument("--max-items", type=int, default=800)
    p_url.add_argument("--timeout", type=float, default=20.0)
    p_url.add_argument("--archives", action="store_true")
    p_url.add_argument("--no-probe", action="store_true")
    p_url.add_argument("--sqlite", default="")
    p_url.add_argument("--out", default="")
    p_url.add_argument("--markdown", action="store_true")

    p_asset = sub.add_parser("asset", help="Analyze one asset URL")
    p_asset.add_argument("url")
    p_asset.add_argument("--timeout", type=float, default=20.0)
    p_asset.add_argument("--out", default="")

    p_text = sub.add_parser("text", help="Extract CDN-ish URLs from a local text/html/js/css file")
    p_text.add_argument("path")
    p_text.add_argument("--base-url", default="")
    p_text.add_argument("--out", default="")

    p_var = sub.add_parser("variants", help="Generate conservative URL variants from an observed URL")
    p_var.add_argument("url")

    args = p.parse_args(argv)

    if args.cmd == "url":
        cfg = CDNConfig(
            timeout_sec=args.timeout,
            max_depth=args.depth,
            max_pages=args.max_pages,
            max_items=args.max_items,
            include_archives=bool(args.archives),
            probe_candidates=not bool(args.no_probe),
            sqlite_path=args.sqlite,
        )
        engine = CDNEngine(cfg)
        try:
            rep = engine.investigate_url(args.url, include_archives=args.archives)
            output = rep.to_markdown() if args.markdown else rep.to_json()
        finally:
            engine.close()
    elif args.cmd == "asset":
        output = json.dumps(cdn_analyze_asset(args.url, timeout_sec=args.timeout), ensure_ascii=False, indent=2)
    elif args.cmd == "text":
        text = Path(args.path).read_text(encoding="utf-8", errors="replace")
        output = json.dumps(cdn_extract_from_text(text, base_url=args.base_url), ensure_ascii=False, indent=2)
    elif args.cmd == "variants":
        output = json.dumps(cdn_url_variants(args.url), ensure_ascii=False, indent=2)
    else:
        p.error("unknown command")
        return 2

    out_path = getattr(args, "out", "")
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
