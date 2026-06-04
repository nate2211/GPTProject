from __future__ import annotations

"""
engines.py

Standalone public/authorized discovery engines for PromptChat/GPT toolbeds.

Included engines:
- ArchiveEngine      -> deleted/lost page discovery through public archives
- SourceMapEngine    -> JavaScript bundle/source-map mining with secret redaction
- MetadataEngine     -> EXIF/IPTC/XMP/OpenGraph/JSON-LD/PDF/media-ish metadata
- OSINTEngine        -> public domain/IP/cert/DNS/search context
- ManifestEngine     -> web app, HLS, DASH, RSS/Atom, sitemap manifests
- RouteEngine        -> client-side route discovery from HTML/JS/framework payloads
- MediaEngine        -> video/audio/image manifest and metadata discovery
- EntityEngine       -> people/brand/product/place extraction and URL linking

Safety boundary:
- Designed for public or explicitly authorized content discovery.
- Does not bypass logins, paywalls, ACLs, signed URL protections, or private buckets.
- Uses conservative probing and redacts secret-like values by default.
- Optional network calls obey timeout/rate settings and do not brute force paths.

The public module-level functions match the names requested by the user, for easy
registration in tools.py or direct use.
"""

import base64
import csv
import dataclasses
import difflib
import email.utils
import hashlib
import html
import json
import mimetypes
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    requests = None


# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 PromptChatEngines/1.0"
)

SECRET_KEY_RE = re.compile(
    r"(?i)(token|secret|signature|sig|key|api[_-]?key|access[_-]?token|auth|password|passwd|pwd|session|cookie|jwt|bearer|credential)"
)
URL_RE = re.compile(
    r"(?ix)\b(?:https?://|//|/)[^\s'\"<>`{}|\\^\[\]]{2,}"
)
ABS_URL_RE = re.compile(r"(?i)\bhttps?://[^\s'\"<>`{}|\\^\[\]]+")
SOURCE_MAP_RE = re.compile(r"(?im)//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)")
CSS_URL_RE = re.compile(r"(?is)url\(\s*['\"]?([^'\")]+)['\"]?\s*\)")
HTML_ATTR_RE = re.compile(
    r"(?is)\b(?:href|src|srcset|poster|data-src|data-href|content|action)\s*=\s*(['\"])(.*?)\1"
)
ROUTE_STRING_RE = re.compile(
    r"(?P<q>['\"])(?P<route>/(?:[A-Za-z0-9_./:@%?=&+#,;~!$*()\[\]-]|\\/){1,250})(?P=q)"
)
CAPITALIZED_PHRASE_RE = re.compile(r"\b(?:[A-Z][a-zA-Z0-9&'._-]+(?:\s+|$)){1,5}")
DATE_RE = re.compile(r"(?P<date>20\d{2}[-_/]\d{1,2}[-_/]\d{1,2}|19\d{2}[-_/]\d{1,2}[-_/]\d{1,2})")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")

MEDIA_EXTENSIONS = {
    ".mp4", ".webm", ".mov", ".m4v", ".mkv", ".avi", ".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg",
    ".m3u8", ".mpd", ".vtt", ".srt", ".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif", ".svg",
}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif", ".svg", ".bmp", ".tif", ".tiff"}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov", ".m4v", ".mkv", ".avi", ".m3u8", ".mpd"}
AUDIO_EXTENSIONS = {".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".json", ".xml"}

CDN_HOST_HINTS = {
    "cloudfront.net", "akamaihd.net", "akamaized.net", "edgesuite.net", "edgekey.net", "fastly.net",
    "cdn77.org", "cloudflare.com", "cloudflare.net", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "shopifycdn.net", "wp.com", "wordpress.com", "imgix.net", "cloudinary.com", "scene7.com",
    "azureedge.net", "googleusercontent.com", "gstatic.com", "fbcdn.net", "twimg.com", "vimeocdn.com",
}


@dataclass
class EngineConfig:
    timeout_sec: float = 20.0
    max_body_bytes: int = 2_000_000
    max_text_chars: int = 300_000
    max_items: int = 2000
    max_pages: int = 25
    max_depth: int = 1
    max_archive_results: int = 80
    max_variants: int = 200
    respect_robots: bool = True
    rate_limit_delay_sec: float = 0.15
    allow_cross_host: bool = False
    keep_secret_query_values: bool = False
    user_agent: str = USER_AGENT
    sqlite_path: str = ""
    artifact_dir: str = "data/engines/artifacts"


@dataclass
class Finding:
    kind: str
    value: str
    source: str
    confidence: float = 0.5
    context: str = ""
    url: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class EngineReport:
    ok: bool
    engine: str
    target: str = ""
    generated_at: str = ""
    elapsed_ms: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=indent)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data or b"").hexdigest()


def clean_text(value: str, limit: int = 500) -> str:
    text = html.unescape(value or "")
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def normalize_url(url: str, base_url: str = "") -> str:
    raw = html.unescape((url or "").strip())
    if not raw:
        return ""
    if raw.startswith("//"):
        scheme = urllib.parse.urlparse(base_url).scheme or "https"
        raw = f"{scheme}:{raw}"
    if base_url:
        raw = urllib.parse.urljoin(base_url, raw)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        if raw.startswith("/") and base_url:
            raw = urllib.parse.urljoin(base_url, raw)
        elif "." in raw.split("/", 1)[0]:
            raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def host_of(url: str) -> str:
    return urllib.parse.urlparse(url or "").netloc.lower()


def registered_domain_guess(host: str) -> str:
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) <= 2:
        return host.lower()
    two_level = {"co.uk", "com.au", "com.br", "co.jp", "com.cn", "co.in", "com.mx"}
    tail2 = ".".join(parts[-2:])
    if tail2 in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def redacted_url(url: str, keep_secret_query_values: bool = False) -> str:
    if keep_secret_query_values:
        return url
    parsed = urllib.parse.urlparse(url or "")
    if not parsed.query:
        return url
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    safe_pairs = []
    for k, v in pairs:
        if SECRET_KEY_RE.search(k):
            safe_pairs.append((k, "<redacted>"))
        else:
            if len(v) > 80 and re.search(r"[A-Za-z0-9_-]{32,}", v):
                safe_pairs.append((k, "<redacted-long-value>"))
            else:
                safe_pairs.append((k, v))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(safe_pairs, doseq=True)))


def classify_url(url: str) -> str:
    path = urllib.parse.urlparse(url or "").path.lower()
    ext = os.path.splitext(path)[1]
    if ext in IMAGE_EXTENSIONS:
        return "image"
    if ext in VIDEO_EXTENSIONS:
        return "video_manifest" if ext in {".m3u8", ".mpd"} else "video"
    if ext in AUDIO_EXTENSIONS:
        return "audio"
    if ext in DOCUMENT_EXTENSIONS:
        return "document"
    if ext in {".js", ".mjs", ".cjs"}:
        return "script"
    if ext == ".css":
        return "stylesheet"
    if ext == ".map":
        return "source_map"
    if ext in {".json", ".webmanifest"}:
        return "json_manifest"
    if ext in {".xml", ".rss", ".atom"}:
        return "xml_manifest"
    return "link"


def is_cdn_host(host: str) -> bool:
    h = (host or "").lower()
    return any(h == c or h.endswith("." + c) for c in CDN_HOST_HINTS) or "cdn" in h or "static" in h or "assets" in h


def extract_urls_from_text(text: str, base_url: str = "", *, keep_secret_query_values: bool = False, max_urls: int = 5000) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()

    def add(candidate: str) -> None:
        u = normalize_url(candidate, base_url)
        if not u:
            return
        u = redacted_url(u, keep_secret_query_values=keep_secret_query_values)
        if u not in seen:
            seen.add(u)
            out.append(u)

    for m in URL_RE.finditer(text or ""):
        add(m.group(0).rstrip(".,);]}'\""))
        if len(out) >= max_urls:
            return out
    for _, raw in HTML_ATTR_RE.findall(text or ""):
        if "srcset" in raw or "," in raw:
            for part in raw.split(","):
                add(part.strip().split(" ")[0])
        else:
            add(raw)
        if len(out) >= max_urls:
            return out
    for raw in CSS_URL_RE.findall(text or ""):
        add(raw)
        if len(out) >= max_urls:
            return out
    return out[:max_urls]


def generate_url_variants(url: str, max_variants: int = 100) -> List[str]:
    """Conservative variants from observed URL only. No brute-force wordlists."""
    base = normalize_url(url)
    if not base:
        return []
    parsed = urllib.parse.urlparse(base)
    path = parsed.path or "/"
    stem, ext = os.path.splitext(path)
    variants: List[str] = []
    seen: Set[str] = set()

    def add(p: str, q: str = "") -> None:
        u = urllib.parse.urlunparse(parsed._replace(path=p, query=q, fragment=""))
        if u not in seen:
            seen.add(u)
            variants.append(u)

    add(path, parsed.query)
    if parsed.query:
        add(path, "")
    if ext:
        add(stem + ext.lower())
        add(stem + ext.upper())
        if ext in {".min.js", ".js"}:
            add(stem.replace(".min", "") + ".js")
            add(stem + ".map")
            add(path + ".map")
        if ext in {".css"}:
            add(stem + ".css.map")
            add(path + ".map")
    if path.endswith("/"):
        for name in ("index.html", "index.json", "manifest.json", "sitemap.xml", "feed.xml", "rss.xml"):
            add(urllib.parse.urljoin(path, name))
    else:
        add(path.rstrip("/") + "/")
    # Common CDN version marker removal from observed URL only.
    path2 = re.sub(r"[._-][a-f0-9]{8,32}(?=\.)", "", path, flags=re.I)
    if path2 != path:
        add(path2)
    return variants[: max(1, int(max_variants or 1))]


def magic_type(data: bytes, content_type: str = "", url: str = "") -> str:
    if content_type:
        return content_type.split(";", 1)[0].strip().lower()
    head = data[:32]
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith(b"\x89PNG"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"GIF8"):
        return "image/gif"
    if head.startswith(b"PK\x03\x04"):
        return "application/zip"
    if b"ftyp" in head[:16]:
        return "video/mp4"
    guessed = mimetypes.guess_type(url)[0]
    return guessed or "application/octet-stream"


def parse_http_date(value: str) -> str:
    if not value:
        return ""
    try:
        return email.utils.parsedate_to_datetime(value).astimezone(timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return value


class Fetcher:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.session = None
        if requests is not None:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": self.cfg.user_agent, "Accept": "*/*"})

    def close(self) -> None:
        try:
            if self.session is not None:
                self.session.close()
        except Exception:
            pass

    def fetch(self, url: str, *, method: str = "GET", max_bytes: Optional[int] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        normalized = normalize_url(url)
        if not normalized:
            return {"ok": False, "url": url, "error": "invalid url"}
        max_b = int(max_bytes or self.cfg.max_body_bytes)
        req_headers = {"User-Agent": self.cfg.user_agent, "Accept": "*/*"}
        if headers:
            req_headers.update(headers)
        started = time.time()
        try:
            if self.session is not None:
                resp = self.session.request(method, normalized, timeout=self.cfg.timeout_sec, allow_redirects=True, headers=req_headers, stream=True)
                body = b""
                if method.upper() != "HEAD":
                    for chunk in resp.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        body += chunk
                        if len(body) >= max_b:
                            body = body[:max_b]
                            break
                return {
                    "ok": True,
                    "url": normalized,
                    "final_url": resp.url,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": body,
                    "text": decode_text(body, resp.headers.get("content-type", ""), self.cfg.max_text_chars),
                    "elapsed_ms": int((time.time() - started) * 1000),
                    "truncated": len(body) >= max_b,
                    "history": [getattr(r, "url", "") for r in getattr(resp, "history", [])],
                }
            request = urllib.request.Request(normalized, method=method.upper(), headers=req_headers)
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
            with opener.open(request, timeout=self.cfg.timeout_sec) as r:
                body = b"" if method.upper() == "HEAD" else r.read(max_b)
                headers_dict = {k.lower(): v for k, v in r.headers.items()}
                final_url = r.geturl()
                return {
                    "ok": True,
                    "url": normalized,
                    "final_url": final_url,
                    "status_code": getattr(r, "status", 0),
                    "headers": headers_dict,
                    "body": body,
                    "text": decode_text(body, headers_dict.get("content-type", ""), self.cfg.max_text_chars),
                    "elapsed_ms": int((time.time() - started) * 1000),
                    "truncated": len(body) >= max_b,
                    "history": [],
                }
        except Exception as exc:
            return {"ok": False, "url": normalized, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}

    def head(self, url: str) -> Dict[str, Any]:
        return self.fetch(url, method="HEAD", max_bytes=0)

    def range_probe(self, url: str, size: int = 4096) -> Dict[str, Any]:
        return self.fetch(url, method="GET", max_bytes=size, headers={"Range": f"bytes=0-{max(0, size-1)}"})


def decode_text(data: bytes, content_type: str = "", limit: int = 300_000) -> str:
    if not data:
        return ""
    charset = ""
    m = re.search(r"charset=([^;]+)", content_type or "", re.I)
    if m:
        charset = m.group(1).strip()
    for enc in [charset, "utf-8", "utf-16", "latin-1"]:
        if not enc:
            continue
        try:
            return data[:limit].decode(enc, errors="replace")
        except Exception:
            continue
    return data[:limit].decode("utf-8", errors="replace")


def make_report(engine: str, target: str, started: float, findings: List[Finding], errors: Optional[List[str]] = None, raw: Optional[Dict[str, Any]] = None) -> EngineReport:
    counts = Counter(f.kind for f in findings)
    sources = Counter(f.source for f in findings)
    return EngineReport(
        ok=not errors,
        engine=engine,
        target=target,
        generated_at=utc_now(),
        elapsed_ms=int((time.time() - started) * 1000),
        summary={"finding_count": len(findings), "kind_counts": dict(counts), "source_counts": dict(sources)},
        findings=[f.as_dict() for f in findings],
        errors=errors or [],
        raw=raw or {},
    )


def dedupe_findings(findings: Iterable[Finding], limit: int = 2000) -> List[Finding]:
    seen: Set[Tuple[str, str, str]] = set()
    out: List[Finding] = []
    for f in findings:
        key = (f.kind, f.value, f.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# ManifestEngine
# ---------------------------------------------------------------------------

class ManifestEngine:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.fetcher = Fetcher(self.cfg)

    def close(self) -> None:
        self.fetcher.close()

    def manifest_find(self, url: str) -> Dict[str, Any]:
        started = time.time()
        resp = self.fetcher.fetch(url)
        findings: List[Finding] = []
        errors: List[str] = []
        if not resp.get("ok"):
            return make_report("manifest", url, started, [], [resp.get("error", "fetch failed")]).as_dict()
        base = resp.get("final_url") or url
        text = resp.get("text", "")
        headers = resp.get("headers", {}) or {}
        link_header = headers.get("link") or headers.get("Link") or ""
        for u in extract_urls_from_text(link_header, base, max_urls=200):
            findings.append(Finding("manifest_link_header", u, "http_link_header", 0.72, url=base))
        # HTML link rel discovery.
        for m in re.finditer(r"(?is)<link\b([^>]+)>", text):
            tag = m.group(0)
            href_m = re.search(r"(?is)href\s*=\s*(['\"])(.*?)\1", tag)
            rel_m = re.search(r"(?is)rel\s*=\s*(['\"])(.*?)\1", tag)
            typ_m = re.search(r"(?is)type\s*=\s*(['\"])(.*?)\1", tag)
            if href_m:
                u = normalize_url(href_m.group(2), base)
                rel = (rel_m.group(2) if rel_m else "").lower()
                typ = (typ_m.group(2) if typ_m else "").lower()
                if u and any(x in rel or x in typ or u.lower().endswith(x) for x in ["manifest", "rss", "atom", "opensearch", "sitemap", "m3u8", "mpd"]):
                    findings.append(Finding("manifest", redacted_url(u, self.cfg.keep_secret_query_values), "html_link_rel", 0.82, context=rel or typ, url=base, extra={"rel": rel, "type": typ}))
        for u in extract_urls_from_text(text, base, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=self.cfg.max_items):
            k = classify_url(u)
            if k in {"video_manifest", "json_manifest", "xml_manifest"} or any(u.lower().endswith(x) for x in ("manifest.json", ".webmanifest", "sitemap.xml", ".rss", ".atom")):
                findings.append(Finding("manifest", u, "page_text", 0.62, url=base, extra={"classified_as": k}))
        # Conventional public manifest paths from same observed host only.
        parsed = urllib.parse.urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}/"
        for p in ("manifest.json", "site.webmanifest", "sitemap.xml", "feed.xml", "rss.xml", "atom.xml", "opensearch.xml"):
            findings.append(Finding("manifest_candidate", urllib.parse.urljoin(root, p), "same_origin_convention", 0.35, url=base))
        return make_report("manifest", url, started, dedupe_findings(findings, self.cfg.max_items), errors, {"status_code": resp.get("status_code"), "final_url": base}).as_dict()

    def manifest_parse_webapp(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text = text_or_url
        target = base_url or "pasted-webapp-manifest"
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return make_report("manifest_webapp", text_or_url, started, [], [r.get("error", "fetch failed")]).as_dict()
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
            base_url = target
        findings: List[Finding] = []
        try:
            data = json.loads(text or "{}")
        except Exception as exc:
            return make_report("manifest_webapp", target, started, [], [f"invalid json: {exc}"]).as_dict()
        for key in ("start_url", "scope", "id"):
            if data.get(key):
                u = normalize_url(str(data[key]), base_url)
                if u:
                    findings.append(Finding("webapp_url", u, "webapp_manifest", 0.78, context=key, url=base_url))
        for bucket in ("icons", "screenshots", "shortcuts", "related_applications"):
            value = data.get(bucket)
            if isinstance(value, list):
                for row in value:
                    if isinstance(row, dict):
                        for k in ("src", "url"):
                            if row.get(k):
                                u = normalize_url(str(row[k]), base_url)
                                if u:
                                    findings.append(Finding("webapp_asset", u, "webapp_manifest", 0.8, context=f"{bucket}.{k}", url=base_url, extra={"item": redact_obj(row)}))
        return make_report("manifest_webapp", target, started, dedupe_findings(findings, self.cfg.max_items), raw={"name": data.get("name"), "short_name": data.get("short_name")}).as_dict()

    def manifest_parse_hls(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text = text_or_url
        target = base_url or "pasted-hls"
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return make_report("manifest_hls", text_or_url, started, [], [r.get("error", "fetch failed")]).as_dict()
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
            base_url = target
        findings: List[Finding] = []
        pending_inf = ""
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#EXT-X-STREAM-INF") or line.startswith("#EXT-X-MEDIA"):
                pending_inf = line
                for u in extract_urls_from_text(line, base_url, keep_secret_query_values=self.cfg.keep_secret_query_values):
                    findings.append(Finding("hls_reference", u, "hls_tag", 0.82, context=line[:300], url=base_url))
                uri_m = re.search(r"URI=\"([^\"]+)\"", line)
                if uri_m:
                    u = normalize_url(uri_m.group(1), base_url)
                    if u:
                        findings.append(Finding("hls_media_uri", u, "hls_tag_uri", 0.85, context=line[:300], url=base_url))
                continue
            if line.startswith("#EXT-X-MAP") or line.startswith("#EXT-X-KEY"):
                uri_m = re.search(r"URI=\"([^\"]+)\"", line)
                if uri_m:
                    u = normalize_url(uri_m.group(1), base_url)
                    if u:
                        findings.append(Finding("hls_map_or_key_uri", u, "hls_tag_uri", 0.72, context=line[:300], url=base_url))
                continue
            if not line.startswith("#"):
                u = normalize_url(line, base_url)
                if u:
                    kind = "hls_variant" if pending_inf else "hls_segment"
                    findings.append(Finding(kind, redacted_url(u, self.cfg.keep_secret_query_values), "hls_line", 0.88 if pending_inf else 0.72, context=pending_inf[:300], url=base_url))
                    pending_inf = ""
        return make_report("manifest_hls", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def manifest_parse_dash(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text = text_or_url
        target = base_url or "pasted-dash"
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return make_report("manifest_dash", text_or_url, started, [], [r.get("error", "fetch failed")]).as_dict()
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
            base_url = target
        findings: List[Finding] = []
        try:
            root = ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
        except Exception as exc:
            return make_report("manifest_dash", target, started, [], [f"invalid mpd/xml: {exc}"]).as_dict()
        for elem in root.iter():
            tag = elem.tag.split("}")[-1]
            if tag in {"BaseURL", "Initialization", "SegmentURL"}:
                raw = elem.text or elem.attrib.get("sourceURL") or elem.attrib.get("media") or ""
                if raw:
                    u = normalize_url(raw, base_url)
                    if u:
                        findings.append(Finding("dash_asset", redacted_url(u, self.cfg.keep_secret_query_values), f"dash_{tag}", 0.82, url=base_url, extra=dict(elem.attrib)))
            for attr in ("media", "initialization", "sourceURL"):
                if elem.attrib.get(attr):
                    u = normalize_url(elem.attrib[attr], base_url)
                    if u:
                        findings.append(Finding("dash_template", redacted_url(u, self.cfg.keep_secret_query_values), f"dash_attr_{attr}", 0.72, url=base_url, extra=dict(elem.attrib)))
        return make_report("manifest_dash", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def manifest_parse_rss(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        return self.manifest_parse_atom(text_or_url, base_url)

    def manifest_parse_atom(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text = text_or_url
        target = base_url or "pasted-feed"
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return make_report("manifest_feed", text_or_url, started, [], [r.get("error", "fetch failed")]).as_dict()
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
            base_url = target
        findings: List[Finding] = []
        try:
            root = ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
        except Exception as exc:
            return make_report("manifest_feed", target, started, [], [f"invalid feed/xml: {exc}"]).as_dict()
        for elem in root.iter():
            tag = elem.tag.split("}")[-1].lower()
            attrs = {k.split("}")[-1]: v for k, v in elem.attrib.items()}
            if tag in {"link", "enclosure", "content", "thumbnail"}:
                raw = attrs.get("href") or attrs.get("url") or attrs.get("src") or ""
                if raw:
                    u = normalize_url(raw, base_url)
                    if u:
                        findings.append(Finding("feed_asset", redacted_url(u, self.cfg.keep_secret_query_values), f"feed_{tag}", 0.78, url=base_url, extra=attrs))
            if elem.text and "http" in elem.text:
                for u in extract_urls_from_text(elem.text, base_url, keep_secret_query_values=self.cfg.keep_secret_query_values):
                    findings.append(Finding("feed_text_url", u, f"feed_{tag}_text", 0.55, url=base_url))
        return make_report("manifest_feed", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def manifest_extract_assets(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        target = normalize_url(text_or_url) or base_url or "pasted-manifest"
        lower = text_or_url.lower()
        if normalize_url(text_or_url):
            lower = urllib.parse.urlparse(text_or_url).path.lower()
        if ".m3u8" in lower or "#extm3u" in text_or_url.lower()[:200]:
            return self.manifest_parse_hls(text_or_url, base_url)
        if ".mpd" in lower or "<mpd" in text_or_url.lower()[:300]:
            return self.manifest_parse_dash(text_or_url, base_url)
        if any(x in lower for x in ("rss", "atom", "feed", ".xml")) or "<rss" in text_or_url.lower()[:300] or "<feed" in text_or_url.lower()[:300]:
            return self.manifest_parse_atom(text_or_url, base_url)
        return self.manifest_parse_webapp(text_or_url, base_url)


# ---------------------------------------------------------------------------
# SourceMapEngine
# ---------------------------------------------------------------------------

class SourceMapEngine:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.fetcher = Fetcher(self.cfg)

    def close(self) -> None:
        self.fetcher.close()

    def sourcemap_find(self, url: str, include_guesses: bool = True) -> Dict[str, Any]:
        started = time.time()
        resp = self.fetcher.fetch(url)
        findings: List[Finding] = []
        errors: List[str] = []
        if not resp.get("ok"):
            return make_report("sourcemap", url, started, [], [resp.get("error", "fetch failed")]).as_dict()
        base = resp.get("final_url") or url
        text = resp.get("text", "")
        scripts = [u for u in extract_urls_from_text(text, base, keep_secret_query_values=self.cfg.keep_secret_query_values) if classify_url(u) == "script"]
        if classify_url(base) == "script":
            scripts.insert(0, base)
        for script in list(dict.fromkeys(scripts))[: self.cfg.max_pages]:
            findings.append(Finding("script", script, "script_reference", 0.65, url=base))
            sr = self.fetcher.fetch(script)
            if not sr.get("ok"):
                continue
            body = sr.get("text", "")
            for m in SOURCE_MAP_RE.finditer(body):
                sm = normalize_url(m.group(1), sr.get("final_url") or script)
                if sm:
                    findings.append(Finding("source_map", redacted_url(sm, self.cfg.keep_secret_query_values), "sourceMappingURL", 0.92, url=script))
            if include_guesses:
                for guess in [script + ".map", re.sub(r"\.min\.js($|\?)", ".js.map", script), re.sub(r"\.js($|\?)", ".js.map", script)]:
                    if normalize_url(guess):
                        findings.append(Finding("source_map_candidate", guess, "script_map_guess", 0.35, url=script))
            # Extract routes and asset strings from JS as secondary evidence.
            for u in extract_urls_from_text(body, sr.get("final_url") or script, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=500):
                if classify_url(u) in {"source_map", "script", "json_manifest", "image", "video", "audio", "document"}:
                    findings.append(Finding("bundle_url", u, "script_text", 0.55, url=script, extra={"classified_as": classify_url(u)}))
        return make_report("sourcemap", url, started, dedupe_findings(findings, self.cfg.max_items), errors, {"script_count": len(scripts)}).as_dict()

    def sourcemap_fetch(self, url: str) -> Dict[str, Any]:
        started = time.time()
        resp = self.fetcher.fetch(url)
        if not resp.get("ok"):
            return make_report("sourcemap_fetch", url, started, [], [resp.get("error", "fetch failed")]).as_dict()
        data = safe_json_loads(resp.get("text", ""))
        if not isinstance(data, dict):
            return make_report("sourcemap_fetch", url, started, [], ["not valid source map JSON"]).as_dict()
        findings = [
            Finding("source_map_metadata", str(data.get("version", "")), "source_map", 0.7, url=url, extra={"file": data.get("file", ""), "sourceRoot": data.get("sourceRoot", ""), "sources_count": len(data.get("sources") or [])})
        ]
        return make_report("sourcemap_fetch", url, started, findings, raw={"source_map": redact_obj(data)}).as_dict()

    def sourcemap_extract_sources(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        data, target, errors = self._load_sourcemap(text_or_url, base_url)
        findings: List[Finding] = []
        if errors:
            return make_report("sourcemap_sources", target, started, [], errors).as_dict()
        source_root = str(data.get("sourceRoot") or "")
        for src in data.get("sources") or []:
            val = str(src)
            resolved = normalize_url(source_root + val, base_url) if source_root.startswith("http") else val
            findings.append(Finding("source_file", resolved, "source_map_sources", 0.82, url=target, extra={"sourceRoot": source_root}))
        return make_report("sourcemap_sources", target, started, findings, raw={"sources_count": len(data.get("sources") or [])}).as_dict()

    def sourcemap_extract_urls(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        data, target, errors = self._load_sourcemap(text_or_url, base_url)
        findings: List[Finding] = []
        if errors:
            return make_report("sourcemap_urls", target, started, [], errors).as_dict()
        hay = json.dumps(redact_obj(data), ensure_ascii=False)
        for u in extract_urls_from_text(hay, base_url or target, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=self.cfg.max_items):
            findings.append(Finding(classify_url(u), u, "source_map_json", 0.65, url=target))
        for content in data.get("sourcesContent") or []:
            if isinstance(content, str):
                for u in extract_urls_from_text(content, base_url or target, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=500):
                    findings.append(Finding(classify_url(u), u, "source_map_sourcesContent", 0.7, url=target))
        return make_report("sourcemap_urls", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def sourcemap_reconstruct_tree(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        data, target, errors = self._load_sourcemap(text_or_url, base_url)
        if errors:
            return make_report("sourcemap_tree", target, started, [], errors).as_dict()
        tree: Dict[str, Any] = {}
        for src in data.get("sources") or []:
            cur = tree
            parts = [p for p in str(src).replace("webpack://", "webpack/").replace("\\", "/").split("/") if p and p != "."]
            for p in parts[:-1]:
                cur = cur.setdefault(p, {})
            if parts:
                cur[parts[-1]] = "file"
        findings = [Finding("source_tree", json.dumps(tree, ensure_ascii=False), "source_map_sources", 0.8, url=target)]
        return make_report("sourcemap_tree", target, started, findings, raw={"tree": tree}).as_dict()

    def sourcemap_secret_redacted_scan(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        data, target, errors = self._load_sourcemap(text_or_url, base_url)
        if errors:
            return make_report("sourcemap_redacted_scan", target, started, [], errors).as_dict()
        findings: List[Finding] = []
        patterns = {
            "possible_api_key": re.compile(r"(?i)(api[_-]?key|token|secret|client_secret)\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=-]{8,})"),
            "possible_jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            "possible_private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        }
        text = json.dumps(data, ensure_ascii=False)
        for name, pat in patterns.items():
            for m in pat.finditer(text):
                findings.append(Finding("redacted_secret_indicator", "<redacted>", "source_map_secret_scan", 0.65, context=name, url=target, extra={"pattern": name, "span": [m.start(), m.end()]}))
                if len(findings) >= self.cfg.max_items:
                    break
        return make_report("sourcemap_redacted_scan", target, started, findings).as_dict()

    def _load_sourcemap(self, text_or_url: str, base_url: str = "") -> Tuple[Dict[str, Any], str, List[str]]:
        target = base_url or "pasted-source-map"
        text = text_or_url
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return {}, text_or_url, [r.get("error", "fetch failed")]
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
        data = safe_json_loads(text or "")
        if not isinstance(data, dict):
            return {}, target, ["not valid source map JSON"]
        return data, target, []


# ---------------------------------------------------------------------------
# MetadataEngine
# ---------------------------------------------------------------------------

class MetadataEngine:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.fetcher = Fetcher(self.cfg)

    def close(self) -> None:
        self.fetcher.close()

    def metadata_url(self, url: str) -> Dict[str, Any]:
        started = time.time()
        resp = self.fetcher.fetch(url)
        if not resp.get("ok"):
            return make_report("metadata", url, started, [], [resp.get("error", "fetch failed")]).as_dict()
        base = resp.get("final_url") or url
        text = resp.get("text", "")
        headers = resp.get("headers", {}) or {}
        findings: List[Finding] = []
        findings.append(Finding("http_metadata", str(resp.get("status_code")), "http_response", 0.75, url=base, extra={"content_type": headers.get("content-type") or headers.get("Content-Type"), "etag": headers.get("etag") or headers.get("ETag"), "last_modified": parse_http_date(headers.get("last-modified") or headers.get("Last-Modified") or "")}))
        title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
        if title_m:
            findings.append(Finding("title", clean_text(title_m.group(1), 300), "html_title", 0.85, url=base))
        for m in re.finditer(r"(?is)<meta\b([^>]+)>", text):
            tag = m.group(0)
            name = attr_value(tag, "name") or attr_value(tag, "property") or attr_value(tag, "itemprop")
            content = attr_value(tag, "content")
            if name and content:
                k = "structured_meta" if any(x in name.lower() for x in ("og:", "twitter:", "schema", "itemprop")) else "meta"
                val = redacted_url(content, self.cfg.keep_secret_query_values) if content.startswith("http") else clean_text(content, 500)
                findings.append(Finding(k, val, "html_meta", 0.72, context=name, url=base))
        for m in re.finditer(r"(?is)<script[^>]+type=['\"]application/ld\+json['\"][^>]*>(.*?)</script>", text):
            data = safe_json_loads(html.unescape(m.group(1)))
            findings.append(Finding("json_ld", json.dumps(redact_obj(data), ensure_ascii=False)[:2000], "json_ld", 0.8, url=base))
            for u in extract_urls_from_text(json.dumps(data, ensure_ascii=False), base, keep_secret_query_values=self.cfg.keep_secret_query_values):
                findings.append(Finding(classify_url(u), u, "json_ld_url", 0.72, url=base))
        for u in extract_urls_from_text(text, base, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=500):
            if classify_url(u) in {"image", "video", "audio", "document", "json_manifest", "xml_manifest"}:
                findings.append(Finding(classify_url(u), u, "metadata_url_extraction", 0.55, url=base))
        return make_report("metadata", url, started, dedupe_findings(findings, self.cfg.max_items), raw={"final_url": base, "sha256": sha256_bytes(resp.get("body", b""))}).as_dict()

    def metadata_file(self, path: str) -> Dict[str, Any]:
        started = time.time()
        p = Path(path)
        if not p.exists() or not p.is_file():
            return make_report("metadata_file", path, started, [], ["file not found"]).as_dict()
        data = p.read_bytes()[: self.cfg.max_body_bytes]
        stat = p.stat()
        mime = magic_type(data, url=str(p))
        findings = [Finding("file_metadata", str(p), "filesystem", 0.9, extra={"size": stat.st_size, "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds"), "sha256": sha256_bytes(data), "md5": md5_bytes(data), "mime": mime})]
        text = decode_text(data, mime, self.cfg.max_text_chars)
        for u in extract_urls_from_text(text, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=500):
            findings.append(Finding(classify_url(u), u, "embedded_file_text", 0.55, url=str(p)))
        return make_report("metadata_file", path, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def metadata_image(self, path_or_url: str) -> Dict[str, Any]:
        if normalize_url(path_or_url):
            return self._metadata_binary_url(path_or_url, expected="image")
        report = self.metadata_file(path_or_url)
        try:
            from PIL import Image  # type: ignore
            img = Image.open(path_or_url)
            exif = img.getexif()
            report["raw"]["image"] = {"format": img.format, "size": list(img.size), "mode": img.mode, "exif_count": len(exif or {})}
            report["findings"].append(Finding("image_dimensions", f"{img.size[0]}x{img.size[1]}", "pillow", 0.95, extra={"format": img.format, "mode": img.mode}).as_dict())
        except Exception as exc:
            report.setdefault("errors", []).append(f"optional image metadata failed: {exc}")
        return report

    def metadata_video(self, path_or_url: str) -> Dict[str, Any]:
        if normalize_url(path_or_url):
            return self._metadata_binary_url(path_or_url, expected="video")
        return self.metadata_file(path_or_url)

    def metadata_pdf(self, path_or_url: str) -> Dict[str, Any]:
        report = self._metadata_binary_url(path_or_url, expected="pdf") if normalize_url(path_or_url) else self.metadata_file(path_or_url)
        if not normalize_url(path_or_url):
            try:
                from pypdf import PdfReader  # type: ignore
                reader = PdfReader(path_or_url)
                meta = {str(k): str(v) for k, v in (reader.metadata or {}).items()}
                report["raw"]["pdf"] = {"pages": len(reader.pages), "metadata": redact_obj(meta)}
                report["findings"].append(Finding("pdf_metadata", json.dumps(redact_obj(meta), ensure_ascii=False), "pypdf", 0.85).as_dict())
            except Exception as exc:
                report.setdefault("errors", []).append(f"optional pdf metadata failed: {exc}")
        return report

    def metadata_compare(self, left: str, right: str) -> Dict[str, Any]:
        started = time.time()
        l = self.metadata_url(left) if normalize_url(left) else self.metadata_file(left)
        r = self.metadata_url(right) if normalize_url(right) else self.metadata_file(right)
        lvals = {f.get("kind") + ":" + f.get("value", "") for f in l.get("findings", [])}
        rvals = {f.get("kind") + ":" + f.get("value", "") for f in r.get("findings", [])}
        raw = {"left_only": sorted(lvals - rvals)[:500], "right_only": sorted(rvals - lvals)[:500], "common_count": len(lvals & rvals)}
        findings = [Finding("metadata_diff", json.dumps(raw, ensure_ascii=False), "metadata_compare", 0.8)]
        return make_report("metadata_compare", f"{left} <> {right}", started, findings, raw=raw).as_dict()

    def metadata_redacted_report(self, target: str) -> Dict[str, Any]:
        report = self.metadata_url(target) if normalize_url(target) else self.metadata_file(target)
        report["findings"] = [redact_obj(f) for f in report.get("findings", [])]
        report["raw"] = redact_obj(report.get("raw", {}))
        return report

    def _metadata_binary_url(self, url: str, expected: str = "") -> Dict[str, Any]:
        started = time.time()
        head = self.fetcher.head(url)
        probe = self.fetcher.range_probe(url, 8192)
        findings: List[Finding] = []
        errors: List[str] = []
        if not head.get("ok") and not probe.get("ok"):
            return make_report("metadata_binary", url, started, [], [head.get("error") or probe.get("error") or "fetch failed"]).as_dict()
        source = probe if probe.get("ok") else head
        headers = source.get("headers", {}) or {}
        body = source.get("body", b"") or b""
        mime = magic_type(body, headers.get("content-type") or headers.get("Content-Type") or "", url)
        findings.append(Finding(f"{expected or 'binary'}_metadata", url, "http_probe", 0.78, extra={"mime": mime, "sha256_first_bytes": sha256_bytes(body), "content_length": headers.get("content-length") or headers.get("Content-Length"), "etag": headers.get("etag") or headers.get("ETag"), "last_modified": parse_http_date(headers.get("last-modified") or headers.get("Last-Modified") or "")}))
        return make_report("metadata_binary", url, started, findings, errors, {"headers": redact_obj(headers)}).as_dict()


# ---------------------------------------------------------------------------
# ArchiveEngine
# ---------------------------------------------------------------------------

class ArchiveEngine:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.fetcher = Fetcher(self.cfg)

    def close(self) -> None:
        self.fetcher.close()

    def archive_search_url(self, url: str, max_results: Optional[int] = None) -> Dict[str, Any]:
        started = time.time()
        limit = int(max_results or self.cfg.max_archive_results)
        findings: List[Finding] = []
        errors: List[str] = []
        cdx_url = "https:/archive.org/cdx?" + urllib.parse.urlencode({"url": url, "output": "json", "fl": "timestamp,original,statuscode,mimetype,digest", "filter": "statuscode:200", "collapse": "digest", "limit": str(limit)})
        r = self.fetcher.fetch(cdx_url)
        if r.get("ok"):
            rows = safe_json_loads(r.get("text", ""))
            if isinstance(rows, list) and rows:
                for row in rows[1:]:
                    if len(row) >= 5:
                        ts, original, status, mime, digest = row[:5]
                        snapshot = f"https://archive.org/web/{ts}id_/{original}"
                        findings.append(Finding("wayback_snapshot", snapshot, "wayback_cdx", 0.86, url=url, extra={"timestamp": ts, "original": original, "status": status, "mime": mime, "digest": digest}))
        else:
            errors.append("wayback cdx: " + r.get("error", "failed"))
        # Memento TimeMap link-format as another public signal.
        timemap = "https://archive.org/web/timemap/link/" + urllib.parse.quote(url, safe="")
        tm = self.fetcher.fetch(timemap, max_bytes=400_000)
        if tm.get("ok"):
            for u in ABS_URL_RE.findall(tm.get("text", ""))[:limit]:
                if "archive.org/web/" in u:
                    findings.append(Finding("memento_snapshot", u.rstrip(">;,"), "memento_timemap", 0.74, url=url))
        return make_report("archive", url, started, dedupe_findings(findings, self.cfg.max_items), errors).as_dict()

    def archive_search_domain(self, domain: str, max_results: Optional[int] = None) -> Dict[str, Any]:
        d = registered_domain_guess(domain.replace("https://", "").replace("http://", "").split("/")[0])
        return self.archive_search_url(f"*.{d}/*", max_results=max_results)

    def archive_fetch_wayback_snapshot(self, url: str, timestamp: str = "") -> Dict[str, Any]:
        started = time.time()
        snap = url
        if "archive.org/web/" not in url:
            ts = timestamp or "2"
            snap = f"https://archive.org/web/{ts}id_/{url}"
        r = self.fetcher.fetch(snap)
        if not r.get("ok"):
            return make_report("archive_fetch", snap, started, [], [r.get("error", "fetch failed")]).as_dict()
        body = r.get("body", b"")
        findings = [Finding("archive_snapshot_body", r.get("final_url") or snap, "wayback_fetch", 0.85, extra={"status_code": r.get("status_code"), "sha256": sha256_bytes(body), "bytes": len(body), "title": extract_title(r.get("text", ""))})]
        for u in extract_urls_from_text(r.get("text", ""), r.get("final_url") or snap, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=500):
            findings.append(Finding(classify_url(u), u, "archive_snapshot_text", 0.55, url=snap))
        return make_report("archive_fetch", snap, started, dedupe_findings(findings, self.cfg.max_items), raw={"text_excerpt": clean_text(r.get("text", ""), 2000)}).as_dict()

    def archive_compare_snapshots(self, left_url: str, right_url: str) -> Dict[str, Any]:
        started = time.time()
        l = self.fetcher.fetch(left_url)
        r = self.fetcher.fetch(right_url)
        if not l.get("ok") or not r.get("ok"):
            return make_report("archive_compare", f"{left_url} <> {right_url}", started, [], [l.get("error", "") or r.get("error", "")]).as_dict()
        lt, rt = l.get("text", ""), r.get("text", "")
        lurls = set(extract_urls_from_text(lt, l.get("final_url") or left_url, keep_secret_query_values=self.cfg.keep_secret_query_values))
        rurls = set(extract_urls_from_text(rt, r.get("final_url") or right_url, keep_secret_query_values=self.cfg.keep_secret_query_values))
        diff = list(difflib.unified_diff(clean_text(lt, 10000).splitlines(), clean_text(rt, 10000).splitlines(), lineterm=""))[:500]
        raw = {"left_only_urls": sorted(lurls - rurls)[:500], "right_only_urls": sorted(rurls - lurls)[:500], "diff_excerpt": diff}
        findings = [Finding("snapshot_diff", json.dumps(raw, ensure_ascii=False), "archive_compare", 0.82)]
        return make_report("archive_compare", f"{left_url} <> {right_url}", started, findings, raw=raw).as_dict()

    def archive_extract_lost_links(self, current_url: str, max_snapshots: int = 5) -> Dict[str, Any]:
        started = time.time()
        cur = self.fetcher.fetch(current_url)
        current_links = set(extract_urls_from_text(cur.get("text", ""), cur.get("final_url") or current_url, keep_secret_query_values=self.cfg.keep_secret_query_values)) if cur.get("ok") else set()
        search = self.archive_search_url(current_url, max_results=max_snapshots)
        findings: List[Finding] = []
        for item in search.get("findings", [])[:max_snapshots]:
            snap = item.get("value", "")
            if not snap:
                continue
            sr = self.fetcher.fetch(snap)
            if not sr.get("ok"):
                continue
            archived_links = set(extract_urls_from_text(sr.get("text", ""), sr.get("final_url") or snap, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=1000))
            for lost in sorted(archived_links - current_links)[:500]:
                findings.append(Finding("lost_link", lost, "archive_minus_current", 0.72, url=snap, extra={"current_url": current_url}))
        return make_report("archive_lost_links", current_url, started, dedupe_findings(findings, self.cfg.max_items), raw={"current_fetch_ok": cur.get("ok", False)}).as_dict()

    def archive_timeline_report(self, url: str, max_results: Optional[int] = None) -> Dict[str, Any]:
        report = self.archive_search_url(url, max_results=max_results)
        timeline: DefaultDict[str, int] = defaultdict(int)
        for f in report.get("findings", []):
            ts = str((f.get("extra") or {}).get("timestamp", ""))
            if len(ts) >= 4:
                timeline[ts[:4]] += 1
        report["raw"]["timeline_by_year"] = dict(sorted(timeline.items()))
        return report


# ---------------------------------------------------------------------------
# OSINTEngine
# ---------------------------------------------------------------------------

class OSINTEngine:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.fetcher = Fetcher(self.cfg)

    def close(self) -> None:
        self.fetcher.close()

    def osint_domain(self, domain: str) -> Dict[str, Any]:
        started = time.time()
        d = registered_domain_guess(host_of(normalize_url(domain)) or domain.split("/")[0])
        findings = []
        findings.extend(self._dns_findings(d))
        findings.extend(self._tls_findings(d))
        rdap = self._rdap_domain(d)
        findings.extend(rdap)
        certs = self.osint_certificates(d).get("findings", [])
        for f in certs[:200]:
            findings.append(Finding(f.get("kind", "certificate"), f.get("value", ""), f.get("source", "crtsh"), f.get("confidence", 0.6), extra=f.get("extra", {})))
        return make_report("osint_domain", d, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def osint_ip(self, ip: str) -> Dict[str, Any]:
        started = time.time()
        findings: List[Finding] = []
        try:
            rev = socket.gethostbyaddr(ip)
            findings.append(Finding("reverse_dns", rev[0], "socket_gethostbyaddr", 0.7, extra={"aliases": rev[1]}))
        except Exception as exc:
            findings.append(Finding("reverse_dns_error", str(exc), "socket_gethostbyaddr", 0.2))
        r = self.fetcher.fetch("https://rdap.org/ip/" + urllib.parse.quote(ip))
        if r.get("ok"):
            data = safe_json_loads(r.get("text", ""))
            findings.append(Finding("rdap_ip", json.dumps(redact_obj(data), ensure_ascii=False)[:3000], "rdap.org", 0.72))
        return make_report("osint_ip", ip, started, findings).as_dict()

    def osint_certificates(self, domain: str, max_results: int = 100) -> Dict[str, Any]:
        started = time.time()
        d = registered_domain_guess(domain)
        findings = []
        live = self._tls_findings(d)
        findings.extend(live)
        crt_url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{d}", "output": "json"})
        r = self.fetcher.fetch(crt_url, max_bytes=1_000_000)
        if r.get("ok"):
            data = safe_json_loads(r.get("text", ""))
            if isinstance(data, list):
                seen = set()
                for row in data[:max_results]:
                    names = str(row.get("name_value", "")).splitlines()
                    for n in names:
                        n = n.strip().lower().lstrip("*.")
                        if n and n not in seen and d in n:
                            seen.add(n)
                            findings.append(Finding("certificate_name", n, "crtsh", 0.72, extra={"issuer": row.get("issuer_name", ""), "not_before": row.get("not_before", ""), "not_after": row.get("not_after", "")}))
        return make_report("osint_certificates", d, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def osint_dns_history(self, domain: str) -> Dict[str, Any]:
        # Public no-key fallback: current DNS + CT names as historical-ish public hints.
        started = time.time()
        d = registered_domain_guess(domain)
        findings = self._dns_findings(d)
        cert_report = self.osint_certificates(d, max_results=200)
        for f in cert_report.get("findings", []):
            if f.get("kind") == "certificate_name":
                findings.append(Finding("dns_history_hint", f.get("value", ""), "certificate_transparency", 0.55, extra=f.get("extra", {})))
        return make_report("osint_dns_history", d, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def osint_public_mentions(self, query: str, max_results: int = 20) -> Dict[str, Any]:
        started = time.time()
        findings: List[Finding] = []
        search_url = "https://duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})
        r = self.fetcher.fetch(search_url, max_bytes=800_000)
        if r.get("ok"):
            for u in extract_urls_from_text(r.get("text", ""), search_url, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=max_results * 4):
                h = host_of(u)
                if h and "duckduckgo" not in h:
                    findings.append(Finding("public_mention", u, "duckduckgo_html", 0.45, context=query))
                    if len(findings) >= max_results:
                        break
        return make_report("osint_public_mentions", query, started, dedupe_findings(findings, max_results)).as_dict()

    def osint_related_domains(self, domain: str) -> Dict[str, Any]:
        started = time.time()
        d = registered_domain_guess(domain)
        findings: List[Finding] = []
        for rep in (self.osint_certificates(d), self.osint_domain(d)):
            for f in rep.get("findings", []):
                val = f.get("value", "")
                h = host_of(normalize_url(val)) or val
                rd = registered_domain_guess(h)
                if rd and rd != d and "." in rd:
                    findings.append(Finding("related_domain", rd, f.get("source", "osint"), 0.5, extra={"from": val}))
                elif h.endswith("." + d) or h == d:
                    findings.append(Finding("related_subdomain", h, f.get("source", "osint"), 0.62, extra={"from": val}))
        return make_report("osint_related_domains", d, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def _dns_findings(self, domain: str) -> List[Finding]:
        findings = []
        try:
            infos = socket.getaddrinfo(domain, None)
            for info in infos:
                sockaddr = info[4]
                if sockaddr:
                    findings.append(Finding("dns_address", str(sockaddr[0]), "socket_getaddrinfo", 0.72, extra={"family": str(info[0])}))
        except Exception as exc:
            findings.append(Finding("dns_error", str(exc), "socket_getaddrinfo", 0.2))
        return findings

    def _tls_findings(self, domain: str) -> List[Finding]:
        findings = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.cfg.timeout_sec) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    findings.append(Finding("tls_certificate", json.dumps(redact_obj(cert), ensure_ascii=False)[:3000], "ssl_getpeercert", 0.78, extra={"cipher": ssock.cipher(), "version": ssock.version()}))
                    for typ, val in cert.get("subjectAltName", []):
                        if typ.lower() == "dns":
                            findings.append(Finding("certificate_name", str(val).lower().lstrip("*."), "live_tls_san", 0.78))
        except Exception as exc:
            findings.append(Finding("tls_error", str(exc), "ssl_getpeercert", 0.2))
        return findings

    def _rdap_domain(self, domain: str) -> List[Finding]:
        r = self.fetcher.fetch("https://rdap.org/domain/" + urllib.parse.quote(domain), max_bytes=500_000)
        if r.get("ok"):
            data = safe_json_loads(r.get("text", ""))
            return [Finding("rdap_domain", json.dumps(redact_obj(data), ensure_ascii=False)[:3000], "rdap.org", 0.72)]
        return []


# ---------------------------------------------------------------------------
# RouteEngine
# ---------------------------------------------------------------------------

class RouteEngine:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.fetcher = Fetcher(self.cfg)

    def close(self) -> None:
        self.fetcher.close()

    def route_extract_from_html(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text, target, errors = self._load_text(text_or_url, base_url)
        findings: List[Finding] = []
        if errors:
            return make_report("route_html", target, started, [], errors).as_dict()
        for u in extract_urls_from_text(text, target, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=self.cfg.max_items):
            p = urllib.parse.urlparse(u).path
            if p and p != "/":
                findings.append(Finding("route_url", u, "html_url", 0.58, url=target))
        for m in ROUTE_STRING_RE.finditer(text):
            route = m.group("route").replace("\\/", "/")
            if likely_route(route):
                findings.append(Finding("route_path", route, "html_route_string", 0.46, url=target))
        findings.extend(self._next_findings(text, target))
        findings.extend(self._nuxt_findings(text, target))
        return make_report("route_html", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def route_extract_from_js(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text, target, errors = self._load_text(text_or_url, base_url)
        findings: List[Finding] = []
        if errors:
            return make_report("route_js", target, started, [], errors).as_dict()
        for m in ROUTE_STRING_RE.finditer(text):
            route = m.group("route").replace("\\/", "/")
            if likely_route(route):
                findings.append(Finding("route_path", route, "js_route_string", 0.58, url=target))
        # Framework patterns.
        patterns = {
            "react_router_path": r"path\s*:\s*['\"]([^'\"]+)['\"]",
            "next_page": r"static/chunks/pages/([^'\"?#]+)",
            "vite_asset": r"assets/([^'\"?#]+\.(?:js|css|png|jpg|webp|svg))",
            "api_endpoint": r"['\"](/api/[^'\"]+)['\"]",
        }
        for name, pat in patterns.items():
            for m in re.finditer(pat, text, re.I):
                val = m.group(1)
                if name == "next_page":
                    val = "/" + val.replace("/index", "").replace(".js", "")
                findings.append(Finding("route_path" if val.startswith("/") else "asset_reference", val, name, 0.62, url=target))
        return make_report("route_js", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def route_extract_nextjs(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        text, target, errors = self._load_text(text_or_url, base_url)
        started = time.time()
        if errors:
            return make_report("route_nextjs", target, started, [], errors).as_dict()
        return make_report("route_nextjs", target, started, dedupe_findings(self._next_findings(text, target), self.cfg.max_items)).as_dict()

    def route_extract_nuxt(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        text, target, errors = self._load_text(text_or_url, base_url)
        started = time.time()
        if errors:
            return make_report("route_nuxt", target, started, [], errors).as_dict()
        return make_report("route_nuxt", target, started, dedupe_findings(self._nuxt_findings(text, target), self.cfg.max_items)).as_dict()

    def route_extract_vite(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text, target, errors = self._load_text(text_or_url, base_url)
        findings: List[Finding] = []
        if errors:
            return make_report("route_vite", target, started, [], errors).as_dict()
        for u in extract_urls_from_text(text, target, keep_secret_query_values=self.cfg.keep_secret_query_values):
            if "/assets/" in u or classify_url(u) in {"script", "stylesheet", "json_manifest"}:
                findings.append(Finding("vite_asset", u, "vite_html_or_manifest", 0.62, url=target))
        data = safe_json_loads(text)
        if isinstance(data, dict):
            for k, v in walk_json(data):
                if isinstance(v, str) and (v.startswith("/") or "/assets/" in v):
                    findings.append(Finding("vite_manifest_entry", normalize_url(v, target) or v, "vite_manifest_json", 0.75, context=".".join(k), url=target))
        return make_report("route_vite", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def route_extract_react_router(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        js_report = self.route_extract_from_js(text_or_url, base_url)
        js_report["engine"] = "route_react_router"
        js_report["elapsed_ms"] = int((time.time() - started) * 1000)
        return js_report

    def route_probe_public_routes(self, base_url: str, routes: Sequence[str], timeout_sec: Optional[int] = None) -> Dict[str, Any]:
        started = time.time()
        old_timeout = self.cfg.timeout_sec
        if timeout_sec:
            self.cfg.timeout_sec = float(timeout_sec)
        findings: List[Finding] = []
        base = normalize_url(base_url)
        base_host = host_of(base)
        for route in list(routes)[: self.cfg.max_items]:
            u = normalize_url(str(route), base)
            if not u:
                continue
            if not self.cfg.allow_cross_host and host_of(u) != base_host:
                continue
            r = self.fetcher.head(u)
            if not r.get("ok") or int(r.get("status_code") or 0) in {405, 0}:
                r = self.fetcher.fetch(u, max_bytes=4096)
            status = int(r.get("status_code") or 0) if r.get("ok") else 0
            findings.append(Finding("route_probe", u, "head_get_probe", 0.75 if status and status < 400 else 0.35, extra={"status_code": status, "content_type": (r.get("headers") or {}).get("content-type") or (r.get("headers") or {}).get("Content-Type"), "ok": r.get("ok", False)}))
            if self.cfg.rate_limit_delay_sec:
                time.sleep(self.cfg.rate_limit_delay_sec)
        self.cfg.timeout_sec = old_timeout
        return make_report("route_probe", base_url, started, findings).as_dict()

    def _load_text(self, text_or_url: str, base_url: str = "") -> Tuple[str, str, List[str]]:
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return "", text_or_url, [r.get("error", "fetch failed")]
            return r.get("text", ""), r.get("final_url") or text_or_url, []
        return text_or_url or "", base_url or "pasted-text", []

    def _next_findings(self, text: str, target: str) -> List[Finding]:
        findings = []
        m = re.search(r"(?is)<script[^>]+id=['\"]__NEXT_DATA__['\"][^>]*>(.*?)</script>", text)
        if m:
            data = safe_json_loads(html.unescape(m.group(1)))
            for path, val in walk_json(data):
                key = ".".join(path)
                if isinstance(val, str) and (val.startswith("/") or "/_next/" in val):
                    findings.append(Finding("nextjs_route_or_asset", normalize_url(val, target) or val, "__NEXT_DATA__", 0.78, context=key, url=target))
        for m in re.finditer(r"/_next/static/[^'\"\s<>]+", text):
            findings.append(Finding("nextjs_asset", normalize_url(m.group(0), target) or m.group(0), "next_static_ref", 0.72, url=target))
        return findings

    def _nuxt_findings(self, text: str, target: str) -> List[Finding]:
        findings = []
        for m in re.finditer(r"(?is)<script[^>]*>\s*window\.__NUXT__\s*=\s*(.*?)</script>", text):
            blob = m.group(1)
            for route_m in ROUTE_STRING_RE.finditer(blob):
                route = route_m.group("route")
                if likely_route(route):
                    findings.append(Finding("nuxt_route", route, "__NUXT__", 0.74, url=target))
        for m in re.finditer(r"/_nuxt/[^'\"\s<>]+", text):
            findings.append(Finding("nuxt_asset", normalize_url(m.group(0), target) or m.group(0), "nuxt_asset_ref", 0.72, url=target))
        return findings


# ---------------------------------------------------------------------------
# MediaEngine
# ---------------------------------------------------------------------------

class MediaEngine:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.fetcher = Fetcher(self.cfg)
        self.manifest_engine = ManifestEngine(self.cfg)
        self.metadata_engine = MetadataEngine(self.cfg)

    def close(self) -> None:
        self.fetcher.close(); self.manifest_engine.close(); self.metadata_engine.close()

    def media_find(self, url: str) -> Dict[str, Any]:
        started = time.time()
        r = self.fetcher.fetch(url)
        if not r.get("ok"):
            return make_report("media", url, started, [], [r.get("error", "fetch failed")]).as_dict()
        base = r.get("final_url") or url
        text = r.get("text", "")
        findings: List[Finding] = []
        for u in extract_urls_from_text(text, base, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=self.cfg.max_items):
            k = classify_url(u)
            if k in {"image", "video", "audio", "video_manifest"}:
                findings.append(Finding(k, u, "page_media_url", 0.65, url=base))
        # Posters, OG, Twitter images, thumbnails.
        findings.extend([Finding("thumbnail", f.get("value", ""), f.get("source", "metadata"), f.get("confidence", 0.6), context=f.get("context", ""), url=base) for f in self.media_extract_thumbnails(base).get("findings", [])])
        # Parse directly referenced manifests.
        for f in list(findings):
            if f.kind == "video_manifest":
                sub = self.media_extract_hls(f.value) if f.value.lower().endswith(".m3u8") else self.media_extract_dash(f.value)
                for sf in sub.get("findings", []):
                    findings.append(Finding(sf.get("kind", "media_asset"), sf.get("value", ""), sf.get("source", "manifest"), sf.get("confidence", 0.5), url=f.value, extra=sf.get("extra", {})))
        return make_report("media", url, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def media_extract_hls(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        report = self.manifest_engine.manifest_parse_hls(text_or_url, base_url)
        report["engine"] = "media_hls"
        return report

    def media_extract_dash(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        report = self.manifest_engine.manifest_parse_dash(text_or_url, base_url)
        report["engine"] = "media_dash"
        return report

    def media_extract_subtitles(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text = text_or_url
        target = base_url or "pasted-media"
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return make_report("media_subtitles", text_or_url, started, [], [r.get("error", "fetch failed")]).as_dict()
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
            base_url = target
        findings = []
        for u in extract_urls_from_text(text, base_url, keep_secret_query_values=self.cfg.keep_secret_query_values):
            if urllib.parse.urlparse(u).path.lower().endswith((".vtt", ".srt", ".ttml", ".dfxp")):
                findings.append(Finding("subtitle", u, "subtitle_url", 0.82, url=target))
        return make_report("media_subtitles", target, started, findings).as_dict()

    def media_extract_thumbnails(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text = text_or_url
        target = base_url or "pasted-media"
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return make_report("media_thumbnails", text_or_url, started, [], [r.get("error", "fetch failed")]).as_dict()
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
            base_url = target
        findings = []
        for m in re.finditer(r"(?is)<meta\b([^>]+)>", text):
            tag = m.group(0)
            name = (attr_value(tag, "property") or attr_value(tag, "name") or "").lower()
            content = attr_value(tag, "content")
            if content and any(x in name for x in ("image", "thumbnail", "og:video:image", "twitter:image")):
                u = normalize_url(content, base_url)
                if u:
                    findings.append(Finding("thumbnail", u, "html_meta_thumbnail", 0.78, context=name, url=target))
        for m in re.finditer(r"(?is)<video\b([^>]*)>", text):
            poster = attr_value(m.group(0), "poster")
            if poster:
                u = normalize_url(poster, base_url)
                if u:
                    findings.append(Finding("thumbnail", u, "video_poster", 0.82, url=target))
        return make_report("media_thumbnails", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def media_probe_dimensions(self, url: str) -> Dict[str, Any]:
        return self.metadata_engine.metadata_image(url)

    def media_rank_best_sources(self, media_items: Sequence[Any]) -> Dict[str, Any]:
        started = time.time()
        findings: List[Finding] = []
        for item in media_items:
            u = item.get("url") if isinstance(item, dict) else str(item)
            score = media_score(u, item if isinstance(item, dict) else {})
            findings.append(Finding("ranked_media", u, "media_ranker", score, extra={"score": score, "kind": classify_url(u)}))
        findings.sort(key=lambda f: f.confidence, reverse=True)
        return make_report("media_rank", "media_items", started, findings).as_dict()


# ---------------------------------------------------------------------------
# EntityEngine
# ---------------------------------------------------------------------------

class EntityEngine:
    def __init__(self, cfg: Optional[EngineConfig] = None):
        self.cfg = cfg or EngineConfig()
        self.fetcher = Fetcher(self.cfg)
        self.metadata_engine = MetadataEngine(self.cfg)
        self.archive_engine = ArchiveEngine(self.cfg)

    def close(self) -> None:
        self.fetcher.close(); self.metadata_engine.close(); self.archive_engine.close()

    def entity_extract(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text = text_or_url
        target = base_url or "pasted-entity-text"
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return make_report("entity", text_or_url, started, [], [r.get("error", "fetch failed")]).as_dict()
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
            base_url = target
        findings: List[Finding] = []
        # Structured metadata first.
        for m in re.finditer(r"(?is)<script[^>]+type=['\"]application/ld\+json['\"][^>]*>(.*?)</script>", text):
            data = safe_json_loads(html.unescape(m.group(1)))
            for path, val in walk_json(data):
                key = ".".join(path).lower()
                if key.endswith("name") or key.endswith("brand") or key.endswith("manufacturer") or key.endswith("author") or key.endswith("location"):
                    if isinstance(val, str) and 2 <= len(val) <= 120:
                        findings.append(Finding(entity_kind_from_path(key), clean_text(val, 160), "json_ld_entity", 0.78, context=key, url=target))
        # Meta title/site/product hints.
        for m in re.finditer(r"(?is)<meta\b([^>]+)>", text):
            tag = m.group(0)
            name = (attr_value(tag, "property") or attr_value(tag, "name") or attr_value(tag, "itemprop") or "").lower()
            content = attr_value(tag, "content")
            if content and any(x in name for x in ("site_name", "title", "brand", "product", "author", "creator", "article:author", "place", "locality")):
                findings.append(Finding(entity_kind_from_path(name), clean_text(content, 160), "html_meta_entity", 0.65, context=name, url=target))
        # Heuristic capitalized names/brands/products.
        visible = clean_text(text, self.cfg.max_text_chars)
        counts = Counter()
        for m in CAPITALIZED_PHRASE_RE.finditer(visible):
            phrase = clean_text(m.group(0), 120).strip()
            if is_probable_entity(phrase):
                counts[phrase] += 1
        for phrase, count in counts.most_common(200):
            findings.append(Finding("entity_candidate", phrase, "capitalized_phrase", min(0.35 + count / 20.0, 0.72), url=target, extra={"mentions": count}))
        for email_addr in EMAIL_RE.findall(text):
            findings.append(Finding("email_reference", "<redacted-email-domain:" + email_addr.split("@")[-1].lower() + ">", "email_reference_redacted", 0.4, url=target))
        return make_report("entity", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def entity_link_urls(self, text_or_url: str, entities: Optional[Sequence[str]] = None, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        text = text_or_url
        target = base_url or "pasted-entity-url-text"
        if normalize_url(text_or_url):
            r = self.fetcher.fetch(text_or_url)
            if not r.get("ok"):
                return make_report("entity_link_urls", text_or_url, started, [], [r.get("error", "fetch failed")]).as_dict()
            text = r.get("text", "")
            target = r.get("final_url") or text_or_url
            base_url = target
        if not entities:
            ent_report = self.entity_extract(text, base_url)
            entities = [f.get("value", "") for f in ent_report.get("findings", []) if f.get("kind", "").startswith("entity")][:50]
        urls = extract_urls_from_text(text, base_url, keep_secret_query_values=self.cfg.keep_secret_query_values, max_urls=self.cfg.max_items)
        findings: List[Finding] = []
        low_text = text.lower()
        for ent in entities or []:
            if not ent:
                continue
            slug = slugify(ent)
            for u in urls:
                score = 0.0
                if slug and slug in slugify(u):
                    score += 0.55
                idx = low_text.find(ent.lower())
                if idx >= 0:
                    pos = low_text.find(u.lower()[:60])
                    if pos >= 0 and abs(pos - idx) < 1200:
                        score += 0.25
                if score > 0:
                    findings.append(Finding("entity_url_link", u, "entity_url_context", min(score, 0.9), context=ent, url=target, extra={"entity": ent}))
        return make_report("entity_link_urls", target, started, dedupe_findings(findings, self.cfg.max_items)).as_dict()

    def entity_timeline(self, text_or_url: str, entity: str = "", base_url: str = "", include_archives: bool = False) -> Dict[str, Any]:
        started = time.time()
        link_report = self.entity_link_urls(text_or_url, [entity] if entity else None, base_url)
        findings: List[Finding] = []
        for f in link_report.get("findings", []):
            u = f.get("value", "")
            dates = DATE_RE.findall(u) or DATE_RE.findall(f.get("context", ""))
            for d in dates:
                findings.append(Finding("entity_timeline_event", u, "url_date", 0.55, context=d, extra={"entity": entity}))
        if include_archives and normalize_url(text_or_url):
            ar = self.archive_engine.archive_timeline_report(text_or_url)
            for year, count in (ar.get("raw", {}).get("timeline_by_year", {}) or {}).items():
                findings.append(Finding("archive_timeline_year", str(count), "archive_timeline", 0.62, context=year, extra={"entity": entity}))
        return make_report("entity_timeline", entity or text_or_url, started, findings).as_dict()

    def entity_cluster(self, text_or_url: str, base_url: str = "") -> Dict[str, Any]:
        started = time.time()
        rep = self.entity_extract(text_or_url, base_url)
        clusters: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in rep.get("findings", []):
            val = f.get("value", "")
            key = slugify(val)[:64]
            if key:
                clusters[key].append(f)
        findings = []
        for key, rows in clusters.items():
            best = max(rows, key=lambda r: r.get("confidence", 0))
            findings.append(Finding("entity_cluster", best.get("value", key), "entity_cluster", best.get("confidence", 0.5), extra={"cluster_key": key, "count": len(rows), "kinds": sorted({r.get("kind", "") for r in rows})}))
        return make_report("entity_cluster", base_url or "entity-text", started, findings, raw={"clusters": {k: len(v) for k, v in clusters.items()}}).as_dict()

    def entity_report(self, text_or_url: str, base_url: str = "", include_archives: bool = False) -> Dict[str, Any]:
        started = time.time()
        extraction = self.entity_extract(text_or_url, base_url)
        links = self.entity_link_urls(text_or_url, base_url=base_url)
        clusters = self.entity_cluster(text_or_url, base_url)
        findings: List[Finding] = []
        for source_name, rep in [("extract", extraction), ("links", links), ("clusters", clusters)]:
            for f in rep.get("findings", []):
                findings.append(Finding(f.get("kind", "entity"), f.get("value", ""), f"entity_{source_name}", f.get("confidence", 0.5), context=f.get("context", ""), url=f.get("url", ""), extra=f.get("extra", {})))
        raw = {"extract_summary": extraction.get("summary"), "link_summary": links.get("summary"), "cluster_summary": clusters.get("summary")}
        if include_archives and normalize_url(text_or_url):
            raw["archive_timeline"] = self.archive_engine.archive_timeline_report(text_or_url).get("raw", {}).get("timeline_by_year", {})
        return make_report("entity_report", base_url or text_or_url[:120], started, dedupe_findings(findings, self.cfg.max_items), raw=raw).as_dict()


# ---------------------------------------------------------------------------
# Helper parsing functions
# ---------------------------------------------------------------------------

def attr_value(tag: str, attr: str) -> str:
    m = re.search(r"(?is)\b" + re.escape(attr) + r"\s*=\s*(['\"])(.*?)\1", tag or "")
    return html.unescape(m.group(2).strip()) if m else ""


def safe_json_loads(text: str) -> Any:
    try:
        return json.loads(text or "")
    except Exception:
        return None


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            ks = str(k)
            if SECRET_KEY_RE.search(ks):
                out[ks] = "<redacted>"
            else:
                out[ks] = redact_obj(v)
        return out
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj[:500]]
    if isinstance(obj, str):
        if SECRET_KEY_RE.search(obj[:80]) and len(obj) > 12:
            return "<redacted>"
        return redacted_url(obj)
    return obj


def walk_json(obj: Any, path: Optional[List[str]] = None) -> Iterable[Tuple[List[str], Any]]:
    path = path or []
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_json(v, path + [str(k)])
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:1000]):
            yield from walk_json(v, path + [str(i)])


def extract_title(text: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text or "")
    return clean_text(m.group(1), 300) if m else ""


def likely_route(route: str) -> bool:
    if not route or not route.startswith("/"):
        return False
    if route.startswith("//"):
        return False
    if len(route) > 250:
        return False
    bad_prefixes = ("/static/", "/assets/", "/images/", "/img/", "/css/", "/js/", "/_next/static/")
    if route.lower().startswith(bad_prefixes):
        return False
    if os.path.splitext(urllib.parse.urlparse(route).path)[1].lower() in MEDIA_EXTENSIONS | DOCUMENT_EXTENSIONS | {".js", ".css", ".map"}:
        return False
    return bool(re.search(r"[A-Za-z0-9]", route))


def media_score(url: str, meta: Dict[str, Any]) -> float:
    u = url.lower()
    score = 0.2
    if u.endswith(".mpd") or u.endswith(".m3u8"):
        score += 0.35
    if any(x in u for x in ("1080", "2160", "4k", "master", "source", "original")):
        score += 0.25
    if any(x in u for x in ("thumb", "poster", "preview", "sprite")):
        score -= 0.1
    if is_cdn_host(host_of(u)):
        score += 0.1
    for k in ("width", "height", "bitrate"):
        try:
            if int(meta.get(k, 0)) > 0:
                score += min(int(meta[k]) / 10000, 0.15)
        except Exception:
            pass
    return max(0.0, min(score, 1.0))


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")


def is_probable_entity(phrase: str) -> bool:
    p = (phrase or "").strip()
    if len(p) < 3 or len(p) > 80:
        return False
    low = p.lower()
    stop = {"the", "and", "home", "login", "privacy policy", "terms", "copyright", "all rights", "javascript"}
    if low in stop:
        return False
    if re.fullmatch(r"[A-Z\s]+", p) and len(p) < 5:
        return False
    return True


def entity_kind_from_path(path: str) -> str:
    p = path.lower()
    if "brand" in p or "manufacturer" in p:
        return "brand"
    if "product" in p or "sku" in p or "model" in p:
        return "product"
    if "author" in p or "creator" in p or "person" in p:
        return "person"
    if "place" in p or "location" in p or "locality" in p or "address" in p:
        return "place"
    return "entity"


# ---------------------------------------------------------------------------
# Module-level helper constructors
# ---------------------------------------------------------------------------

def _cfg(**kwargs: Any) -> EngineConfig:
    cfg = EngineConfig()
    for k, v in kwargs.items():
        if hasattr(cfg, k) and v is not None:
            setattr(cfg, k, v)
    return cfg


# Archive public functions

def archive_search_url(url: str, max_results: int = 80, timeout_sec: int = 20) -> Dict[str, Any]:
    e = ArchiveEngine(_cfg(max_archive_results=max_results, timeout_sec=timeout_sec))
    try: return e.archive_search_url(url, max_results=max_results)
    finally: e.close()


def archive_search_domain(domain: str, max_results: int = 80, timeout_sec: int = 20) -> Dict[str, Any]:
    e = ArchiveEngine(_cfg(max_archive_results=max_results, timeout_sec=timeout_sec))
    try: return e.archive_search_domain(domain, max_results=max_results)
    finally: e.close()


def archive_fetch_wayback_snapshot(url: str, timestamp: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = ArchiveEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.archive_fetch_wayback_snapshot(url, timestamp=timestamp)
    finally: e.close()


def archive_compare_snapshots(left_url: str, right_url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = ArchiveEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.archive_compare_snapshots(left_url, right_url)
    finally: e.close()


def archive_extract_lost_links(current_url: str, max_snapshots: int = 5, timeout_sec: int = 20) -> Dict[str, Any]:
    e = ArchiveEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.archive_extract_lost_links(current_url, max_snapshots=max_snapshots)
    finally: e.close()


def archive_timeline_report(url: str, max_results: int = 80, timeout_sec: int = 20) -> Dict[str, Any]:
    e = ArchiveEngine(_cfg(max_archive_results=max_results, timeout_sec=timeout_sec))
    try: return e.archive_timeline_report(url, max_results=max_results)
    finally: e.close()


# Source map public functions

def sourcemap_find(url: str, include_guesses: bool = True, timeout_sec: int = 20) -> Dict[str, Any]:
    e = SourceMapEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.sourcemap_find(url, include_guesses=include_guesses)
    finally: e.close()


def sourcemap_fetch(url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = SourceMapEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.sourcemap_fetch(url)
    finally: e.close()


def sourcemap_extract_sources(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = SourceMapEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.sourcemap_extract_sources(text_or_url, base_url)
    finally: e.close()


def sourcemap_extract_urls(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = SourceMapEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.sourcemap_extract_urls(text_or_url, base_url)
    finally: e.close()


def sourcemap_reconstruct_tree(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = SourceMapEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.sourcemap_reconstruct_tree(text_or_url, base_url)
    finally: e.close()


def sourcemap_secret_redacted_scan(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = SourceMapEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.sourcemap_secret_redacted_scan(text_or_url, base_url)
    finally: e.close()


# Metadata public functions

def metadata_url(url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = MetadataEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.metadata_url(url)
    finally: e.close()


def metadata_file(path: str) -> Dict[str, Any]:
    e = MetadataEngine(_cfg())
    try: return e.metadata_file(path)
    finally: e.close()


def metadata_image(path_or_url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = MetadataEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.metadata_image(path_or_url)
    finally: e.close()


def metadata_video(path_or_url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = MetadataEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.metadata_video(path_or_url)
    finally: e.close()


def metadata_pdf(path_or_url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = MetadataEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.metadata_pdf(path_or_url)
    finally: e.close()


def metadata_compare(left: str, right: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = MetadataEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.metadata_compare(left, right)
    finally: e.close()


def metadata_redacted_report(target: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = MetadataEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.metadata_redacted_report(target)
    finally: e.close()


# OSINT public functions

def osint_domain(domain: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = OSINTEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.osint_domain(domain)
    finally: e.close()


def osint_ip(ip: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = OSINTEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.osint_ip(ip)
    finally: e.close()


def osint_certificates(domain: str, max_results: int = 100, timeout_sec: int = 20) -> Dict[str, Any]:
    e = OSINTEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.osint_certificates(domain, max_results=max_results)
    finally: e.close()


def osint_dns_history(domain: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = OSINTEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.osint_dns_history(domain)
    finally: e.close()


def osint_public_mentions(query: str, max_results: int = 20, timeout_sec: int = 20) -> Dict[str, Any]:
    e = OSINTEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.osint_public_mentions(query, max_results=max_results)
    finally: e.close()


def osint_related_domains(domain: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = OSINTEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.osint_related_domains(domain)
    finally: e.close()


# Manifest public functions

def manifest_find(url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = ManifestEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.manifest_find(url)
    finally: e.close()


def manifest_parse_webapp(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = ManifestEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.manifest_parse_webapp(text_or_url, base_url)
    finally: e.close()


def manifest_parse_hls(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = ManifestEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.manifest_parse_hls(text_or_url, base_url)
    finally: e.close()


def manifest_parse_dash(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = ManifestEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.manifest_parse_dash(text_or_url, base_url)
    finally: e.close()


def manifest_parse_rss(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = ManifestEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.manifest_parse_rss(text_or_url, base_url)
    finally: e.close()


def manifest_parse_atom(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = ManifestEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.manifest_parse_atom(text_or_url, base_url)
    finally: e.close()


def manifest_extract_assets(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = ManifestEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.manifest_extract_assets(text_or_url, base_url)
    finally: e.close()


# Route public functions

def route_extract_from_html(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = RouteEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.route_extract_from_html(text_or_url, base_url)
    finally: e.close()


def route_extract_from_js(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = RouteEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.route_extract_from_js(text_or_url, base_url)
    finally: e.close()


def route_extract_nextjs(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = RouteEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.route_extract_nextjs(text_or_url, base_url)
    finally: e.close()


def route_extract_nuxt(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = RouteEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.route_extract_nuxt(text_or_url, base_url)
    finally: e.close()


def route_extract_vite(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = RouteEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.route_extract_vite(text_or_url, base_url)
    finally: e.close()


def route_extract_react_router(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = RouteEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.route_extract_react_router(text_or_url, base_url)
    finally: e.close()


def route_probe_public_routes(base_url: str, routes: Sequence[str], timeout_sec: int = 20) -> Dict[str, Any]:
    e = RouteEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.route_probe_public_routes(base_url, routes, timeout_sec=timeout_sec)
    finally: e.close()


# Media public functions

def media_find(url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = MediaEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.media_find(url)
    finally: e.close()


def media_extract_hls(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = MediaEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.media_extract_hls(text_or_url, base_url)
    finally: e.close()


def media_extract_dash(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = MediaEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.media_extract_dash(text_or_url, base_url)
    finally: e.close()


def media_extract_subtitles(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = MediaEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.media_extract_subtitles(text_or_url, base_url)
    finally: e.close()


def media_extract_thumbnails(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = MediaEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.media_extract_thumbnails(text_or_url, base_url)
    finally: e.close()


def media_probe_dimensions(url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    e = MediaEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.media_probe_dimensions(url)
    finally: e.close()


def media_rank_best_sources(media_items: Sequence[Any]) -> Dict[str, Any]:
    e = MediaEngine(_cfg())
    try: return e.media_rank_best_sources(media_items)
    finally: e.close()


# Entity public functions

def entity_extract(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = EntityEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.entity_extract(text_or_url, base_url)
    finally: e.close()


def entity_link_urls(text_or_url: str, entities: Optional[Sequence[str]] = None, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = EntityEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.entity_link_urls(text_or_url, entities, base_url)
    finally: e.close()


def entity_timeline(text_or_url: str, entity: str = "", base_url: str = "", include_archives: bool = False, timeout_sec: int = 20) -> Dict[str, Any]:
    e = EntityEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.entity_timeline(text_or_url, entity, base_url, include_archives)
    finally: e.close()


def entity_cluster(text_or_url: str, base_url: str = "", timeout_sec: int = 20) -> Dict[str, Any]:
    e = EntityEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.entity_cluster(text_or_url, base_url)
    finally: e.close()


def entity_report(text_or_url: str, base_url: str = "", include_archives: bool = False, timeout_sec: int = 20) -> Dict[str, Any]:
    e = EntityEngine(_cfg(timeout_sec=timeout_sec))
    try: return e.entity_report(text_or_url, base_url, include_archives)
    finally: e.close()


ALL_ENGINE_FUNCTIONS = [
    "archive_search_url", "archive_search_domain", "archive_fetch_wayback_snapshot", "archive_compare_snapshots", "archive_extract_lost_links", "archive_timeline_report",
    "sourcemap_find", "sourcemap_fetch", "sourcemap_extract_sources", "sourcemap_extract_urls", "sourcemap_reconstruct_tree", "sourcemap_secret_redacted_scan",
    "metadata_url", "metadata_file", "metadata_image", "metadata_video", "metadata_pdf", "metadata_compare", "metadata_redacted_report",
    "osint_domain", "osint_ip", "osint_certificates", "osint_dns_history", "osint_public_mentions", "osint_related_domains",
    "manifest_find", "manifest_parse_webapp", "manifest_parse_hls", "manifest_parse_dash", "manifest_parse_rss", "manifest_parse_atom", "manifest_extract_assets",
    "route_extract_from_html", "route_extract_from_js", "route_extract_nextjs", "route_extract_nuxt", "route_extract_vite", "route_extract_react_router", "route_probe_public_routes",
    "media_find", "media_extract_hls", "media_extract_dash", "media_extract_subtitles", "media_extract_thumbnails", "media_probe_dimensions", "media_rank_best_sources",
    "entity_extract", "entity_link_urls", "entity_timeline", "entity_cluster", "entity_report",
]


def engines_status() -> Dict[str, Any]:
    return {
        "ok": True,
        "module": "engines.py",
        "function_count": len(ALL_ENGINE_FUNCTIONS),
        "functions": ALL_ENGINE_FUNCTIONS,
        "optional_dependencies": {
            "requests": requests is not None,
            "Pillow": optional_import_available("PIL"),
            "pypdf": optional_import_available("pypdf"),
        },
        "safety": "Public/authorized discovery only. No login/paywall/ACL/signed-URL bypass. Secret-like values redacted by default.",
    }


def optional_import_available(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Standalone PromptChat discovery engines")
    parser.add_argument("engine", nargs="?", default="status", help="status, manifest_find, route_extract_from_js, entity_extract, metadata_url, archive_search_url, media_find, osint_domain, sourcemap_find")
    parser.add_argument("target", nargs="?", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    if args.engine == "status":
        result = engines_status()
    else:
        fn = globals().get(args.engine)
        if not callable(fn):
            raise SystemExit(f"Unknown engine function {args.engine}. Try status.")
        if args.engine.startswith(("route_extract", "entity_", "manifest_parse", "media_extract", "sourcemap_extract", "sourcemap_reconstruct", "sourcemap_secret")):
            result = fn(args.target, base_url=args.base_url)  # type: ignore[misc]
        else:
            result = fn(args.target)  # type: ignore[misc]
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
