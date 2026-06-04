from __future__ import annotations

"""
sniffer_engine.py

Shared PromptChat asset sniffer for links, videos, audio, images, manifests, JSON,
runtime/browser network responses, and pasted HTML/text.

Drop this next to tools.py.  The tools rewrite imports this engine so every web,
link, media, image, and reverse-image workflow uses one common extraction,
classification, dedupe, and verification layer.

Design goals:
- Pure requests/static HTML path works without Playwright.
- Optional Playwright path captures network responses, redirects, MSE-ish media,
  and JavaScript-rendered assets when playwright is installed.
- Safe defaults: no credential stealing, no cookie dumping, no secret query values
  emitted unless you explicitly choose to keep them.
"""

import asyncio
import hashlib
import html
import json
import mimetypes
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urldefrag, urljoin, urlparse, urlunparse

import requests


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 PromptChatSniffer/2.0"
)

VOLATILE_QUERY_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "gclid", "dclid", "gbraid", "wbraid", "fbclid", "msclkid", "ttclid", "twclid",
    "yclid", "mc_cid", "mc_eid", "ref", "referrer", "spm",
}

SIGNED_QUERY_HINTS = {
    "token", "auth", "authorization", "sig", "signature", "expires", "expire", "exp",
    "policy", "key-pair-id", "x-amz-", "x-goog-", "x-ms-", "hdnts", "hmac", "session",
    "sess", "psid", "key",
}


@dataclass
class SnifferConfig:
    timeout_sec: float = 20.0
    max_page_chars: int = 500_000
    max_text_chars: int = 25_000
    max_items: int = 400
    max_json_hits: int = 160
    max_manifest_derived: int = 250
    max_probe_items: int = 80
    max_probe_bytes: int = 4096
    verify_assets: bool = True
    use_range_probe: bool = True
    follow_redirects: bool = True
    allow_insecure_tls: bool = False

    # Browser/runtime path.
    use_playwright: bool = False
    playwright_headless: bool = True
    playwright_wait_until: str = "domcontentloaded"
    playwright_channel: str = ""
    playwright_proxy: Optional[Dict[str, Any]] = None
    playwright_launch_args: List[str] = field(default_factory=lambda: [
        "--disable-quic",
        "--disable-http3",
        "--disable-features=UseDnsHttpsSvcb",
    ])
    enable_auto_scroll: bool = True
    max_scroll_steps: int = 12
    scroll_delay_ms: int = 250

    # Filtering / classification.
    keep_signed_query_values: bool = False
    keep_tracking_query_values: bool = False
    include_junk: bool = False
    host_allow_substrings: Set[str] = field(default_factory=set)
    host_deny_substrings: Set[str] = field(default_factory=set)

    video_extensions: Set[str] = field(default_factory=lambda: {
        ".mp4", ".webm", ".mkv", ".mov", ".avi", ".flv", ".wmv", ".m3u8", ".mpd",
        ".ts", ".3gp", ".m4v", ".f4v", ".ogv", ".m4s", ".ism", ".ismv",
    })
    audio_extensions: Set[str] = field(default_factory=lambda: {
        ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".wav", ".weba", ".alac",
        ".aiff", ".wma", ".mid", ".midi",
    })
    image_extensions: Set[str] = field(default_factory=lambda: {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".avif", ".heic",
        ".heif", ".tiff", ".ico",
    })
    document_extensions: Set[str] = field(default_factory=lambda: {
        ".pdf", ".txt", ".csv", ".json", ".xml", ".rss", ".atom", ".md", ".zip",
    })
    junk_extensions: Set[str] = field(default_factory=lambda: {
        ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".vtt",
        ".srt",
    })

    video_mime_prefixes: Set[str] = field(default_factory=lambda: {"video/"})
    audio_mime_prefixes: Set[str] = field(default_factory=lambda: {"audio/"})
    image_mime_prefixes: Set[str] = field(default_factory=lambda: {"image/"})
    hls_mime_types: Set[str] = field(default_factory=lambda: {
        "application/x-mpegurl", "application/vnd.apple.mpegurl", "audio/mpegurl",
    })
    dash_mime_types: Set[str] = field(default_factory=lambda: {
        "application/dash+xml", "application/vnd.mpeg.dash.mpd",
    })
    json_mime_types: Set[str] = field(default_factory=lambda: {
        "application/json", "text/json", "application/ld+json",
        "application/problem+json", "application/vnd.api+json",
    })

    media_url_hints: Set[str] = field(default_factory=lambda: {
        "videoplayback", "manifest", "master.m3u8", "chunklist.m3u8", "playlist",
        "dash", "hls", "stream", "cdn", "segment", "/seg/", "/segments/", "frag",
        "m4s", "bytestream", "media", "audio", "video", "download",
    })


@dataclass
class SniffItem:
    url: str
    kind: str = "link"  # link|video|audio|image|manifest|json|document|script|style|unknown
    tag: str = "asset"
    source: str = "static"
    text: str = ""
    content_type: str = ""
    size: str = ""
    status: str = ""
    final_url: str = ""
    referer: str = ""
    derived_from: str = ""
    evidence: str = ""
    score: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in ("", None, [], {})}


@dataclass
class SniffResult:
    ok: bool
    url: str = ""
    final_url: str = ""
    mode: str = "static"
    title: str = ""
    description: str = ""
    text: str = ""
    html: str = ""
    items: List[SniffItem] = field(default_factory=list)
    json_hits: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    log: List[str] = field(default_factory=list)
    elapsed_ms: int = 0

    def by_kind(self, *kinds: str) -> List[Dict[str, Any]]:
        wanted = set(kinds)
        return [x.as_dict() for x in self.items if x.kind in wanted]

    def as_dict(self, *, include_html: bool = False) -> Dict[str, Any]:
        links = [x.as_dict() for x in self.items if x.kind == "link"]
        videos = [x.as_dict() for x in self.items if x.kind in {"video", "manifest"}]
        audio = [x.as_dict() for x in self.items if x.kind == "audio"]
        images = [x.as_dict() for x in self.items if x.kind == "image"]
        docs = [x.as_dict() for x in self.items if x.kind == "document"]
        data = {
            "ok": self.ok,
            "mode": self.mode,
            "url": self.url,
            "final_url": self.final_url,
            "title": self.title,
            "description": self.description,
            "text": self.text,
            "count": len(self.items),
            "links_count": len(links),
            "videos_count": len(videos),
            "audio_count": len(audio),
            "images_count": len(images),
            "documents_count": len(docs),
            "items": [x.as_dict() for x in self.items],
            "links": links,
            "videos": videos,
            "audio": audio,
            "images": images,
            "documents": docs,
            "json_hits": self.json_hits,
            "errors": self.errors,
            "log": self.log,
            "elapsed_ms": self.elapsed_ms,
        }
        if include_html:
            data["html"] = self.html
        return data


class SnifferEngine:
    def __init__(
        self,
        config: Optional[SnifferConfig] = None,
        *,
        session: Optional[requests.Session] = None,
        logger: Any = None,
    ) -> None:
        self.cfg = config or SnifferConfig()
        self.session = session or self._make_session()
        self.logger = logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def sniff_text(
        self,
        text: str,
        *,
        base_url: str = "",
        include_html: bool = False,
    ) -> SniffResult:
        started = time.time()
        log: List[str] = []
        html_text = text or ""
        items: List[SniffItem] = []

        self._collect_static_assets(
            html_text,
            base_url=base_url,
            items=items,
            source="text",
            log=log,
        )

        if base_url:
            for item in items:
                item.referer = base_url

        items = self._rank_dedupe(items)
        title = self._extract_title(html_text)
        desc = self._extract_meta_description(html_text)
        plain = self._clean_html_to_text(html_text)[: self.cfg.max_text_chars]

        return SniffResult(
            ok=True,
            url=base_url,
            final_url=base_url,
            mode="text",
            title=title,
            description=desc,
            text=plain,
            html=html_text if include_html else "",
            items=items,
            json_hits=self._mine_jsonish_text(html_text, base_url=base_url, log=log),
            log=log,
            elapsed_ms=int((time.time() - started) * 1000),
        )

    def sniff_url(
        self,
        url: str,
        *,
        timeout_sec: Optional[float] = None,
        max_items: Optional[int] = None,
        include_html: bool = False,
        tor_socks_url: Optional[str] = None,
        use_playwright: Optional[bool] = None,
    ) -> SniffResult:
        if use_playwright if use_playwright is not None else self.cfg.use_playwright:
            return asyncio.run(
                self.sniff_url_async(
                    url,
                    timeout_sec=timeout_sec,
                    max_items=max_items,
                    include_html=include_html,
                    tor_socks_url=tor_socks_url,
                )
            )
        return self._sniff_url_static(
            url,
            timeout_sec=timeout_sec,
            max_items=max_items,
            include_html=include_html,
            tor_socks_url=tor_socks_url,
        )

    async def sniff_url_async(
        self,
        url: str,
        *,
        timeout_sec: Optional[float] = None,
        max_items: Optional[int] = None,
        include_html: bool = False,
        tor_socks_url: Optional[str] = None,
    ) -> SniffResult:
        """
        Playwright network sniffer. Falls back to static requests when Playwright is
        missing or navigation fails.
        """
        started = time.time()
        log: List[str] = []
        page_url = self._normalize_url(url)
        tmo = float(timeout_sec or self.cfg.timeout_sec)
        limit = int(max_items or self.cfg.max_items)

        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception as exc:
            log.append(f"playwright unavailable: {exc}; falling back to static")
            res = self._sniff_url_static(
                page_url,
                timeout_sec=tmo,
                max_items=limit,
                include_html=include_html,
                tor_socks_url=tor_socks_url,
            )
            res.log = log + res.log
            return res

        items: List[SniffItem] = []
        json_hits: List[Dict[str, Any]] = []
        html_text = ""
        final_url = page_url
        errors: List[str] = []

        async with async_playwright() as pw:
            browser = None
            context = None
            try:
                launch_kwargs: Dict[str, Any] = {
                    "headless": bool(self.cfg.playwright_headless),
                    "args": list(self.cfg.playwright_launch_args or []),
                }
                if self.cfg.playwright_channel:
                    launch_kwargs["channel"] = self.cfg.playwright_channel
                if self.cfg.playwright_proxy:
                    launch_kwargs["proxy"] = self.cfg.playwright_proxy

                browser = await pw.chromium.launch(**launch_kwargs)
                context = await browser.new_context(
                    user_agent=DEFAULT_USER_AGENT,
                    ignore_https_errors=bool(self.cfg.allow_insecure_tls),
                )
                page = await context.new_page()

                async def on_response(resp: Any) -> None:
                    try:
                        rurl = self._canonicalize_url(resp.url)
                        if not rurl or not self._host_allowed(rurl):
                            return
                        headers = {str(k).lower(): str(v) for k, v in (await resp.all_headers()).items()}
                        ctype = headers.get("content-type", "")
                        size = headers.get("content-length", "")
                        status = str(resp.status)
                        req = resp.request
                        resource_type = getattr(req, "resource_type", "") or ""
                        kind = self._classify_url(rurl, content_type=ctype, resource_type=resource_type)
                        if not kind and not self.cfg.include_junk:
                            return
                        item = SniffItem(
                            url=rurl,
                            final_url=self._canonicalize_url(resp.url),
                            kind=kind or "link",
                            tag=resource_type or "network",
                            source="playwright_response",
                            text=f"[{resource_type or 'response'}]",
                            content_type=ctype,
                            size=size,
                            status=status,
                            referer=page_url,
                            evidence="network-response",
                        )
                        item.score = self._score_item(item)
                        items.append(item)

                        if self._should_read_json(rurl, ctype) and len(json_hits) < self.cfg.max_json_hits:
                            try:
                                body = await resp.text()
                                for hit in self._mine_jsonish_text(body[: 384 * 1024], base_url=rurl, log=log):
                                    json_hits.append(hit)
                                    if len(json_hits) >= self.cfg.max_json_hits:
                                        break
                            except Exception:
                                pass
                    except Exception as exc:
                        if len(errors) < 20:
                            errors.append(f"response handler: {exc}")

                page.on("response", on_response)

                await page.goto(
                    page_url,
                    wait_until=self.cfg.playwright_wait_until or "domcontentloaded",
                    timeout=int(tmo * 1000),
                )
                final_url = self._canonicalize_url(page.url)

                if self.cfg.enable_auto_scroll:
                    await self._auto_scroll(page, log)

                try:
                    html_text = await page.content()
                except Exception as exc:
                    errors.append(f"page.content failed: {exc}")
                    html_text = ""

                self._collect_static_assets(html_text, base_url=final_url, items=items, source="dom", log=log)

            except Exception as exc:
                errors.append(f"playwright failed: {exc}")
                log.append("falling back to static requests")
                res = self._sniff_url_static(
                    page_url,
                    timeout_sec=tmo,
                    max_items=limit,
                    include_html=include_html,
                    tor_socks_url=tor_socks_url,
                )
                res.mode = "playwright-fallback-static"
                res.errors = errors + res.errors
                res.log = log + res.log
                return res
            finally:
                try:
                    if context:
                        await context.close()
                except Exception:
                    pass
                try:
                    if browser:
                        await browser.close()
                except Exception:
                    pass

        derived = self._expand_manifests_from_items(items, log=log)
        items.extend(derived)
        if self.cfg.verify_assets:
            self._probe_items(items, referer=final_url, log=log, tor_socks_url=tor_socks_url)

        items = self._rank_dedupe(items)[:limit]
        title = self._extract_title(html_text)
        desc = self._extract_meta_description(html_text)
        plain = self._clean_html_to_text(html_text)[: self.cfg.max_text_chars]

        return SniffResult(
            ok=True,
            url=page_url,
            final_url=final_url,
            mode="playwright",
            title=title,
            description=desc,
            text=plain,
            html=html_text if include_html else "",
            items=items,
            json_hits=json_hits[: self.cfg.max_json_hits],
            errors=errors,
            log=log,
            elapsed_ms=int((time.time() - started) * 1000),
        )

    # ------------------------------------------------------------------
    # Static requests path
    # ------------------------------------------------------------------
    def _sniff_url_static(
        self,
        url: str,
        *,
        timeout_sec: Optional[float] = None,
        max_items: Optional[int] = None,
        include_html: bool = False,
        tor_socks_url: Optional[str] = None,
    ) -> SniffResult:
        started = time.time()
        page_url = self._normalize_url(url)
        limit = int(max_items or self.cfg.max_items)
        log: List[str] = []
        errors: List[str] = []
        html_text = ""
        final_url = page_url
        items: List[SniffItem] = []
        json_hits: List[Dict[str, Any]] = []

        session = self._make_session(tor_socks_url=tor_socks_url)
        try:
            resp = session.get(
                page_url,
                timeout=float(timeout_sec or self.cfg.timeout_sec),
                allow_redirects=bool(self.cfg.follow_redirects),
                verify=not self.cfg.allow_insecure_tls,
            )
            final_url = self._canonicalize_url(resp.url)
            content_type = resp.headers.get("content-type", "")
            content_length = resp.headers.get("content-length", "")
            status = str(resp.status_code)

            # Always emit the fetched URL as an item too. It may itself be a media file.
            kind = self._classify_url(final_url, content_type=content_type)
            if kind and kind not in {"link", "unknown"}:
                items.append(
                    SniffItem(
                        url=final_url,
                        kind=kind,
                        tag="fetched",
                        source="fetch",
                        text="[Fetched URL]",
                        content_type=content_type,
                        size=content_length,
                        status=status,
                        final_url=final_url,
                        evidence="response-content-type",
                    )
                )

            body_bytes = resp.content[: int(self.cfg.max_page_chars)]
            encoding = resp.encoding or "utf-8"
            html_text = body_bytes.decode(encoding, errors="replace")
            if resp.status_code >= 400:
                errors.append(f"HTTP {resp.status_code}")

            self._collect_static_assets(html_text, base_url=final_url, items=items, source="html", log=log)

            if self._should_read_json(final_url, content_type):
                json_hits.extend(self._mine_jsonish_text(html_text, base_url=final_url, log=log))

        except Exception as exc:
            errors.append(str(exc))
            return SniffResult(
                ok=False,
                url=page_url,
                final_url=final_url,
                mode="static",
                errors=errors,
                log=log,
                elapsed_ms=int((time.time() - started) * 1000),
            )
        finally:
            session.close()

        derived = self._expand_manifests_from_items(items, log=log, tor_socks_url=tor_socks_url)
        items.extend(derived)

        if self.cfg.verify_assets:
            self._probe_items(items, referer=final_url, log=log, tor_socks_url=tor_socks_url)

        items = self._rank_dedupe(items)[:limit]
        title = self._extract_title(html_text)
        desc = self._extract_meta_description(html_text)
        plain = self._clean_html_to_text(html_text)[: self.cfg.max_text_chars]

        return SniffResult(
            ok=not errors or bool(items) or bool(plain),
            url=page_url,
            final_url=final_url,
            mode="static",
            title=title,
            description=desc,
            text=plain,
            html=html_text if include_html else "",
            items=items,
            json_hits=json_hits[: self.cfg.max_json_hits],
            errors=errors,
            log=log,
            elapsed_ms=int((time.time() - started) * 1000),
        )

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------
    def _collect_static_assets(
        self,
        html_text: str,
        *,
        base_url: str,
        items: List[SniffItem],
        source: str,
        log: List[str],
    ) -> None:
        text = html_text or ""
        seen_local: Set[str] = set()

        def add(
            raw_url: str,
            *,
            tag: str,
            text_label: str = "",
            kind_hint: str = "",
            evidence: str = "",
        ) -> None:
            if not raw_url:
                return
            u = self._absolutize_url(raw_url, base_url)
            u = self._canonicalize_url(u)
            if not u or u in seen_local or not self._host_allowed(u):
                return
            seen_local.add(u)
            kind = kind_hint or self._classify_url(u) or "link"
            if kind == "junk" and not self.cfg.include_junk:
                return
            item = SniffItem(
                url=u,
                kind=kind,
                tag=tag,
                source=source,
                text=(text_label or "").strip()[:240],
                referer=base_url,
                evidence=evidence or tag,
            )
            item.score = self._score_item(item)
            items.append(item)

        # href/src/action/data-* / CSS url() / @import / absolute raw URLs
        for found in self.extract_urls_from_text(text, base_url=base_url):
            add(found, tag="text_url", text_label="[URL]", evidence="regex-or-attr")

        # Structured HTML tags.
        attr_patterns = [
            (r'(?is)<a\b[^>]*?\bhref\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', "a", ""),
            (r'(?is)<img\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "img", "image"),
            (r'(?is)<source\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "source", ""),
            (r'(?is)<video\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "video", "video"),
            (r'(?is)<audio\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "audio", "audio"),
            (r'(?is)<script\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "script", "script"),
            (r'(?is)<link\b[^>]*?\bhref\s*=\s*["\']([^"\']+)["\'][^>]*>', "link", ""),
            (r'(?is)<iframe\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', "iframe", "link"),
            (r'(?is)<meta\b[^>]*?\bcontent\s*=\s*["\']([^"\']+)["\'][^>]*>', "meta", ""),
        ]
        for rx, tag, hint in attr_patterns:
            for m in re.finditer(rx, text):
                raw = html.unescape(m.group(1) or "")
                label = ""
                if tag == "a" and len(m.groups()) > 1:
                    label = self._clean_html_to_text(m.group(2) or "")[:200]
                add(raw, tag=tag, text_label=label, kind_hint=hint, evidence=f"html-{tag}")

        # srcset produces "url 1x, url 2x" or "url 800w".
        for m in re.finditer(r'(?is)\bsrcset\s*=\s*["\']([^"\']+)["\']', text):
            for part in html.unescape(m.group(1)).split(","):
                raw = part.strip().split(" ")[0]
                add(raw, tag="srcset", kind_hint="image", evidence="html-srcset")

        # JSON-LD and embedded JSON: media URLs are often there even if HTML attrs are empty.
        for hit in self._mine_jsonish_text(text, base_url=base_url, log=log):
            for u in hit.get("urls", [])[:80]:
                add(str(u), tag="json_url", text_label="[JSON URL]", evidence=hit.get("source", "json"))

    def extract_urls_from_text(self, text: str, *, base_url: str = "") -> List[str]:
        if not text:
            return []

        out: List[str] = []
        seen: Set[str] = set()

        def push(raw: str) -> None:
            u = html.unescape(str(raw or "")).strip().strip("()[]{}<>\"'`")
            if not u:
                return
            if u.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "about:", "#")):
                return
            if u.startswith("//"):
                u = "https:" + u
            elif base_url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
                # Keep this conservative for relative path discovery.
                if u.startswith("/") or re.search(r"\.(?:jpg|png|webp|gif|mp4|m3u8|mpd|m4s|ts|mp3|m4a|pdf)(?:[?#]|$)", u, re.I):
                    u = urljoin(base_url, u)
                else:
                    return
            cu = self._canonicalize_url(u)
            if cu and cu not in seen:
                seen.add(cu)
                out.append(cu)

        for rx in (
            r"\b(?:https?|wss?)://[^\s\"'<>`]+",
            r"(?<!:)\b//[^\s\"'<>`]+",
            r"""(?is)\b(?:href|src|action|formaction|poster|data-src|data-href|data-url|data-video|data-audio)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""",
            r"""(?is)\burl\(\s*['"]?([^'"\)\s]+)""",
            r"""(?is)@import\s+(?:url\()?\s*['"]?([^'"\)\s;]+)""",
        ):
            for m in re.finditer(rx, text):
                if isinstance(m.group(0), str) and m.lastindex is None:
                    push(m.group(0))
                else:
                    for g in m.groups():
                        if g:
                            push(g)
        return out

    # ------------------------------------------------------------------
    # JSON + manifest mining
    # ------------------------------------------------------------------
    def _mine_jsonish_text(self, text: str, *, base_url: str, log: List[str]) -> List[Dict[str, Any]]:
        if not text:
            return []
        hits: List[Dict[str, Any]] = []

        def add_hit(source: str, obj: Any) -> None:
            if len(hits) >= self.cfg.max_json_hits:
                return
            urls = self._extract_candidate_urls_from_obj(obj, base_url=base_url)
            if not urls:
                return
            hits.append({
                "source": source,
                "url_count": len(urls),
                "urls": urls[:100],
                "sha1": hashlib.sha1(json.dumps(obj, default=str, sort_keys=True)[:10000].encode("utf-8", "ignore")).hexdigest(),
            })

        # Plain body JSON.
        stripped = text.strip()
        if stripped.startswith(("{", "[")):
            try:
                add_hit("body-json", json.loads(stripped))
            except Exception:
                pass

        # JSON-LD / script application JSON.
        for m in re.finditer(
            r'(?is)<script\b[^>]*type\s*=\s*["\'](?:application/ld\+json|application/json|text/json)["\'][^>]*>(.*?)</script>',
            text,
        ):
            body = html.unescape(m.group(1) or "").strip()
            try:
                add_hit("script-json", json.loads(body))
            except Exception:
                pass

        # Assignment-ish JSON object snippets. Capped and conservative.
        for m in re.finditer(r"(?is)(?:window\.__[A-Z0-9_]+__|ytInitialPlayerResponse|__NEXT_DATA__)\s*=?\s*(\{.*?\})\s*;?\s*</script", text[: 768 * 1024]):
            body = html.unescape(m.group(1) or "").strip()
            try:
                add_hit("embedded-json", json.loads(body))
            except Exception:
                pass

        return hits[: self.cfg.max_json_hits]

    def _extract_candidate_urls_from_obj(self, obj: Any, *, base_url: str) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()

        def visit(x: Any, key_path: str = "") -> None:
            if len(out) >= 500:
                return
            if isinstance(x, Mapping):
                for k, v in x.items():
                    visit(v, f"{key_path}.{k}" if key_path else str(k))
            elif isinstance(x, list):
                for v in x[:250]:
                    visit(v, key_path)
            elif isinstance(x, str):
                s = x.strip()
                likely_key = any(h in key_path.lower() for h in ("url", "src", "href", "image", "video", "audio", "manifest", "media"))
                if likely_key or "http" in s or s.startswith("/"):
                    for u in self.extract_urls_from_text(s, base_url=base_url):
                        cu = self._canonicalize_url(u)
                        if cu and cu not in seen:
                            seen.add(cu)
                            out.append(cu)

        visit(obj)
        return out

    def _expand_manifests_from_items(
        self,
        items: List[SniffItem],
        *,
        log: List[str],
        tor_socks_url: Optional[str] = None,
    ) -> List[SniffItem]:
        derived: List[SniffItem] = []
        count = 0
        for item in list(items):
            if count >= self.cfg.max_manifest_derived:
                break
            if item.kind not in {"manifest", "video", "audio"} and not item.url.lower().endswith((".m3u8", ".mpd")):
                continue
            lower = item.url.lower()
            if not (".m3u8" in lower or ".mpd" in lower):
                continue
            try:
                manifest_text = self._fetch_text_prefix(item.url, tor_socks_url=tor_socks_url)
                if not manifest_text:
                    continue
                if ".m3u8" in lower or "#extm3u" in manifest_text.lower():
                    urls = self._expand_hls_manifest(item.url, manifest_text)
                else:
                    urls = self._expand_dash_manifest(item.url, manifest_text)
                for u in urls:
                    if count >= self.cfg.max_manifest_derived:
                        break
                    kind = self._classify_url(u) or ("video" if ".m3u8" not in u.lower() else "manifest")
                    derived_item = SniffItem(
                        url=self._canonicalize_url(u),
                        kind=kind if kind != "link" else "video",
                        tag="manifest_asset",
                        source="manifest",
                        text="[Manifest Derived Asset]",
                        referer=item.referer,
                        derived_from=item.url,
                        evidence="manifest",
                    )
                    derived_item.score = self._score_item(derived_item) + 2.0
                    derived.append(derived_item)
                    count += 1
            except Exception as exc:
                log.append(f"manifest expand failed {item.url}: {exc}")
        return derived

    def _expand_hls_manifest(self, manifest_url: str, body: str) -> List[str]:
        urls: List[str] = []
        for line in (body or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                # EXT-X-MEDIA can contain URI="..."
                m = re.search(r'URI=["\']([^"\']+)["\']', line)
                if m:
                    urls.append(urljoin(manifest_url, html.unescape(m.group(1))))
                continue
            urls.append(urljoin(manifest_url, line))
        return urls

    def _expand_dash_manifest(self, manifest_url: str, body: str) -> List[str]:
        urls: List[str] = []
        try:
            root = ET.fromstring(body)
        except Exception:
            return self.extract_urls_from_text(body, base_url=manifest_url)

        nsless = lambda tag: tag.rsplit("}", 1)[-1] if "}" in tag else tag
        base_urls: List[str] = [manifest_url]
        for elem in root.iter():
            tag = nsless(elem.tag)
            if tag == "BaseURL" and elem.text:
                base_urls.append(urljoin(manifest_url, elem.text.strip()))
            if tag in {"SegmentTemplate", "SegmentURL", "Initialization"}:
                for attr in ("media", "sourceURL", "initialization"):
                    val = elem.attrib.get(attr)
                    if val:
                        # Keep template URL too; it is useful evidence even before Number substitution.
                        urls.append(urljoin(base_urls[-1], val))
        return urls

    # ------------------------------------------------------------------
    # Verification / binary sniff
    # ------------------------------------------------------------------
    def _probe_items(
        self,
        items: List[SniffItem],
        *,
        referer: str,
        log: List[str],
        tor_socks_url: Optional[str] = None,
    ) -> None:
        session = self._make_session(tor_socks_url=tor_socks_url)
        probed = 0
        try:
            for item in items:
                if probed >= self.cfg.max_probe_items:
                    return
                if item.status and item.content_type:
                    continue
                if item.url.startswith(("blob:", "data:")):
                    continue

                headers = {"Referer": referer} if referer else {}
                try:
                    if self.cfg.use_range_probe:
                        headers["Range"] = f"bytes=0-{max(0, self.cfg.max_probe_bytes - 1)}"
                        resp = session.get(
                            item.url,
                            headers=headers,
                            timeout=min(self.cfg.timeout_sec, 8),
                            allow_redirects=True,
                            stream=True,
                            verify=not self.cfg.allow_insecure_tls,
                        )
                    else:
                        resp = session.head(
                            item.url,
                            headers=headers,
                            timeout=min(self.cfg.timeout_sec, 8),
                            allow_redirects=True,
                            verify=not self.cfg.allow_insecure_tls,
                        )
                    probed += 1
                    item.status = item.status or str(resp.status_code)
                    item.final_url = self._canonicalize_url(resp.url)
                    item.content_type = item.content_type or resp.headers.get("content-type", "")
                    item.size = item.size or resp.headers.get("content-length", "")
                    guessed = self._classify_url(item.url, content_type=item.content_type)
                    if guessed and (item.kind in {"link", "unknown", "script", "style"}):
                        item.kind = guessed
                    if item.kind in {"link", "unknown"} and self.cfg.use_range_probe:
                        prefix = b""
                        try:
                            prefix = next(resp.iter_content(chunk_size=self.cfg.max_probe_bytes), b"")
                        except Exception:
                            pass
                        magic_kind, magic_ct, evidence = self._guess_kind_from_magic(prefix)
                        if magic_kind:
                            item.kind = magic_kind
                            item.content_type = item.content_type or magic_ct or ""
                            item.evidence = item.evidence + f";{evidence}"
                    item.score = self._score_item(item)
                except Exception:
                    continue
        finally:
            session.close()

    def _fetch_text_prefix(self, url: str, *, tor_socks_url: Optional[str] = None) -> str:
        session = self._make_session(tor_socks_url=tor_socks_url)
        try:
            resp = session.get(
                url,
                timeout=min(self.cfg.timeout_sec, 10),
                headers={"Range": "bytes=0-524287"},
                allow_redirects=True,
                verify=not self.cfg.allow_insecure_tls,
            )
            data = resp.content[: 512 * 1024]
            return data.decode(resp.encoding or "utf-8", errors="replace")
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Classification / ranking / dedupe
    # ------------------------------------------------------------------
    def _classify_url(
        self,
        url: str,
        *,
        content_type: str = "",
        resource_type: str = "",
    ) -> str:
        u = (url or "").lower()
        p = urlparse(u)
        path = p.path.lower()
        ext = self._extension(path)
        ct = (content_type or "").lower().split(";")[0].strip()
        rt = (resource_type or "").lower().strip()

        if ct in self.cfg.hls_mime_types or u.endswith(".m3u8"):
            return "manifest"
        if ct in self.cfg.dash_mime_types or u.endswith(".mpd"):
            return "manifest"
        if any(ct.startswith(x) for x in self.cfg.video_mime_prefixes):
            return "video"
        if any(ct.startswith(x) for x in self.cfg.audio_mime_prefixes):
            return "audio"
        if any(ct.startswith(x) for x in self.cfg.image_mime_prefixes):
            return "image"
        if ct in self.cfg.json_mime_types:
            return "json"

        if ext in self.cfg.video_extensions:
            return "manifest" if ext in {".m3u8", ".mpd"} else "video"
        if ext in self.cfg.audio_extensions:
            return "audio"
        if ext in self.cfg.image_extensions:
            return "image"
        if ext in self.cfg.document_extensions:
            return "json" if ext == ".json" else "document"
        if ext in self.cfg.junk_extensions:
            if ext in {".js", ".map"}:
                return "script"
            if ext == ".css":
                return "style"
            return "junk"

        if rt in {"image"}:
            return "image"
        if rt in {"media"}:
            return "video"
        if rt in {"script"}:
            return "script"
        if rt in {"stylesheet", "font"}:
            return "junk"

        if any(h in u for h in self.cfg.media_url_hints):
            # Opaque video/audio endpoints like videoplayback or signed CDN chunks.
            if any(h in u for h in ("audio", ".mp3", ".m4a", ".aac", ".opus")):
                return "audio"
            if any(h in u for h in ("manifest", "m3u8", "mpd", "playlist")):
                return "manifest"
            return "video"

        return "link"

    def _should_read_json(self, url: str, content_type: str) -> bool:
        u = (url or "").lower()
        ct = (content_type or "").lower().split(";")[0].strip()
        return (
            ct in self.cfg.json_mime_types
            or u.endswith(".json")
            or any(x in u for x in ("/api/", "graphql", "metadata", "player", "manifest", "playlist"))
        )

    def _rank_dedupe(self, items: List[SniffItem]) -> List[SniffItem]:
        by_url: Dict[str, SniffItem] = {}
        for item in items:
            cu = self._canonicalize_url(item.url)
            if not cu:
                continue
            item.url = cu
            item.score = item.score or self._score_item(item)
            old = by_url.get(cu)
            if old is None or self._score_item(item) > self._score_item(old):
                by_url[cu] = item

        ranked = list(by_url.values())
        ranked.sort(key=self._rank_tuple, reverse=True)
        return ranked[: self.cfg.max_items]

    def _score_item(self, item: SniffItem) -> float:
        score = 0.0
        score += {
            "manifest": 9.0,
            "video": 8.0,
            "audio": 7.0,
            "image": 6.0,
            "document": 4.0,
            "json": 3.0,
            "link": 1.0,
            "script": 0.5,
            "style": 0.2,
            "junk": -5.0,
        }.get(item.kind, 0.0)
        if item.source in {"playwright_response", "manifest"}:
            score += 1.5
        if item.status.startswith(("2", "206")):
            score += 1.0
        if item.content_type:
            score += 0.5
        if item.derived_from:
            score += 1.0
        if self._is_probably_ad_or_tracker(item.url):
            score -= 2.5
        return score

    def _rank_tuple(self, item: SniffItem) -> Tuple[float, int, int]:
        return (self._score_item(item), len(item.url), len(item.text or ""))

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def _make_session(self, *, tor_socks_url: Optional[str] = None) -> requests.Session:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=12, pool_maxsize=24, max_retries=0)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        })
        if tor_socks_url:
            s.proxies = {"http": tor_socks_url, "https": tor_socks_url}
        return s

    def _normalize_url(self, url: str) -> str:
        raw = (url or "").strip()
        if not raw:
            raise ValueError("URL is required.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            first = raw.split("/", 1)[0].lower()
            raw = ("http://" if first.endswith(".onion") else "https://") + raw
        p = urlparse(raw)
        if not p.scheme or not p.netloc:
            raise ValueError(f"Invalid URL: {url}")
        return raw

    def _absolutize_url(self, raw_url: str, base_url: str) -> str:
        u = html.unescape(str(raw_url or "")).strip()
        if not u:
            return ""
        if u.startswith("//"):
            return "https:" + u
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", u):
            return u
        return urljoin(base_url, u)

    def _canonicalize_url(self, url: str) -> str:
        u = str(url or "").strip()
        if not u:
            return ""
        try:
            u, _frag = urldefrag(u)
            p = urlparse(u)
            scheme = (p.scheme or "https").lower()
            netloc = p.netloc.lower()
            path = p.path or "/"
            kept: List[Tuple[str, str]] = []
            for k, v in parse_qsl(p.query, keep_blank_values=False):
                lk = k.lower()
                if not self.cfg.keep_tracking_query_values and lk in VOLATILE_QUERY_KEYS:
                    continue
                if not self.cfg.keep_signed_query_values and any(h in lk for h in SIGNED_QUERY_HINTS):
                    # Keep key without volatile value so duplicates collapse and secrets do not spill.
                    continue
                kept.append((k, v))
            return urlunparse((scheme, netloc, path, p.params, urlencode(kept, doseq=True), ""))
        except Exception:
            return u

    def _host_allowed(self, url: str) -> bool:
        try:
            host = urlparse(url).netloc.lower()
        except Exception:
            return True
        if self.cfg.host_deny_substrings and any(x.lower() in host for x in self.cfg.host_deny_substrings):
            return False
        if self.cfg.host_allow_substrings:
            return any(x.lower() in host for x in self.cfg.host_allow_substrings)
        return True

    def _extension(self, path: str) -> str:
        name = path.rsplit("/", 1)[-1]
        if "." not in name:
            return ""
        ext = "." + name.rsplit(".", 1)[-1].lower()
        return ext if len(ext) <= 12 else ""

    def _is_probably_ad_or_tracker(self, url: str) -> bool:
        u = (url or "").lower()
        host = urlparse(u).netloc
        return any(x in host for x in ("doubleclick", "googlesyndication", "adservice", "analytics", "metrics", "scorecardresearch")) or any(
            x in u for x in ("/ads/", "/adserver/", "/tracking/", "/pixel", "/impression")
        )

    def _extract_title(self, html_text: str) -> str:
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_text or "")
        return self._clean_html_to_text(m.group(1))[:300] if m else ""

    def _extract_meta_description(self, html_text: str) -> str:
        for pattern in (
            r'(?is)<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
            r'(?is)<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']description["\']',
            r'(?is)<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']',
            r'(?is)<meta[^>]+content=["\'](.*?)["\'][^>]+property=["\']og:description["\']',
        ):
            m = re.search(pattern, html_text or "")
            if m:
                return html.unescape(m.group(1)).strip()[:500]
        return ""

    def _clean_html_to_text(self, html_text: str) -> str:
        text = html_text or ""
        text = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
        text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
        text = re.sub(r"(?is)<noscript.*?>.*?</noscript>", " ", text)
        text = re.sub(r"(?i)<br\s*/?>", "\n", text)
        text = re.sub(r"(?i)</(?:p|div|li|tr|h[1-6])\s*>", "\n", text)
        text = re.sub(r"(?s)<.*?>", " ", text)
        text = html.unescape(text)
        text = re.sub(r"\r\n?", "\n", text)
        text = re.sub(r"[ \t\f\v]+", " ", text)
        text = re.sub(r"\n[ \t]+", "\n", text)
        text = re.sub(r"[ \t]+\n", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _guess_kind_from_magic(self, b: bytes) -> Tuple[Optional[str], Optional[str], str]:
        if not b:
            return None, None, "no-bytes"
        bb = bytes(b[:4096])
        if bb.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image", "image/png", "magic:png"
        if bb[:3] == b"\xff\xd8\xff":
            return "image", "image/jpeg", "magic:jpeg"
        if bb.startswith((b"GIF87a", b"GIF89a")):
            return "image", "image/gif", "magic:gif"
        if bb.startswith(b"RIFF") and b"WEBP" in bb[:16]:
            return "image", "image/webp", "magic:webp"
        if b"ftyp" in bb[:32]:
            # mp4/m4a/mov family.
            return "video", "video/mp4", "magic:ftyp"
        if bb.startswith(b"ID3") or bb[:2] == b"\xff\xfb":
            return "audio", "audio/mpeg", "magic:mp3"
        if bb.startswith(b"OggS"):
            return "audio", "audio/ogg", "magic:ogg"
        if bb.startswith(b"%PDF"):
            return "document", "application/pdf", "magic:pdf"
        if bb.startswith(b"#EXTM3U"):
            return "manifest", "application/vnd.apple.mpegurl", "magic:hls"
        if bb.lstrip().startswith(b"<MPD"):
            return "manifest", "application/dash+xml", "magic:dash"
        return None, None, "unknown"

    async def _auto_scroll(self, page: Any, log: List[str]) -> None:
        try:
            last_height = 0
            for _ in range(max(0, int(self.cfg.max_scroll_steps))):
                height = await page.evaluate("() => document.documentElement.scrollHeight || document.body.scrollHeight || 0")
                if height == last_height:
                    break
                last_height = height
                await page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight || document.body.scrollHeight || 0)")
                await page.wait_for_timeout(int(self.cfg.scroll_delay_ms))
            await page.evaluate("() => window.scrollTo(0, 0)")
        except Exception as exc:
            log.append(f"auto-scroll failed: {exc}")


def sniff_url(url: str, **kwargs: Any) -> Dict[str, Any]:
    """Convenience wrapper for callers that want a JSON-serializable dict."""
    cfg = SnifferConfig()
    for key in list(kwargs.keys()):
        if hasattr(cfg, key):
            setattr(cfg, key, kwargs.pop(key))
    engine = SnifferEngine(cfg)
    return engine.sniff_url(url, **kwargs).as_dict(include_html=bool(kwargs.get("include_html", False)))


def sniff_text(text: str, *, base_url: str = "", **kwargs: Any) -> Dict[str, Any]:
    cfg = SnifferConfig()
    for key in list(kwargs.keys()):
        if hasattr(cfg, key):
            setattr(cfg, key, kwargs.pop(key))
    engine = SnifferEngine(cfg)
    return engine.sniff_text(text, base_url=base_url, include_html=bool(kwargs.get("include_html", False))).as_dict(
        include_html=bool(kwargs.get("include_html", False))
    )
