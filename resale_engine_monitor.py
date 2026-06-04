from __future__ import annotations

"""Safe resale marketplace monitor engine.

Supported public search targets:
- depop
- poshmark
- grailed
- mercari
- mercari_japan / mercari_jp
- bunjang / bunjung

The engine only uses public pages or user-provided public/exported HTML. It does not log in,
solve CAPTCHAs, use proxies to evade limits, bypass access controls, or automate checkout.
Many resale sites render listings through changing web apps; when public HTML has no usable
listing data, this engine returns a blocked/no_items status and a ready-to-open search URL.
"""

import hashlib
import html
import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote_plus, urljoin, urlparse

import requests

DEFAULT_TIMEOUT_SEC = 20.0
DEFAULT_MAX_ITEMS = 60
DEFAULT_STATE_PATH = "data/resale_monitor/state.json"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 ResaleMonitor/1.0"
)

PLATFORM_ALIASES = {
    "depop": "depop",
    "poshmark": "poshmark",
    "grailed": "grailed",
    "mercari": "mercari",
    "mercari_us": "mercari",
    "mercari_japan": "mercari_japan",
    "mercari_jp": "mercari_japan",
    "bunjang": "bunjang",
    "bunjung": "bunjang",  # common misspelling
    "번개장터": "bunjang",
}

PLATFORM_HOME = {
    "depop": "https://www.depop.com",
    "poshmark": "https://poshmark.com",
    "grailed": "https://www.grailed.com",
    "mercari": "https://www.mercari.com",
    "mercari_japan": "https://jp.mercari.com",
    "bunjang": "https://m.bunjang.co.kr",
}

PLATFORM_ITEM_PATTERNS = {
    "depop": [r"/products/[A-Za-z0-9_.~%+\-]+/?"],
    "poshmark": [r"/listing/[A-Za-z0-9_.~%+\-]+"],
    "grailed": [r"/listings/\d+[A-Za-z0-9_.~%+\-/]*"],
    "mercari": [r"/us/item/[A-Za-z0-9_.~%+\-]+/?", r"/item/[A-Za-z0-9_.~%+\-]+/?"],
    "mercari_japan": [r"/item/[A-Za-z0-9_.~%+\-]+/?"],
    "bunjang": [r"/products/\d+/?", r"/product/\d+/?"],
}

KNOWN_CURRENCY_MARKS = {
    "$": "USD",
    "US$": "USD",
    "¥": "JPY",
    "￥": "JPY",
    "₩": "KRW",
    "KRW": "KRW",
    "JPY": "JPY",
    "USD": "USD",
    "EUR": "EUR",
    "GBP": "GBP",
}


@dataclass
class ResaleSearchSpec:
    platform: str
    query: str
    brand: str = ""
    size: str = ""
    min_price: Optional[float] = None
    max_price: Optional[float] = None
    currency: str = ""
    sort: str = "newest"
    limit: int = DEFAULT_MAX_ITEMS
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResaleMonitorConfig:
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    verify_tls: bool = True
    state_path: str = DEFAULT_STATE_PATH
    user_agent: str = DEFAULT_USER_AGENT
    write_state: bool = False
    include_html: bool = False
    include_raw_json: bool = False
    respect_robots: bool = True
    polite_delay_sec: float = 0.6


class ResaleMonitorEngine:
    def __init__(self, config: Optional[ResaleMonitorConfig] = None) -> None:
        self.config = config or ResaleMonitorConfig()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.config.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.7",
                "Accept-Language": "en-US,en;q=0.9,ja;q=0.6,ko;q=0.6",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            }
        )

    # ----------------------------- state ---------------------------------
    def _load_state(self) -> Dict[str, Any]:
        path = Path(self.config.state_path)
        if not path.exists():
            return {"ok": True, "version": 1, "seen": {}, "runs": []}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {"ok": True, "version": 1, "seen": {}, "runs": []}
            data.setdefault("version", 1)
            data.setdefault("seen", {})
            data.setdefault("runs", [])
            return data
        except Exception:
            return {"ok": True, "version": 1, "seen": {}, "runs": []}

    def _save_state(self, state: Dict[str, Any]) -> None:
        path = Path(self.config.state_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)

    # ----------------------------- search --------------------------------
    def search(self, spec: ResaleSearchSpec) -> Dict[str, Any]:
        started = time.time()
        platform = normalize_platform(spec.platform)
        if platform not in PLATFORM_HOME:
            return {"ok": False, "platform": spec.platform, "error": f"Unsupported platform: {spec.platform}"}
        clean_spec = normalize_spec(spec)
        urls = build_platform_search_urls(clean_spec)
        result_pages: List[Dict[str, Any]] = []
        items: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for idx, url in enumerate(urls):
            if idx > 0 and self.config.polite_delay_sec > 0:
                time.sleep(float(self.config.polite_delay_sec))
            page = self.fetch_public_page(url, platform=platform)
            result_pages.append(compact_page_result(page))
            if not page.get("ok"):
                errors.append(compact_page_result(page))
                continue
            html_text = str(page.get("html", "") or "")
            parsed = parse_marketplace_page(platform, html_text, url, limit=clean_spec.limit, include_raw_json=self.config.include_raw_json)
            items.extend(parsed.get("items", []))
            errors.extend(parsed.get("errors", []))
            if len(items) >= clean_spec.limit:
                break

        normalized_items = dedupe_and_filter_items(items, clean_spec)[: clean_spec.limit]
        out = {
            "ok": bool(normalized_items) or not errors,
            "engine": "resale_engine_monitor",
            "mode": "search",
            "platform": platform,
            "query": clean_spec.query,
            "search_urls": urls,
            "count": len(normalized_items),
            "items": normalized_items,
            "pages": result_pages,
            "errors": errors[:20],
            "fetched_at": utc_now_iso(),
            "elapsed_ms": int((time.time() - started) * 1000),
            "limits": safe_limits(),
        }
        if self.config.include_html:
            out["html_samples"] = [p.get("html_sample", "") for p in result_pages if p.get("html_sample")]
        if not normalized_items:
            out["note"] = (
                "No usable listing data was found in the public HTML. Open search_urls in a browser, "
                "or add an official/API/HTML-export adapter for this platform."
            )
        return out

    def monitor(
        self,
        searches: Sequence[Dict[str, Any]],
        alert_rules: Optional[Dict[str, Any]] = None,
        new_only: bool = True,
    ) -> Dict[str, Any]:
        started = time.time()
        state = self._load_state()
        all_items: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        alerts: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for row in searches or []:
            spec = coerce_search_spec(row)
            result = self.search(spec)
            results.append(compact_search_result(result))
            if not result.get("ok") and not result.get("items"):
                errors.append({"platform": normalize_platform(spec.platform), "query": spec.query, "error": result.get("error", result.get("note", ""))})
            for item in result.get("items", []) or []:
                key = item_key(item)
                was_seen = key in state.get("seen", {})
                item["seen_before"] = was_seen
                if not was_seen or not new_only:
                    all_items.append(item)
                    item_alerts = evaluate_resale_alerts(item, alert_rules or {}, is_new=not was_seen)
                    alerts.extend(item_alerts)
                state.setdefault("seen", {})[key] = {
                    "first_seen_at": state.get("seen", {}).get(key, {}).get("first_seen_at", utc_now_iso()),
                    "last_seen_at": utc_now_iso(),
                    "platform": item.get("platform", ""),
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "price": item.get("price"),
                    "currency": item.get("currency", ""),
                }

        if self.config.write_state:
            state.setdefault("runs", []).append({"ran_at": utc_now_iso(), "searches": len(searches or []), "items": len(all_items), "alerts": len(alerts)})
            state["runs"] = state.get("runs", [])[-100:]
            self._save_state(state)

        return {
            "ok": len(errors) == 0 or bool(all_items) or bool(results),
            "engine": "resale_engine_monitor",
            "mode": "monitor",
            "searches_count": len(searches or []),
            "new_only": bool(new_only),
            "items_count": len(all_items),
            "alerts_count": len(alerts),
            "errors_count": len(errors),
            "items": all_items,
            "alerts": alerts,
            "results": results,
            "errors": errors,
            "state_path": self.config.state_path if self.config.write_state else "",
            "limits": safe_limits(),
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    def fetch_public_page(self, url: str, platform: str = "") -> Dict[str, Any]:
        started = time.time()
        try:
            resp = self.session.get(
                url,
                timeout=float(self.config.timeout_sec),
                verify=bool(self.config.verify_tls),
                allow_redirects=True,
            )
            elapsed_ms = int((time.time() - started) * 1000)
            text = resp.text or ""
            blocked = looks_blocked(resp.status_code, text)
            out: Dict[str, Any] = {
                "ok": resp.status_code < 400 and not blocked,
                "platform": platform,
                "url": url,
                "final_url": resp.url,
                "status_code": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "elapsed_ms": elapsed_ms,
                "bytes": len(resp.content or b""),
                "blocked": blocked,
                "html": text,
            }
            if blocked:
                out["error"] = "Public request appears blocked, rate-limited, or requires browser verification/login."
            if resp.status_code >= 400:
                out["error"] = summarize_http_error(resp.status_code, text)
            return out
        except Exception as exc:
            return {"ok": False, "platform": platform, "url": url, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}


# ----------------------------- public funcs -------------------------------
def resale_search(
    platform: str,
    query: str,
    brand: str = "",
    size: str = "",
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    currency: str = "",
    sort: str = "newest",
    limit: int = DEFAULT_MAX_ITEMS,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    include_html: bool = False,
    include_raw_json: bool = False,
) -> Dict[str, Any]:
    engine = ResaleMonitorEngine(
        ResaleMonitorConfig(
            timeout_sec=timeout_sec,
            verify_tls=verify_tls,
            include_html=include_html,
            include_raw_json=include_raw_json,
        )
    )
    return engine.search(
        ResaleSearchSpec(
            platform=platform,
            query=query,
            brand=brand,
            size=size,
            min_price=min_price,
            max_price=max_price,
            currency=currency,
            sort=sort,
            limit=limit,
        )
    )


def resale_monitor(
    searches: Sequence[Dict[str, Any]],
    alert_rules: Optional[Dict[str, Any]] = None,
    new_only: bool = True,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    write_state: bool = False,
    state_path: str = DEFAULT_STATE_PATH,
    include_html: bool = False,
    include_raw_json: bool = False,
) -> Dict[str, Any]:
    engine = ResaleMonitorEngine(
        ResaleMonitorConfig(
            timeout_sec=timeout_sec,
            verify_tls=verify_tls,
            write_state=write_state,
            state_path=state_path or DEFAULT_STATE_PATH,
            include_html=include_html,
            include_raw_json=include_raw_json,
        )
    )
    return engine.monitor(searches, alert_rules=alert_rules or {}, new_only=new_only)


def resale_parse_html(
    platform: str,
    html_text: str,
    base_url: str = "",
    query: str = "",
    brand: str = "",
    size: str = "",
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    currency: str = "",
    limit: int = DEFAULT_MAX_ITEMS,
    include_raw_json: bool = False,
) -> Dict[str, Any]:
    platform_norm = normalize_platform(platform)
    spec = ResaleSearchSpec(platform=platform_norm, query=query, brand=brand, size=size, min_price=min_price, max_price=max_price, currency=currency, limit=limit)
    parsed = parse_marketplace_page(platform_norm, html_text or "", base_url or PLATFORM_HOME.get(platform_norm, ""), limit=limit, include_raw_json=include_raw_json)
    items = dedupe_and_filter_items(parsed.get("items", []), spec)[:limit]
    return {
        "ok": True,
        "engine": "resale_engine_monitor",
        "mode": "parse_html",
        "platform": platform_norm,
        "base_url": base_url,
        "count": len(items),
        "items": items,
        "errors": parsed.get("errors", []),
        "limits": safe_limits(),
    }


def resale_build_search_urls(
    platform: str,
    query: str,
    brand: str = "",
    size: str = "",
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    currency: str = "",
    sort: str = "newest",
    limit: int = DEFAULT_MAX_ITEMS,
) -> Dict[str, Any]:
    spec = ResaleSearchSpec(platform=platform, query=query, brand=brand, size=size, min_price=min_price, max_price=max_price, currency=currency, sort=sort, limit=limit)
    spec = normalize_spec(spec)
    return {"ok": True, "platform": spec.platform, "query": spec.query, "search_urls": build_platform_search_urls(spec), "limits": safe_limits()}


def resale_engine_status() -> Dict[str, Any]:
    return {
        "ok": True,
        "engine": "resale_engine_monitor",
        "version": 1,
        "dependencies": {"requests": requests.__version__},
        "platforms": sorted(PLATFORM_HOME.keys()),
        "aliases": PLATFORM_ALIASES,
        "safe_limits": safe_limits(),
    }


# ----------------------------- url builders -------------------------------
def normalize_platform(platform: str) -> str:
    key = re.sub(r"\s+", "_", str(platform or "").strip().lower())
    return PLATFORM_ALIASES.get(key, key)


def normalize_spec(spec: ResaleSearchSpec) -> ResaleSearchSpec:
    platform = normalize_platform(spec.platform)
    query_parts = [str(spec.query or "").strip()]
    if spec.brand and spec.brand.lower() not in str(spec.query).lower():
        query_parts.append(str(spec.brand).strip())
    if spec.size and spec.size.lower() not in str(spec.query).lower():
        query_parts.append(str(spec.size).strip())
    query = " ".join(p for p in query_parts if p).strip()
    return ResaleSearchSpec(
        platform=platform,
        query=query,
        brand=str(spec.brand or "").strip(),
        size=str(spec.size or "").strip(),
        min_price=safe_float(spec.min_price),
        max_price=safe_float(spec.max_price),
        currency=str(spec.currency or "").strip().upper(),
        sort=str(spec.sort or "newest").strip().lower(),
        limit=max(1, min(int(spec.limit or DEFAULT_MAX_ITEMS), 500)),
        extra=dict(spec.extra or {}),
    )


def build_platform_search_urls(spec: ResaleSearchSpec) -> List[str]:
    platform = normalize_platform(spec.platform)
    q = quote_plus(spec.query or "")
    urls: List[str] = []
    if platform == "depop":
        urls.append(f"https://www.depop.com/search/?q={q}")
    elif platform == "poshmark":
        urls.append(f"https://poshmark.com/search?query={q}&type=listings&src=dir")
    elif platform == "grailed":
        urls.append(f"https://www.grailed.com/shop?search={q}")
    elif platform == "mercari":
        urls.append(f"https://www.mercari.com/search/?keyword={q}")
    elif platform == "mercari_japan":
        urls.append(f"https://jp.mercari.com/search?keyword={q}")
    elif platform == "bunjang":
        urls.append(f"https://m.bunjang.co.kr/search/products?q={q}")
        urls.append(f"https://bunjang.co.kr/search/products?q={q}")
    return urls


# ----------------------------- parsing ------------------------------------
def parse_marketplace_page(
    platform: str,
    html_text: str,
    base_url: str,
    limit: int = DEFAULT_MAX_ITEMS,
    include_raw_json: bool = False,
) -> Dict[str, Any]:
    platform = normalize_platform(platform)
    errors: List[Dict[str, Any]] = []
    items: List[Dict[str, Any]] = []
    if not html_text:
        return {"ok": False, "items": [], "errors": [{"error": "No HTML text supplied."}]}

    json_blobs = extract_json_blobs(html_text)
    for label, blob in json_blobs:
        try:
            found = extract_items_from_json(platform, blob, base_url, limit=limit)
            for item in found:
                item["evidence"] = f"embedded_json:{label}"
                if include_raw_json:
                    item["raw_source"] = compact_json(blob, 3000)
                items.append(item)
                if len(items) >= limit:
                    break
        except Exception as exc:
            errors.append({"stage": "json_extract", "label": label, "error": str(exc)})
        if len(items) >= limit:
            break

    if len(items) < limit:
        items.extend(extract_anchor_items(platform, html_text, base_url, limit=limit - len(items)))

    cleaned = dedupe_items(items)[:limit]
    return {"ok": True, "items": cleaned, "errors": errors, "json_blobs_count": len(json_blobs)}


def extract_json_blobs(html_text: str) -> List[Tuple[str, Any]]:
    blobs: List[Tuple[str, Any]] = []
    # Next.js payloads
    for m in re.finditer(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html_text, re.I | re.S):
        text = html.unescape(m.group(1)).strip()
        add_json_blob(blobs, "__NEXT_DATA__", text)
    # JSON-LD
    for m in re.finditer(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', html_text, re.I | re.S):
        text = html.unescape(m.group(1)).strip()
        add_json_blob(blobs, "json_ld", text)
    # Generic hydration tags
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', html_text, re.I | re.S):
        text = m.group(1) or ""
        if len(text) < 50:
            continue
        for name in ("__APOLLO_STATE__", "__INITIAL_STATE__", "__PRELOADED_STATE__", "__NUXT__", "window.__data"):
            if name in text:
                for candidate in possible_json_literals(text):
                    add_json_blob(blobs, name, candidate)
    return blobs[:40]


def add_json_blob(blobs: List[Tuple[str, Any]], label: str, text: str) -> None:
    text = (text or "").strip().rstrip(";")
    if not text:
        return
    try:
        blobs.append((label, json.loads(text)))
        return
    except Exception:
        pass
    # HTML script assignment: window.foo = {...};
    m = re.search(r"({.*})", text, re.S)
    if m:
        sample = m.group(1)
        try:
            blobs.append((label, json.loads(sample)))
        except Exception:
            pass


def possible_json_literals(text: str) -> List[str]:
    out: List[str] = []
    # Conservative extraction only. Avoid trying to execute JS.
    for m in re.finditer(r"=\s*({.*?})\s*;", text, re.S):
        candidate = m.group(1)
        if len(candidate) > 100 and len(candidate) < 2_000_000:
            out.append(candidate)
    return out[:8]


def extract_items_from_json(platform: str, blob: Any, base_url: str, limit: int = DEFAULT_MAX_ITEMS) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for node in walk_json(blob, max_nodes=25000):
        if not isinstance(node, dict):
            continue
        item = dict_to_item(platform, node, base_url)
        if item:
            rows.append(item)
            if len(rows) >= limit:
                break
    return rows


def dict_to_item(platform: str, node: Dict[str, Any], base_url: str) -> Optional[Dict[str, Any]]:
    title = first_text(node, ["title", "name", "description", "displayName", "listingTitle", "itemName", "productName"])
    url = first_text(node, ["url", "href", "canonicalUrl", "webUrl", "permalink", "productUrl", "itemUrl"])
    if not url:
        id_value = first_text(node, ["id", "listingId", "itemId", "productId", "slug"])
        url = url_from_platform_id(platform, id_value)
    if url:
        url = absolutize(base_url or PLATFORM_HOME.get(platform, ""), url)
    price, currency = extract_price_from_node(node)
    image = first_text(node, ["image", "imageUrl", "picture", "photo", "thumbnail", "thumbnailUrl"])
    if isinstance(node.get("images"), list) and not image:
        image = first_nested_text(node.get("images"), ["url", "src", "imageUrl"])
    if isinstance(node.get("photos"), list) and not image:
        image = first_nested_text(node.get("photos"), ["url", "src", "imageUrl"])
    seller = first_text(node, ["seller", "sellerName", "username", "userName", "owner", "shopName"])
    brand = first_text(node, ["brand", "brandName", "designer", "designerName", "manufacturer"])
    size = first_text(node, ["size", "sizeName", "displaySize"])
    condition = first_text(node, ["condition", "conditionName", "itemCondition"])
    sold = truthy_from_node(node, ["sold", "isSold", "soldOut", "isSoldOut", "status"])

    if not title and not url:
        return None
    if url and not is_platform_item_url(platform, url):
        # Keep schema.org Product pages even when URL pattern is not exact.
        kind = str(node.get("@type", "")).lower()
        if "product" not in kind and not price:
            return None
    if not price and not title:
        return None

    return normalize_item(
        {
            "platform": platform,
            "title": clean_text(title)[:300],
            "url": url,
            "price": price,
            "currency": currency,
            "image": absolutize(base_url or PLATFORM_HOME.get(platform, ""), image) if image else "",
            "seller": clean_text(seller)[:120],
            "brand": clean_text(brand)[:120],
            "size": clean_text(size)[:80],
            "condition": clean_text(condition)[:120],
            "sold": sold,
            "id": first_text(node, ["id", "listingId", "itemId", "productId"]),
            "fetched_at": utc_now_iso(),
        }
    )


def extract_anchor_items(platform: str, html_text: str, base_url: str, limit: int = DEFAULT_MAX_ITEMS) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for m in re.finditer(r'<a\b([^>]*?)href=["\']([^"\']+)["\']([^>]*)>(.*?)</a>', html_text, re.I | re.S):
        href = html.unescape(m.group(2)).strip()
        url = absolutize(base_url or PLATFORM_HOME.get(platform, ""), href)
        if not is_platform_item_url(platform, url):
            continue
        inner = m.group(4) or ""
        title = clean_text(inner)
        context_start = max(0, m.start() - 1200)
        context_end = min(len(html_text), m.end() + 1200)
        context = html_text[context_start:context_end]
        price, currency = extract_price_from_text(context)
        image = extract_first_image_url(context, base_url or PLATFORM_HOME.get(platform, ""))
        rows.append(
            normalize_item(
                {
                    "platform": platform,
                    "title": title[:300],
                    "url": url,
                    "price": price,
                    "currency": currency,
                    "image": image,
                    "seller": "",
                    "brand": "",
                    "size": "",
                    "condition": "",
                    "sold": None,
                    "id": id_from_url(url),
                    "evidence": "html_anchor",
                    "fetched_at": utc_now_iso(),
                }
            )
        )
        if len(rows) >= limit:
            break
    return rows


# ----------------------------- filtering ----------------------------------
def dedupe_and_filter_items(items: Sequence[Dict[str, Any]], spec: ResaleSearchSpec) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in dedupe_items(items):
        if item_matches_spec(item, spec):
            out.append(item)
    return out


def dedupe_items(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for item in items or []:
        norm = normalize_item(dict(item))
        key = item_key(norm)
        if key in seen:
            continue
        seen.add(key)
        out.append(norm)
    return out


def item_matches_spec(item: Dict[str, Any], spec: ResaleSearchSpec) -> bool:
    price = safe_float(item.get("price"))
    if spec.min_price is not None and price is not None and price < float(spec.min_price):
        return False
    if spec.max_price is not None and price is not None and price > float(spec.max_price):
        return False
    if spec.currency and item.get("currency") and str(item.get("currency")).upper() != spec.currency.upper():
        return False
    hay = " ".join(str(item.get(k, "")) for k in ("title", "brand", "size", "condition", "seller")).lower()
    # Soft keyword check: require at least one meaningful token from query unless the parsed item came from an exact platform item URL.
    tokens = [t for t in re.split(r"\W+", spec.query.lower()) if len(t) >= 3]
    if tokens and hay:
        if not any(t in hay for t in tokens[:8]):
            # Some sites omit title text in anchors; do not drop URL-only finds.
            if item.get("title"):
                return False
    return True


def evaluate_resale_alerts(item: Dict[str, Any], rules: Dict[str, Any], is_new: bool = True) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    if not isinstance(rules, dict):
        rules = {}
    title = str(item.get("title", ""))
    hay = " ".join(str(item.get(k, "")) for k in ("title", "brand", "size", "condition", "seller")).lower()
    price = safe_float(item.get("price"))
    max_price = safe_float(rules.get("max_price"))
    min_price = safe_float(rules.get("min_price"))
    required_words = [str(x).lower() for x in rules.get("required_words", []) if str(x).strip()]
    banned_words = [str(x).lower() for x in rules.get("banned_words", []) if str(x).strip()]

    passed = True
    reasons: List[str] = []
    if rules.get("new_only", False) and not is_new:
        passed = False
    if max_price is not None and price is not None and price > max_price:
        passed = False
    if min_price is not None and price is not None and price < min_price:
        passed = False
    if required_words and not all(w in hay for w in required_words):
        passed = False
    if banned_words and any(w in hay for w in banned_words):
        passed = False
    if is_new:
        reasons.append("new_listing")
    if max_price is not None and price is not None and price <= max_price:
        reasons.append(f"price<= {max_price}")
    if required_words:
        reasons.append("required_words_match")

    if passed:
        alerts.append(
            {
                "ok": True,
                "kind": "resale_alert",
                "platform": item.get("platform", ""),
                "title": title,
                "price": price,
                "currency": item.get("currency", ""),
                "url": item.get("url", ""),
                "image": item.get("image", ""),
                "is_new": bool(is_new),
                "reasons": reasons,
                "fired_at": utc_now_iso(),
            }
        )
    return alerts


# ----------------------------- helpers ------------------------------------
def coerce_search_spec(row: Dict[str, Any]) -> ResaleSearchSpec:
    if not isinstance(row, dict):
        return ResaleSearchSpec(platform="", query="")
    return ResaleSearchSpec(
        platform=str(row.get("platform", "")),
        query=str(row.get("query", "")),
        brand=str(row.get("brand", "") or ""),
        size=str(row.get("size", "") or ""),
        min_price=safe_float(row.get("min_price")),
        max_price=safe_float(row.get("max_price")),
        currency=str(row.get("currency", "") or ""),
        sort=str(row.get("sort", "newest") or "newest"),
        limit=max(1, min(int(row.get("limit", DEFAULT_MAX_ITEMS) or DEFAULT_MAX_ITEMS), 500)),
        extra={k: v for k, v in row.items() if k not in {"platform", "query", "brand", "size", "min_price", "max_price", "currency", "sort", "limit"}},
    )


def normalize_item(item: Dict[str, Any]) -> Dict[str, Any]:
    platform = normalize_platform(item.get("platform", ""))
    url = str(item.get("url", "") or "").strip()
    price = safe_float(item.get("price"))
    currency = str(item.get("currency", "") or "").strip().upper()
    title = clean_text(str(item.get("title", "") or ""))
    if not item.get("id") and url:
        item["id"] = id_from_url(url)
    item.update(
        {
            "platform": platform,
            "title": title,
            "url": url,
            "price": round_float(price),
            "currency": currency,
            "image": str(item.get("image", "") or "").strip(),
            "seller": clean_text(str(item.get("seller", "") or "")),
            "brand": clean_text(str(item.get("brand", "") or "")),
            "size": clean_text(str(item.get("size", "") or "")),
            "condition": clean_text(str(item.get("condition", "") or "")),
            "sold": item.get("sold") if item.get("sold") is not None else None,
            "id": str(item.get("id", "") or ""),
            "fetched_at": item.get("fetched_at", utc_now_iso()),
        }
    )
    return item


def item_key(item: Dict[str, Any]) -> str:
    platform = normalize_platform(item.get("platform", ""))
    basis = str(item.get("url") or item.get("id") or (str(item.get("title", "")) + str(item.get("price", ""))))
    return hashlib.sha1(f"{platform}|{basis}".encode("utf-8", errors="ignore")).hexdigest()


def build_url(path: str, base: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def absolutize(base_url: str, maybe_url: Any) -> str:
    value = str(maybe_url or "").strip()
    if not value:
        return ""
    if value.startswith("//"):
        return "https:" + value
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return value
    return urljoin(base_url or "", value)


def is_platform_item_url(platform: str, url: str) -> bool:
    platform = normalize_platform(platform)
    parsed = urlparse(url)
    path = parsed.path or ""
    for pattern in PLATFORM_ITEM_PATTERNS.get(platform, []):
        if re.search(pattern, path, re.I):
            return True
    return False


def url_from_platform_id(platform: str, id_value: Any) -> str:
    id_s = str(id_value or "").strip()
    if not id_s or id_s.lower() in {"none", "null"}:
        return ""
    platform = normalize_platform(platform)
    if platform == "grailed" and id_s.isdigit():
        return f"https://www.grailed.com/listings/{id_s}"
    if platform == "bunjang" and id_s.isdigit():
        return f"https://m.bunjang.co.kr/products/{id_s}"
    if platform == "mercari_japan" and re.match(r"^m\d+", id_s, re.I):
        return f"https://jp.mercari.com/item/{id_s}"
    if platform == "mercari" and re.match(r"^m\d+", id_s, re.I):
        return f"https://www.mercari.com/us/item/{id_s}/"
    return ""


def id_from_url(url: str) -> str:
    path = urlparse(url).path.rstrip("/")
    return path.rsplit("/", 1)[-1] if path else ""


def extract_price_from_node(node: Dict[str, Any]) -> Tuple[Optional[float], str]:
    candidates = ["price", "salePrice", "listingPrice", "currentPrice", "amount", "priceAmount", "price_cents", "priceCents"]
    currency = first_text(node, ["currency", "priceCurrency", "currencyCode"])
    for key in candidates:
        if key not in node:
            continue
        value = node.get(key)
        if isinstance(value, dict):
            p = safe_float(value.get("amount") or value.get("value") or value.get("price") or value.get("cents"))
            c = first_text(value, ["currency", "currencyCode", "priceCurrency"]) or currency
            if p is not None:
                if key.lower().endswith("cents") or "cents" in value:
                    p = p / 100.0
                return p, str(c or "").upper()
        elif isinstance(value, (int, float)):
            p = safe_float(value)
            if p is not None:
                if "cents" in key.lower() or (p > 100000 and not currency):
                    p = p / 100.0
                return p, str(currency or "").upper()
        elif isinstance(value, str):
            p, c = extract_price_from_text(value)
            if p is not None:
                return p, (c or currency or "").upper()
    # Look for nested offers: schema.org
    offers = node.get("offers")
    if isinstance(offers, dict):
        p, c = extract_price_from_node(offers)
        if p is not None:
            return p, c or currency
    if isinstance(offers, list):
        for offer in offers:
            if isinstance(offer, dict):
                p, c = extract_price_from_node(offer)
                if p is not None:
                    return p, c or currency
    return None, str(currency or "").upper()


def extract_price_from_text(text: str) -> Tuple[Optional[float], str]:
    sample = html.unescape(text or "")
    patterns = [
        r"(?P<cur>US\$|\$|¥|￥|₩)\s*(?P<num>\d[\d,]*(?:\.\d{1,2})?)",
        r"(?P<num>\d[\d,]*(?:\.\d{1,2})?)\s*(?P<cur>KRW|JPY|USD|EUR|GBP)",
    ]
    for pattern in patterns:
        m = re.search(pattern, sample, re.I)
        if m:
            num = safe_float(m.group("num"))
            cur = KNOWN_CURRENCY_MARKS.get(m.group("cur").upper(), KNOWN_CURRENCY_MARKS.get(m.group("cur"), m.group("cur").upper()))
            return num, cur
    return None, ""


def extract_first_image_url(text: str, base_url: str) -> str:
    m = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', text or "", re.I)
    if m:
        return absolutize(base_url, html.unescape(m.group(1)))
    m = re.search(r'(https?://[^\s"\']+\.(?:jpg|jpeg|png|webp)(?:\?[^\s"\']*)?)', text or "", re.I)
    if m:
        return m.group(1)
    return ""


def first_text(node: Dict[str, Any], keys: Sequence[str]) -> str:
    for key in keys:
        if key in node:
            value = node.get(key)
            if isinstance(value, str):
                return value
            if isinstance(value, (int, float)):
                return str(value)
            if isinstance(value, dict):
                nested = first_text(value, ["name", "title", "url", "href", "value", "text"])
                if nested:
                    return nested
    return ""


def first_nested_text(value: Any, keys: Sequence[str]) -> str:
    if isinstance(value, list):
        for row in value:
            found = first_nested_text(row, keys)
            if found:
                return found
    if isinstance(value, dict):
        return first_text(value, keys)
    if isinstance(value, str):
        return value
    return ""


def truthy_from_node(node: Dict[str, Any], keys: Sequence[str]) -> Optional[bool]:
    for key in keys:
        if key not in node:
            continue
        value = node.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low in {"sold", "sold_out", "soldout", "completed", "closed", "true", "unavailable"}:
                return True
            if low in {"available", "active", "on_sale", "false"}:
                return False
        if isinstance(value, (int, float)):
            return bool(value)
    return None


def walk_json(value: Any, max_nodes: int = 20000) -> Iterable[Any]:
    stack = [value]
    seen = 0
    while stack and seen < max_nodes:
        node = stack.pop()
        seen += 1
        yield node
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def compact_json(value: Any, max_chars: int = 3000) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)[:max_chars]
    except Exception:
        return str(value)[:max_chars]


def compact_page_result(page: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ok": bool(page.get("ok")),
        "platform": page.get("platform", ""),
        "url": page.get("url", ""),
        "final_url": page.get("final_url", ""),
        "status_code": page.get("status_code"),
        "content_type": page.get("content_type", ""),
        "blocked": bool(page.get("blocked", False)),
        "bytes": page.get("bytes", 0),
        "elapsed_ms": page.get("elapsed_ms", 0),
        "error": page.get("error", ""),
        "html_sample": (page.get("html", "") or "")[:1000],
    }


def compact_search_result(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ok": bool(result.get("ok")),
        "platform": result.get("platform", ""),
        "query": result.get("query", ""),
        "count": result.get("count", 0),
        "search_urls": result.get("search_urls", []),
        "errors_count": len(result.get("errors", []) or []),
        "note": result.get("note", ""),
    }


def looks_blocked(status_code: int, text: str) -> bool:
    low = (text or "")[:5000].lower()
    if status_code in {401, 403, 407, 409, 418, 429, 503}:
        return True
    needles = ["captcha", "cloudflare", "access denied", "verify you are human", "unusual traffic", "rate limit", "blocked"]
    return any(n in low for n in needles)


def summarize_http_error(status_code: int, text: str) -> str:
    sample = clean_text((text or "")[:300])
    return f"HTTP {status_code}" + (f": {sample}" if sample else "")


def safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        if isinstance(value, str):
            v = html.unescape(value).strip()
            v = re.sub(r"[^0-9.\-]", "", v.replace(",", ""))
            if not v or v in {"-", "."}:
                return None
            value = v
        f = float(value)
        if not math.isfinite(f):
            return None
        return f
    except Exception:
        return None


def round_float(value: Any, digits: int = 2) -> Optional[float]:
    f = safe_float(value)
    if f is None:
        return None
    return round(f, digits)


def clean_text(text: str) -> str:
    value = html.unescape(text or "")
    value = re.sub(r"(?is)<script.*?>.*?</script>", " ", value)
    value = re.sub(r"(?is)<style.*?>.*?</style>", " ", value)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_limits() -> Dict[str, Any]:
    return {
        "public_pages_only": True,
        "no_login": True,
        "no_captcha_bypass": True,
        "no_proxy_evasion": True,
        "no_checkout_automation": True,
        "respect_marketplace_terms": True,
        "best_effort_public_html": True,
    }


# ----------------------------- CLI ----------------------------------------
def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Safe resale marketplace monitor")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s_search = sub.add_parser("search")
    s_search.add_argument("platform")
    s_search.add_argument("query")
    s_search.add_argument("--max-price", type=float, default=None)
    s_search.add_argument("--limit", type=int, default=DEFAULT_MAX_ITEMS)

    s_urls = sub.add_parser("urls")
    s_urls.add_argument("platform")
    s_urls.add_argument("query")

    sub.add_parser("status")

    args = parser.parse_args()
    if args.cmd == "search":
        print(json.dumps(resale_search(args.platform, args.query, max_price=args.max_price, limit=args.limit), ensure_ascii=False, indent=2))
    elif args.cmd == "urls":
        print(json.dumps(resale_build_search_urls(args.platform, args.query), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(resale_engine_status(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
