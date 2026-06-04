from __future__ import annotations

"""Safe public news/source monitor engine for PromptChat / GPT tools.

What this engine does
---------------------
- Reads public RSS/Atom feeds and public section/search pages.
- Normalizes articles into JSON-safe dictionaries.
- Filters by keywords, sources, category, age, and alert rules.
- Persists a small seen-item state file when requested.

What this engine intentionally does not do
------------------------------------------
- No login, paywall bypass, CAPTCHA solving, proxy evasion, or scraping private content.
- No article text republishing; it stores headline/summary/link metadata only.
- No background scheduling by itself; call it periodically from your app/automation layer.
"""

import hashlib
import html
import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote_plus, urljoin, urlparse

import requests

DEFAULT_TIMEOUT_SEC = 20.0
DEFAULT_MAX_ITEMS = 80
DEFAULT_STATE_PATH = "data/news_monitor/state.json"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 NewsMonitor/1.0"
)

SAFE_NOTICE = (
    "Public news monitor: RSS/public pages only. No login, paywall bypass, CAPTCHA solving, "
    "proxy evasion, private-source access, or content republishing."
)

SOURCE_ALIASES = {
    "cnbc": "cnbc",
    "cnbc_news": "cnbc",
    "fox": "fox",
    "foxnews": "fox",
    "fox_news": "fox",
    "foxbusiness": "fox_business",
    "fox_business": "fox_business",
    "hypebeast": "hypebeast",
    "hb": "hypebeast",
    "vogue": "vogue",
    "vogue_business": "vogue_business",
    "voguebusiness": "vogue_business",
    "reuters": "reuters",
    "ap": "ap",
    "associated_press": "ap",
    "bbc": "bbc",
    "bbc_news": "bbc",
    "cnn": "cnn",
    "the_verge": "the_verge",
    "verge": "the_verge",
    "nyt": "nytimes",
    "nytimes": "nytimes",
    "new_york_times": "nytimes",
    "custom": "custom",
}

# Each source has feed URLs where known and public section/search pages as fallback.
# Feed URLs can change; engine reports per-feed failures instead of trying to bypass protection.
NEWS_SOURCES: Dict[str, Dict[str, Any]] = {
    "cnbc": {
        "name": "CNBC",
        "home": "https://www.cnbc.com",
        "kind": "business",
        "feeds": {
            "top": ["https://www.cnbc.com/id/100003114/device/rss/rss.html"],
            "finance": ["https://www.cnbc.com/id/10000664/device/rss/rss.html"],
            "markets": ["https://www.cnbc.com/id/15839135/device/rss/rss.html"],
            "investing": ["https://www.cnbc.com/id/15839069/device/rss/rss.html"],
            "technology": ["https://www.cnbc.com/id/19854910/device/rss/rss.html"],
        },
        "pages": {
            "top": ["https://www.cnbc.com/"],
            "markets": ["https://www.cnbc.com/markets/"],
            "finance": ["https://www.cnbc.com/finance/"],
            "technology": ["https://www.cnbc.com/technology/"],
        },
        "search": "https://www.cnbc.com/search/?query={query}",
    },
    "fox": {
        "name": "Fox News",
        "home": "https://www.foxnews.com",
        "kind": "news",
        "feeds": {
            "top": ["https://moxie.foxnews.com/google-publisher/latest.xml"],
            "latest": ["https://moxie.foxnews.com/google-publisher/latest.xml"],
            "world": ["https://moxie.foxnews.com/google-publisher/world.xml"],
            "us": ["https://moxie.foxnews.com/google-publisher/us.xml"],
            "politics": ["https://moxie.foxnews.com/google-publisher/politics.xml"],
            "tech": ["https://moxie.foxnews.com/google-publisher/tech.xml"],
            "science": ["https://moxie.foxnews.com/google-publisher/science.xml"],
            "health": ["https://moxie.foxnews.com/google-publisher/health.xml"],
            "sports": ["https://moxie.foxnews.com/google-publisher/sports.xml"],
            "opinion": ["https://moxie.foxnews.com/google-publisher/opinion.xml"],
        },
        "pages": {
            "top": ["https://www.foxnews.com/"],
            "politics": ["https://www.foxnews.com/politics"],
            "world": ["https://www.foxnews.com/world"],
            "us": ["https://www.foxnews.com/us"],
            "tech": ["https://www.foxnews.com/tech"],
        },
        "search": "https://www.foxnews.com/search-results/search?q={query}",
    },
    "fox_business": {
        "name": "Fox Business",
        "home": "https://www.foxbusiness.com",
        "kind": "business",
        "feeds": {},
        "pages": {
            "top": ["https://www.foxbusiness.com/"],
            "markets": ["https://www.foxbusiness.com/markets"],
            "economy": ["https://www.foxbusiness.com/economy"],
            "technology": ["https://www.foxbusiness.com/technology"],
        },
        "search": "https://www.foxbusiness.com/search-results/search?q={query}",
    },
    "hypebeast": {
        "name": "Hypebeast",
        "home": "https://hypebeast.com",
        "kind": "fashion_culture",
        "feeds": {
            "top": ["https://hypebeast.com/feed"],
            "latest": ["https://hypebeast.com/feed"],
        },
        "pages": {
            "top": ["https://hypebeast.com/"],
            "fashion": ["https://hypebeast.com/fashion"],
            "footwear": ["https://hypebeast.com/footwear"],
            "style": ["https://hypebeast.com/style"],
            "art": ["https://hypebeast.com/art"],
        },
        "search": "https://hypebeast.com/search?s={query}",
    },
    "vogue": {
        "name": "Vogue",
        "home": "https://www.vogue.com",
        "kind": "fashion",
        "feeds": {},
        "pages": {
            "top": ["https://www.vogue.com/"],
            "fashion": ["https://www.vogue.com/fashion"],
            "beauty": ["https://www.vogue.com/beauty"],
            "culture": ["https://www.vogue.com/culture"],
            "runway": ["https://www.vogue.com/fashion-shows"],
            "shopping": ["https://www.vogue.com/shopping"],
            "business": ["https://www.vogue.com/business"],
        },
        "search": "https://www.vogue.com/search?q={query}",
    },
    "vogue_business": {
        "name": "Vogue Business",
        "home": "https://www.vogue.com/business",
        "kind": "fashion_business",
        "feeds": {},
        "pages": {
            "top": ["https://www.vogue.com/business"],
            "retail": ["https://www.vogue.com/business/retail"],
            "technology": ["https://www.vogue.com/business/technology"],
            "sustainability": ["https://www.vogue.com/business/sustainability"],
        },
        "search": "https://www.vogue.com/search?q={query}",
    },
    "reuters": {
        "name": "Reuters",
        "home": "https://www.reuters.com",
        "kind": "wire",
        "feeds": {},
        "pages": {
            "top": ["https://www.reuters.com/"],
            "business": ["https://www.reuters.com/business/"],
            "markets": ["https://www.reuters.com/markets/"],
            "technology": ["https://www.reuters.com/technology/"],
            "world": ["https://www.reuters.com/world/"],
        },
        "search": "https://www.reuters.com/site-search/?query={query}",
    },
    "ap": {
        "name": "Associated Press",
        "home": "https://apnews.com",
        "kind": "wire",
        "feeds": {},
        "pages": {
            "top": ["https://apnews.com/"],
            "world": ["https://apnews.com/world-news"],
            "business": ["https://apnews.com/business"],
            "technology": ["https://apnews.com/technology"],
            "politics": ["https://apnews.com/politics"],
        },
        "search": "https://apnews.com/search?q={query}",
    },
    "bbc": {
        "name": "BBC News",
        "home": "https://www.bbc.com/news",
        "kind": "news",
        "feeds": {
            "top": ["https://feeds.bbci.co.uk/news/rss.xml"],
            "world": ["https://feeds.bbci.co.uk/news/world/rss.xml"],
            "business": ["https://feeds.bbci.co.uk/news/business/rss.xml"],
            "technology": ["https://feeds.bbci.co.uk/news/technology/rss.xml"],
        },
        "pages": {"top": ["https://www.bbc.com/news"]},
        "search": "https://www.bbc.co.uk/search?q={query}",
    },
    "cnn": {
        "name": "CNN",
        "home": "https://www.cnn.com",
        "kind": "news",
        "feeds": {
            "top": ["http://rss.cnn.com/rss/cnn_topstories.rss"],
            "world": ["http://rss.cnn.com/rss/cnn_world.rss"],
            "business": ["http://rss.cnn.com/rss/money_latest.rss"],
            "technology": ["http://rss.cnn.com/rss/cnn_tech.rss"],
        },
        "pages": {"top": ["https://www.cnn.com/"]},
        "search": "https://www.cnn.com/search?q={query}",
    },
    "the_verge": {
        "name": "The Verge",
        "home": "https://www.theverge.com",
        "kind": "technology",
        "feeds": {"top": ["https://www.theverge.com/rss/index.xml"]},
        "pages": {"top": ["https://www.theverge.com/"], "tech": ["https://www.theverge.com/tech"]},
        "search": "https://www.theverge.com/search?q={query}",
    },
    "nytimes": {
        "name": "New York Times",
        "home": "https://www.nytimes.com",
        "kind": "news",
        "feeds": {
            "top": ["https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml"],
            "business": ["https://rss.nytimes.com/services/xml/rss/nyt/Business.xml"],
            "technology": ["https://rss.nytimes.com/services/xml/rss/nyt/Technology.xml"],
            "fashion": ["https://rss.nytimes.com/services/xml/rss/nyt/FashionandStyle.xml"],
        },
        "pages": {"top": ["https://www.nytimes.com/"]},
        "search": "https://www.nytimes.com/search?query={query}",
    },
}

@dataclass
class NewsWatchSpec:
    source: str = ""
    category: str = "top"
    query: str = ""
    url: str = ""
    required_words: Sequence[str] = field(default_factory=list)
    banned_words: Sequence[str] = field(default_factory=list)
    limit: int = DEFAULT_MAX_ITEMS
    max_age_hours: Optional[float] = None

@dataclass
class NewsEngineConfig:
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    verify_tls: bool = True
    state_path: str = DEFAULT_STATE_PATH
    user_agent: str = DEFAULT_USER_AGENT
    write_state: bool = False
    include_html: bool = False
    include_raw: bool = False
    polite_delay_sec: float = 0.25
    max_items: int = DEFAULT_MAX_ITEMS

class NewsEngine:
    def __init__(self, config: Optional[NewsEngineConfig] = None) -> None:
        self.config = config or NewsEngineConfig()
        self.config.timeout_sec = float(self.config.timeout_sec or DEFAULT_TIMEOUT_SEC)
        self.config.max_items = clamp_int(self.config.max_items, DEFAULT_MAX_ITEMS, 1, 1000)
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=16, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update(
            {
                "User-Agent": self.config.user_agent or DEFAULT_USER_AGENT,
                "Accept": "application/rss+xml,application/atom+xml,application/xml,text/xml,text/html,application/json;q=0.9,*/*;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
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

    # ----------------------------- fetch ---------------------------------
    def fetch_url(self, url: str) -> Dict[str, Any]:
        clean = normalize_url(url)
        started = time.time()
        try:
            resp = self.session.get(
                clean,
                timeout=self.config.timeout_sec,
                verify=bool(self.config.verify_tls),
                allow_redirects=True,
            )
            elapsed_ms = int((time.time() - started) * 1000)
            text = resp.text or ""
            ctype = resp.headers.get("content-type", "")
            blocked = looks_blocked(resp.status_code, text)
            return {
                "ok": resp.status_code < 400 and not blocked,
                "url": clean,
                "final_url": resp.url,
                "status_code": resp.status_code,
                "content_type": ctype,
                "elapsed_ms": elapsed_ms,
                "bytes": len(resp.content or b""),
                "blocked": blocked,
                "text": text,
                "error": summarize_http_error(resp.status_code, text) if resp.status_code >= 400 else ("Public request appears blocked/rate-limited/browser-gated." if blocked else ""),
            }
        except Exception as exc:
            return {"ok": False, "url": clean, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}

    def fetch_source(self, source: str, category: str = "top", query: str = "", limit: int = DEFAULT_MAX_ITEMS) -> Dict[str, Any]:
        started = time.time()
        src = normalize_source(source)
        urls_info = news_build_source_urls(src, category=category, query=query)
        if not urls_info.get("ok"):
            return urls_info
        rows: List[Dict[str, Any]] = []
        pages: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        url_rows = urls_info.get("urls", [])[:8]
        for idx, urow in enumerate(url_rows):
            if idx and self.config.polite_delay_sec > 0:
                time.sleep(float(self.config.polite_delay_sec))
            url = str(urow.get("url", ""))
            kind = str(urow.get("kind", "auto"))
            page = self.fetch_url(url)
            pages.append(compact_page(page, keep_html=self.config.include_html))
            if not page.get("ok"):
                errors.append(compact_page(page))
                continue
            text = str(page.get("text", "") or "")
            if kind == "feed" or looks_like_feed(text, page.get("content_type", "")):
                parsed = parse_feed_text(text, source=src, base_url=page.get("final_url") or url, limit=limit, include_raw=self.config.include_raw)
            else:
                parsed = parse_news_html(text, source=src, base_url=page.get("final_url") or url, limit=limit, include_raw=self.config.include_raw)
            rows.extend(parsed.get("items", []))
            errors.extend(parsed.get("errors", []))
            if len(rows) >= limit:
                break
        source_meta = NEWS_SOURCES.get(src, {})
        items = dedupe_news_items(rows)
        spec = NewsWatchSpec(source=src, category=category, query=query, limit=limit)
        items = filter_news_items(items, spec)[: clamp_int(limit, DEFAULT_MAX_ITEMS, 1, 1000)]
        return {
            "ok": bool(items) or bool(pages),
            "engine": "news_engine",
            "mode": "fetch_source",
            "source": src,
            "source_name": source_meta.get("name", src),
            "category": category or "top",
            "query": query or "",
            "count": len(items),
            "items": items,
            "pages": pages,
            "errors": errors[:20],
            "urls": url_rows,
            "notice": SAFE_NOTICE,
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    def search(self, query: str, sources: Optional[Sequence[str]] = None, category: str = "top", limit_per_source: int = 20) -> Dict[str, Any]:
        started = time.time()
        clean_query = (query or "").strip()
        if not clean_query:
            return {"ok": False, "error": "query is required"}
        srcs = [normalize_source(s) for s in (sources or ["cnbc", "fox", "hypebeast", "vogue", "bbc", "the_verge"])]
        results: List[Dict[str, Any]] = []
        all_items: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        for src in unique_keep_order(srcs):
            result = self.fetch_source(src, category=category or "top", query=clean_query, limit=limit_per_source)
            results.append(compact_source_result(result))
            all_items.extend(result.get("items", []) or [])
            errors.extend(result.get("errors", []) or [])
        all_items = dedupe_news_items(all_items)
        spec = NewsWatchSpec(query=clean_query, required_words=split_words(clean_query), limit=len(all_items) or DEFAULT_MAX_ITEMS)
        # Search should keep semantic broad matches, so do not require every token if too many.
        if len(spec.required_words) > 5:
            spec.required_words = spec.required_words[:5]
        filtered = filter_news_items(all_items, spec)
        return {
            "ok": bool(filtered) or bool(results),
            "engine": "news_engine",
            "mode": "search",
            "query": clean_query,
            "sources": unique_keep_order(srcs),
            "count": len(filtered),
            "items": filtered,
            "results": results,
            "errors": errors[:30],
            "notice": SAFE_NOTICE,
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    def monitor(self, watches: Sequence[Mapping[str, Any]], alert_rules: Optional[Mapping[str, Any]] = None, new_only: bool = True) -> Dict[str, Any]:
        started = time.time()
        rules = dict(alert_rules or {})
        state = self._load_state()
        all_items: List[Dict[str, Any]] = []
        alerts: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        for row in watches or []:
            spec = coerce_watch_spec(row)
            if spec.url:
                result = fetch_custom_url(self, spec)
            else:
                result = self.fetch_source(spec.source, category=spec.category, query=spec.query, limit=spec.limit)
            results.append(compact_source_result(result))
            if not result.get("ok") and not result.get("items"):
                errors.append({"source": spec.source, "category": spec.category, "query": spec.query, "url": spec.url, "error": result.get("error", "") or result.get("errors", [])})
            items = filter_news_items(result.get("items", []) or [], spec)
            for item in items:
                key = news_item_key(item)
                was_seen = key in state.get("seen", {})
                item["seen_before"] = was_seen
                if not was_seen or not new_only:
                    all_items.append(item)
                    alerts.extend(evaluate_news_alerts(item, rules, is_new=not was_seen))
                state.setdefault("seen", {})[key] = {
                    "first_seen_at": state.get("seen", {}).get(key, {}).get("first_seen_at", utc_now_iso()),
                    "last_seen_at": utc_now_iso(),
                    "source": item.get("source", ""),
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "published_at": item.get("published_at", ""),
                }
        if self.config.write_state:
            state.setdefault("runs", []).append({"ran_at": utc_now_iso(), "watches": len(watches or []), "items": len(all_items), "alerts": len(alerts)})
            state["runs"] = state.get("runs", [])[-200:]
            self._save_state(state)
        return {
            "ok": bool(all_items) or bool(results),
            "engine": "news_engine",
            "mode": "monitor",
            "watches_count": len(watches or []),
            "new_only": bool(new_only),
            "items_count": len(all_items),
            "alerts_count": len(alerts),
            "errors_count": len(errors),
            "items": all_items,
            "alerts": alerts,
            "results": results,
            "errors": errors[:30],
            "state_path": self.config.state_path if self.config.write_state else "",
            "notice": SAFE_NOTICE,
            "elapsed_ms": int((time.time() - started) * 1000),
        }

# ----------------------------- public funcs -------------------------------
def news_fetch_source(
    source: str,
    category: str = "top",
    query: str = "",
    limit: int = DEFAULT_MAX_ITEMS,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    include_html: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    engine = NewsEngine(NewsEngineConfig(timeout_sec=timeout_sec, verify_tls=verify_tls, include_html=include_html, include_raw=include_raw, max_items=limit))
    return engine.fetch_source(source, category=category, query=query, limit=limit)


def news_search(
    query: str,
    sources: Optional[Sequence[str]] = None,
    category: str = "top",
    limit_per_source: int = 20,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    include_html: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    engine = NewsEngine(NewsEngineConfig(timeout_sec=timeout_sec, verify_tls=verify_tls, include_html=include_html, include_raw=include_raw, max_items=limit_per_source))
    return engine.search(query, sources=sources, category=category, limit_per_source=limit_per_source)


def news_monitor(
    watches: Sequence[Dict[str, Any]],
    alert_rules: Optional[Dict[str, Any]] = None,
    new_only: bool = True,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    write_state: bool = False,
    state_path: str = DEFAULT_STATE_PATH,
    include_html: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    engine = NewsEngine(
        NewsEngineConfig(
            timeout_sec=timeout_sec,
            verify_tls=verify_tls,
            write_state=write_state,
            state_path=state_path or DEFAULT_STATE_PATH,
            include_html=include_html,
            include_raw=include_raw,
        )
    )
    return engine.monitor(watches, alert_rules=alert_rules or {}, new_only=new_only)


def news_parse_feed(
    xml_or_html_text: str,
    source: str = "custom",
    base_url: str = "",
    query: str = "",
    limit: int = DEFAULT_MAX_ITEMS,
    include_raw: bool = False,
) -> Dict[str, Any]:
    src = normalize_source(source or "custom")
    text = xml_or_html_text or ""
    if looks_like_feed(text, ""):
        parsed = parse_feed_text(text, source=src, base_url=base_url or NEWS_SOURCES.get(src, {}).get("home", ""), limit=limit, include_raw=include_raw)
    else:
        parsed = parse_news_html(text, source=src, base_url=base_url or NEWS_SOURCES.get(src, {}).get("home", ""), limit=limit, include_raw=include_raw)
    spec = NewsWatchSpec(source=src, query=query, required_words=split_words(query), limit=limit)
    items = filter_news_items(parsed.get("items", []), spec)[: clamp_int(limit, DEFAULT_MAX_ITEMS, 1, 1000)]
    return {
        "ok": True,
        "engine": "news_engine",
        "mode": "parse_feed",
        "source": src,
        "base_url": base_url or "",
        "query": query or "",
        "count": len(items),
        "items": items,
        "errors": parsed.get("errors", []),
        "notice": SAFE_NOTICE,
    }


def news_build_source_urls(source: str = "", category: str = "top", query: str = "", custom_url: str = "") -> Dict[str, Any]:
    if custom_url:
        return {"ok": True, "source": "custom", "category": category or "top", "query": query or "", "count": 1, "urls": [{"url": normalize_url(custom_url), "kind": "auto", "label": "custom"}]}
    src = normalize_source(source or "cnbc")
    if src not in NEWS_SOURCES:
        return {"ok": False, "source": source, "error": f"Unsupported news source: {source}", "supported_sources": sorted(NEWS_SOURCES)}
    meta = NEWS_SOURCES[src]
    cat = (category or "top").strip().lower()
    rows: List[Dict[str, str]] = []
    if query and meta.get("search"):
        rows.append({"url": str(meta["search"]).format(query=quote_plus(query)), "kind": "page", "label": "search"})
    feeds = meta.get("feeds", {}) or {}
    pages = meta.get("pages", {}) or {}
    for f in feeds.get(cat, []) or feeds.get("top", []):
        rows.append({"url": f, "kind": "feed", "label": f"{cat or 'top'} feed"})
    for p in pages.get(cat, []) or pages.get("top", []):
        rows.append({"url": p, "kind": "page", "label": f"{cat or 'top'} page"})
    seen: set[str] = set()
    deduped: List[Dict[str, str]] = []
    for row in rows:
        u = row.get("url", "")
        if not u or u in seen:
            continue
        seen.add(u)
        deduped.append(row)
    return {
        "ok": True,
        "engine": "news_engine",
        "mode": "build_source_urls",
        "source": src,
        "source_name": meta.get("name", src),
        "category": cat,
        "query": query or "",
        "count": len(deduped),
        "urls": deduped,
        "notice": SAFE_NOTICE,
    }


def news_engine_status() -> Dict[str, Any]:
    return {
        "ok": True,
        "engine": "news_engine",
        "version": 1,
        "supported_sources": sorted(NEWS_SOURCES),
        "aliases": SOURCE_ALIASES,
        "sources": {k: {"name": v.get("name"), "home": v.get("home"), "kind": v.get("kind"), "feed_categories": sorted((v.get("feeds") or {}).keys()), "page_categories": sorted((v.get("pages") or {}).keys()), "has_search": bool(v.get("search"))} for k, v in NEWS_SOURCES.items()},
        "notice": SAFE_NOTICE,
    }

# ----------------------------- parsers ------------------------------------
def parse_feed_text(text: str, source: str = "custom", base_url: str = "", limit: int = DEFAULT_MAX_ITEMS, include_raw: bool = False) -> Dict[str, Any]:
    errors: List[Dict[str, Any]] = []
    items: List[Dict[str, Any]] = []
    raw = (text or "").strip()
    if not raw:
        return {"ok": False, "items": [], "errors": [{"error": "empty feed"}]}
    try:
        root = ET.fromstring(raw.encode("utf-8", errors="ignore"))
    except Exception as exc:
        return {"ok": False, "items": [], "errors": [{"error": f"feed XML parse failed: {exc}"}]}

    limit_n = clamp_int(limit, DEFAULT_MAX_ITEMS, 1, 1000)
    # RSS 2.0 items
    rss_items = root.findall(".//item")
    atom_entries = root.findall(".//{http://www.w3.org/2005/Atom}entry") or root.findall(".//entry")
    for node in rss_items[:limit_n]:
        item = rss_item_to_dict(node, source=source, base_url=base_url, include_raw=include_raw)
        if item:
            items.append(item)
    if not items:
        for node in atom_entries[:limit_n]:
            item = atom_entry_to_dict(node, source=source, base_url=base_url, include_raw=include_raw)
            if item:
                items.append(item)
    return {"ok": True, "items": dedupe_news_items(items)[:limit_n], "errors": errors}


def rss_item_to_dict(node: ET.Element, source: str, base_url: str, include_raw: bool) -> Dict[str, Any]:
    title = clean_text(child_text(node, "title"))
    link = clean_text(child_text(node, "link"))
    guid = clean_text(child_text(node, "guid"))
    desc = clean_text(child_text(node, "description"))
    pub = child_text(node, "pubDate") or child_text(node, "date")
    author = child_text(node, "author") or child_text(node, "{http://purl.org/dc/elements/1.1/}creator")
    categories = [clean_text(c.text or "") for c in node.findall("category") if clean_text(c.text or "")]
    # media thumbnail/content
    image = ""
    for media_tag in ("{http://search.yahoo.com/mrss/}thumbnail", "{http://search.yahoo.com/mrss/}content"):
        m = node.find(media_tag)
        if m is not None and m.attrib.get("url"):
            image = m.attrib.get("url", "")
            break
    if not link and guid.startswith("http"):
        link = guid
    url = urljoin(base_url or "", link) if link else ""
    out = normalize_news_item({
        "source": source,
        "title": title,
        "url": url,
        "id": guid or url or title,
        "summary": desc,
        "author": clean_text(author),
        "published_at": parse_datetime_to_iso(pub),
        "categories": categories,
        "image_url": image,
        "raw_kind": "rss_item",
    })
    if include_raw:
        out["raw_xml"] = ET.tostring(node, encoding="unicode")[:20000]
    return out


def atom_entry_to_dict(node: ET.Element, source: str, base_url: str, include_raw: bool) -> Dict[str, Any]:
    ns = "{http://www.w3.org/2005/Atom}"
    title = clean_text(child_text(node, f"{ns}title") or child_text(node, "title"))
    summary = clean_text(child_text(node, f"{ns}summary") or child_text(node, f"{ns}content") or child_text(node, "summary"))
    link = ""
    for lnk in node.findall(f"{ns}link") + node.findall("link"):
        href = lnk.attrib.get("href", "")
        rel = lnk.attrib.get("rel", "alternate")
        if href and rel in {"alternate", ""}:
            link = href
            break
    published = child_text(node, f"{ns}published") or child_text(node, f"{ns}updated") or child_text(node, "published") or child_text(node, "updated")
    author = ""
    auth = node.find(f"{ns}author") or node.find("author")
    if auth is not None:
        author = child_text(auth, f"{ns}name") or child_text(auth, "name") or clean_text(auth.text or "")
    categories = [c.attrib.get("term", "") for c in node.findall(f"{ns}category") if c.attrib.get("term")]
    url = urljoin(base_url or "", link) if link else ""
    out = normalize_news_item({
        "source": source,
        "title": title,
        "url": url,
        "id": child_text(node, f"{ns}id") or url or title,
        "summary": summary,
        "author": clean_text(author),
        "published_at": parse_datetime_to_iso(published),
        "categories": categories,
        "raw_kind": "atom_entry",
    })
    if include_raw:
        out["raw_xml"] = ET.tostring(node, encoding="unicode")[:20000]
    return out


def parse_news_html(text: str, source: str = "custom", base_url: str = "", limit: int = DEFAULT_MAX_ITEMS, include_raw: bool = False) -> Dict[str, Any]:
    html_text = text or ""
    limit_n = clamp_int(limit, DEFAULT_MAX_ITEMS, 1, 1000)
    items: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    # JSON-LD NewsArticle/Article blocks are the cleanest source when present.
    for block in extract_json_ld_blocks(html_text):
        for obj in iter_json_objects(block):
            item = json_article_to_item(obj, source=source, base_url=base_url)
            if item:
                if include_raw:
                    item["raw_json"] = compact_json(obj)
                items.append(item)
                if len(items) >= limit_n:
                    break
        if len(items) >= limit_n:
            break

    # Generic anchor fallback: useful for Vogue/Hypebeast/CNBC sections.
    if len(items) < limit_n:
        for item in extract_anchor_articles(html_text, source=source, base_url=base_url, limit=limit_n * 3):
            items.append(item)
            if len(items) >= limit_n:
                break

    items = dedupe_news_items(items)[:limit_n]
    if not items:
        errors.append({"error": "No article-like items found in public HTML."})
    return {"ok": True, "items": items, "errors": errors}


def extract_json_ld_blocks(html_text: str) -> List[Any]:
    blocks: List[Any] = []
    for m in re.finditer(r'(?is)<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', html_text or ""):
        raw = html.unescape(m.group(1)).strip()
        if not raw:
            continue
        try:
            blocks.append(json.loads(raw))
        except Exception:
            # Some pages include invalid trailing JS-ish text; skip rather than guessing too hard.
            continue
    return blocks


def iter_json_objects(obj: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(obj, Mapping):
        yield obj
        graph = obj.get("@graph")
        if isinstance(graph, list):
            for item in graph:
                yield from iter_json_objects(item)
        for key in ("itemListElement", "hasPart", "mainEntity", "about"):
            val = obj.get(key)
            if isinstance(val, list):
                for item in val:
                    yield from iter_json_objects(item)
            elif isinstance(val, Mapping):
                yield from iter_json_objects(val)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_json_objects(item)


def json_article_to_item(obj: Mapping[str, Any], source: str, base_url: str) -> Dict[str, Any]:
    typ = obj.get("@type") or obj.get("type") or ""
    if isinstance(typ, list):
        type_text = " ".join(map(str, typ)).lower()
    else:
        type_text = str(typ).lower()
    url = obj.get("url") or obj.get("mainEntityOfPage") or ""
    if isinstance(url, Mapping):
        url = url.get("@id") or url.get("url") or ""
    name = obj.get("headline") or obj.get("name") or ""
    if not name or ("article" not in type_text and "news" not in type_text and not url):
        return {}
    author = obj.get("author") or ""
    if isinstance(author, list):
        author = ", ".join([str(a.get("name", a)) if isinstance(a, Mapping) else str(a) for a in author])
    elif isinstance(author, Mapping):
        author = author.get("name", "")
    image = obj.get("image") or ""
    if isinstance(image, list):
        image = image[0] if image else ""
    if isinstance(image, Mapping):
        image = image.get("url") or image.get("@id") or ""
    return normalize_news_item({
        "source": source,
        "title": clean_text(str(name)),
        "url": urljoin(base_url or "", str(url)) if url else "",
        "id": obj.get("@id") or url or name,
        "summary": clean_text(str(obj.get("description") or obj.get("abstract") or "")),
        "author": clean_text(str(author)),
        "published_at": parse_datetime_to_iso(obj.get("datePublished") or obj.get("dateModified") or ""),
        "categories": [clean_text(str(obj.get("articleSection") or ""))] if obj.get("articleSection") else [],
        "image_url": urljoin(base_url or "", str(image)) if image else "",
        "raw_kind": "json_ld_article",
    })


def extract_anchor_articles(html_text: str, source: str, base_url: str, limit: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    base_host = urlparse(base_url).netloc
    article_url_re = re.compile(r"/(?:news|article|articles|story|stories|business|markets|technology|tech|fashion|style|culture|runway|shopping|world|politics|us|health|science|footwear|art|design|entertainment|sports|202\d|20\d\d/\d\d/\d\d)/", re.I)
    for m in re.finditer(r'(?is)<a\b([^>]*)href=["\']([^"\']+)["\']([^>]*)>(.*?)</a>', html_text or ""):
        href = html.unescape(m.group(2)).strip()
        if not href or href.startswith("#") or href.lower().startswith(("javascript:", "mailto:", "tel:")):
            continue
        url = urljoin(base_url or "", href)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            continue
        if base_host and parsed.netloc and parsed.netloc != base_host and parsed.netloc.replace("www.", "") != base_host.replace("www.", ""):
            # Skip unrelated social/CDN links.
            continue
        label = clean_text(m.group(4))
        if len(label) < 12:
            continue
        if not article_url_re.search(parsed.path + "/") and len(label.split()) < 5:
            continue
        key = url.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        rows.append(normalize_news_item({
            "source": source,
            "title": label[:300],
            "url": key,
            "id": key,
            "summary": "",
            "published_at": "",
            "categories": infer_categories_from_url(key),
            "raw_kind": "html_anchor",
        }))
        if len(rows) >= limit:
            break
    return rows

# ----------------------------- filtering ----------------------------------
def filter_news_items(items: Sequence[Dict[str, Any]], spec: NewsWatchSpec) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    req = [w.lower() for w in (spec.required_words or []) if w]
    banned = [w.lower() for w in (spec.banned_words or []) if w]
    if spec.query and not req:
        # Use query terms when explicit required_words are absent, but keep broad enough for section pages.
        req = split_words(spec.query)[:6]
    max_age = spec.max_age_hours
    cutoff: Optional[datetime] = None
    if max_age is not None:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=float(max_age))
        except Exception:
            cutoff = None
    for item in items or []:
        hay = news_haystack(item)
        if banned and any(w in hay for w in banned):
            continue
        if req and not all(w in hay for w in req):
            continue
        if cutoff:
            dt = parse_iso_datetime(item.get("published_at", ""))
            if dt and dt < cutoff:
                continue
        out.append(item)
    return out


def evaluate_news_alerts(item: Mapping[str, Any], rules: Mapping[str, Any], is_new: bool) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    hay = news_haystack(item)
    required = [str(w).lower() for w in rules.get("required_words", []) or []]
    any_words = [str(w).lower() for w in rules.get("any_words", []) or []]
    banned = [str(w).lower() for w in rules.get("banned_words", []) or []]
    sources = [normalize_source(str(s)) for s in rules.get("sources", []) or []]
    categories = [str(c).lower() for c in rules.get("categories", []) or []]
    min_score = safe_float(rules.get("min_score"), None)
    score = 0.0
    if rules.get("new_only", False) and not is_new:
        return []
    if sources and normalize_source(str(item.get("source", ""))) not in sources:
        return []
    cats_text = " ".join(str(c).lower() for c in item.get("categories", []) or [])
    if categories and not any(c in cats_text for c in categories):
        return []
    if banned and any(w in hay for w in banned):
        return []
    if required and not all(w in hay for w in required):
        return []
    if any_words and not any(w in hay for w in any_words):
        return []
    score += 1.0 if is_new else 0.25
    if required:
        score += len(required) * 0.5
    if any_words:
        score += sum(1 for w in any_words if w in hay) * 0.35
    if categories and any(c in cats_text for c in categories):
        score += 0.5
    if min_score is not None and score < min_score:
        return []
    if required or any_words or categories or sources or rules.get("new_only", False):
        alerts.append({
            "type": "news_match",
            "is_new": bool(is_new),
            "score": round(score, 3),
            "source": item.get("source", ""),
            "title": item.get("title", ""),
            "url": item.get("url", ""),
            "published_at": item.get("published_at", ""),
            "note": rules.get("note", ""),
        })
    return alerts

# ----------------------------- helpers ------------------------------------
def fetch_custom_url(engine: NewsEngine, spec: NewsWatchSpec) -> Dict[str, Any]:
    page = engine.fetch_url(spec.url)
    if not page.get("ok"):
        return {"ok": False, "engine": "news_engine", "mode": "fetch_custom_url", "url": spec.url, "items": [], "errors": [compact_page(page)], "notice": SAFE_NOTICE}
    text = page.get("text", "") or ""
    if looks_like_feed(text, page.get("content_type", "")):
        parsed = parse_feed_text(text, source=spec.source or "custom", base_url=page.get("final_url") or spec.url, limit=spec.limit, include_raw=engine.config.include_raw)
    else:
        parsed = parse_news_html(text, source=spec.source or "custom", base_url=page.get("final_url") or spec.url, limit=spec.limit, include_raw=engine.config.include_raw)
    return {"ok": True, "engine": "news_engine", "mode": "fetch_custom_url", "url": spec.url, "items": parsed.get("items", []), "errors": parsed.get("errors", []), "pages": [compact_page(page, keep_html=engine.config.include_html)], "notice": SAFE_NOTICE}


def coerce_watch_spec(row: Mapping[str, Any]) -> NewsWatchSpec:
    return NewsWatchSpec(
        source=normalize_source(str(row.get("source", "") or "custom")),
        category=str(row.get("category", "top") or "top"),
        query=str(row.get("query", "") or ""),
        url=str(row.get("url", "") or ""),
        required_words=to_words(row.get("required_words", [])),
        banned_words=to_words(row.get("banned_words", [])),
        limit=clamp_int(row.get("limit", DEFAULT_MAX_ITEMS), DEFAULT_MAX_ITEMS, 1, 1000),
        max_age_hours=safe_float(row.get("max_age_hours"), None),
    )


def normalize_source(source: str) -> str:
    s = (source or "").strip().lower().replace("-", "_").replace(" ", "_")
    return SOURCE_ALIASES.get(s, s or "custom")


def normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("URL is required")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return raw


def child_text(node: ET.Element, name: str) -> str:
    found = node.find(name)
    if found is None:
        return ""
    return found.text or ""


def clean_text(value: Any) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?s)<.*?>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_datetime_to_iso(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass
    try:
        fixed = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(fixed)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return raw[:80]


def parse_iso_datetime(value: str) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_news_item(item: Mapping[str, Any]) -> Dict[str, Any]:
    url = str(item.get("url", "") or "").strip()
    title = clean_text(item.get("title", ""))
    summary = clean_text(item.get("summary", ""))
    cats = item.get("categories", []) or []
    if isinstance(cats, str):
        cats = [cats]
    cats_clean = [clean_text(c) for c in cats if clean_text(c)]
    return {
        "id": str(item.get("id", "") or url or title_hash(title)),
        "source": normalize_source(str(item.get("source", "") or "custom")),
        "source_name": NEWS_SOURCES.get(normalize_source(str(item.get("source", "") or "custom")), {}).get("name", item.get("source", "custom")),
        "title": title,
        "url": url,
        "summary": summary[:1000],
        "author": clean_text(item.get("author", ""))[:200],
        "published_at": parse_datetime_to_iso(item.get("published_at", "")),
        "categories": cats_clean[:20],
        "image_url": str(item.get("image_url", "") or "")[:1000],
        "raw_kind": str(item.get("raw_kind", "") or ""),
        "fingerprint": news_item_fingerprint(str(item.get("source", "")), title, url),
    }


def dedupe_news_items(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in items or []:
        if not item:
            continue
        key = news_item_key(item)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return sorted(out, key=sort_key_news, reverse=True)


def sort_key_news(item: Mapping[str, Any]) -> Tuple[int, str]:
    dt = parse_iso_datetime(str(item.get("published_at", "")))
    return (int(dt.timestamp()) if dt else 0, str(item.get("title", "")))


def news_item_key(item: Mapping[str, Any]) -> str:
    return str(item.get("fingerprint") or news_item_fingerprint(str(item.get("source", "")), str(item.get("title", "")), str(item.get("url", ""))))


def news_item_fingerprint(source: str, title: str, url: str) -> str:
    seed = "|".join([normalize_source(source), normalize_article_url(url), clean_text(title).lower()[:200]])
    return hashlib.sha1(seed.encode("utf-8", errors="ignore")).hexdigest()


def title_hash(title: str) -> str:
    return hashlib.sha1(clean_text(title).lower().encode("utf-8", errors="ignore")).hexdigest()


def normalize_article_url(url: str) -> str:
    raw = str(url or "").split("#", 1)[0].strip()
    # Keep query for sites where URLs need it, but drop common trackers.
    raw = re.sub(r"([?&])(utm_[^=&]+|fbclid|gclid|srsltid)=[^&]+", r"\1", raw)
    raw = raw.rstrip("?&")
    return raw


def news_haystack(item: Mapping[str, Any]) -> str:
    parts = [item.get("title", ""), item.get("summary", ""), item.get("source", ""), item.get("source_name", ""), " ".join(map(str, item.get("categories", []) or [])), item.get("url", "")]
    return clean_text(" ".join(map(str, parts))).lower()


def split_words(text: str) -> List[str]:
    words = re.findall(r"[\w$#@.\-']{2,}", (text or "").lower())
    stop = {"the", "and", "for", "with", "from", "that", "this", "are", "was", "were", "about", "into", "after", "before", "latest", "news"}
    return [w for w in words if w not in stop]


def to_words(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return split_words(value) if "," not in value else [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, Iterable):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()] if str(value).strip() else []


def clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        n = int(value)
    except Exception:
        n = default
    return max(minimum, min(maximum, n))


def safe_float(value: Any, default: Optional[float]) -> Optional[float]:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def looks_like_feed(text: str, content_type: str = "") -> bool:
    sample = (text or "")[:500].lower()
    ctype = (content_type or "").lower()
    return "rss" in ctype or "atom" in ctype or "xml" in ctype or sample.lstrip().startswith(("<?xml", "<rss", "<feed"))


def looks_blocked(status_code: int, text: str) -> bool:
    if status_code in {401, 403, 429, 503}:
        return True
    sample = (text or "")[:5000].lower()
    needles = ["captcha", "access denied", "verify you are human", "unusual traffic", "cloudflare", "akamai", "rate limit"]
    return any(n in sample for n in needles)


def summarize_http_error(status_code: int, text: str) -> str:
    body = clean_text((text or "")[:1000])
    return f"HTTP {status_code}: {body[:400]}" if body else f"HTTP {status_code}"


def compact_page(page: Mapping[str, Any], keep_html: bool = False) -> Dict[str, Any]:
    out = {
        "ok": bool(page.get("ok")),
        "url": page.get("url", ""),
        "final_url": page.get("final_url", ""),
        "status_code": page.get("status_code", 0),
        "content_type": page.get("content_type", ""),
        "elapsed_ms": page.get("elapsed_ms", 0),
        "bytes": page.get("bytes", 0),
        "blocked": bool(page.get("blocked", False)),
        "error": page.get("error", ""),
    }
    if keep_html:
        out["html_sample"] = (page.get("text", "") or "")[:5000]
    return out


def compact_source_result(result: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "ok": bool(result.get("ok")),
        "source": result.get("source", ""),
        "source_name": result.get("source_name", ""),
        "category": result.get("category", ""),
        "query": result.get("query", ""),
        "count": result.get("count", len(result.get("items", []) or [])),
        "errors_count": len(result.get("errors", []) or []),
        "urls": result.get("urls", [])[:5],
        "elapsed_ms": result.get("elapsed_ms", 0),
    }


def infer_categories_from_url(url: str) -> List[str]:
    path = urlparse(url).path.lower()
    cats: List[str] = []
    for name in ["business", "markets", "technology", "tech", "fashion", "style", "culture", "runway", "shopping", "world", "politics", "health", "science", "sports", "footwear", "art", "design"]:
        if f"/{name}" in path:
            cats.append(name)
    return cats[:5]


def unique_keep_order(values: Sequence[str]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for v in values or []:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def compact_json(obj: Any) -> Any:
    try:
        text = json.dumps(obj, ensure_ascii=False)
        if len(text) > 20000:
            return text[:20000]
        return obj
    except Exception:
        return str(obj)[:20000]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Safe public news monitor engine")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_status = sub.add_parser("status")
    p_urls = sub.add_parser("urls")
    p_urls.add_argument("source")
    p_urls.add_argument("--category", default="top")
    p_urls.add_argument("--query", default="")
    p_fetch = sub.add_parser("fetch")
    p_fetch.add_argument("source")
    p_fetch.add_argument("--category", default="top")
    p_fetch.add_argument("--query", default="")
    p_fetch.add_argument("--limit", type=int, default=20)
    p_search = sub.add_parser("search")
    p_search.add_argument("query")
    p_search.add_argument("--sources", default="cnbc,fox,hypebeast,vogue,bbc,the_verge")
    p_search.add_argument("--limit-per-source", type=int, default=10)
    args = parser.parse_args()
    if args.cmd == "status":
        print(json.dumps(news_engine_status(), ensure_ascii=False, indent=2))
    elif args.cmd == "urls":
        print(json.dumps(news_build_source_urls(args.source, category=args.category, query=args.query), ensure_ascii=False, indent=2))
    elif args.cmd == "fetch":
        print(json.dumps(news_fetch_source(args.source, category=args.category, query=args.query, limit=args.limit), ensure_ascii=False, indent=2))
    elif args.cmd == "search":
        srcs = [s.strip() for s in args.sources.split(",") if s.strip()]
        print(json.dumps(news_search(args.query, sources=srcs, limit_per_source=args.limit_per_source), ensure_ascii=False, indent=2))
