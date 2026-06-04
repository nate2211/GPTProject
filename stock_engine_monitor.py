from __future__ import annotations

"""Safe stock/ETF/crypto quote monitor engine.

Design goals
------------
- One small dependency: requests.
- Public market-data readers only; no trading, no broker login, no scraping paywalled data.
- Designed to plug into PromptChat tools.py using the companion patch file.
- Stateless by default, but can persist snapshots/alert history in data/stock_monitor/state.json.

Notes
-----
Yahoo Finance chart endpoints are unofficial/public web endpoints and may change.
Stooq quote endpoints are used as a fallback for common US/equity symbols. For production,
use an official licensed feed such as Polygon, IEX Cloud, Twelve Data, Alpaca, or a broker API.
"""

import csv
import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests

DEFAULT_TIMEOUT_SEC = 15.0
DEFAULT_STATE_PATH = "data/stock_monitor/state.json"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 StockMonitor/1.0"
)

YAHOO_CHART_URL = "https://query1.finance.yahoo.com/v8/finance/chart/{symbol}"
STOOQ_QUOTE_URL = "https://stooq.com/q/l/"


@dataclass
class StockAlertRule:
    symbol: str
    price_above: Optional[float] = None
    price_below: Optional[float] = None
    percent_change_above: Optional[float] = None
    percent_change_below: Optional[float] = None
    volume_above: Optional[float] = None
    market_state: str = ""  # e.g. REGULAR, PRE, POST, CLOSED
    note: str = ""


@dataclass
class StockMonitorConfig:
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    verify_tls: bool = True
    state_path: str = DEFAULT_STATE_PATH
    user_agent: str = DEFAULT_USER_AGENT
    write_state: bool = False
    include_raw: bool = False


class StockMonitorEngine:
    def __init__(self, config: Optional[StockMonitorConfig] = None) -> None:
        self.config = config or StockMonitorConfig()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.config.user_agent,
                "Accept": "application/json,text/csv,text/plain,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            }
        )

    # ----------------------------- state ---------------------------------
    def _load_state(self) -> Dict[str, Any]:
        path = Path(self.config.state_path)
        if not path.exists():
            return {"ok": True, "version": 1, "symbols": {}, "alerts": {}}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {"ok": True, "version": 1, "symbols": {}, "alerts": {}}
            data.setdefault("version", 1)
            data.setdefault("symbols", {})
            data.setdefault("alerts", {})
            return data
        except Exception:
            return {"ok": True, "version": 1, "symbols": {}, "alerts": {}}

    def _save_state(self, state: Dict[str, Any]) -> None:
        path = Path(self.config.state_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)

    # ----------------------------- fetchers ------------------------------
    def fetch_yahoo_chart(
        self,
        symbol: str,
        range_: str = "1d",
        interval: str = "1m",
        include_prepost: bool = True,
    ) -> Dict[str, Any]:
        symbol = normalize_symbol(symbol)
        params = {
            "range": range_ or "1d",
            "interval": interval or "1m",
            "includePrePost": "true" if include_prepost else "false",
            "events": "div,splits,capitalGains",
        }
        url = YAHOO_CHART_URL.format(symbol=quote(symbol, safe=""))
        started = time.time()
        try:
            resp = self.session.get(
                url,
                params=params,
                timeout=float(self.config.timeout_sec),
                verify=bool(self.config.verify_tls),
            )
            elapsed_ms = int((time.time() - started) * 1000)
            text = resp.text or ""
            try:
                payload = resp.json()
            except Exception:
                payload = None
            if resp.status_code >= 400:
                return {
                    "ok": False,
                    "source": "yahoo_chart",
                    "symbol": symbol,
                    "status_code": resp.status_code,
                    "elapsed_ms": elapsed_ms,
                    "error": summarize_http_error(resp.status_code, text),
                }
            if not isinstance(payload, dict):
                return {
                    "ok": False,
                    "source": "yahoo_chart",
                    "symbol": symbol,
                    "status_code": resp.status_code,
                    "elapsed_ms": elapsed_ms,
                    "error": "Yahoo chart response was not JSON.",
                }
            quote_data = parse_yahoo_chart(symbol, payload)
            quote_data.update({"source": "yahoo_chart", "elapsed_ms": elapsed_ms, "status_code": resp.status_code})
            if self.config.include_raw:
                quote_data["raw"] = payload
            return quote_data
        except Exception as exc:
            return {"ok": False, "source": "yahoo_chart", "symbol": symbol, "error": str(exc)}

    def fetch_stooq_quote(self, symbol: str) -> Dict[str, Any]:
        raw_symbol = normalize_symbol(symbol)
        stooq_symbol = to_stooq_symbol(raw_symbol)
        params = {"s": stooq_symbol, "f": "sd2t2ohlcv", "h": "", "e": "csv"}
        started = time.time()
        try:
            resp = self.session.get(
                STOOQ_QUOTE_URL,
                params=params,
                timeout=float(self.config.timeout_sec),
                verify=bool(self.config.verify_tls),
            )
            elapsed_ms = int((time.time() - started) * 1000)
            text = resp.text or ""
            if resp.status_code >= 400:
                return {
                    "ok": False,
                    "source": "stooq_quote",
                    "symbol": raw_symbol,
                    "stooq_symbol": stooq_symbol,
                    "status_code": resp.status_code,
                    "elapsed_ms": elapsed_ms,
                    "error": summarize_http_error(resp.status_code, text),
                }
            parsed = parse_stooq_csv(raw_symbol, stooq_symbol, text)
            parsed.update({"source": "stooq_quote", "elapsed_ms": elapsed_ms, "status_code": resp.status_code})
            if self.config.include_raw:
                parsed["raw_csv"] = text[:20000]
            return parsed
        except Exception as exc:
            return {"ok": False, "source": "stooq_quote", "symbol": raw_symbol, "stooq_symbol": stooq_symbol, "error": str(exc)}

    def get_quote(
        self,
        symbol: str,
        range_: str = "1d",
        interval: str = "1m",
        fallback: bool = True,
    ) -> Dict[str, Any]:
        primary = self.fetch_yahoo_chart(symbol, range_=range_, interval=interval)
        if primary.get("ok"):
            return primary
        if fallback:
            secondary = self.fetch_stooq_quote(symbol)
            if secondary.get("ok"):
                secondary["primary_error"] = primary.get("error", "")
                return secondary
            return {
                "ok": False,
                "symbol": normalize_symbol(symbol),
                "source": "combined",
                "primary": compact_error(primary),
                "fallback": compact_error(secondary),
                "error": "Both Yahoo chart and Stooq quote fetch failed.",
            }
        return primary

    # ----------------------------- monitor -------------------------------
    def monitor(
        self,
        symbols: Sequence[str],
        rules: Optional[Sequence[Dict[str, Any]]] = None,
        range_: str = "1d",
        interval: str = "1m",
        fallback: bool = True,
    ) -> Dict[str, Any]:
        started = time.time()
        clean_symbols = unique_symbols(symbols)
        state = self._load_state()
        rules_by_symbol: Dict[str, List[StockAlertRule]] = {}
        for row in rules or []:
            rule = coerce_stock_rule(row)
            if rule.symbol:
                rules_by_symbol.setdefault(normalize_symbol(rule.symbol), []).append(rule)

        quotes: List[Dict[str, Any]] = []
        alerts: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for symbol in clean_symbols:
            quote_data = self.get_quote(symbol, range_=range_, interval=interval, fallback=fallback)
            quotes.append(quote_data)
            if not quote_data.get("ok"):
                errors.append(compact_error(quote_data))
                continue
            previous = (state.get("symbols") or {}).get(symbol, {})
            quote_data["previous"] = compact_previous_quote(previous)
            quote_alerts = evaluate_stock_alerts(quote_data, rules_by_symbol.get(symbol, []), previous)
            alerts.extend(quote_alerts)
            state.setdefault("symbols", {})[symbol] = compact_quote_for_state(quote_data)

        if self.config.write_state:
            state.setdefault("last_run", utc_now_iso())
            for alert in alerts:
                key = alert_fingerprint(alert)
                state.setdefault("alerts", {})[key] = alert
            self._save_state(state)

        return {
            "ok": len(errors) == 0 or len(quotes) > len(errors),
            "engine": "stock_engine_monitor",
            "mode": "monitor",
            "symbols": clean_symbols,
            "count": len(quotes),
            "alerts_count": len(alerts),
            "errors_count": len(errors),
            "alerts": alerts,
            "quotes": quotes,
            "errors": errors,
            "state_path": self.config.state_path if self.config.write_state else "",
            "elapsed_ms": int((time.time() - started) * 1000),
        }


# ----------------------------- public funcs -------------------------------
def stock_quote(
    symbol: str,
    range_: str = "1d",
    interval: str = "1m",
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    fallback: bool = True,
    include_raw: bool = False,
) -> Dict[str, Any]:
    engine = StockMonitorEngine(
        StockMonitorConfig(timeout_sec=timeout_sec, verify_tls=verify_tls, include_raw=include_raw)
    )
    return engine.get_quote(symbol, range_=range_, interval=interval, fallback=fallback)


def stock_monitor(
    symbols: Sequence[str],
    rules: Optional[Sequence[Dict[str, Any]]] = None,
    range_: str = "1d",
    interval: str = "1m",
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    fallback: bool = True,
    include_raw: bool = False,
    write_state: bool = False,
    state_path: str = DEFAULT_STATE_PATH,
) -> Dict[str, Any]:
    engine = StockMonitorEngine(
        StockMonitorConfig(
            timeout_sec=timeout_sec,
            verify_tls=verify_tls,
            include_raw=include_raw,
            write_state=write_state,
            state_path=state_path or DEFAULT_STATE_PATH,
        )
    )
    return engine.monitor(symbols, rules=rules, range_=range_, interval=interval, fallback=fallback)


def stock_compare_watchlist(
    watchlist: Sequence[Dict[str, Any]],
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    write_state: bool = False,
    state_path: str = DEFAULT_STATE_PATH,
) -> Dict[str, Any]:
    """Monitor a richer watchlist: [{symbol, price_below, price_above, ...}]."""
    symbols: List[str] = []
    rules: List[Dict[str, Any]] = []
    for row in watchlist or []:
        if not isinstance(row, dict):
            continue
        sym = normalize_symbol(str(row.get("symbol", "")))
        if not sym:
            continue
        symbols.append(sym)
        rule = dict(row)
        rule["symbol"] = sym
        rules.append(rule)
    return stock_monitor(
        symbols=symbols,
        rules=rules,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        write_state=write_state,
        state_path=state_path,
    )


def stock_engine_status() -> Dict[str, Any]:
    return {
        "ok": True,
        "engine": "stock_engine_monitor",
        "version": 1,
        "dependencies": {"requests": requests.__version__},
        "sources": ["yahoo_chart", "stooq_quote"],
        "safe_limits": {
            "no_trading": True,
            "no_broker_login": True,
            "no_paywall_bypass": True,
            "unofficial_sources_can_change": True,
        },
    }


# ----------------------------- parsers ------------------------------------
def parse_yahoo_chart(symbol: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    chart = payload.get("chart") or {}
    errors = chart.get("error")
    if errors:
        return {"ok": False, "symbol": symbol, "error": str(errors)}
    results = chart.get("result") or []
    if not results:
        return {"ok": False, "symbol": symbol, "error": "No chart result returned."}
    result = results[0] or {}
    meta = result.get("meta") or {}
    timestamps = result.get("timestamp") or []
    indicators = result.get("indicators") or {}
    quote_rows = indicators.get("quote") or [{}]
    quote = quote_rows[0] if quote_rows else {}
    closes = quote.get("close") or []
    volumes = quote.get("volume") or []

    last_price = safe_float(meta.get("regularMarketPrice"))
    previous_close = safe_float(meta.get("previousClose") or meta.get("chartPreviousClose"))
    if last_price is None:
        last_price = last_non_null_float(closes)
    if previous_close is None:
        previous_close = infer_previous_close(closes)

    currency = str(meta.get("currency") or "")
    exchange = str(meta.get("exchangeName") or meta.get("fullExchangeName") or "")
    instrument_type = str(meta.get("instrumentType") or "")
    market_state = str(meta.get("marketState") or "")
    regular_time = meta.get("regularMarketTime") or meta.get("firstTradeDate")

    change = None
    change_percent = None
    if last_price is not None and previous_close not in (None, 0):
        change = last_price - float(previous_close)
        change_percent = (change / float(previous_close)) * 100.0

    return {
        "ok": True,
        "symbol": normalize_symbol(symbol),
        "price": round_float(last_price),
        "previous_close": round_float(previous_close),
        "change": round_float(change),
        "change_percent": round_float(change_percent),
        "currency": currency,
        "exchange": exchange,
        "instrument_type": instrument_type,
        "market_state": market_state,
        "regular_market_time": epoch_to_iso(regular_time),
        "regular_market_epoch": safe_int(regular_time),
        "volume": safe_int(meta.get("regularMarketVolume")) or safe_int(last_non_null_float(volumes)),
        "timezone": str(meta.get("timezone") or meta.get("exchangeTimezoneName") or ""),
        "range": str(meta.get("range") or ""),
        "data_granularity": str(meta.get("dataGranularity") or ""),
        "points_count": len(timestamps),
        "fetched_at": utc_now_iso(),
    }


def parse_stooq_csv(symbol: str, stooq_symbol: str, text: str) -> Dict[str, Any]:
    rows = list(csv.DictReader((text or "").splitlines()))
    if not rows:
        return {"ok": False, "symbol": symbol, "stooq_symbol": stooq_symbol, "error": "Stooq returned no CSV rows."}
    row = rows[0]
    close = safe_float(row.get("Close"))
    open_ = safe_float(row.get("Open"))
    high = safe_float(row.get("High"))
    low = safe_float(row.get("Low"))
    if close is None or str(row.get("Close", "")).upper() == "N/D":
        return {"ok": False, "symbol": symbol, "stooq_symbol": stooq_symbol, "error": "Stooq quote was N/D."}
    return {
        "ok": True,
        "symbol": normalize_symbol(symbol),
        "stooq_symbol": stooq_symbol,
        "price": round_float(close),
        "open": round_float(open_),
        "high": round_float(high),
        "low": round_float(low),
        "previous_close": None,
        "change": None,
        "change_percent": None,
        "currency": "",
        "exchange": "stooq",
        "instrument_type": "",
        "market_state": "",
        "regular_market_time": stooq_datetime_to_iso(row.get("Date"), row.get("Time")),
        "regular_market_epoch": None,
        "volume": safe_int(row.get("Volume")),
        "timezone": "",
        "points_count": 1,
        "fetched_at": utc_now_iso(),
    }


# ----------------------------- alerts -------------------------------------
def evaluate_stock_alerts(
    quote_data: Dict[str, Any],
    rules: Sequence[StockAlertRule],
    previous: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    if not quote_data.get("ok"):
        return alerts
    symbol = normalize_symbol(quote_data.get("symbol", ""))
    price = safe_float(quote_data.get("price"))
    change_percent = safe_float(quote_data.get("change_percent"))
    volume = safe_float(quote_data.get("volume"))
    market_state = str(quote_data.get("market_state") or "")

    for rule in rules or []:
        checks: List[Tuple[str, bool, Any]] = []
        if rule.price_above is not None and price is not None:
            checks.append(("price_above", price >= float(rule.price_above), rule.price_above))
        if rule.price_below is not None and price is not None:
            checks.append(("price_below", price <= float(rule.price_below), rule.price_below))
        if rule.percent_change_above is not None and change_percent is not None:
            checks.append(("percent_change_above", change_percent >= float(rule.percent_change_above), rule.percent_change_above))
        if rule.percent_change_below is not None and change_percent is not None:
            checks.append(("percent_change_below", change_percent <= float(rule.percent_change_below), rule.percent_change_below))
        if rule.volume_above is not None and volume is not None:
            checks.append(("volume_above", volume >= float(rule.volume_above), rule.volume_above))
        if rule.market_state:
            checks.append(("market_state", market_state.upper() == rule.market_state.upper(), rule.market_state))

        for field, fired, threshold in checks:
            if fired:
                alerts.append(
                    {
                        "ok": True,
                        "kind": "stock_alert",
                        "symbol": symbol,
                        "field": field,
                        "threshold": threshold,
                        "price": price,
                        "change_percent": round_float(change_percent),
                        "volume": safe_int(volume),
                        "market_state": market_state,
                        "note": rule.note,
                        "fired_at": utc_now_iso(),
                    }
                )
    return alerts


# ----------------------------- helpers ------------------------------------
def coerce_stock_rule(row: Dict[str, Any]) -> StockAlertRule:
    if not isinstance(row, dict):
        return StockAlertRule(symbol="")
    return StockAlertRule(
        symbol=normalize_symbol(str(row.get("symbol", ""))),
        price_above=safe_float(row.get("price_above")),
        price_below=safe_float(row.get("price_below")),
        percent_change_above=safe_float(row.get("percent_change_above")),
        percent_change_below=safe_float(row.get("percent_change_below")),
        volume_above=safe_float(row.get("volume_above")),
        market_state=str(row.get("market_state", "") or ""),
        note=str(row.get("note", "") or ""),
    )


def unique_symbols(symbols: Sequence[str]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for sym in symbols or []:
        clean = normalize_symbol(str(sym))
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


def normalize_symbol(symbol: str) -> str:
    return re.sub(r"\s+", "", str(symbol or "")).upper()


def to_stooq_symbol(symbol: str) -> str:
    sym = normalize_symbol(symbol).lower()
    if "." in sym or "^" in sym or "=" in sym:
        return sym
    # Stooq uses aapl.us for US equities/ETFs. This default is a reasonable fallback.
    return f"{sym}.us"


def compact_error(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ok": bool(data.get("ok")),
        "source": data.get("source", ""),
        "symbol": data.get("symbol", ""),
        "status_code": data.get("status_code", None),
        "error": data.get("error", ""),
    }


def compact_quote_for_state(q: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "symbol": q.get("symbol", ""),
        "price": q.get("price"),
        "previous_close": q.get("previous_close"),
        "change_percent": q.get("change_percent"),
        "volume": q.get("volume"),
        "market_state": q.get("market_state", ""),
        "source": q.get("source", ""),
        "regular_market_time": q.get("regular_market_time", ""),
        "fetched_at": q.get("fetched_at", utc_now_iso()),
    }


def compact_previous_quote(previous: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(previous, dict) or not previous:
        return {}
    return {
        "price": previous.get("price"),
        "change_percent": previous.get("change_percent"),
        "volume": previous.get("volume"),
        "fetched_at": previous.get("fetched_at", ""),
    }


def alert_fingerprint(alert: Dict[str, Any]) -> str:
    raw = json.dumps(
        {
            "kind": alert.get("kind"),
            "symbol": alert.get("symbol"),
            "field": alert.get("field"),
            "threshold": alert.get("threshold"),
            "date": utc_now_iso()[:10],
        },
        sort_keys=True,
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def summarize_http_error(status_code: int, text: str) -> str:
    sample = re.sub(r"\s+", " ", (text or "")[:300]).strip()
    return f"HTTP {status_code}" + (f": {sample}" if sample else "")


def safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        if isinstance(value, str):
            v = value.strip().replace(",", "")
            if not v or v.upper() in {"N/A", "N/D", "NULL", "NONE", "-"}:
                return None
            value = v
        f = float(value)
        if not math.isfinite(f):
            return None
        return f
    except Exception:
        return None


def safe_int(value: Any) -> Optional[int]:
    f = safe_float(value)
    if f is None:
        return None
    return int(f)


def round_float(value: Any, digits: int = 6) -> Optional[float]:
    f = safe_float(value)
    if f is None:
        return None
    return round(f, digits)


def last_non_null_float(values: Sequence[Any]) -> Optional[float]:
    for value in reversed(list(values or [])):
        f = safe_float(value)
        if f is not None:
            return f
    return None


def infer_previous_close(values: Sequence[Any]) -> Optional[float]:
    clean = [safe_float(v) for v in values or []]
    clean = [v for v in clean if v is not None]
    if len(clean) >= 2:
        return clean[0]
    return None


def epoch_to_iso(value: Any) -> str:
    ts = safe_int(value)
    if ts is None or ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat()
    except Exception:
        return ""


def stooq_datetime_to_iso(date_s: Any, time_s: Any) -> str:
    date_s = str(date_s or "").strip()
    time_s = str(time_s or "").strip()
    if not date_s or date_s.upper() == "N/D":
        return ""
    raw = f"{date_s} {time_s or '00:00:00'}"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y%m%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            pass
    return raw


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ----------------------------- CLI ----------------------------------------
def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Safe stock quote/alert monitor")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s_quote = sub.add_parser("quote")
    s_quote.add_argument("symbol")
    s_quote.add_argument("--range", dest="range_", default="1d")
    s_quote.add_argument("--interval", default="1m")

    s_mon = sub.add_parser("monitor")
    s_mon.add_argument("symbols", nargs="+")
    s_mon.add_argument("--below", type=float, default=None)
    s_mon.add_argument("--above", type=float, default=None)
    s_mon.add_argument("--write-state", action="store_true")
    s_mon.add_argument("--state-path", default=DEFAULT_STATE_PATH)

    sub.add_parser("status")

    args = parser.parse_args()
    if args.cmd == "quote":
        print(json.dumps(stock_quote(args.symbol, range_=args.range_, interval=args.interval), indent=2))
    elif args.cmd == "monitor":
        rules = []
        for symbol in args.symbols:
            rules.append({"symbol": symbol, "price_below": args.below, "price_above": args.above})
        print(json.dumps(stock_monitor(args.symbols, rules=rules, write_state=args.write_state, state_path=args.state_path), indent=2))
    else:
        print(json.dumps(stock_engine_status(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
