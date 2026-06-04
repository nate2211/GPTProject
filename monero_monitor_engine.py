from __future__ import annotations

"""
monero_monitor_engine.py

Safe Monero monitoring helpers for PromptChat / GPT tool use.

What this engine CAN do:
- Check whether a known Monero tx hash is visible to your own monerod RPC.
- Report pool-vs-block inclusion, block height, timestamp, and confirmations.
- Check P2Pool Observer / Mini / Nano public miner stats for your own wallet/alias.
- Return structured JSON-safe dictionaries for a ToolRegistry wrapper.

What this engine intentionally DOES NOT do:
- It does not deanonymize Monero senders, receivers, or amounts.
- It does not claim a seller wallet can be traced or funds recovered.
- It does not scrape private accounts, bypass auth, or use exploit-style probing.

Best accuracy comes from your own synced monerod:
    monerod --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18081
"""

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote, urljoin, urlparse, urlunparse

import requests


TX_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
DEFAULT_DAEMON_RPC_URL = "http://127.0.0.1:18081"
DEFAULT_TIMEOUT_SEC = 20.0
DEFAULT_CONFIRMATIONS_TARGET = 10

P2POOL_BASES: Dict[str, str] = {
    "main": "https://p2pool.observer",
    "mini": "https://mini.p2pool.observer",
    "nano": "https://nano.p2pool.observer",
}

PRIVACY_NOTICE = (
    "Monero public lookups can confirm that a known transaction hash exists, "
    "is in the mempool, or is mined at a block height. They cannot reveal the "
    "sender, recipient, transferred amount, or seller wallet without wallet-side "
    "proof data such as a view key, tx key/proof, or records from a party to the transaction."
)


@dataclass
class MoneroMonitorConfig:
    daemon_rpc_url: str = DEFAULT_DAEMON_RPC_URL
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    confirmations_target: int = DEFAULT_CONFIRMATIONS_TARGET
    verify_tls: bool = True
    user_agent: str = "PromptChat-MoneroMonitor/1.0"
    p2pool_network: str = "mini"
    p2pool_base_url: str = ""
    include_raw: bool = False
    max_items: int = 50
    # Keep fallbacks conservative and public. These are API/JSON guesses used because
    # observer mirrors occasionally differ between main/mini/nano deployments.
    p2pool_miner_info_paths: Sequence[str] = field(default_factory=lambda: (
        "/api/miner_info/{miner}",
        "/api/miner/{miner}",
        "/api/miner_by_address/{miner}",
        "/api/miner_by_id/{miner}",
    ))
    p2pool_miner_shares_paths: Sequence[str] = field(default_factory=lambda: (
        "/api/miner_shares/{miner}?limit={limit}",
        "/api/shares/{miner}?limit={limit}",
        "/api/miner/{miner}/shares?limit={limit}",
    ))
    p2pool_miner_payments_paths: Sequence[str] = field(default_factory=lambda: (
        "/api/miner_payments/{miner}?limit={limit}",
        "/api/payments/{miner}?limit={limit}",
        "/api/miner/{miner}/payments?limit={limit}",
    ))
    p2pool_pool_info_paths: Sequence[str] = field(default_factory=lambda: (
        "/api/pool_info",
        "/api/network/stats",
        "/api/stats",
    ))


def _now_unix() -> int:
    return int(time.time())


def _clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        n = int(value)
    except Exception:
        n = default
    return max(minimum, min(maximum, n))


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _validate_tx_hash(tx_hash: str) -> str:
    clean = (tx_hash or "").strip()
    if not TX_HASH_RE.fullmatch(clean):
        raise ValueError("tx_hash must be exactly 64 hexadecimal characters.")
    return clean.lower()


def _normalize_base_url(url: str) -> str:
    raw = (url or "").strip().rstrip("/")
    if not raw:
        raise ValueError("Base URL is required.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid HTTP(S) URL: {url}")
    return raw


def _requests_session(user_agent: str) -> requests.Session:
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=16, max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": user_agent or "PromptChat-MoneroMonitor/1.0",
        "Accept": "application/json,text/plain,*/*;q=0.8",
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })
    return session


def _auth_from_url(url: str) -> Tuple[str, Optional[Tuple[str, str]]]:
    """Extract basic auth from http://user:pass@host without leaking it into returned URLs."""
    parsed = urlparse(url)
    if not parsed.username:
        return url, None
    hostname = parsed.hostname or ""
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    clean = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    return clean, (parsed.username, parsed.password or "")


def _json_or_text(resp: requests.Response) -> Any:
    text = resp.text or ""
    ctype = (resp.headers.get("content-type") or "").lower()
    if "json" in ctype or text[:1] in {"{", "["}:
        try:
            return resp.json()
        except Exception:
            try:
                return json.loads(text)
            except Exception:
                pass
    return text[:5000]


def _summarize_http_error(resp: requests.Response) -> Dict[str, Any]:
    return {
        "status_code": resp.status_code,
        "reason": resp.reason,
        "url": resp.url,
        "body_excerpt": (resp.text or "")[:1000],
    }


class MoneroMonitorEngine:
    def __init__(self, config: Optional[MoneroMonitorConfig] = None) -> None:
        self.config = config or MoneroMonitorConfig()
        self.config.daemon_rpc_url = _normalize_base_url(self.config.daemon_rpc_url)
        self.config.timeout_sec = float(self.config.timeout_sec or DEFAULT_TIMEOUT_SEC)
        self.config.confirmations_target = _clamp_int(
            self.config.confirmations_target,
            DEFAULT_CONFIRMATIONS_TARGET,
            0,
            1_000_000,
        )
        self.config.max_items = _clamp_int(self.config.max_items, 50, 1, 1000)
        self.session = _requests_session(self.config.user_agent)

    # ---------------------------- monerod RPC -----------------------------
    def _daemon_url(self, path: str) -> Tuple[str, Optional[Tuple[str, str]]]:
        base, auth = _auth_from_url(self.config.daemon_rpc_url)
        return urljoin(base + "/", path.lstrip("/")), auth

    def daemon_json_rpc(self, method: str, params: Optional[Any] = None) -> Dict[str, Any]:
        url, auth = self._daemon_url("/json_rpc")
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params is not None:
            payload["params"] = params
        resp = self.session.post(
            url,
            data=json.dumps(payload),
            timeout=self.config.timeout_sec,
            verify=self.config.verify_tls,
            auth=auth,
        )
        if not (200 <= resp.status_code < 300):
            return {"ok": False, "error": "monerod JSON-RPC HTTP error", "http": _summarize_http_error(resp)}
        data = _json_or_text(resp)
        if not isinstance(data, dict):
            return {"ok": False, "error": "monerod JSON-RPC returned non-JSON", "response": data}
        if data.get("error"):
            return {"ok": False, "error": "monerod JSON-RPC error", "rpc_error": data.get("error")}
        return {"ok": True, "result": data.get("result", data)}

    def daemon_other_rpc(self, path: str, payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        url, auth = self._daemon_url(path)
        resp = self.session.post(
            url,
            data=json.dumps(dict(payload or {})),
            timeout=self.config.timeout_sec,
            verify=self.config.verify_tls,
            auth=auth,
        )
        if not (200 <= resp.status_code < 300):
            return {"ok": False, "error": "monerod RPC HTTP error", "http": _summarize_http_error(resp)}
        data = _json_or_text(resp)
        if not isinstance(data, dict):
            return {"ok": False, "error": "monerod RPC returned non-JSON", "response": data}
        status = str(data.get("status", "OK")).upper()
        if status not in {"OK", ""}:
            return {"ok": False, "error": "monerod RPC status was not OK", "status": data.get("status"), "response": data}
        return {"ok": True, "result": data}

    def daemon_status(self) -> Dict[str, Any]:
        info = self.daemon_json_rpc("get_info")
        if not info.get("ok"):
            # fallback for old daemons
            other = self.daemon_other_rpc("/get_info", {})
            if not other.get("ok"):
                return {
                    "ok": False,
                    "mode": "monero_daemon_status",
                    "daemon_rpc_url": self.config.daemon_rpc_url,
                    "privacy_notice": PRIVACY_NOTICE,
                    "error": "Could not reach monerod get_info through JSON-RPC or /get_info.",
                    "json_rpc_error": info,
                    "other_rpc_error": other,
                }
            result = other.get("result", {})
        else:
            result = info.get("result", {})

        return {
            "ok": True,
            "mode": "monero_daemon_status",
            "daemon_rpc_url": self.config.daemon_rpc_url,
            "height": result.get("height"),
            "target_height": result.get("target_height"),
            "synchronized": result.get("synchronized"),
            "offline": result.get("offline"),
            "testnet": result.get("testnet"),
            "stagenet": result.get("stagenet"),
            "mainnet": not bool(result.get("testnet")) and not bool(result.get("stagenet")),
            "difficulty": result.get("difficulty"),
            "wide_difficulty": result.get("wide_difficulty"),
            "tx_count": result.get("tx_count"),
            "tx_pool_size": result.get("tx_pool_size"),
            "was_bootstrap_ever_used": result.get("was_bootstrap_ever_used"),
            "untrusted": result.get("untrusted"),
            "privacy_notice": PRIVACY_NOTICE,
            "raw": result if self.config.include_raw else None,
        }

    def get_height(self) -> Dict[str, Any]:
        status = self.daemon_status()
        if status.get("ok"):
            return {"ok": True, "height": status.get("height"), "status": status}
        # Last fallback. /get_height is documented as a non-JSON-RPC method.
        other = self.daemon_other_rpc("/get_height", {})
        if other.get("ok"):
            result = other.get("result", {})
            return {"ok": True, "height": result.get("height"), "status": result}
        return {"ok": False, "error": "Could not read monerod height.", "status_error": status, "height_error": other}

    def _decode_tx_json(self, tx_entry: Mapping[str, Any]) -> Dict[str, Any]:
        raw = tx_entry.get("as_json") or ""
        if not raw or not isinstance(raw, str):
            return {}
        try:
            parsed = json.loads(raw)
        except Exception:
            return {"parse_error": "as_json was returned but could not be parsed"}
        if not isinstance(parsed, dict):
            return {}
        vin = parsed.get("vin") or []
        vout = parsed.get("vout") or []
        return {
            "version": parsed.get("version"),
            "unlock_time": parsed.get("unlock_time"),
            "vin_count": len(vin) if isinstance(vin, list) else None,
            "vout_count": len(vout) if isinstance(vout, list) else None,
            "fee_atomic": ((parsed.get("rct_signatures") or {}).get("txnFee") if isinstance(parsed.get("rct_signatures"), dict) else None),
            "extra_len": len(parsed.get("extra") or []) if isinstance(parsed.get("extra"), list) else None,
            "raw": parsed if self.config.include_raw else None,
        }

    def get_transaction(self, tx_hash: str, *, include_tx_json: bool = False) -> Dict[str, Any]:
        clean_hash = _validate_tx_hash(tx_hash)
        height_res = self.get_height()
        chain_height = height_res.get("height") if height_res.get("ok") else None

        tx_res = self.daemon_other_rpc(
            "/get_transactions",
            {
                "txs_hashes": [clean_hash],
                "decode_as_json": bool(include_tx_json),
                "prune": True,
                "split": False,
            },
        )
        if not tx_res.get("ok"):
            return {
                "ok": False,
                "mode": "monero_monitor_transaction",
                "tx_hash": clean_hash,
                "daemon_rpc_url": self.config.daemon_rpc_url,
                "privacy_notice": PRIVACY_NOTICE,
                "error": "Could not query /get_transactions.",
                "details": tx_res,
            }

        result = tx_res.get("result", {}) or {}
        missed = result.get("missed_tx") or []
        txs = result.get("txs") or []
        found = bool(txs) and clean_hash not in missed

        if not found:
            return {
                "ok": True,
                "mode": "monero_monitor_transaction",
                "tx_hash": clean_hash,
                "found": False,
                "state": "not_found",
                "chain_height": chain_height,
                "confirmations": 0,
                "confirmations_target": self.config.confirmations_target,
                "confirmed_enough": False,
                "missed_tx": missed,
                "daemon_rpc_url": self.config.daemon_rpc_url,
                "privacy_notice": PRIVACY_NOTICE,
                "note": "Not found by this daemon. The tx may be invalid, not propagated to this node, pruned/hidden by endpoint policy, or not yet relayed.",
            }

        entry = dict(txs[0])
        in_pool = bool(entry.get("in_pool"))
        block_height = entry.get("block_height")
        block_timestamp = entry.get("block_timestamp")
        double_spend_seen = bool(entry.get("double_spend_seen"))

        confirmations = 0
        if not in_pool and isinstance(chain_height, int) and isinstance(block_height, int) and block_height > 0:
            confirmations = max(0, chain_height - block_height + 1)

        state = "mempool" if in_pool else "mined"
        if double_spend_seen:
            state = "double_spend_seen"

        decoded = self._decode_tx_json(entry) if include_tx_json else {}

        out: Dict[str, Any] = {
            "ok": True,
            "mode": "monero_monitor_transaction",
            "tx_hash": clean_hash,
            "found": True,
            "state": state,
            "in_pool": in_pool,
            "block_height": block_height,
            "block_timestamp": block_timestamp,
            "block_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(block_timestamp)) if isinstance(block_timestamp, int) and block_timestamp > 0 else "",
            "chain_height": chain_height,
            "confirmations": confirmations,
            "confirmations_target": self.config.confirmations_target,
            "confirmed_enough": confirmations >= self.config.confirmations_target,
            "double_spend_seen": double_spend_seen,
            "output_indices_count": len(entry.get("output_indices") or []),
            "prunable_hash": entry.get("prunable_hash", ""),
            "daemon_rpc_url": self.config.daemon_rpc_url,
            "privacy_notice": PRIVACY_NOTICE,
            "decoded_summary": decoded,
        }
        if self.config.include_raw:
            out["raw"] = entry
        return out

    def monitor_transactions(self, tx_hashes: Iterable[str], *, include_tx_json: bool = False) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = []
        for raw_hash in tx_hashes:
            try:
                rows.append(self.get_transaction(str(raw_hash), include_tx_json=include_tx_json))
            except Exception as exc:
                rows.append({"ok": False, "tx_hash": str(raw_hash), "error": str(exc)})

        counts: Dict[str, int] = {}
        for row in rows:
            state = str(row.get("state", "error" if not row.get("ok") else "unknown"))
            counts[state] = counts.get(state, 0) + 1

        return {
            "ok": True,
            "mode": "monero_monitor_transactions",
            "count": len(rows),
            "state_counts": counts,
            "transactions": rows,
            "privacy_notice": PRIVACY_NOTICE,
        }

    # -------------------------- P2Pool Observer ----------------------------
    def _p2pool_base(self, network: str = "", base_url: str = "") -> str:
        if base_url:
            return _normalize_base_url(base_url)
        key = (network or self.config.p2pool_network or "mini").strip().lower()
        return P2POOL_BASES.get(key, P2POOL_BASES["mini"])

    def _p2pool_get_first_json(self, base: str, path_templates: Sequence[str], **fmt: Any) -> Dict[str, Any]:
        errors: List[Dict[str, Any]] = []
        for path_tmpl in path_templates:
            path = path_tmpl.format(**{k: quote(str(v), safe="") for k, v in fmt.items()})
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.session.get(
                    url,
                    timeout=self.config.timeout_sec,
                    verify=self.config.verify_tls,
                    headers={"Accept": "application/json,text/plain,*/*;q=0.8"},
                )
                if 200 <= resp.status_code < 300:
                    data = _json_or_text(resp)
                    return {
                        "ok": True,
                        "url": url,
                        "data": data,
                        "content_type": resp.headers.get("content-type", ""),
                    }
                errors.append(_summarize_http_error(resp))
            except Exception as exc:
                errors.append({"url": url, "error": str(exc)})
        return {"ok": False, "error": "No P2Pool Observer API candidate returned success.", "attempts": errors}

    def p2pool_pool_info(self, *, network: str = "", base_url: str = "") -> Dict[str, Any]:
        base = self._p2pool_base(network, base_url)
        res = self._p2pool_get_first_json(base, self.config.p2pool_pool_info_paths)
        return {
            "ok": bool(res.get("ok")),
            "mode": "p2pool_observer_pool_info",
            "network": network or self.config.p2pool_network,
            "base_url": base,
            "source_url": res.get("url", ""),
            "data": res.get("data"),
            "error": res.get("error", ""),
            "attempts": res.get("attempts", []),
        }

    def p2pool_miner_info(
        self,
        miner: str,
        *,
        network: str = "",
        base_url: str = "",
        include_shares: bool = True,
        include_payments: bool = True,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        miner_clean = (miner or "").strip()
        if not miner_clean:
            raise ValueError("miner must be a Monero payout address, miner id, or observer alias.")

        base = self._p2pool_base(network, base_url)
        item_limit = _clamp_int(limit if limit is not None else self.config.max_items, self.config.max_items, 1, 1000)

        info = self._p2pool_get_first_json(base, self.config.p2pool_miner_info_paths, miner=miner_clean, limit=item_limit)
        shares = self._p2pool_get_first_json(base, self.config.p2pool_miner_shares_paths, miner=miner_clean, limit=item_limit) if include_shares else {"ok": False, "skipped": True}
        payments = self._p2pool_get_first_json(base, self.config.p2pool_miner_payments_paths, miner=miner_clean, limit=item_limit) if include_payments else {"ok": False, "skipped": True}

        return {
            "ok": bool(info.get("ok") or shares.get("ok") or payments.get("ok")),
            "mode": "p2pool_observer_miner_info",
            "network": network or self.config.p2pool_network,
            "base_url": base,
            "miner": miner_clean,
            "limit": item_limit,
            "info": {
                "ok": bool(info.get("ok")),
                "source_url": info.get("url", ""),
                "data": info.get("data"),
                "error": info.get("error", ""),
                "attempts": info.get("attempts", []),
            },
            "shares": {
                "ok": bool(shares.get("ok")),
                "source_url": shares.get("url", ""),
                "data": shares.get("data"),
                "error": shares.get("error", ""),
                "attempts": shares.get("attempts", []),
                "skipped": bool(shares.get("skipped", False)),
            },
            "payments": {
                "ok": bool(payments.get("ok")),
                "source_url": payments.get("url", ""),
                "data": payments.get("data"),
                "error": payments.get("error", ""),
                "attempts": payments.get("attempts", []),
                "skipped": bool(payments.get("skipped", False)),
            },
            "privacy_notice": (
                "P2Pool Observer shows public mining/share/payout statistics associated with a submitted payout address/alias. "
                "It does not provide a general Monero transaction tracing capability."
            ),
        }

    def combined_monitor(
        self,
        *,
        tx_hash: str = "",
        tx_hashes: Optional[Sequence[str]] = None,
        miner: str = "",
        network: str = "",
        base_url: str = "",
        include_tx_json: bool = False,
        include_shares: bool = True,
        include_payments: bool = True,
    ) -> Dict[str, Any]:
        tx_rows: Optional[Dict[str, Any]] = None
        miner_rows: Optional[Dict[str, Any]] = None

        all_hashes: List[str] = []
        if tx_hash:
            all_hashes.append(tx_hash)
        if tx_hashes:
            all_hashes.extend([str(x) for x in tx_hashes if str(x).strip()])
        if all_hashes:
            tx_rows = self.monitor_transactions(all_hashes, include_tx_json=include_tx_json)

        if miner:
            miner_rows = self.p2pool_miner_info(
                miner,
                network=network,
                base_url=base_url,
                include_shares=include_shares,
                include_payments=include_payments,
            )

        return {
            "ok": bool((tx_rows and tx_rows.get("ok")) or (miner_rows and miner_rows.get("ok"))),
            "mode": "monero_combined_monitor",
            "checked_at_unix": _now_unix(),
            "transactions": tx_rows,
            "p2pool": miner_rows,
            "privacy_notice": PRIVACY_NOTICE,
        }


def _make_config(
    *,
    daemon_rpc_url: str = DEFAULT_DAEMON_RPC_URL,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    confirmations_target: int = DEFAULT_CONFIRMATIONS_TARGET,
    verify_tls: bool = True,
    p2pool_network: str = "mini",
    p2pool_base_url: str = "",
    include_raw: bool = False,
    max_items: int = 50,
) -> MoneroMonitorConfig:
    return MoneroMonitorConfig(
        daemon_rpc_url=daemon_rpc_url or DEFAULT_DAEMON_RPC_URL,
        timeout_sec=float(timeout_sec or DEFAULT_TIMEOUT_SEC),
        confirmations_target=_clamp_int(confirmations_target, DEFAULT_CONFIRMATIONS_TARGET, 0, 1_000_000),
        verify_tls=_safe_bool(verify_tls, True),
        p2pool_network=(p2pool_network or "mini"),
        p2pool_base_url=p2pool_base_url or "",
        include_raw=_safe_bool(include_raw, False),
        max_items=_clamp_int(max_items, 50, 1, 1000),
    )


def monero_daemon_status(
    daemon_rpc_url: str = DEFAULT_DAEMON_RPC_URL,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    include_raw: bool = False,
) -> Dict[str, Any]:
    engine = MoneroMonitorEngine(_make_config(
        daemon_rpc_url=daemon_rpc_url,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        include_raw=include_raw,
    ))
    return engine.daemon_status()


def monero_monitor_transaction(
    tx_hash: str,
    daemon_rpc_url: str = DEFAULT_DAEMON_RPC_URL,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    confirmations_target: int = DEFAULT_CONFIRMATIONS_TARGET,
    verify_tls: bool = True,
    include_tx_json: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    engine = MoneroMonitorEngine(_make_config(
        daemon_rpc_url=daemon_rpc_url,
        timeout_sec=timeout_sec,
        confirmations_target=confirmations_target,
        verify_tls=verify_tls,
        include_raw=include_raw,
    ))
    return engine.get_transaction(tx_hash, include_tx_json=include_tx_json)


def monero_monitor_transactions(
    tx_hashes: Sequence[str],
    daemon_rpc_url: str = DEFAULT_DAEMON_RPC_URL,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    confirmations_target: int = DEFAULT_CONFIRMATIONS_TARGET,
    verify_tls: bool = True,
    include_tx_json: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    engine = MoneroMonitorEngine(_make_config(
        daemon_rpc_url=daemon_rpc_url,
        timeout_sec=timeout_sec,
        confirmations_target=confirmations_target,
        verify_tls=verify_tls,
        include_raw=include_raw,
    ))
    return engine.monitor_transactions(tx_hashes, include_tx_json=include_tx_json)


def p2pool_observer_pool_info(
    network: str = "mini",
    base_url: str = "",
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    engine = MoneroMonitorEngine(_make_config(
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        p2pool_network=network,
        p2pool_base_url=base_url,
    ))
    return engine.p2pool_pool_info(network=network, base_url=base_url)


def p2pool_observer_miner_info(
    miner: str,
    network: str = "mini",
    base_url: str = "",
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    verify_tls: bool = True,
    include_shares: bool = True,
    include_payments: bool = True,
    limit: int = 50,
) -> Dict[str, Any]:
    engine = MoneroMonitorEngine(_make_config(
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        p2pool_network=network,
        p2pool_base_url=base_url,
        max_items=limit,
    ))
    return engine.p2pool_miner_info(
        miner,
        network=network,
        base_url=base_url,
        include_shares=include_shares,
        include_payments=include_payments,
        limit=limit,
    )


def monero_combined_monitor(
    tx_hash: str = "",
    tx_hashes: Optional[Sequence[str]] = None,
    miner: str = "",
    daemon_rpc_url: str = DEFAULT_DAEMON_RPC_URL,
    network: str = "mini",
    base_url: str = "",
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    confirmations_target: int = DEFAULT_CONFIRMATIONS_TARGET,
    verify_tls: bool = True,
    include_tx_json: bool = False,
    include_raw: bool = False,
    include_shares: bool = True,
    include_payments: bool = True,
) -> Dict[str, Any]:
    engine = MoneroMonitorEngine(_make_config(
        daemon_rpc_url=daemon_rpc_url,
        timeout_sec=timeout_sec,
        confirmations_target=confirmations_target,
        verify_tls=verify_tls,
        p2pool_network=network,
        p2pool_base_url=base_url,
        include_raw=include_raw,
    ))
    return engine.combined_monitor(
        tx_hash=tx_hash,
        tx_hashes=tx_hashes,
        miner=miner,
        network=network,
        base_url=base_url,
        include_tx_json=include_tx_json,
        include_shares=include_shares,
        include_payments=include_payments,
    )


if __name__ == "__main__":
    # Minimal smoke CLI:
    #   python monero_monitor_engine.py status
    #   python monero_monitor_engine.py tx <tx_hash>
    #   python monero_monitor_engine.py p2pool <wallet_or_alias> mini
    import sys

    cmd = (sys.argv[1] if len(sys.argv) > 1 else "status").lower()
    if cmd == "status":
        print(json.dumps(monero_daemon_status(), indent=2))
    elif cmd == "tx" and len(sys.argv) > 2:
        print(json.dumps(monero_monitor_transaction(sys.argv[2]), indent=2))
    elif cmd == "p2pool" and len(sys.argv) > 2:
        network_arg = sys.argv[3] if len(sys.argv) > 3 else "mini"
        print(json.dumps(p2pool_observer_miner_info(sys.argv[2], network=network_arg), indent=2))
    else:
        print("Usage: python monero_monitor_engine.py status | tx <hash> | p2pool <wallet_or_alias> [main|mini|nano]")
