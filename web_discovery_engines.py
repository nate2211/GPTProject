from __future__ import annotations

"""
Passive Web Discovery Engines for a GPT/tool runtime.

Design goals:
- Passive or low-impact checks only. No brute-force fuzzing, exploit attempts, credential use,
  websocket connection attempts, GraphQL introspection, or form submissions.
- Small fixed limits, timeouts, and byte caps so a GPT can call these safely.
- Compatible with projects that already define StandaloneDiscoveryEngine and EngineReport.
  If those classes are not present, this file provides lightweight fallbacks.

Install dependency:
    pip install requests

Typical use:
    engine = WebSocketDiscoveryEngine()
    report = engine.run("scan", {"url": "https://example.com"})
    print(report.data)
"""

import datetime as _dt
import html as _html
import ipaddress
import json
import re
import socket
import ssl
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import requests
except Exception as exc:  # pragma: no cover - makes import failure explicit at runtime
    requests = None  # type: ignore[assignment]
    _REQUESTS_IMPORT_ERROR = exc
else:
    _REQUESTS_IMPORT_ERROR = None


# ---------------------------------------------------------------------------
# Optional compatibility with an existing engines.py framework
# ---------------------------------------------------------------------------

try:  # If your project already provides these, they will be used instead.
    StandaloneDiscoveryEngine  # type: ignore[name-defined]
    EngineReport  # type: ignore[name-defined]
except NameError:
    @dataclass
    class EngineReport:
        ok: bool
        message: str = ""
        data: Dict[str, Any] = field(default_factory=dict)
        error: Optional[str] = None
        engine: Optional[str] = None
        action: Optional[str] = None

        def to_dict(self) -> Dict[str, Any]:
            return {
                "ok": self.ok,
                "message": self.message,
                "data": self.data,
                "error": self.error,
                "engine": self.engine,
                "action": self.action,
            }

    class StandaloneDiscoveryEngine:
        """Small fallback base class matching the simple run/report pattern."""

        name = "standalone_discovery_engine"

        def run(self, action: str = "status", payload: Any = None) -> EngineReport:
            if action in {"status", "health", "ping"}:
                return self._make_report(True, "ready", {"engine": self.name})
            return self._make_report(True, "initialized", {"engine": self.name})

        def _make_report(
            self,
            ok: bool,
            message: str = "",
            data: Optional[Dict[str, Any]] = None,
            error: Optional[str] = None,
            action: Optional[str] = None,
        ) -> EngineReport:
            return EngineReport(
                ok=ok,
                message=message,
                data=data or {},
                error=error,
                engine=getattr(self, "name", self.__class__.__name__),
                action=action,
            )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 10
MAX_HTML_BYTES = 1_500_000
MAX_JS_BYTES = 900_000
MAX_XML_BYTES = 2_000_000
DEFAULT_HEADERS = {
    "User-Agent": "GPT-WebDiscoveryEngine/1.0 (+passive; authorized-use)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class EngineInputError(ValueError):
    pass


def _require_requests() -> None:
    if requests is None:
        raise RuntimeError(f"requests is required: {_REQUESTS_IMPORT_ERROR}")


def _normalise_url(url: str, default_scheme: str = "https") -> str:
    if not isinstance(url, str) or not url.strip():
        raise EngineInputError("url must be a non-empty string")
    url = url.strip()
    if "://" not in url:
        url = f"{default_scheme}://{url}"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise EngineInputError("only http and https URLs are supported")
    if not parsed.netloc:
        raise EngineInputError("url must include a host")
    return urllib.parse.urlunparse(parsed)


def _domain_to_url(domain: str) -> str:
    if not isinstance(domain, str) or not domain.strip():
        raise EngineInputError("domain must be a non-empty string")
    value = domain.strip()
    if "://" in value:
        return _normalise_url(value)
    return _normalise_url(f"https://{value}")


def _hostname(value: str) -> str:
    parsed = urllib.parse.urlparse(_normalise_url(value) if "://" not in value else value)
    host = parsed.hostname or ""
    return host.lower().strip(".")


def _same_site(base_url: str, target_url: str) -> bool:
    base_host = _hostname(base_url)
    target_host = _hostname(target_url)
    return target_host == base_host or target_host.endswith("." + base_host)


def _safe_join(base_url: str, maybe_relative: str) -> str:
    return urllib.parse.urljoin(base_url, _html.unescape(maybe_relative.strip()))


def _get_text(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_HTML_BYTES,
    headers: Optional[Mapping[str, str]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Fetch text with a hard byte cap."""
    _require_requests()
    clean_url = _normalise_url(url)
    hdrs = dict(DEFAULT_HEADERS)
    if headers:
        hdrs.update(headers)

    response = requests.get(  # type: ignore[union-attr]
        clean_url,
        timeout=timeout,
        headers=hdrs,
        stream=True,
        allow_redirects=True,
    )
    response.raise_for_status()

    chunks: List[bytes] = []
    total = 0
    truncated = False
    for chunk in response.iter_content(chunk_size=32768):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            remaining = max(0, max_bytes - sum(len(c) for c in chunks))
            if remaining:
                chunks.append(chunk[:remaining])
            truncated = True
            break
        chunks.append(chunk)

    raw = b"".join(chunks)
    encoding = response.encoding or response.apparent_encoding or "utf-8"
    text = raw.decode(encoding, errors="replace")
    meta = {
        "url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "bytes_read": len(raw),
        "truncated": truncated,
    }
    return text, meta


def fetch_html(url: str, base_url: Optional[str] = None) -> str:
    # Kept as a simple helper because the user's snippets referenced fetch_html().
    del base_url
    text, _ = _get_text(url, max_bytes=MAX_HTML_BYTES)
    return text


def _extract_attr_values(html_text: str, tag: str, attr: str) -> List[str]:
    pattern = rf"<{tag}\b[^>]*\b{attr}\s*=\s*([\"'])(.*?)\1"
    return [_html.unescape(m.group(2).strip()) for m in re.finditer(pattern, html_text, re.I | re.S)]


def extract_js_files(html_text: str, base_url: str) -> List[str]:
    scripts = _extract_attr_values(html_text, "script", "src")
    seen: set[str] = set()
    out: List[str] = []
    for src in scripts:
        full = _safe_join(base_url, src)
        parsed = urllib.parse.urlparse(full)
        if parsed.scheme not in {"http", "https"}:
            continue
        if full in seen:
            continue
        seen.add(full)
        out.append(full)
    return out


def _extract_css_files(html_text: str, base_url: str) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"<link\b[^>]*>", html_text, re.I | re.S):
        tag = match.group(0)
        rel_match = re.search(r"\brel\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
        href_match = re.search(r"\bhref\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
        if not href_match:
            continue
        rel = rel_match.group(2).lower() if rel_match else ""
        href = _safe_join(base_url, href_match.group(2))
        if "stylesheet" not in rel and not href.lower().split("?")[0].endswith(".css"):
            continue
        if href not in seen:
            seen.add(href)
            out.append(href)
    return out


def _dedupe_dicts(items: Iterable[Dict[str, Any]], key_fields: Sequence[str]) -> List[Dict[str, Any]]:
    seen: set[Tuple[Any, ...]] = set()
    out: List[Dict[str, Any]] = []
    for item in items:
        key = tuple(item.get(k) for k in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _payload_dict(payload: Any) -> Dict[str, Any]:
    if payload is None:
        return {}
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        stripped = payload.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        return {"url": stripped}
    return {"value": payload}


def _safe_head_or_probe(url: str, timeout: int = 5) -> Dict[str, Any]:
    """HEAD first, then a tiny GET only when HEAD is blocked or not useful."""
    _require_requests()
    clean_url = _normalise_url(url)
    result: Dict[str, Any] = {"url": clean_url, "ok": False}
    headers = dict(DEFAULT_HEADERS)
    headers["Accept"] = "application/json,text/plain,*/*"

    try:
        response = requests.head(  # type: ignore[union-attr]
            clean_url,
            timeout=timeout,
            headers=headers,
            allow_redirects=True,
        )
        result.update(
            {
                "ok": True,
                "method": "HEAD",
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "server": response.headers.get("server", ""),
                "final_url": response.url,
                "text_sample": "",
            }
        )
        if response.status_code not in {405, 403, 404}:
            return result
    except Exception as exc:
        result["head_error"] = str(exc)

    try:
        probe_headers = dict(headers)
        probe_headers["Range"] = "bytes=0-8191"
        response = requests.get(  # type: ignore[union-attr]
            clean_url,
            timeout=timeout,
            headers=probe_headers,
            stream=True,
            allow_redirects=True,
        )
        body = b""
        for chunk in response.iter_content(8192):
            body += chunk or b""
            break
        encoding = response.encoding or "utf-8"
        result.update(
            {
                "ok": True,
                "method": "GET_RANGE",
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "server": response.headers.get("server", ""),
                "final_url": response.url,
                "text_sample": body.decode(encoding, errors="replace")[:1000],
            }
        )
    except Exception as exc:
        result["get_error"] = str(exc)
    return result


def _parse_cert_time(value: str) -> Optional[str]:
    if not value:
        return None
    # Example from ssl.getpeercert(): 'Jun  1 00:00:00 2026 GMT'
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return _dt.datetime.strptime(value, fmt).replace(tzinfo=_dt.timezone.utc).isoformat()
        except Exception:
            continue
    return value


def _name_tuple_to_dict(value: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not value:
        return out
    for rdn in value:
        for key, val in rdn:
            out[str(key)] = str(val)
    return out


def _resolve_url_like(base_url: str, value: str, prefer_ws: bool = False) -> str:
    value = _html.unescape(value.strip())
    if not value:
        return value
    if value.startswith("//"):
        base_scheme = urllib.parse.urlparse(base_url).scheme or "https"
        scheme = "wss" if prefer_ws and base_scheme == "https" else "ws" if prefer_ws else base_scheme
        return f"{scheme}:{value}"
    if value.startswith(("ws://", "wss://", "http://", "https://")):
        return value
    joined = urllib.parse.urljoin(base_url, value)
    if prefer_ws:
        parsed = urllib.parse.urlparse(joined)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        joined = urllib.parse.urlunparse(parsed._replace(scheme=scheme))
    return joined


# ---------------------------------------------------------------------------
# 1. TLS fingerprint / certificate handshake analysis
# ---------------------------------------------------------------------------

def tls_fingerprint(url: str) -> Dict[str, Any]:
    """Analyze SSL/TLS handshake characteristics for a HTTPS host.

    This does not bypass TLS, intercept traffic, or attempt vulnerability exploitation.
    It opens one normal TLS socket and records public handshake/certificate details.
    """
    try:
        clean_url = _normalise_url(url)
        parsed = urllib.parse.urlparse(clean_url)
        host = parsed.hostname
        if not host:
            raise EngineInputError("url host is missing")
        port = parsed.port or 443

        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])

        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                cipher = tls_sock.cipher()
                peercert_der = tls_sock.getpeercert(binary_form=True)
                serial = cert.get("serialNumber")

                return {
                    "ok": True,
                    "url": clean_url,
                    "host": host,
                    "port": port,
                    "tls_version": tls_sock.version(),
                    "cipher": {
                        "name": cipher[0] if cipher else None,
                        "protocol": cipher[1] if cipher else None,
                        "secret_bits": cipher[2] if cipher else None,
                    },
                    "alpn_protocol": tls_sock.selected_alpn_protocol(),
                    "sni_used": True,
                    "subject": _name_tuple_to_dict(cert.get("subject")),
                    "issuer": _name_tuple_to_dict(cert.get("issuer")),
                    "serial_number": serial,
                    "not_before": _parse_cert_time(cert.get("notBefore", "")),
                    "not_after": _parse_cert_time(cert.get("notAfter", "")),
                    "subject_alt_names": [v for k, v in cert.get("subjectAltName", []) if k.lower() == "dns"],
                    "cert_der_sha256_available": bool(peercert_der),
                    "method": "single_tls_socket_handshake",
                }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "single_tls_socket_handshake"}


# ---------------------------------------------------------------------------
# 3. DNS history reconstruction from public archive artifacts
# ---------------------------------------------------------------------------

def dns_history_reconstruct(domain: str) -> Dict[str, Any]:
    """Recover possible historical IP/domain artifacts from public archives.

    Important: the Wayback CDX API is not a passive-DNS database. This engine scans
    archived URL records for literal IPv4/IPv6/domain artifacts and reports them as
    hints, not confirmed historical DNS answers.
    """
    try:
        _require_requests()
        host = _hostname(_domain_to_url(domain))
        wayback_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"{host}/*",
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "limit": "200",
        }
        response = requests.get(wayback_url, params=params, timeout=DEFAULT_TIMEOUT)  # type: ignore[union-attr]
        response.raise_for_status()
        rows = response.json()

        ipv4_found: set[str] = set()
        ipv6_found: set[str] = set()
        domains_found: set[str] = set()
        samples: List[Dict[str, Any]] = []

        for row in rows[1:] if isinstance(rows, list) else []:
            if not isinstance(row, list) or len(row) < 2:
                continue
            timestamp, original = row[0], urllib.parse.unquote(str(row[1]))
            for ip in re.findall(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", original):
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    ipv4_found.add(str(ip_obj))
                    if len(samples) < 20:
                        samples.append({"timestamp": timestamp, "artifact": str(ip_obj), "source_url": original})
                except Exception:
                    pass
            for ip in re.findall(r"\[[0-9a-fA-F:]{3,}\]", original):
                try:
                    ip_obj = ipaddress.ip_address(ip.strip("[]"))
                    ipv6_found.add(str(ip_obj))
                except Exception:
                    pass
            parsed = urllib.parse.urlparse(original)
            if parsed.hostname and parsed.hostname != host:
                domains_found.add(parsed.hostname.lower())

        return {
            "ok": True,
            "domain": host,
            "unique_ips_detected": sorted(ipv4_found | ipv6_found),
            "ip_count": len(ipv4_found | ipv6_found),
            "related_domains_detected": sorted(domains_found)[:50],
            "related_domain_count": len(domains_found),
            "samples": samples,
            "method": "wayback_cdx_artifact_extraction_not_passive_dns",
            "note": "These are archive artifacts/hints, not verified historical DNS records.",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "wayback_cdx_artifact_extraction_not_passive_dns"}


# ---------------------------------------------------------------------------
# 4. JavaScript chunk mining without source maps
# ---------------------------------------------------------------------------

def js_chunk_mine(url: str) -> Dict[str, Any]:
    """Extract lightweight code structure hints from first-party JS bundles.

    No source maps are required. The engine only downloads a small number of linked
    JS files and searches for function/class/import/route-like patterns.
    """
    try:
        clean_url = _normalise_url(url)
        html_text, html_meta = _get_text(clean_url, max_bytes=MAX_HTML_BYTES)
        scripts = extract_js_files(html_text, html_meta.get("url") or clean_url)

        results: List[Dict[str, Any]] = []
        files_scanned = 0
        skipped_external = 0

        for script_src in scripts[:10]:
            # Passive and conservative: same-site bundles only by default.
            if not _same_site(clean_url, script_src):
                skipped_external += 1
                continue
            try:
                js_content, js_meta = _get_text(
                    script_src,
                    timeout=DEFAULT_TIMEOUT,
                    max_bytes=MAX_JS_BYTES,
                    headers={"Accept": "application/javascript,text/javascript,*/*"},
                )
                files_scanned += 1

                patterns = [
                    ("function", r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\("),
                    ("class", r"\bclass\s+([A-Za-z_$][\w$]*)\b"),
                    ("const_function", r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"),
                    ("import_path", r"\bimport\s*\([^)]*[\"']([^\"']+)[\"']\s*\)"),
                    ("route_literal", r"[\"']((?:/api|/v\d|/graphql|/ws|/socket)[^\"'`\s<>]{1,160})[\"']"),
                ]
                for chunk_type, pattern in patterns:
                    for match in re.finditer(pattern, js_content, re.I | re.S):
                        identifier = match.group(1)[:220]
                        results.append(
                            {
                                "source_file": script_src,
                                "chunk_type": chunk_type,
                                "identifier": identifier,
                                "confidence": 0.7 if chunk_type in {"function", "class", "const_function"} else 0.8,
                                "truncated_source": js_meta.get("truncated", False),
                            }
                        )
                        if len(results) >= 250:
                            break
                    if len(results) >= 250:
                        break
            except Exception:
                continue

        results = _dedupe_dicts(results, ["source_file", "chunk_type", "identifier"])
        return {
            "ok": True,
            "url": clean_url,
            "scripts_discovered": len(scripts),
            "scripts_scanned": files_scanned,
            "external_scripts_skipped": skipped_external,
            "chunks_found": len(results),
            "samples": results[:40],
            "method": "first_party_js_static_pattern_mining",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "first_party_js_static_pattern_mining"}


# ---------------------------------------------------------------------------
# 5. WebSocket discovery from HTML/JS payloads
# ---------------------------------------------------------------------------

def websocket_discovery(url: str) -> Dict[str, Any]:
    """Find WebSocket URL hints in HTML and first-party JS payloads.

    This only discovers references. It does not open websocket connections.
    """
    try:
        clean_url = _normalise_url(url)
        html_text, html_meta = _get_text(clean_url, max_bytes=MAX_HTML_BYTES)
        base_url = html_meta.get("url") or clean_url
        scripts = extract_js_files(html_text, base_url)

        blobs: List[Tuple[str, str]] = [("html", html_text)]
        for script_src in scripts[:8]:
            if not _same_site(base_url, script_src):
                continue
            try:
                js_text, _ = _get_text(
                    script_src,
                    timeout=DEFAULT_TIMEOUT,
                    max_bytes=MAX_JS_BYTES,
                    headers={"Accept": "application/javascript,text/javascript,*/*"},
                )
                blobs.append((script_src, js_text))
            except Exception:
                continue

        patterns = [
            ("new_websocket", r"new\s+WebSocket\s*\(\s*[\"']([^\"']+?)[\"']"),
            ("socket_io_connect", r"\bio\s*\(\s*[\"']([^\"']+?)[\"']"),
            ("socket_connect", r"\bsocket\.connect\s*\(\s*[\"']([^\"']+?)[\"']"),
            ("react_hook_websocket", r"react-use-websocket|react-hook-websocket|useWebSocket[\s\S]{0,220}?[\"']((?:wss?:)?//[^\"']+|/[^\"']+)[\"']"),
            ("literal_ws_url", r"[\"']((?:wss?:)?//[^\"']+|/(?:ws|socket|realtime|events)[^\"']*)[\"']"),
        ]

        found: List[Dict[str, Any]] = []
        for source, blob in blobs:
            for label, pattern in patterns:
                for match in re.finditer(pattern, blob, re.I | re.S):
                    raw = match.group(1).strip()
                    full = _resolve_url_like(base_url, raw, prefer_ws=True)
                    found.append(
                        {
                            "type": "absolute" if re.match(r"^(?:wss?:)?//", raw) else "relative_or_literal",
                            "url": full,
                            "raw": raw[:220],
                            "source": source,
                            "pattern": label,
                            "confidence": 0.9 if full.startswith(("ws://", "wss://")) else 0.65,
                        }
                    )

        found = _dedupe_dicts(found, ["url", "pattern"])
        return {
            "ok": True,
            "url": clean_url,
            "websockets_found": len(found),
            "samples": found[:30],
            "method": "html_and_first_party_js_reference_scan_no_connection",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "html_and_first_party_js_reference_scan_no_connection"}


# ---------------------------------------------------------------------------
# 6. GraphQL endpoint detection
# ---------------------------------------------------------------------------

def graphql_detect(url: str) -> Dict[str, Any]:
    """Detect potential GraphQL endpoints from HTML/JS and common path probes.

    No introspection query is sent. Only static references plus HEAD/tiny GET probes.
    """
    try:
        clean_url = _normalise_url(url)
        html_text, html_meta = _get_text(clean_url, max_bytes=MAX_HTML_BYTES)
        base_url = html_meta.get("url") or clean_url
        scripts = extract_js_files(html_text, base_url)
        blobs: List[Tuple[str, str]] = [("html", html_text)]

        for script_src in scripts[:8]:
            if not _same_site(base_url, script_src):
                continue
            try:
                js_text, _ = _get_text(
                    script_src,
                    timeout=DEFAULT_TIMEOUT,
                    max_bytes=MAX_JS_BYTES,
                    headers={"Accept": "application/javascript,text/javascript,*/*"},
                )
                blobs.append((script_src, js_text))
            except Exception:
                continue

        endpoints: List[Dict[str, Any]] = []
        patterns = [
            ("window_graphql_endpoint", r"window\.graphqlEndpoint\s*=\s*[\"']([^\"']+?)[\"']"),
            ("graphql_url_literal", r"[\"']([^\"']*graphql[^\"']*)[\"']"),
            ("apollo_uri", r"\buri\s*:\s*[\"']([^\"']+?)[\"'][\s\S]{0,160}?(?:ApolloClient|createHttpLink|GraphQL)"),
            ("gql_fetch", r"fetch\s*\(\s*[\"']([^\"']*graphql[^\"']*)[\"']"),
            ("graphql_ws", r"[\"']((?:wss?:)?//[^\"']*graphql[^\"']*)[\"']"),
        ]

        for source, blob in blobs:
            for label, pattern in patterns:
                for match in re.finditer(pattern, blob, re.I | re.S):
                    raw = match.group(1).strip()
                    if not raw or len(raw) > 250:
                        continue
                    endpoint_url = _resolve_url_like(base_url, raw, prefer_ws=raw.startswith(("ws", "//")))
                    endpoints.append(
                        {
                            "pattern": label,
                            "url": endpoint_url,
                            "source": source,
                            "confidence": 0.85,
                            "method_tested": "static_reference",
                        }
                    )

        graphql_paths = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql"]
        for path in graphql_paths:
            test_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            probe = _safe_head_or_probe(test_url, timeout=5)
            text = (probe.get("content_type", "") + " " + probe.get("text_sample", "")).lower()
            status = int(probe.get("status_code") or 0)
            if probe.get("ok") and status < 500 and ("graphql" in text or status in {200, 204, 400, 405}):
                confidence = 0.9 if "graphql" in text else 0.55
                endpoints.append(
                    {
                        "path": path,
                        "url": probe.get("final_url") or test_url,
                        "method_tested": probe.get("method"),
                        "status_code": status,
                        "content_type": probe.get("content_type", ""),
                        "confidence": confidence,
                    }
                )

        endpoints = _dedupe_dicts(endpoints, ["url", "method_tested"])
        return {
            "ok": True,
            "url": clean_url,
            "endpoints_found": len(endpoints),
            "samples": endpoints[:30],
            "method": "static_reference_scan_plus_common_path_head_probe_no_introspection",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "static_reference_scan_plus_common_path_head_probe_no_introspection"}


# ---------------------------------------------------------------------------
# 7. REST API route enumeration via fixed HEAD probes
# ---------------------------------------------------------------------------

def rest_api_enumerate(url: str, depth: int = 3) -> Dict[str, Any]:
    """Discover likely REST API prefixes with a small fixed path list.

    This is intentionally not a fuzzer. Keep depth low and only use on assets you are
    authorized to test.
    """
    try:
        clean_url = _normalise_url(url)
        base_url = clean_url.rstrip("/") + "/"
        safe_depth = max(1, min(int(depth), 10))

        api_patterns = [
            "/api/",
            "/api/v1/",
            "/api/v2/",
            "/rest/api/2/",
            "/json-api/",
            "/wp-json/",
            "/_api/",
            "/.well-known/",
            "/openapi.json",
            "/swagger.json",
        ][:safe_depth]

        found_routes: List[Dict[str, Any]] = []
        for prefix in api_patterns:
            test_url = urllib.parse.urljoin(base_url, prefix.lstrip("/"))
            try:
                probe = _safe_head_or_probe(test_url, timeout=5)
                status = int(probe.get("status_code") or 0)
                content_blob = (probe.get("content_type", "") + " " + probe.get("text_sample", "")).lower()
                looks_api = any(
                    token in content_blob
                    for token in ["application/json", "application/vnd.api+json", "openapi", "swagger", "json"]
                )
                if probe.get("ok") and status < 500 and (looks_api or status in {200, 204, 401, 403, 405}):
                    found_routes.append(
                        {
                            "prefix": prefix,
                            "url": probe.get("final_url") or test_url,
                            "status": status,
                            "content_type": probe.get("content_type", ""),
                            "method_tested": probe.get("method"),
                            "confidence": 0.9 if looks_api else 0.55,
                        }
                    )
            except Exception:
                continue

        return {
            "ok": True,
            "url": clean_url,
            "routes_found": len(found_routes),
            "samples": found_routes,
            "method": "small_fixed_rest_prefix_head_probe",
            "depth_used": safe_depth,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "small_fixed_rest_prefix_head_probe"}


# ---------------------------------------------------------------------------
# 8. Sitemap XML deep parse
# ---------------------------------------------------------------------------

def _discover_sitemaps(url: str, html_text: Optional[str] = None) -> List[str]:
    clean_url = _normalise_url(url)
    candidates: List[str] = []

    if html_text:
        # <link rel="sitemap" href="...">
        for match in re.finditer(r"<link\b[^>]*>", html_text, re.I | re.S):
            tag = match.group(0)
            rel = re.search(r"\brel\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
            href = re.search(r"\bhref\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
            if href and rel and "sitemap" in rel.group(2).lower():
                candidates.append(_safe_join(clean_url, href.group(2)))

    base = urllib.parse.urlparse(clean_url)
    origin = urllib.parse.urlunparse((base.scheme, base.netloc, "", "", "", ""))
    candidates.extend(
        [
            urllib.parse.urljoin(origin + "/", "sitemap.xml"),
            urllib.parse.urljoin(origin + "/", "sitemap_index.xml"),
            urllib.parse.urljoin(origin + "/", "sitemap-index.xml"),
            urllib.parse.urljoin(origin + "/", "robots.txt"),
        ]
    )

    out: List[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out[:10]


def _parse_sitemap_xml(xml_text: str, sitemap_url: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    urls: List[Dict[str, Any]] = []
    nested: List[str] = []
    root = ET.fromstring(xml_text)

    for elem in root.iter():
        tag = elem.tag.split("}")[-1].lower()
        if tag == "sitemap":
            loc = None
            lastmod = None
            for child in elem:
                child_tag = child.tag.split("}")[-1].lower()
                if child_tag == "loc":
                    loc = (child.text or "").strip()
                elif child_tag == "lastmod":
                    lastmod = (child.text or "").strip()
            if loc:
                nested.append(_safe_join(sitemap_url, loc))
            continue
        if tag == "url":
            data: Dict[str, Any] = {"source_sitemap": sitemap_url}
            for child in elem:
                child_tag = child.tag.split("}")[-1].lower()
                text = (child.text or "").strip()
                if child_tag in {"loc", "lastmod", "changefreq", "priority"} and text:
                    data[child_tag if child_tag != "loc" else "url"] = text
            if data.get("url"):
                urls.append(data)
    return urls, nested


def sitemap_deep_parse(url: str) -> Dict[str, Any]:
    """Extract pages from sitemap XML, including nested sitemap indexes."""
    try:
        clean_url = _normalise_url(url)
        html_text = ""
        try:
            html_text, _ = _get_text(clean_url, max_bytes=MAX_HTML_BYTES)
        except Exception:
            pass

        queue = _discover_sitemaps(clean_url, html_text)
        all_urls: List[Dict[str, Any]] = []
        sitemaps_checked: List[str] = []
        seen_sitemaps: set[str] = set()

        while queue and len(sitemaps_checked) < 20 and len(all_urls) < 500:
            sitemap_url = queue.pop(0)
            if sitemap_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sitemap_url)

            try:
                if sitemap_url.endswith("robots.txt"):
                    robots_text, _ = _get_text(sitemap_url, max_bytes=250_000)
                    for sm in re.findall(r"(?im)^\s*Sitemap\s*:\s*(\S+)", robots_text):
                        queue.append(_safe_join(clean_url, sm))
                    sitemaps_checked.append(sitemap_url)
                    continue

                xml_text, meta = _get_text(
                    sitemap_url,
                    timeout=DEFAULT_TIMEOUT,
                    max_bytes=MAX_XML_BYTES,
                    headers={"Accept": "application/xml,text/xml,*/*"},
                )
                urls, nested = _parse_sitemap_xml(xml_text, meta.get("url") or sitemap_url)
                all_urls.extend(urls)
                for nested_url in nested:
                    if nested_url not in seen_sitemaps:
                        queue.append(nested_url)
                sitemaps_checked.append(sitemap_url)
            except Exception:
                continue

        all_urls = _dedupe_dicts(all_urls, ["url"])
        return {
            "ok": True,
            "url": clean_url,
            "sitemaps_found": len(sitemaps_checked),
            "sitemaps_checked": sitemaps_checked,
            "urls_extracted": len(all_urls),
            "samples": all_urls[:50],
            "method": "linked_default_and_robots_sitemap_parse",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "linked_default_and_robots_sitemap_parse"}


# ---------------------------------------------------------------------------
# 9. Robots.txt edge case harvester
# ---------------------------------------------------------------------------

def robots_edge_harvest(url: str) -> Dict[str, Any]:
    """Find interesting robots.txt rules that hint at intentionally published paths."""
    try:
        clean_url = _normalise_url(url)
        parsed = urllib.parse.urlparse(clean_url)
        origin = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        robot_paths = ["/robots.txt", "/.well-known/robotstxt"]
        interesting_tokens = [
            "/admin",
            "/debug",
            "/test",
            "/backup",
            "/staging",
            "/private",
            "/internal",
            "/api",
            "/graphql",
            "/wp-admin",
        ]

        found_rules: List[Dict[str, Any]] = []
        robots_checked: List[str] = []

        for path in robot_paths:
            test_url = urllib.parse.urljoin(origin + "/", path.lstrip("/"))
            try:
                response_text, meta = _get_text(test_url, max_bytes=250_000, headers={"Accept": "text/plain,*/*"})
                robots_checked.append(meta.get("url") or test_url)
                lines = response_text.splitlines()
                rule_count = 0
                sitemaps: List[str] = []
                for idx, line in enumerate(lines):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or ":" not in stripped:
                        continue
                    key, value = stripped.split(":", 1)
                    key_l = key.strip().lower()
                    value = value.strip()
                    if key_l in {"allow", "disallow"}:
                        rule_count += 1
                        lower_value = value.lower()
                        for token in interesting_tokens:
                            if token in lower_value:
                                found_rules.append(
                                    {
                                        "robots_url": meta.get("url") or test_url,
                                        "directive": key_l,
                                        "path_hint": value[:220],
                                        "matched_token": token,
                                        "line": idx + 1,
                                        "confidence": 0.8,
                                    }
                                )
                    elif key_l == "sitemap" and value:
                        sitemaps.append(value)
                found_rules.append(
                    {
                        "robots_url": meta.get("url") or test_url,
                        "has_allow_directives": bool(re.search(r"(?im)^\s*Allow\s*:", response_text)),
                        "has_disallow_directives": bool(re.search(r"(?im)^\s*Disallow\s*:", response_text)),
                        "rule_count": rule_count,
                        "sitemaps": sitemaps[:10],
                        "confidence": 0.6,
                    }
                )
            except Exception:
                continue

        found_rules = _dedupe_dicts(found_rules, ["robots_url", "directive", "path_hint", "matched_token"])
        return {
            "ok": True,
            "url": clean_url,
            "robots_checked": robots_checked,
            "rules_found": len(found_rules),
            "samples": found_rules[:30],
            "method": "robots_txt_edge_case_analysis",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "robots_txt_edge_case_analysis"}


# ---------------------------------------------------------------------------
# 10. OpenGraph/social metadata deep dive
# ---------------------------------------------------------------------------

def social_metadata_harvest(url: str) -> Dict[str, Any]:
    """Extract OpenGraph, Twitter Card, JSON-LD, and common metadata."""
    try:
        clean_url = _normalise_url(url)
        html_text, meta = _get_text(clean_url, max_bytes=MAX_HTML_BYTES)

        meta_tags: List[Dict[str, Any]] = []
        for match in re.finditer(r"<meta\b[^>]*>", html_text, re.I | re.S):
            tag = match.group(0)
            prop = re.search(r"\bproperty\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
            name = re.search(r"\bname\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
            content = re.search(r"\bcontent\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
            key = (prop.group(2) if prop else name.group(2) if name else "").strip()
            if not key or not content:
                continue
            key_l = key.lower()
            if key_l.startswith("og:") or key_l.startswith("twitter:") or key_l in {
                "description",
                "keywords",
                "author",
                "article:published_time",
                "article:modified_time",
            }:
                meta_tags.append({"key": key, "content": _html.unescape(content.group(2).strip())[:500]})

        json_ld_samples: List[Dict[str, Any]] = []
        for match in re.finditer(
            r"<script\b[^>]+type\s*=\s*([\"'])application/ld\+json\1[^>]*>(.*?)</script>",
            html_text,
            re.I | re.S,
        ):
            raw = match.group(2).strip()
            if not raw:
                continue
            try:
                parsed = json.loads(_html.unescape(raw))
                sample: Dict[str, Any] = {}
                if isinstance(parsed, dict):
                    for key in ["@type", "name", "headline", "description", "url", "datePublished", "dateModified"]:
                        if key in parsed:
                            sample[key] = parsed[key]
                elif isinstance(parsed, list):
                    sample["list_length"] = len(parsed)
                    sample["types"] = [x.get("@type") for x in parsed[:5] if isinstance(x, dict)]
                if sample:
                    json_ld_samples.append(sample)
            except Exception:
                json_ld_samples.append({"raw_sample": raw[:500], "parse_error": True})
            if len(json_ld_samples) >= 5:
                break

        og_tags = [x for x in meta_tags if x["key"].lower().startswith("og:")]
        twitter_tags = [x for x in meta_tags if x["key"].lower().startswith("twitter:")]

        return {
            "ok": True,
            "url": clean_url,
            "final_url": meta.get("url"),
            "og_tags_found": len(og_tags),
            "twitter_cards_found": len(twitter_tags),
            "meta_tags_found": len(meta_tags),
            "json_ld_blocks_found": len(json_ld_samples),
            "samples": {
                "og": og_tags[:20],
                "twitter": twitter_tags[:15],
                "json_ld": json_ld_samples,
                "other_meta": [x for x in meta_tags if not x["key"].lower().startswith(("og:", "twitter:"))][:15],
            },
            "method": "html_social_and_structured_metadata_parse",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "html_social_and_structured_metadata_parse"}


# ---------------------------------------------------------------------------
# Extra: CDN asset hunter engine referenced in the prompt
# ---------------------------------------------------------------------------

def cdn_asset_hunt(url: str) -> Dict[str, Any]:
    """Collect linked asset hosts and mark CDN-looking hosts by public hints."""
    try:
        clean_url = _normalise_url(url)
        html_text, meta = _get_text(clean_url, max_bytes=MAX_HTML_BYTES)
        base_url = meta.get("url") or clean_url

        assets: List[Dict[str, Any]] = []
        for src in _extract_attr_values(html_text, "script", "src"):
            assets.append({"type": "script", "url": _safe_join(base_url, src)})
        for href in _extract_attr_values(html_text, "link", "href"):
            assets.append({"type": "link", "url": _safe_join(base_url, href)})
        for src in _extract_attr_values(html_text, "img", "src")[:50]:
            assets.append({"type": "image", "url": _safe_join(base_url, src)})

        cdn_tokens = [
            "cdn",
            "cloudfront.net",
            "akamai",
            "fastly",
            "cloudflare",
            "jsdelivr",
            "unpkg",
            "gstatic",
            "static",
            "assets",
            "edgekey",
            "azureedge",
        ]
        host_map: Dict[str, Dict[str, Any]] = {}
        for asset in assets:
            parsed = urllib.parse.urlparse(asset["url"])
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            entry = host_map.setdefault(
                host,
                {
                    "host": host,
                    "asset_count": 0,
                    "types": set(),
                    "samples": [],
                    "same_site": _same_site(base_url, asset["url"]),
                    "cdn_hint": False,
                    "matched_hints": [],
                },
            )
            entry["asset_count"] += 1
            entry["types"].add(asset["type"])
            if len(entry["samples"]) < 5:
                entry["samples"].append(asset["url"])
            matched = [token for token in cdn_tokens if token in host]
            if matched:
                entry["cdn_hint"] = True
                entry["matched_hints"] = sorted(set(entry["matched_hints"] + matched))

        hosts = []
        for entry in host_map.values():
            entry["types"] = sorted(entry["types"])
            hosts.append(entry)
        hosts.sort(key=lambda x: (not x["cdn_hint"], -x["asset_count"], x["host"]))

        return {
            "ok": True,
            "url": clean_url,
            "assets_found": len(assets),
            "hosts_found": len(hosts),
            "cdn_like_hosts": sum(1 for h in hosts if h["cdn_hint"]),
            "samples": hosts[:30],
            "method": "html_asset_host_harvest_with_cdn_name_hints",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": "html_asset_host_harvest_with_cdn_name_hints"}


# ---------------------------------------------------------------------------
# Engine classes
# ---------------------------------------------------------------------------

class _FunctionEngine(StandaloneDiscoveryEngine):
    name = "function_engine"
    actions: Mapping[str, Any] = {}
    default_action = "scan"

    def run(self, action: str = "status", payload: Any = None) -> EngineReport:  # type: ignore[override]
        if action in {"status", "health", "ping"}:
            return self._make_report(True, "ready", {"actions": sorted(self.actions)}, action=action)

        if action not in self.actions:
            if action == "scan" and self.default_action in self.actions:
                action = self.default_action
            else:
                return self._make_report(
                    False,
                    f"Unknown action: {action}",
                    {"actions": sorted(self.actions)},
                    error="unknown_action",
                    action=action,
                )

        if not super().run(action, payload).ok:
            return self._make_report(False, f"Failed to initialize {self.__class__.__name__}", action=action)

        try:
            args = _payload_dict(payload)
            func = self.actions[action]
            data = self._call_action(func, args)
            ok = bool(data.get("ok", True)) if isinstance(data, dict) else True
            return self._make_report(ok, "completed" if ok else "failed", data if isinstance(data, dict) else {"result": data}, action=action)
        except Exception as exc:
            return self._make_report(False, "failed", error=str(exc), action=action)

    def _call_action(self, func: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        # Override when actions need non-url arguments.
        url = args.get("url") or args.get("domain") or args.get("target") or args.get("value")
        if not url:
            raise EngineInputError("payload must include url/domain/target")
        return func(str(url))


class TLSFingerprintEngine(_FunctionEngine):
    name = "tls_fingerprint"
    actions = {"scan": tls_fingerprint, "tls_fingerprint": tls_fingerprint}


class DNSHistoryReconstructionEngine(_FunctionEngine):
    name = "dns_history_reconstruct"
    actions = {"scan": dns_history_reconstruct, "dns_history_reconstruct": dns_history_reconstruct}

    def _call_action(self, func: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        domain = args.get("domain") or args.get("url") or args.get("target") or args.get("value")
        if not domain:
            raise EngineInputError("payload must include domain/url/target")
        return func(str(domain))


class JSChunkMiningEngine(_FunctionEngine):
    name = "js_chunk_mine"
    actions = {"scan": js_chunk_mine, "js_chunk_mine": js_chunk_mine}


class WebSocketDiscoveryEngine(_FunctionEngine):
    name = "websocket_discovery"
    actions = {"scan": websocket_discovery, "websocket_discovery": websocket_discovery}


class GraphQLEndpointDetectionEngine(_FunctionEngine):
    name = "graphql_detect"
    actions = {"scan": graphql_detect, "graphql_detect": graphql_detect}


class RESTAPIRouteEnumerationEngine(_FunctionEngine):
    name = "rest_api_enumerate"
    actions = {"scan": rest_api_enumerate, "rest_api_enumerate": rest_api_enumerate}

    def _call_action(self, func: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        url = args.get("url") or args.get("target") or args.get("value")
        if not url:
            raise EngineInputError("payload must include url/target")
        depth = int(args.get("depth", 3))
        return func(str(url), depth=depth)


class SitemapDeepParseEngine(_FunctionEngine):
    name = "sitemap_deep_parse"
    actions = {"scan": sitemap_deep_parse, "sitemap_deep_parse": sitemap_deep_parse}


class RobotsEdgeHarvestEngine(_FunctionEngine):
    name = "robots_edge_harvest"
    actions = {"scan": robots_edge_harvest, "robots_edge_harvest": robots_edge_harvest}


class SocialMetadataHarvestEngine(_FunctionEngine):
    name = "social_metadata_harvest"
    actions = {"scan": social_metadata_harvest, "social_metadata_harvest": social_metadata_harvest}


class CDNAsetHunterEngine(_FunctionEngine):
    # Keeping the user's spelling: CDNAsetHunterEngine.
    name = "cdn_asset_hunt"
    actions = {"scan": cdn_asset_hunt, "cdn_asset_hunt": cdn_asset_hunt}


class WebDiscoveryEngine(_FunctionEngine):
    """Multiplexer engine for GPT tool use.

    Payload examples:
        {"url": "https://example.com", "engine": "websocket"}
        {"domain": "example.com", "engine": "dns_history"}
        {"url": "https://example.com", "engine": "all_passive"}
    """

    name = "web_discovery"
    actions = {
        "tls": tls_fingerprint,
        "tls_fingerprint": tls_fingerprint,
        "dns_history": dns_history_reconstruct,
        "dns_history_reconstruct": dns_history_reconstruct,
        "js": js_chunk_mine,
        "js_chunk_mine": js_chunk_mine,
        "websocket": websocket_discovery,
        "websocket_discovery": websocket_discovery,
        "graphql": graphql_detect,
        "graphql_detect": graphql_detect,
        "rest": rest_api_enumerate,
        "rest_api_enumerate": rest_api_enumerate,
        "sitemap": sitemap_deep_parse,
        "sitemap_deep_parse": sitemap_deep_parse,
        "robots": robots_edge_harvest,
        "robots_edge_harvest": robots_edge_harvest,
        "social": social_metadata_harvest,
        "social_metadata_harvest": social_metadata_harvest,
        "cdn": cdn_asset_hunt,
        "cdn_asset_hunt": cdn_asset_hunt,
    }

    def run(self, action: str = "status", payload: Any = None) -> EngineReport:  # type: ignore[override]
        args = _payload_dict(payload)
        if action == "scan" and args.get("engine"):
            action = str(args["engine"])
        if action == "all_passive" or (action == "scan" and args.get("all_passive")):
            return self._run_all(args, action="all_passive")
        return super().run(action, args)

    def _call_action(self, func: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        if func is dns_history_reconstruct:
            target = args.get("domain") or args.get("url") or args.get("target") or args.get("value")
            if not target:
                raise EngineInputError("payload must include domain/url/target")
            return func(str(target))
        if func is rest_api_enumerate:
            url = args.get("url") or args.get("target") or args.get("value")
            if not url:
                raise EngineInputError("payload must include url/target")
            return func(str(url), depth=int(args.get("depth", 3)))
        url = args.get("url") or args.get("target") or args.get("value")
        if not url:
            raise EngineInputError("payload must include url/target")
        return func(str(url))

    def _run_all(self, args: Dict[str, Any], action: str) -> EngineReport:
        url = args.get("url") or args.get("target") or args.get("value")
        domain = args.get("domain") or url
        if not url:
            return self._make_report(False, "payload must include url", error="missing_url", action=action)

        funcs = [
            ("tls", lambda: tls_fingerprint(str(url))),
            ("dns_history", lambda: dns_history_reconstruct(str(domain))),
            ("cdn", lambda: cdn_asset_hunt(str(url))),
            ("sitemap", lambda: sitemap_deep_parse(str(url))),
            ("robots", lambda: robots_edge_harvest(str(url))),
            ("social", lambda: social_metadata_harvest(str(url))),
            ("websocket", lambda: websocket_discovery(str(url))),
            ("graphql", lambda: graphql_detect(str(url))),
            ("rest", lambda: rest_api_enumerate(str(url), depth=int(args.get("depth", 3)))),
            ("js", lambda: js_chunk_mine(str(url))),
        ]
        data: Dict[str, Any] = {}
        for name, thunk in funcs:
            try:
                data[name] = thunk()
            except Exception as exc:
                data[name] = {"ok": False, "error": str(exc)}
        ok = any(isinstance(v, dict) and v.get("ok") for v in data.values())
        return self._make_report(ok, "completed" if ok else "failed", data, action=action)


ENGINE_REGISTRY = {
    "tls_fingerprint": TLSFingerprintEngine,
    "dns_history_reconstruct": DNSHistoryReconstructionEngine,
    "js_chunk_mine": JSChunkMiningEngine,
    "websocket_discovery": WebSocketDiscoveryEngine,
    "graphql_detect": GraphQLEndpointDetectionEngine,
    "rest_api_enumerate": RESTAPIRouteEnumerationEngine,
    "sitemap_deep_parse": SitemapDeepParseEngine,
    "robots_edge_harvest": RobotsEdgeHarvestEngine,
    "social_metadata_harvest": SocialMetadataHarvestEngine,
    "cdn_asset_hunt": CDNAsetHunterEngine,
    "web_discovery": WebDiscoveryEngine,
}


def get_engine(name: str) -> StandaloneDiscoveryEngine:
    key = name.strip().lower()
    if key not in ENGINE_REGISTRY:
        raise KeyError(f"Unknown engine {name!r}. Available: {', '.join(sorted(ENGINE_REGISTRY))}")
    return ENGINE_REGISTRY[key]()


if __name__ == "__main__":
    # Tiny CLI smoke test:
    #   python web_discovery_engines.py https://example.com social
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    action = sys.argv[2] if len(sys.argv) > 2 else "social"
    engine = WebDiscoveryEngine()
    print(json.dumps(engine.run(action, {"url": target}).to_dict(), indent=2, default=str))
