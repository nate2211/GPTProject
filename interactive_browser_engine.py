from __future__ import annotations

"""Human-in-the-loop interactive browser/Tor engine for PromptChat.

This engine intentionally does NOT solve CAPTCHAs, bypass logins, extract raw
cookies, or read passwords/tokens. It opens a visible browser for the user,
keeps a persistent local Playwright profile, and only reads visible page content
when the caller passes allow_read=True.

Install optional dependency:
    pip install playwright
    python -m playwright install chromium

For Tor mode, run Tor Browser/Tor first, or provide tor_exe_path. Default SOCKS:
    socks5h://127.0.0.1:9150
"""

import base64
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, urlparse

DEFAULT_TOR_SOCKS_URL = "socks5h://127.0.0.1:9150"
DEFAULT_TOR_START_TIMEOUT_SEC = 45
DEFAULT_TOR_DATA_DIR = "data/tor"
DEFAULT_DATA_DIR = "data/interactive_browser"
DEFAULT_TIMEOUT_SEC = 300
# Human handoff timeout is intentionally longer than normal navigation timeout.
# This is the value used by open_wait_for_close/open_wait_read unless overridden
# with params.wait_timeout_sec.
DEFAULT_HANDOFF_TIMEOUT_SEC = 7200
DEFAULT_MAX_CHARS = 20000

JAVASCRIPT_MODE_BROWSER = "browser"
JAVASCRIPT_MODE_DISABLED = "disabled"
JAVASCRIPT_MODE_SAFE = "safe"
JAVASCRIPT_MODES = {JAVASCRIPT_MODE_BROWSER, JAVASCRIPT_MODE_DISABLED, JAVASCRIPT_MODE_SAFE, "on", "off", "enabled", "true", "false"}
DEFAULT_VISUAL_ELEMENTS_LIMIT = 250
DEFAULT_OCR_LANGUAGE = "eng"

INTERACTIVE_BROWSER_ACTIONS = [
    "capabilities",
    "status",
    "open_user_session",
    "search",
    "wait_for_handoff",
    # Opens the visible browser, blocks until the user closes it, then returns.
    # This is useful when the GPT must not answer until the human handoff is done.
    "open_wait_for_close",
    # Same as open_wait_for_close, but also reopens headlessly and reads the approved
    # visible page when allow_read=True. After this returns, the normal tool loop can
    # continue with any other tool, not only interactive_tor/interactive_search.
    "open_wait_read",
    "read_session",
    "continue_session",
    "close_session",
    "clear_session",
]

_DENIED_SELECTORS = [
    "input[type='password']",
    "input[name*='password' i]",
    "input[id*='password' i]",
    "input[name*='pass' i]",
    "input[id*='pass' i]",
    "input[name*='token' i]",
    "input[id*='token' i]",
    "input[name*='secret' i]",
    "input[id*='secret' i]",
    "input[name*='key' i]",
    "input[id*='key' i]",
]

_SESSION_LOCK = threading.RLock()
_SESSIONS: Dict[str, "BrowserSession"] = {}
_TOR_PROCESSES: Dict[str, subprocess.Popen] = {}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_session_id(value: str, default: str) -> str:
    raw = (value or default or "default").strip()
    raw = re.sub(r"[^a-zA-Z0-9_.-]+", "_", raw)
    raw = raw.strip("._-") or default or "default"
    return raw[:80]


def _as_int(value: Any, default: int, minimum: int = 0, maximum: int = 2_000_000) -> int:
    try:
        n = int(value)
    except Exception:
        n = int(default)
    return max(minimum, min(maximum, n))


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _normalize_javascript_mode(value: Any, default: str = JAVASCRIPT_MODE_BROWSER) -> str:
    raw = _as_str(value, default).strip().lower()
    if raw in {"", "1", "true", "yes", "y", "on", "enabled", "enable"}:
        return JAVASCRIPT_MODE_BROWSER
    if raw in {"0", "false", "no", "n", "off", "disabled", "disable", "none"}:
        return JAVASCRIPT_MODE_DISABLED
    if raw in {"safe", "browser", "automation"}:
        return JAVASCRIPT_MODE_BROWSER if raw in {"browser", "automation"} else JAVASCRIPT_MODE_SAFE
    return default


def _javascript_enabled(javascript_mode: Any) -> bool:
    return _normalize_javascript_mode(javascript_mode) != JAVASCRIPT_MODE_DISABLED


def _browser_automation_enabled(javascript_mode: Any) -> bool:
    return _normalize_javascript_mode(javascript_mode) == JAVASCRIPT_MODE_BROWSER



def _extract_visual_elements(page: Any, *, limit: int = DEFAULT_VISUAL_ELEMENTS_LIMIT) -> List[Dict[str, Any]]:
    """Return visible, programmatically detectable UI elements with bounding boxes."""
    limit = _as_int(limit, DEFAULT_VISUAL_ELEMENTS_LIMIT, minimum=1, maximum=2000)
    try:
        data = page.evaluate(
            """
            (limit) => {
                const interestingSelector = [
                    'a[href]',
                    'button',
                    'input',
                    'textarea',
                    'select',
                    'summary',
                    '[role]',
                    '[aria-label]',
                    '[onclick]',
                    'img',
                    'svg',
                    'canvas',
                    'video',
                    'iframe'
                ].join(',');

                const isVisible = (el, rect, style) => {
                    if (!rect || rect.width <= 0 || rect.height <= 0) return false;
                    if (!style) return false;
                    if (style.visibility === 'hidden' || style.display === 'none' || Number(style.opacity || 1) === 0) return false;
                    return true;
                };

                const textOf = (el) => {
                    const parts = [];
                    const attrs = ['aria-label', 'title', 'alt', 'placeholder', 'value'];
                    for (const attr of attrs) {
                        const v = el.getAttribute && el.getAttribute(attr);
                        if (v) parts.push(v);
                    }
                    const t = (el.innerText || el.textContent || '').trim();
                    if (t) parts.push(t);
                    return Array.from(new Set(parts.map(x => String(x).trim()).filter(Boolean))).join(' | ').slice(0, 500);
                };

                const out = [];
                const seen = new Set();
                for (const el of Array.from(document.querySelectorAll(interestingSelector))) {
                    if (out.length >= limit) break;
                    let rect;
                    let style;
                    try {
                        rect = el.getBoundingClientRect();
                        style = window.getComputedStyle(el);
                    } catch (e) {
                        continue;
                    }
                    if (!isVisible(el, rect, style)) continue;

                    const tag = (el.tagName || '').toLowerCase();
                    const type = (el.getAttribute && el.getAttribute('type')) || '';
                    const role = (el.getAttribute && el.getAttribute('role')) || '';
                    const href = (el.href || (el.getAttribute && el.getAttribute('href')) || '');
                    const src = (el.currentSrc || el.src || (el.getAttribute && el.getAttribute('src')) || '');
                    const label = textOf(el);

                    const key = [tag, type, role, href, src, label, Math.round(rect.x), Math.round(rect.y), Math.round(rect.width), Math.round(rect.height)].join('|');
                    if (seen.has(key)) continue;
                    seen.add(key);

                    out.push({
                        index: out.length,
                        tag,
                        type: String(type).slice(0, 80),
                        role: String(role).slice(0, 80),
                        text: label,
                        href: String(href).slice(0, 1200),
                        src: String(src).slice(0, 1200),
                        bounds: {
                            x: Math.round(rect.x),
                            y: Math.round(rect.y),
                            width: Math.round(rect.width),
                            height: Math.round(rect.height)
                        },
                        viewport_visible: rect.bottom >= 0 && rect.right >= 0 && rect.top <= window.innerHeight && rect.left <= window.innerWidth
                    });
                }
                return out;
            }
            """,
            limit,
        )
        if isinstance(data, list):
            clean: List[Dict[str, Any]] = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                item = dict(item)
                if item.get("href"):
                    item["href"] = _redact_url(str(item.get("href") or ""))
                if item.get("src"):
                    item["src"] = _redact_url(str(item.get("src") or ""))
                clean.append(item)
            return clean
    except Exception:
        pass
    return []


def _maybe_inject_tesseract(page: Any, *, tesseract_js_path: str = "", tesseract_js_url: str = "") -> Dict[str, Any]:
    """Make Tesseract.js available inside the browser context when requested.

    Prefer a local tesseract.min.js file. A URL is accepted only when the caller
    explicitly provides one. Nothing is downloaded automatically by default.
    """
    try:
        available = page.evaluate("() => !!(window.Tesseract && window.Tesseract.recognize)")
        if available:
            return {"ok": True, "source": "already_loaded"}
    except Exception:
        pass

    local_path = _as_str(tesseract_js_path, "").strip().strip('"')
    if local_path:
        try:
            p = Path(local_path).expanduser()
            if p.exists() and p.is_file():
                page.add_script_tag(path=str(p.resolve()))
                available = page.evaluate("() => !!(window.Tesseract && window.Tesseract.recognize)")
                return {"ok": bool(available), "source": str(p.resolve()) if available else "", "error": "" if available else "Tesseract.js loaded but window.Tesseract.recognize was not found."}
            return {"ok": False, "error": f"tesseract_js_path does not exist: {local_path}"}
        except Exception as exc:
            return {"ok": False, "error": f"Failed to inject tesseract_js_path: {exc}"}

    explicit_url = _as_str(tesseract_js_url, "").strip()
    if explicit_url:
        try:
            page.add_script_tag(url=explicit_url)
            available = page.evaluate("() => !!(window.Tesseract && window.Tesseract.recognize)")
            return {"ok": bool(available), "source": explicit_url if available else "", "error": "" if available else "Tesseract.js URL loaded but window.Tesseract.recognize was not found."}
        except Exception as exc:
            return {"ok": False, "error": f"Failed to inject tesseract_js_url: {exc}"}

    return {
        "ok": False,
        "error": "Tesseract.js is not loaded. Pass params.tesseract_js_path to a local tesseract.min.js, or load Tesseract.js on the page yourself.",
    }


def _run_browser_ocr(
    page: Any,
    *,
    artifacts_dir: Path,
    language: str = DEFAULT_OCR_LANGUAGE,
    tesseract_js_path: str = "",
    tesseract_js_url: str = "",
    timeout_sec: int = 60,
) -> Dict[str, Any]:
    """OCR the visible viewport using Tesseract.js inside the browser.

    CAPTCHA/security challenge pages are deliberately excluded. The goal is
    accessibility/visual reading of normal pages, not challenge bypass.
    """

    inject = _maybe_inject_tesseract(page, tesseract_js_path=tesseract_js_path, tesseract_js_url=tesseract_js_url)
    if not inject.get("ok"):
        return {"ok": False, "skipped": True, "reason": inject.get("error") or "Tesseract.js unavailable.", "inject": inject}

    try:
        png_bytes = page.screenshot(full_page=False, timeout=max(5000, int(timeout_sec or 60) * 1000))
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = artifacts_dir / f"ocr_viewport_{_now_ms()}.png"
        screenshot_path.write_bytes(png_bytes)
        data_url = "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")
        lang = _as_str(language, DEFAULT_OCR_LANGUAGE).strip() or DEFAULT_OCR_LANGUAGE

        text = page.evaluate(
            """
            async ({ dataUrl, lang }) => {
                const result = await window.Tesseract.recognize(dataUrl, lang);
                return result && result.data && result.data.text ? result.data.text : '';
            }
            """,
            {"dataUrl": data_url, "lang": lang},
        )
        text = _as_str(text, "")
        return {
            "ok": True,
            "language": lang,
            "text": text[:20000],
            "text_chars": len(text),
            "text_truncated": len(text) > 20000,
            "screenshot_path": str(screenshot_path),
            "tesseract_source": inject.get("source", ""),
        }
    except Exception as exc:
        return {"ok": False, "skipped": True, "reason": f"Browser OCR failed: {exc}", "inject": inject}



_ONION_HOST_RE = re.compile(r"(?i)^(?:[a-z2-7]{16}|[a-z2-7]{56}|[a-z0-9-]{16,80})\.onion\.?$")
_ONION_LINK_RE = re.compile(
    r"(?i)\b((?:https?://)?(?:[a-z2-7]{16}|[a-z2-7]{56}|[a-z0-9-]{16,80})\.onion(?::\d{1,5})?(?:/[^\s<>'\"`)]*)?)"
)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _strip_url_wrapping(value: str) -> str:
    raw = (value or "").strip()
    raw = raw.strip("\ufeff\u200b \t\r\n")
    raw = raw.strip("<>[]{}()'\"`")
    # Common copy/paste punctuation at the end of links.
    while raw and raw[-1] in ".,;:!?)>]}'\"`":
        # Keep slash because http://example.onion/ is valid.
        raw = raw[:-1].rstrip()
    return raw


def _first_urlish_token(value: str) -> str:
    """Return the first direct URL/onion token from free text.

    This lets a model/user pass text like "open abcdef...onion/login" through
    the query field without accidentally turning it into a DuckDuckGo search.
    """
    raw = _strip_url_wrapping(value)
    if not raw:
        return ""

    onion_match = _ONION_LINK_RE.search(raw)
    if onion_match:
        return _strip_url_wrapping(onion_match.group(1))

    # A normal URL pasted into query should also navigate directly.
    normal_match = re.search(r"(?i)\b((?:https?|file)://[^\s<>'\"`]+)", raw)
    if normal_match:
        return _strip_url_wrapping(normal_match.group(1))

    if " " not in raw and "\t" not in raw and "\n" not in raw:
        return raw
    return ""


def _host_from_urlish(value: str) -> str:
    token = _first_urlish_token(value)
    if not token:
        return ""
    if token == "about:blank":
        return ""
    if not _SCHEME_RE.match(token):
        token_for_parse = "http://" + token
    else:
        token_for_parse = token
    try:
        parsed = urlparse(token_for_parse)
        return (parsed.hostname or "").strip(".").lower()
    except Exception:
        return ""


def _is_onion_host(host: str) -> bool:
    return bool(_ONION_HOST_RE.match((host or "").strip().strip(".").lower()))


def _is_onion_value(value: str) -> bool:
    return _is_onion_host(_host_from_urlish(value)) or bool(_ONION_LINK_RE.search(value or ""))


def _looks_like_url_or_host(value: str) -> bool:
    token = _first_urlish_token(value)
    if not token:
        return False
    lowered = token.lower()
    if lowered == "about:blank":
        return True
    if _SCHEME_RE.match(token):
        return True
    if _is_onion_value(token):
        return True
    if lowered.startswith("www."):
        return True
    # Host/path without a scheme. Keep this conservative so normal search text
    # still goes to search instead of becoming https://some words.
    if " " not in token and "." in token:
        host = token.split("/", 1)[0].split(":", 1)[0]
        return bool(re.match(r"(?i)^[a-z0-9.-]+\.[a-z]{2,}$", host))
    return False


def _normalize_url(url: str) -> str:
    raw = _first_urlish_token(url)
    if not raw:
        raise ValueError(f"Invalid URL: {url}")

    if raw.lower() == "about:blank":
        return "about:blank"

    if not _SCHEME_RE.match(raw):
        host = raw.split("/", 1)[0].split(":", 1)[0].strip(".").lower()
        if _is_onion_host(host):
            # Most onion services are HTTP-only. Do not auto-upgrade onion links.
            raw = "http://" + raw
        elif raw.lower().startswith("www."):
            raw = "https://" + raw
        else:
            raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme == "about" and parsed.path == "blank":
        return "about:blank"
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return raw


def _resolve_navigation_target(*, mode: str, url: str = "", query: str = "", previous_url: str = "") -> Tuple[str, str, bool]:
    """Resolve navigation for normal and Tor sessions.

    Crucial onion behavior:
    - url="abcdef...onion/path" -> http://abcdef...onion/path
    - query="abcdef...onion/path" -> direct onion navigation, NOT search
    - query="open http://abcdef...onion" -> direct onion navigation
    - normal query text -> DuckDuckGo search
    """
    source = "blank"
    target = "about:blank"

    if url and str(url).strip():
        target = _normalize_url(str(url))
        source = "url"
    elif query and str(query).strip():
        q = str(query).strip()
        if _looks_like_url_or_host(q) or _is_onion_value(q):
            target = _normalize_url(q)
            source = "query_direct_url"
        else:
            target = _search_url(q)
            source = "query_search"
    elif previous_url and str(previous_url).strip():
        prev = str(previous_url).strip()
        if prev == "about:blank":
            target = "about:blank"
        else:
            target = _normalize_url(prev)
        source = "previous_url"

    onion = _is_onion_value(target)
    if onion and mode != "tor":
        raise ValueError("Onion links require interactive_tor/Tor mode. Use interactive_tor instead of interactive_search.")
    return target, source, onion


def _search_url(query: str) -> str:
    q = quote_plus((query or "").strip())
    return f"https://duckduckgo.com/?q={q}" if q else "https://duckduckgo.com/"


def _parse_socks_host_port(socks_url: str) -> Tuple[str, int]:
    url = (socks_url or DEFAULT_TOR_SOCKS_URL).strip()
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = int(parsed.port or 9150)
    return host, port


def _playwright_proxy_server(socks_url: str) -> str:
    # Playwright expects socks5:// rather than requests-style socks5h://.
    url = (socks_url or DEFAULT_TOR_SOCKS_URL).strip()
    if url.startswith("socks5h://"):
        url = "socks5://" + url[len("socks5h://"):]
    return url


def _port_open(host: str, port: int, timeout: float = 0.75) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _find_tor_exe(explicit: str = "") -> str:
    explicit = (explicit or "").strip().strip('"')
    if explicit and Path(explicit).exists():
        return explicit

    found = shutil.which("tor") or shutil.which("tor.exe")
    if found:
        return found

    candidates: List[Path] = []
    home = Path.home()
    env_candidates = [
        os.environ.get("TOR_EXE", ""),
        os.environ.get("TOR_BROWSER_TOR_EXE", ""),
    ]
    for c in env_candidates:
        if c:
            candidates.append(Path(c))

    candidates.extend(
        [
            home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            home / "Downloads" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            home / "Documents" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            Path("C:/Program Files/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
            Path("C:/Program Files (x86)/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
        ]
    )

    for path in candidates:
        try:
            if path and path.exists():
                return str(path)
        except Exception:
            pass
    return ""


def _tor_data_root(tor_data_dir: str = DEFAULT_TOR_DATA_DIR) -> Path:
    root = Path(tor_data_dir or DEFAULT_TOR_DATA_DIR).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _find_geoip_files(tor_exe: str) -> Dict[str, str]:
    """Find Tor Browser geoip files when available.

    Tor can run without these files, but Tor Browser bundles them next to tor.exe
    on most Windows installs. Passing them explicitly makes direct tor.exe startup
    more reliable when launching outside the Tor Browser shell.
    """
    result: Dict[str, str] = {}
    try:
        base = Path(tor_exe).resolve().parent
        for name, arg in (("geoip", "--GeoIPFile"), ("geoip6", "--GeoIPv6File")):
            candidate = base / name
            if candidate.exists():
                result[arg] = str(candidate)
    except Exception:
        pass
    return result


def _build_tor_command(tor_exe_path: str, tor_socks_url: str, tor_data_dir: str) -> Tuple[List[str], str, int, str]:
    host, port = _parse_socks_host_port(tor_socks_url)
    data_root = _tor_data_root(tor_data_dir)
    exe = str(Path(tor_exe_path).expanduser().resolve())

    # Explicitly bind the SOCKS listener to the configured host/port. This is
    # the key fix: Tor Browser's tor.exe does not guarantee it will use 9150
    # unless Tor Browser itself supplies its torrc. We supply the port here.
    socks_bind = f"{host}:{port}"
    cmd: List[str] = [
        exe,
        "--SocksPort",
        socks_bind,
        "--DataDirectory",
        str(data_root),
        "--AvoidDiskWrites",
        "1",
        "--ClientOnly",
        "1",
        "--Log",
        "notice stdout",
    ]

    for arg, value in _find_geoip_files(exe).items():
        cmd.extend([arg, value])

    return cmd, host, port, str(data_root)


def _ensure_tor_running(
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    timeout_sec: int = DEFAULT_TOR_START_TIMEOUT_SEC,
    *,
    auto_start: bool = True,
    tor_data_dir: str = DEFAULT_TOR_DATA_DIR,
) -> Dict[str, Any]:
    host, port = _parse_socks_host_port(tor_socks_url)
    if _port_open(host, port):
        return {
            "ok": True,
            "already_running": True,
            "host": host,
            "port": port,
            "tor_socks_url": tor_socks_url,
            "tor_started_by_engine": False,
        }

    if not auto_start:
        return {
            "ok": False,
            "error": "Tor SOCKS port is not open and tor_auto_start is disabled.",
            "host": host,
            "port": port,
            "tor_socks_url": tor_socks_url,
            "hint": "Enable tor_auto_start or start Tor Browser/Tor manually.",
        }

    exe = _find_tor_exe(tor_exe_path)
    if not exe:
        return {
            "ok": False,
            "error": "Tor SOCKS port is not open and tor.exe was not found.",
            "host": host,
            "port": port,
            "tor_socks_url": tor_socks_url,
            "tor_exe_path": tor_exe_path,
            "hint": r"Set GPTPROJECT_TOR_EXE_PATH or choose Tor Browser\Browser\TorBrowser\Tor\tor.exe in the GUI.",
        }

    cmd, host, port, resolved_data_dir = _build_tor_command(exe, tor_socks_url, tor_data_dir)
    key = f"{host}:{port}:{resolved_data_dir}"

    with _SESSION_LOCK:
        proc = _TOR_PROCESSES.get(key)
        if proc is None or proc.poll() is not None:
            try:
                creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(Path(exe).resolve().parent),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=creationflags,
                )
                _TOR_PROCESSES[key] = proc
            except Exception as exc:
                return {
                    "ok": False,
                    "error": f"Failed to start tor.exe: {exc}",
                    "tor_exe_path": exe,
                    "tor_command": [cmd[0], "--SocksPort", f"{host}:{port}", "--DataDirectory", resolved_data_dir],
                }

    deadline = time.time() + max(3, int(timeout_sec or DEFAULT_TOR_START_TIMEOUT_SEC))
    while time.time() < deadline:
        if _port_open(host, port):
            return {
                "ok": True,
                "already_running": False,
                "host": host,
                "port": port,
                "tor_socks_url": tor_socks_url,
                "tor_exe_path": exe,
                "tor_data_dir": resolved_data_dir,
                "tor_started_by_engine": True,
            }
        time.sleep(0.35)

    return {
        "ok": False,
        "error": "tor.exe was started with the configured SOCKS port, but the port did not become reachable before timeout.",
        "tor_exe_path": exe,
        "tor_data_dir": resolved_data_dir,
        "host": host,
        "port": port,
        "tor_socks_url": tor_socks_url,
        "hint": "Check whether another Tor is already using the port, or increase tor_start_timeout_sec.",
    }


def _redact_url(url: str) -> str:
    raw = url or ""
    # Keep URL useful, but avoid dumping obvious token/password query values.
    raw = re.sub(r"(?i)([?&](?:token|access_token|auth|apikey|api_key|key|secret|password|pass|session|sid)=)[^&#]+", r"\1[REDACTED]", raw)
    return raw


def _data_root(data_dir: str = DEFAULT_DATA_DIR) -> Path:
    root = Path(data_dir or DEFAULT_DATA_DIR)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _session_root(session_id: str, data_dir: str = DEFAULT_DATA_DIR) -> Path:
    root = _data_root(data_dir) / _safe_session_id(session_id, "default")
    root.mkdir(parents=True, exist_ok=True)
    (root / "profile").mkdir(parents=True, exist_ok=True)
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    return root


def _state_path(session_id: str, data_dir: str = DEFAULT_DATA_DIR) -> Path:
    return _session_root(session_id, data_dir) / "session_state.json"


def _load_state(session_id: str, data_dir: str = DEFAULT_DATA_DIR) -> Dict[str, Any]:
    path = _state_path(session_id, data_dir)
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_state(session_id: str, data: Dict[str, Any], data_dir: str = DEFAULT_DATA_DIR) -> None:
    path = _state_path(session_id, data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    safe = dict(data or {})
    # Never persist cookies/localStorage through our JSON file. Playwright keeps
    # browser profile data locally inside the profile directory.
    safe.pop("cookies", None)
    safe.pop("storage_state", None)
    path.write_text(json.dumps(safe, ensure_ascii=False, indent=2), encoding="utf-8")


@dataclass
class BrowserSession:
    session_id: str
    mode: str
    data_dir: str = DEFAULT_DATA_DIR
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL
    playwright: Any = None
    context: Any = None
    started_at_ms: int = field(default_factory=_now_ms)
    last_read_at_ms: int = 0
    last_url: str = ""
    last_title: str = ""
    tor_started_by_engine: bool = False
    javascript_mode: str = JAVASCRIPT_MODE_BROWSER
    closed_event: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def root(self) -> Path:
        return _session_root(self.session_id, self.data_dir)

    @property
    def profile_dir(self) -> Path:
        return self.root / "profile"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    def mark_closed(self) -> None:
        try:
            self.closed_event.set()
        except Exception:
            pass

    def _has_open_page(self) -> bool:
        try:
            if self.context is None:
                return False
            pages = list(self.context.pages)
            if not pages:
                return False
            for page in pages:
                try:
                    if not page.is_closed():
                        return True
                except Exception:
                    pass
            return False
        except Exception:
            return False

    def alive(self) -> bool:
        """Return True only while the visible Playwright browser is still open.

        This version uses both Playwright close events and page-count checks.
        Some Chromium persistent-context closes do not immediately make the
        old context.pages check trustworthy, so the explicit closed_event keeps
        wait_for_handoff(wait_for_close=True) from hanging forever.
        """
        try:
            if self.closed_event.is_set():
                return False
            if self.context is None:
                self.mark_closed()
                return False
            alive = self._has_open_page()
            if not alive:
                self.mark_closed()
            return alive
        except Exception:
            self.mark_closed()
            return False

    def current_page(self) -> Any:
        if self.context is None:
            return None
        try:
            pages = list(self.context.pages)
        except Exception:
            return None
        if not pages:
            try:
                return self.context.new_page()
            except Exception:
                return None
        for page in reversed(pages):
            try:
                if not page.is_closed():
                    return page
            except Exception:
                pass
        return pages[-1] if pages else None

    def close(self) -> None:
        self.mark_closed()
        try:
            if self.context is not None:
                self.context.close()
        except Exception:
            pass
        self.context = None
        try:
            if self.playwright is not None:
                self.playwright.stop()
        except Exception:
            pass
        self.playwright = None


def _snapshot_session_page_state(session: Optional[BrowserSession], *, reason: str = "") -> Dict[str, Any]:
    """Persist the latest visible page URL/title for this profile.

    This is what makes the closed-browser handoff usable: the user can browse
    manually, close the window, and the later headless read reopens the same
    persistent profile at the last page we observed. Cookies/localStorage stay
    inside Playwright's profile directory; this JSON state file stores only
    safe routing metadata.
    """
    if session is None:
        return {"ok": False, "reason": "no_session"}

    url = ""
    title = ""
    try:
        if session.context is not None:
            pages = list(session.context.pages)
            chosen = None
            for page in reversed(pages):
                try:
                    if not page.is_closed():
                        chosen = page
                        break
                except Exception:
                    pass
            if chosen is None and pages:
                chosen = pages[-1]

            if chosen is not None:
                try:
                    url = chosen.url or ""
                except Exception:
                    url = ""
                try:
                    title = chosen.title() or ""
                except Exception:
                    title = ""
    except Exception:
        pass

    if url:
        session.last_url = url
    if title:
        session.last_title = title

    state = _load_state(session.session_id, session.data_dir)
    _save_state(
        session.session_id,
        {
            **state,
            "session_id": session.session_id,
            "mode": session.mode,
            "last_url": session.last_url,
            "last_title": session.last_title,
            "profile_dir": str(session.profile_dir),
            "artifacts_dir": str(session.artifacts_dir),
            "updated_at_ms": _now_ms(),
            "last_snapshot_reason": reason,
        },
        session.data_dir,
    )
    return {
        "ok": True,
        "session_id": session.session_id,
        "url": _redact_url(session.last_url),
        "title": session.last_title,
        "reason": reason,
    }


def _install_session_close_watchers(session: BrowserSession) -> None:
    """Register Playwright callbacks so wait_for_close is reliable.

    The important part is not only noticing close. We also snapshot navigation
    while the user browses. Without this, open_wait_read could reopen the old
    starting URL instead of the final page the user closed on.
    """

    attached_pages: set[int] = set()

    def mark_if_closed(*_args: Any) -> None:
        try:
            _snapshot_session_page_state(session, reason="page_or_context_close")
            if not session._has_open_page():
                session.mark_closed()
        except Exception:
            session.mark_closed()

    def attach_page(page: Any) -> None:
        try:
            ident = id(page)
            if ident in attached_pages:
                return
            attached_pages.add(ident)
        except Exception:
            pass

        try:
            page.on("framenavigated", lambda *_args: _snapshot_session_page_state(session, reason="framenavigated"))
        except Exception:
            pass
        try:
            page.on("domcontentloaded", lambda *_args: _snapshot_session_page_state(session, reason="domcontentloaded"))
        except Exception:
            pass
        try:
            page.on("load", lambda *_args: _snapshot_session_page_state(session, reason="load"))
        except Exception:
            pass
        try:
            page.on("close", mark_if_closed)
        except Exception:
            pass

    try:
        if session.context is not None:
            session.context.on("close", lambda *_args: ( _snapshot_session_page_state(session, reason="context_close"), session.mark_closed() ))
    except Exception:
        pass

    try:
        if session.context is not None:
            session.context.on("page", lambda page: attach_page(page))
    except Exception:
        pass

    try:
        if session.context is not None:
            for page in list(session.context.pages):
                attach_page(page)
    except Exception:
        pass

    _snapshot_session_page_state(session, reason="watchers_installed")
def _session_live_for_wait(session: Optional[BrowserSession]) -> bool:
    try:
        return bool(session is not None and session.alive())
    except Exception:
        if session is not None:
            try:
                session.mark_closed()
            except Exception:
                pass
        return False


def _cleanup_closed_session(sid: str) -> None:
    with _SESSION_LOCK:
        session = _SESSIONS.get(sid)
        if session is not None and not session.alive():
            _SESSIONS.pop(sid, None)
    try:
        if session is not None:
            session.close()
    except Exception:
        pass


def _playwright_available() -> Tuple[bool, str, Any]:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        return True, "", sync_playwright
    except Exception as exc:
        return False, str(exc), None


def _launch_session(
    *,
    mode: str,
    session_id: str,
    url: str = "",
    query: str = "",
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    tor_auto_start: bool = True,
    tor_data_dir: str = DEFAULT_TOR_DATA_DIR,
    tor_start_timeout_sec: int = DEFAULT_TOR_START_TIMEOUT_SEC,
    data_dir: str = DEFAULT_DATA_DIR,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    headless: bool = False,
    browser_channel: str = "",
    slow_mo_ms: int = 0,
    javascript_mode: str = JAVASCRIPT_MODE_BROWSER,
) -> Dict[str, Any]:
    ok, import_error, sync_playwright = _playwright_available()
    if not ok:
        return {
            "ok": False,
            "error": "Playwright is not installed or not importable.",
            "install_hint": "pip install playwright && python -m playwright install chromium",
            "import_error": import_error,
        }

    sid = _safe_session_id(session_id, "default_tor" if mode == "tor" else "default_search")
    state = _load_state(sid, data_dir)

    try:
        target_url, navigation_source, is_onion_target = _resolve_navigation_target(
            mode=mode,
            url=url,
            query=query,
            previous_url=str(state.get("last_url") or ""),
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "mode": mode,
            "session_id": sid,
            "url": _redact_url(url),
            "query": query,
        }

    tor_info: Dict[str, Any] = {"ok": True}
    if mode == "tor":
        tor_info = _ensure_tor_running(
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url,
            timeout_sec=min(_as_int(tor_start_timeout_sec, DEFAULT_TOR_START_TIMEOUT_SEC, 3, 3600), timeout_sec),
            auto_start=bool(tor_auto_start),
            tor_data_dir=tor_data_dir,
        )
        if not tor_info.get("ok"):
            return tor_info

    with _SESSION_LOCK:
        existing = _SESSIONS.get(sid)
        if existing is not None and existing.mode == mode and existing.alive():
            session = existing
        else:
            if existing is not None:
                existing.close()
            root = _session_root(sid, data_dir)
            profile_dir = root / "profile"
            artifacts_dir = root / "artifacts"
            artifacts_dir.mkdir(parents=True, exist_ok=True)

            pw = sync_playwright().start()
            launch_kwargs: Dict[str, Any] = {
                "headless": bool(headless),
                "accept_downloads": False,
                "ignore_https_errors": True,
                "java_script_enabled": _javascript_enabled(javascript_mode),
                "viewport": {"width": 1365, "height": 900},
                "timeout": max(5000, int(timeout_sec or DEFAULT_TIMEOUT_SEC) * 1000),
                "slow_mo": max(0, int(slow_mo_ms or 0)),
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-features=Translate,PasswordManagerOnboarding,AutofillServerCommunication,HttpsUpgrades,HttpsFirstBalancedModeAutoEnable",
                    "--disable-quic",
                    "--disable-dns-prefetch",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
            }
            if browser_channel:
                launch_kwargs["channel"] = browser_channel

            if mode == "tor":
                proxy_server = _playwright_proxy_server(tor_socks_url)
                launch_kwargs["proxy"] = {"server": proxy_server}
                # Belt-and-suspenders: Playwright's proxy option is the primary
                # path; this Chromium arg makes the visible browser clearly show
                # all navigation through Tor's SOCKS listener, including .onion.
                launch_kwargs["args"].append(f"--proxy-server={proxy_server}")
                # Reduce local DNS leakage risk if Chromium tries to resolve a
                # hostname outside the SOCKS proxy path. SOCKS still receives
                # .onion hostnames and Tor resolves them internally.
                launch_kwargs["args"].append("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1")

            try:
                ctx = pw.chromium.launch_persistent_context(str(profile_dir), **launch_kwargs)
            except Exception:
                try:
                    pw.stop()
                except Exception:
                    pass
                raise

            session = BrowserSession(
                session_id=sid,
                mode=mode,
                data_dir=data_dir,
                tor_socks_url=tor_socks_url,
                playwright=pw,
                context=ctx,
                tor_started_by_engine=bool(tor_info.get("tor_started_by_engine")),
                javascript_mode=_normalize_javascript_mode(javascript_mode),
            )
            _install_session_close_watchers(session)
            _SESSIONS[sid] = session

    page = session.current_page()
    navigated = False
    nav_error = ""
    if page is not None and target_url and target_url != "about:blank":
        try:
            page.goto(target_url, wait_until="domcontentloaded", timeout=max(5000, int(timeout_sec or 30) * 1000))
            navigated = True
        except Exception as exc:
            nav_error = str(exc)
            try:
                page.goto(target_url, wait_until="commit", timeout=max(5000, min(15000, int(timeout_sec or 15) * 1000)))
                navigated = True
            except Exception:
                pass

    try:
        if page is not None:
            try:
                page.bring_to_front()
            except Exception:
                pass
            session.last_url = page.url or target_url or session.last_url
            try:
                session.last_title = page.title() or ""
            except Exception:
                session.last_title = ""
    except Exception:
        pass

    _save_state(
        sid,
        {
            **state,
            "session_id": sid,
            "mode": mode,
            "last_url": session.last_url or target_url,
            "last_title": session.last_title,
            "profile_dir": str(session.profile_dir),
            "artifacts_dir": str(session.artifacts_dir),
            "updated_at_ms": _now_ms(),
        },
        data_dir,
    )

    return {
        "ok": True,
        "action": "open_user_session",
        "mode": mode,
        "session_id": sid,
        "url": _redact_url(session.last_url or target_url),
        "title": session.last_title,
        "navigated": navigated,
        "navigation_source": navigation_source,
        "is_onion_target": bool(is_onion_target),
        "navigation_error": nav_error,
        "profile_dir": str(session.profile_dir),
        "artifacts_dir": str(session.artifacts_dir),
        "tor": tor_info if mode == "tor" else None,
        "handoff_instructions": (
            "A visible browser window is open. The user can browse, login, solve challenges, or choose a page manually. "
            "When ready, call read_session with allow_read=true. This engine will not return cookies, passwords, or hidden tokens."
        ),
    }


def _get_or_reopen_session(
    *,
    mode: str,
    session_id: str,
    url: str = "",
    query: str = "",
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    tor_auto_start: bool = True,
    tor_data_dir: str = DEFAULT_TOR_DATA_DIR,
    tor_start_timeout_sec: int = DEFAULT_TOR_START_TIMEOUT_SEC,
    data_dir: str = DEFAULT_DATA_DIR,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    headless: bool = False,
    javascript_mode: str = JAVASCRIPT_MODE_BROWSER,
) -> Tuple[Optional[BrowserSession], Dict[str, Any]]:
    sid = _safe_session_id(session_id, "default_tor" if mode == "tor" else "default_search")
    with _SESSION_LOCK:
        session = _SESSIONS.get(sid)
        if session is not None and session.mode == mode and session.alive():
            return session, {"ok": True, "reopened": False}

    opened = _launch_session(
        mode=mode,
        session_id=sid,
        url=url,
        query=query,
        tor_exe_path=tor_exe_path,
        tor_socks_url=tor_socks_url,
        tor_auto_start=tor_auto_start,
        tor_data_dir=tor_data_dir,
        tor_start_timeout_sec=tor_start_timeout_sec,
        data_dir=data_dir,
        timeout_sec=timeout_sec,
        headless=headless,
        javascript_mode=javascript_mode,
    )
    if not opened.get("ok"):
        return None, opened
    with _SESSION_LOCK:
        return _SESSIONS.get(sid), {"ok": True, "reopened": True, "open_result": opened}


def _extract_visible_page(
    page: Any,
    *,
    max_chars: int,
    include_links: bool = True,
    include_screenshot: bool = False,
    include_visual: bool = False,
    include_ocr: bool = False,
    javascript_mode: str = JAVASCRIPT_MODE_BROWSER,
    visual_limit: int = DEFAULT_VISUAL_ELEMENTS_LIMIT,
    ocr_language: str = DEFAULT_OCR_LANGUAGE,
    tesseract_js_path: str = "",
    tesseract_js_url: str = "",
    ocr_timeout_sec: int = 60,
    artifacts_dir: Path,
) -> Dict[str, Any]:
    title = ""
    url = ""
    text = ""
    links: List[Dict[str, str]] = []
    screenshot_path = ""
    visual_elements: List[Dict[str, Any]] = []
    visual_guard: Dict[str, Any] = {}
    ocr_result: Dict[str, Any] = {"ok": False, "skipped": True, "reason": "OCR not requested."}

    browser_mode = _browser_automation_enabled(javascript_mode)

    try:
        url = page.url or ""
    except Exception:
        url = ""
    try:
        title = page.title() or ""
    except Exception:
        title = ""

    # Redact sensitive input values from the page before reading body text.
    if _javascript_enabled(javascript_mode):
        try:
            page.evaluate(
                """
                (selectors) => {
                    for (const sel of selectors) {
                        for (const el of document.querySelectorAll(sel)) {
                            try { el.value = '[REDACTED]'; } catch (e) {}
                            try { el.setAttribute('value', '[REDACTED]'); } catch (e) {}
                            try { el.setAttribute('data-redacted-by-interactive-browser', 'true'); } catch (e) {}
                        }
                    }
                }
                """,
                _DENIED_SELECTORS,
            )
        except Exception:
            pass

    try:
        text = page.locator("body").inner_text(timeout=6000) or ""
    except Exception:
        if _javascript_enabled(javascript_mode):
            try:
                text = page.evaluate("() => document.body ? document.body.innerText : document.documentElement.innerText") or ""
            except Exception:
                text = ""

    if include_links and _javascript_enabled(javascript_mode):
        try:
            raw_links = page.evaluate(
                """
                () => Array.from(document.querySelectorAll('a[href]')).slice(0, 400).map(a => ({
                    url: a.href || '',
                    text: (a.innerText || a.textContent || '').trim().slice(0, 240),
                    title: (a.getAttribute('title') || '').slice(0, 240)
                }))
                """
            )
            seen = set()
            for item in raw_links or []:
                href = str((item or {}).get("url") or "").strip()
                if not href or href in seen:
                    continue
                seen.add(href)
                links.append(
                    {
                        "url": _redact_url(href),
                        "text": str((item or {}).get("text") or "")[:240],
                        "title": str((item or {}).get("title") or "")[:240],
                    }
                )
        except Exception:
            links = []

    if include_visual and browser_mode:
        visual_elements = _extract_visual_elements(page, limit=visual_limit)

    if include_screenshot:
        try:
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = str(artifacts_dir / f"screenshot_{_now_ms()}.png")
            page.screenshot(path=screenshot_path, full_page=False)
        except Exception:
            screenshot_path = ""

    if include_ocr:
        if not browser_mode:
            ocr_result = {
                "ok": False,
                "skipped": True,
                "reason": "OCR requires params.javascript_mode='browser'.",
            }
        else:
            ocr_result = _run_browser_ocr(
                page,
                artifacts_dir=artifacts_dir,
                language=ocr_language,
                tesseract_js_path=tesseract_js_path,
                tesseract_js_url=tesseract_js_url,
                timeout_sec=ocr_timeout_sec,
            )

    max_chars = _as_int(max_chars, DEFAULT_MAX_CHARS, minimum=500, maximum=2_000_000)
    truncated = len(text) > max_chars
    if truncated:
        text = text[:max_chars]

    return {
        "title": title,
        "url": _redact_url(url),
        "text": text,
        "text_chars": len(text),
        "text_truncated": truncated,
        "links": links,
        "links_count": len(links),
        "screenshot_path": screenshot_path,
        "javascript_mode": _normalize_javascript_mode(javascript_mode),
        "visual_elements": visual_elements,
        "visual_elements_count": len(visual_elements),
        "visual_guard": visual_guard,
        "ocr": ocr_result,
        "automation_safety_note": (
            "Browser-mode visual detection returns visible DOM/screenshot-derived information only. "
            "CAPTCHA/security challenge OCR or automated solving is disabled and left for the user."
        ),
    }


def _read_session(
    *,
    mode: str,
    session_id: str,
    url: str = "",
    query: str = "",
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    tor_auto_start: bool = True,
    tor_data_dir: str = DEFAULT_TOR_DATA_DIR,
    tor_start_timeout_sec: int = DEFAULT_TOR_START_TIMEOUT_SEC,
    data_dir: str = DEFAULT_DATA_DIR,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_CHARS,
    allow_read: bool = False,
    include_links: bool = True,
    include_screenshot: bool = False,
    include_visual: bool = False,
    include_ocr: bool = False,
    javascript_mode: str = JAVASCRIPT_MODE_BROWSER,
    visual_limit: int = DEFAULT_VISUAL_ELEMENTS_LIMIT,
    ocr_language: str = DEFAULT_OCR_LANGUAGE,
    tesseract_js_path: str = "",
    tesseract_js_url: str = "",
    ocr_timeout_sec: int = 60,
    headless_reopen: bool = False,
) -> Dict[str, Any]:
    if not allow_read:
        return {
            "ok": False,
            "error": "Reading session contents requires allow_read=true after the user approves handoff.",
            "mode": mode,
            "session_id": _safe_session_id(session_id, "default"),
        }

    session, info = _get_or_reopen_session(
        mode=mode,
        session_id=session_id,
        url=url,
        query=query,
        tor_exe_path=tor_exe_path,
        tor_socks_url=tor_socks_url,
        tor_auto_start=tor_auto_start,
        tor_data_dir=tor_data_dir,
        tor_start_timeout_sec=tor_start_timeout_sec,
        data_dir=data_dir,
        timeout_sec=timeout_sec,
        headless=headless_reopen,
        javascript_mode=javascript_mode,
    )
    if session is None:
        return info

    page = session.current_page()
    if page is None:
        return {"ok": False, "error": "No active page is available in this session.", "session_id": session.session_id}

    result = _extract_visible_page(
        page,
        max_chars=max_chars,
        include_links=include_links,
        include_screenshot=include_screenshot,
        include_visual=include_visual,
        include_ocr=include_ocr,
        javascript_mode=javascript_mode,
        visual_limit=visual_limit,
        ocr_language=ocr_language,
        tesseract_js_path=tesseract_js_path,
        tesseract_js_url=tesseract_js_url,
        ocr_timeout_sec=ocr_timeout_sec,
        artifacts_dir=session.artifacts_dir,
    )
    session.last_read_at_ms = _now_ms()
    session.last_url = result.get("url", "")
    session.last_title = result.get("title", "")

    state = _load_state(session.session_id, data_dir)
    _save_state(
        session.session_id,
        {
            **state,
            "session_id": session.session_id,
            "mode": mode,
            "last_url": session.last_url,
            "last_title": session.last_title,
            "last_read_at_ms": session.last_read_at_ms,
            "profile_dir": str(session.profile_dir),
            "artifacts_dir": str(session.artifacts_dir),
            "updated_at_ms": _now_ms(),
        },
        data_dir,
    )

    return {
        "ok": True,
        "action": "read_session",
        "mode": mode,
        "session_id": session.session_id,
        "reopened": bool(info.get("reopened")),
        **result,
        "privacy_note": "Returned visible page text/links only. Raw cookies, passwords, hidden token fields, and storage state are not returned.",
    }


def _continue_session(
    *,
    mode: str,
    session_id: str,
    url: str = "",
    query: str = "",
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    tor_auto_start: bool = True,
    tor_data_dir: str = DEFAULT_TOR_DATA_DIR,
    tor_start_timeout_sec: int = DEFAULT_TOR_START_TIMEOUT_SEC,
    data_dir: str = DEFAULT_DATA_DIR,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_CHARS,
    allow_read: bool = False,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    params = params or {}
    session, info = _get_or_reopen_session(
        mode=mode,
        session_id=session_id,
        url="",
        query="",
        tor_exe_path=tor_exe_path,
        tor_socks_url=tor_socks_url,
        tor_auto_start=tor_auto_start,
        tor_data_dir=tor_data_dir,
        tor_start_timeout_sec=tor_start_timeout_sec,
        data_dir=data_dir,
        timeout_sec=timeout_sec,
        headless=False,
        javascript_mode=_normalize_javascript_mode(params.get("javascript_mode"), JAVASCRIPT_MODE_BROWSER),
    )
    if session is None:
        return info

    nav_url = url or str(params.get("url") or "")
    nav_query = query or str(params.get("query") or "")
    try:
        target, navigation_source, is_onion_target = _resolve_navigation_target(
            mode=mode,
            url=nav_url,
            query=nav_query,
            previous_url="",
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "mode": mode,
            "session_id": session.session_id,
            "url": _redact_url(nav_url),
            "query": nav_query,
        }

    if not target or target == "about:blank":
        return {"ok": False, "error": "continue_session requires url or query.", "session_id": session.session_id}

    page = session.current_page()
    if page is None:
        return {"ok": False, "error": "No active page is available in this session.", "session_id": session.session_id}

    nav_error = ""
    try:
        page.goto(target, wait_until=str(params.get("wait_until") or "domcontentloaded"), timeout=max(5000, int(timeout_sec or 30) * 1000))
    except Exception as exc:
        nav_error = str(exc)
        try:
            page.goto(target, wait_until="commit", timeout=max(5000, min(15000, int(timeout_sec or 15) * 1000)))
        except Exception:
            pass

    try:
        page.bring_to_front()
    except Exception:
        pass

    session.last_url = getattr(page, "url", target) or target
    try:
        session.last_title = page.title() or ""
    except Exception:
        session.last_title = ""

    state = _load_state(session.session_id, data_dir)
    _save_state(
        session.session_id,
        {
            **state,
            "session_id": session.session_id,
            "mode": mode,
            "last_url": session.last_url,
            "last_title": session.last_title,
            "profile_dir": str(session.profile_dir),
            "artifacts_dir": str(session.artifacts_dir),
            "updated_at_ms": _now_ms(),
        },
        data_dir,
    )

    if allow_read:
        read = _read_session(
            mode=mode,
            session_id=session.session_id,
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url,
            tor_auto_start=tor_auto_start,
            tor_data_dir=tor_data_dir,
            tor_start_timeout_sec=tor_start_timeout_sec,
            data_dir=data_dir,
            timeout_sec=timeout_sec,
            max_chars=max_chars,
            allow_read=True,
            include_links=_as_bool(params.get("include_links"), True),
            include_screenshot=_as_bool(params.get("include_screenshot"), False),
            include_visual=_as_bool(params.get("include_visual"), _normalize_javascript_mode(params.get("javascript_mode"), JAVASCRIPT_MODE_BROWSER) == JAVASCRIPT_MODE_BROWSER),
            include_ocr=_as_bool(params.get("include_ocr"), False),
            javascript_mode=_normalize_javascript_mode(params.get("javascript_mode"), JAVASCRIPT_MODE_BROWSER),
            visual_limit=_as_int(params.get("visual_limit"), DEFAULT_VISUAL_ELEMENTS_LIMIT, minimum=1, maximum=2000),
            ocr_language=str(params.get("ocr_language") or DEFAULT_OCR_LANGUAGE),
            tesseract_js_path=str(params.get("tesseract_js_path") or ""),
            tesseract_js_url=str(params.get("tesseract_js_url") or ""),
            ocr_timeout_sec=_as_int(params.get("ocr_timeout_sec"), 60, minimum=5, maximum=600),
        )
        read["navigation_error"] = nav_error
        read["navigation_source"] = navigation_source
        read["is_onion_target"] = bool(is_onion_target)
        return read

    return {
        "ok": True,
        "action": "continue_session",
        "mode": mode,
        "session_id": session.session_id,
        "url": _redact_url(session.last_url),
        "title": session.last_title,
        "navigation_source": navigation_source,
        "is_onion_target": bool(is_onion_target),
        "navigation_error": nav_error,
        "read_skipped": True,
        "handoff_instructions": "Page was opened in the visible browser. Call read_session with allow_read=true after user approval.",
    }


def _status(mode: str, session_id: str, data_dir: str = DEFAULT_DATA_DIR) -> Dict[str, Any]:
    sid = _safe_session_id(session_id, "default_tor" if mode == "tor" else "default_search")
    state = _load_state(sid, data_dir)
    with _SESSION_LOCK:
        session = _SESSIONS.get(sid)
        live = session is not None and session.alive()
    return {
        "ok": True,
        "action": "status",
        "mode": mode,
        "session_id": sid,
        "live": live,
        "last_url": _redact_url(str(state.get("last_url") or "")),
        "last_title": str(state.get("last_title") or ""),
        "profile_dir": str(_session_root(sid, data_dir) / "profile"),
        "artifacts_dir": str(_session_root(sid, data_dir) / "artifacts"),
    }


def _wait_for_handoff(mode: str, session_id: str, timeout_sec: int, data_dir: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    params = params or {}
    sid = _safe_session_id(session_id, "default_tor" if mode == "tor" else "default_search")
    timeout_sec = _as_int(timeout_sec, DEFAULT_HANDOFF_TIMEOUT_SEC, minimum=1, maximum=86400)

    handoff_file = str(params.get("handoff_file") or "").strip()
    if not handoff_file:
        handoff_file = str(_session_root(sid, data_dir) / "HANDOFF.txt")

    wait_for_close = _as_bool(params.get("wait_for_close"), False)
    cleanup_closed = _as_bool(params.get("cleanup_closed_session"), True)
    snapshot_every_sec = max(0.25, float(params.get("snapshot_every_sec") or 1.0))
    next_snapshot_at = 0.0

    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if handoff_file and Path(handoff_file).exists():
            with _SESSION_LOCK:
                session = _SESSIONS.get(sid)
            snapshot = _snapshot_session_page_state(session, reason="handoff_file_detected") if session is not None else {}
            return {
                "ok": True,
                "action": "wait_for_handoff",
                "mode": mode,
                "session_id": sid,
                "handoff_file": handoff_file,
                "reason": "handoff_file_detected",
                "snapshot": snapshot,
            }

        if wait_for_close:
            with _SESSION_LOCK:
                session = _SESSIONS.get(sid)
                live = _session_live_for_wait(session)

            now = time.time()
            if session is not None and live and now >= next_snapshot_at:
                _snapshot_session_page_state(session, reason="wait_poll")
                next_snapshot_at = now + snapshot_every_sec

            if not live:
                snapshot = _snapshot_session_page_state(session, reason="browser_closed_or_session_not_live") if session is not None else {}
                if cleanup_closed:
                    _cleanup_closed_session(sid)
                return {
                    "ok": True,
                    "action": "wait_for_handoff",
                    "mode": mode,
                    "session_id": sid,
                    "reason": "browser_closed_or_session_not_live",
                    "snapshot": snapshot,
                }
        time.sleep(0.5)

    return {
        "ok": False,
        "action": "wait_for_handoff",
        "mode": mode,
        "session_id": sid,
        "error": "Timed out waiting for handoff.",
        "handoff_file": handoff_file,
        "timeout_sec": timeout_sec,
        "hint": (
            "Close the visible browser window, create the handoff file, or increase "
            "params.wait_timeout_sec. The model/runtime must not continue to the next "
            "tool until this call returns ok=true."
        ),
    }

def _close_session(mode: str, session_id: str, data_dir: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    params = params or {}
    sid = _safe_session_id(session_id, "default_tor" if mode == "tor" else "default_search")
    closed = False
    with _SESSION_LOCK:
        session = _SESSIONS.pop(sid, None)
    if session is not None:
        session.close()
        closed = True

    stop_tor = _as_bool(params.get("stop_tor"), False)
    stopped_tor = False
    if stop_tor:
        with _SESSION_LOCK:
            procs = list(_TOR_PROCESSES.items())
        for key, proc in procs:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    stopped_tor = True
            except Exception:
                pass
            with _SESSION_LOCK:
                _TOR_PROCESSES.pop(key, None)

    return {"ok": True, "action": "close_session", "mode": mode, "session_id": sid, "closed": closed, "stopped_tor": stopped_tor}


def _clear_session(mode: str, session_id: str, data_dir: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    params = params or {}
    close_first = _as_bool(params.get("close_first"), True)
    if close_first:
        _close_session(mode, session_id, data_dir, params={})
    sid = _safe_session_id(session_id, "default_tor" if mode == "tor" else "default_search")
    root = _session_root(sid, data_dir)
    try:
        shutil.rmtree(root)
        return {"ok": True, "action": "clear_session", "mode": mode, "session_id": sid, "removed": str(root)}
    except Exception as exc:
        return {"ok": False, "action": "clear_session", "mode": mode, "session_id": sid, "error": str(exc), "path": str(root)}


def _capabilities(mode: str) -> Dict[str, Any]:
    pw_ok, pw_error, _ = _playwright_available()
    tor_host, tor_port = _parse_socks_host_port(DEFAULT_TOR_SOCKS_URL)
    return {
        "ok": True,
        "action": "capabilities",
        "mode": mode,
        "playwright_available": pw_ok,
        "playwright_error": pw_error,
        "actions": INTERACTIVE_BROWSER_ACTIONS,
        "tor_default_socks_url": DEFAULT_TOR_SOCKS_URL,
        "tor_default_data_dir": DEFAULT_TOR_DATA_DIR,
        "tor_found_exe": _find_tor_exe(os.getenv("GPTPROJECT_TOR_EXE_PATH", "")),
        "tor_default_port_open": _port_open(tor_host, tor_port),
        "onion_support": {
            "direct_onion_navigation": True,
            "query_field_onion_detection": True,
            "default_onion_scheme": "http",
            "requires_tor_mode": True,
        },
        "browser_mode": {
            "javascript_mode_param": "params.javascript_mode",
            "values": ["browser", "safe", "disabled"],
            "visual_detection": True,
            "optional_browser_ocr": True,
            "ocr_requires": "params.include_ocr=true and Tesseract.js loaded or params.tesseract_js_path/params.tesseract_js_url",
            "captcha_ocr_or_solving": False,
        },
        "privacy_model": {
            "human_in_loop": True,
            "requires_allow_read_for_page_contents": True,
            "returns_raw_cookies": False,
            "returns_password_fields": False,
            "persistent_profile_reuses_cookies": True,
            "blocks_until_browser_close_by_default": True,
            "captcha_bypass": False,
        },
    }



def _read_kwargs_from_params(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert params into _read_session keyword arguments.

    Kept in one place so read_session, continue_session, and the blocking
    open_wait_read path all return the same browser-mode/visual/OCR fields.
    """
    params = params or {}
    javascript_mode = _normalize_javascript_mode(params.get("javascript_mode"), JAVASCRIPT_MODE_BROWSER)
    return {
        "include_links": _as_bool(params.get("include_links"), True),
        "include_screenshot": _as_bool(params.get("include_screenshot"), False),
        "include_visual": _as_bool(
            params.get("include_visual"),
            javascript_mode == JAVASCRIPT_MODE_BROWSER,
        ),
        "include_ocr": _as_bool(params.get("include_ocr"), False),
        "javascript_mode": javascript_mode,
        "visual_limit": _as_int(params.get("visual_limit"), DEFAULT_VISUAL_ELEMENTS_LIMIT, minimum=1, maximum=2000),
        "ocr_language": str(params.get("ocr_language") or DEFAULT_OCR_LANGUAGE),
        "tesseract_js_path": str(params.get("tesseract_js_path") or ""),
        "tesseract_js_url": str(params.get("tesseract_js_url") or ""),
        "ocr_timeout_sec": _as_int(params.get("ocr_timeout_sec"), 60, minimum=5, maximum=600),
        "headless_reopen": _as_bool(params.get("headless_reopen"), False),
    }


def _open_wait_for_close_then_optionally_read(
    *,
    mode: str,
    action: str,
    url: str = "",
    query: str = "",
    session_id: str = "",
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    tor_auto_start: bool = True,
    tor_data_dir: str = DEFAULT_TOR_DATA_DIR,
    tor_start_timeout_sec: int = DEFAULT_TOR_START_TIMEOUT_SEC,
    data_dir: str = DEFAULT_DATA_DIR,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_CHARS,
    allow_read: bool = False,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Open a human browser, block until user close/handoff, then optionally read.

    This is the orchestration primitive that prevents the GPT/tool runner from
    moving ahead too early. The function call itself blocks until the visible
    browser closes or the handoff file is created. When it returns ok=true, the
    normal model/tool loop can continue with any next tool.

    Session/cookie behavior:
    - The visible browser uses launch_persistent_context(profile_dir).
    - Cookies/localStorage/sessionStorage remain in that profile directory.
    - After close, open_wait_read reopens the SAME profile headlessly and reads
      only visible page content when allow_read=True.
    - Raw cookies/passwords/hidden tokens are never returned in JSON.
    """
    params = dict(params or {})
    sid = _safe_session_id(session_id, "default_tor" if mode == "tor" else "default_search")
    javascript_mode = _normalize_javascript_mode(params.get("javascript_mode"), JAVASCRIPT_MODE_BROWSER)

    opened = _launch_session(
        mode=mode,
        session_id=sid,
        url=url,
        query=query,
        tor_exe_path=tor_exe_path,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
        tor_auto_start=tor_auto_start,
        tor_data_dir=tor_data_dir,
        tor_start_timeout_sec=tor_start_timeout_sec,
        data_dir=data_dir,
        timeout_sec=timeout_sec,
        headless=_as_bool(params.get("headless"), False),
        browser_channel=str(params.get("browser_channel") or ""),
        slow_mo_ms=_as_int(params.get("slow_mo_ms"), 0, minimum=0, maximum=10000),
        javascript_mode=javascript_mode,
    )
    if not opened.get("ok"):
        return opened

    # Snapshot once after open so a fast close still has a last_url to reopen.
    with _SESSION_LOCK:
        opened_session = _SESSIONS.get(sid)
    open_snapshot = _snapshot_session_page_state(opened_session, reason="after_open_before_wait") if opened_session is not None else {}

    wait_params = dict(params)
    wait_params["wait_for_close"] = True
    # Keep this separate from navigation timeout. Users may need several minutes
    # to login, solve a challenge manually, or browse. The GPT/tool runner will
    # not receive a result and cannot proceed until this wait returns.
    wait_timeout_sec = _as_int(
        params.get("wait_timeout_sec"),
        DEFAULT_HANDOFF_TIMEOUT_SEC,
        minimum=1,
        maximum=86400,
    )
    handoff = _wait_for_handoff(
        mode,
        sid,
        timeout_sec=wait_timeout_sec,
        data_dir=data_dir,
        params=wait_params,
    )
    if not handoff.get("ok"):
        return {
            "ok": False,
            "action": action,
            "mode": mode,
            "session_id": sid,
            "opened": opened,
            "open_snapshot": open_snapshot,
            "handoff": handoff,
            "wait_timeout_sec": wait_timeout_sec,
            "blocked_until_handoff": True,
            "error": handoff.get("error") or "Browser handoff did not complete.",
        }

    should_read = (
        action == "open_wait_read"
        or allow_read
        or _as_bool(params.get("read_after_close"), False)
    )
    if not should_read:
        return {
            "ok": True,
            "action": action,
            "mode": mode,
            "session_id": sid,
            "opened": opened,
            "open_snapshot": open_snapshot,
            "handoff": handoff,
            "wait_timeout_sec": wait_timeout_sec,
            "blocked_until_handoff": True,
            "read_skipped": True,
            "profile_reusable": True,
            "session_reuse_note": (
                "Browser was closed by the user. Cookies and local browser state remain in the "
                "persistent Playwright profile_dir, so later read_session/continue_session calls "
                "with this same session_id reuse the same logged-in/session state."
            ),
            "next_tool_ready": True,
            "next_tool_hint": (
                "Browser was closed by the user. The runtime should now continue the normal tool loop; "
                "the next tool can be any registered tool, not only interactive_tor/interactive_search."
            ),
        }

    if not allow_read:
        return {
            "ok": True,
            "action": action,
            "mode": mode,
            "session_id": sid,
            "opened": opened,
            "open_snapshot": open_snapshot,
            "handoff": handoff,
            "wait_timeout_sec": wait_timeout_sec,
            "blocked_until_handoff": True,
            "read_skipped": True,
            "profile_reusable": True,
            "read_error": "open_wait_read/read_after_close requires allow_read=true before visible page contents are returned.",
            "next_tool_ready": True,
            "next_tool_hint": "Call read_session with allow_read=true, or let the model continue with another non-browser tool.",
        }

    read_kwargs = _read_kwargs_from_params(params)
    # The visible browser was closed, so reopen the same persistent profile at
    # the saved last_url just long enough to read the approved visible page.
    read_kwargs["headless_reopen"] = True
    read = _read_session(
        mode=mode,
        session_id=sid,
        url="",
        query="",
        tor_exe_path=tor_exe_path,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
        tor_auto_start=tor_auto_start,
        tor_data_dir=tor_data_dir,
        tor_start_timeout_sec=tor_start_timeout_sec,
        data_dir=data_dir,
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        allow_read=True,
        **read_kwargs,
    )

    return {
        "ok": bool(read.get("ok", True)),
        "action": action,
        "mode": mode,
        "session_id": sid,
        "opened": opened,
        "open_snapshot": open_snapshot,
        "handoff": handoff,
        "wait_timeout_sec": wait_timeout_sec,
        "blocked_until_handoff": True,
        "profile_reusable": True,
        "read": read,
        "next_tool_ready": True,
        "next_tool_hint": (
            "Browser handoff is complete and the same profile was reopened for reading. "
            "Continue the normal model/tool loop; the next tool may be search_web, sniff_url, "
            "project tools, or another interactive browser action."
        ),
    }

def _force_wait_for_action(action: str, params: Optional[Dict[str, Any]]) -> bool:
    """Default visible browser opens to human-in-the-loop blocking mode.

    This is the engine-level safety latch. Even if the model/tool schema calls
    action=open_user_session/search/continue_session, a visible non-headless
    browser is converted to open_wait_for_close/open_wait_read behavior unless
    the caller explicitly opts out with params.no_wait_for_close=true or
    params.background=true.

    Result: the GPT/runtime cannot receive a successful tool result and cannot
    move to the next tool until the browser is closed or handoff is completed.
    """
    params = params or {}
    if action not in {"open_user_session", "search", "continue_session"}:
        return False
    if _as_bool(params.get("headless"), False):
        return False
    if _as_bool(params.get("no_wait_for_close"), False):
        return False
    if _as_bool(params.get("background"), False):
        return False
    return _as_bool(
        params.get("force_wait_for_close"),
        _as_bool(os.getenv("GPTPROJECT_INTERACTIVE_FORCE_WAIT_ON_OPEN", "1"), True),
    )

def _interactive_browser_dispatch(
    *,
    mode: str,
    action: str,
    url: str = "",
    query: str = "",
    session_id: str = "",
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    tor_auto_start: bool = True,
    tor_data_dir: str = DEFAULT_TOR_DATA_DIR,
    tor_start_timeout_sec: int = DEFAULT_TOR_START_TIMEOUT_SEC,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_CHARS,
    allow_read: bool = False,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    params = params or {}
    action = (action or "status").strip().lower()
    if action not in INTERACTIVE_BROWSER_ACTIONS:
        return {"ok": False, "error": f"Unknown action: {action}", "actions": INTERACTIVE_BROWSER_ACTIONS}

    sid = _safe_session_id(session_id, "default_tor" if mode == "tor" else "default_search")
    data_dir = str(params.get("data_dir") or DEFAULT_DATA_DIR)
    tor_exe_path = str(tor_exe_path or params.get("tor_exe_path") or os.getenv("GPTPROJECT_TOR_EXE_PATH", "") or "")
    tor_socks_url = str(tor_socks_url or params.get("tor_socks_url") or DEFAULT_TOR_SOCKS_URL)
    tor_auto_start = _as_bool(params.get("tor_auto_start"), True)
    tor_data_dir = str(params.get("tor_data_dir") or DEFAULT_TOR_DATA_DIR)
    tor_start_timeout_sec = _as_int(params.get("tor_start_timeout_sec"), DEFAULT_TOR_START_TIMEOUT_SEC, minimum=3, maximum=3600)
    timeout_sec = _as_int(timeout_sec, DEFAULT_TIMEOUT_SEC, minimum=1, maximum=3600)
    max_chars = _as_int(max_chars, DEFAULT_MAX_CHARS, minimum=500, maximum=2_000_000)

    if action == "capabilities":
        return _capabilities(mode)
    if action == "status":
        return _status(mode, sid, data_dir=data_dir)

    if _force_wait_for_action(action, params):
        wait_params = dict(params)
        wait_params.setdefault("wait_for_close", True)
        # When allow_read is true, upgrade to open_wait_read so the model receives
        # approved visible page data after the user closes the browser. Otherwise
        # it still waits and then returns a normal handoff-complete result.
        wait_action = "open_wait_read" if (allow_read or _as_bool(wait_params.get("read_after_close"), False)) else "open_wait_for_close"
        return _open_wait_for_close_then_optionally_read(
            mode=mode,
            action=wait_action,
            url=url,
            query=query or str(params.get("query") or ""),
            session_id=sid,
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
            tor_auto_start=tor_auto_start,
            tor_data_dir=tor_data_dir,
            tor_start_timeout_sec=tor_start_timeout_sec,
            data_dir=data_dir,
            timeout_sec=timeout_sec,
            max_chars=max_chars,
            allow_read=allow_read,
            params=wait_params,
        )

    if action in {"open_wait_for_close", "open_wait_read"}:
        return _open_wait_for_close_then_optionally_read(
            mode=mode,
            action=action,
            url=url,
            query=query,
            session_id=sid,
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
            tor_auto_start=tor_auto_start,
            tor_data_dir=tor_data_dir,
            tor_start_timeout_sec=tor_start_timeout_sec,
            data_dir=data_dir,
            timeout_sec=timeout_sec,
            max_chars=max_chars,
            allow_read=allow_read,
            params=params,
        )
    if action == "open_user_session":
        return _launch_session(
            mode=mode,
            session_id=sid,
            url=url,
            query=query,
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
            tor_auto_start=tor_auto_start,
            tor_data_dir=tor_data_dir,
            tor_start_timeout_sec=tor_start_timeout_sec,
            data_dir=data_dir,
            timeout_sec=timeout_sec,
            headless=_as_bool(params.get("headless"), False),
            browser_channel=str(params.get("browser_channel") or ""),
            slow_mo_ms=_as_int(params.get("slow_mo_ms"), 0, minimum=0, maximum=10000),
            javascript_mode=_normalize_javascript_mode(params.get("javascript_mode"), JAVASCRIPT_MODE_BROWSER),
        )
    if action == "search":
        return _continue_session(
            mode=mode,
            session_id=sid,
            query=query or str(params.get("query") or ""),
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
            tor_auto_start=tor_auto_start,
            tor_data_dir=tor_data_dir,
            tor_start_timeout_sec=tor_start_timeout_sec,
            data_dir=data_dir,
            timeout_sec=timeout_sec,
            max_chars=max_chars,
            allow_read=allow_read,
            params=params,
        ) if (query or params.get("query")) else _launch_session(
            mode=mode,
            session_id=sid,
            url=_search_url(query or str(params.get("query") or "")),
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
            tor_auto_start=tor_auto_start,
            tor_data_dir=tor_data_dir,
            tor_start_timeout_sec=tor_start_timeout_sec,
            data_dir=data_dir,
            timeout_sec=timeout_sec,
        )
    if action == "wait_for_handoff":
        return _wait_for_handoff(mode, sid, timeout_sec=timeout_sec, data_dir=data_dir, params=params)
    if action == "read_session":
        return _read_session(
            mode=mode,
            session_id=sid,
            url=url,
            query=query,
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
            tor_auto_start=tor_auto_start,
            tor_data_dir=tor_data_dir,
            tor_start_timeout_sec=tor_start_timeout_sec,
            data_dir=data_dir,
            timeout_sec=timeout_sec,
            max_chars=max_chars,
            allow_read=allow_read,
            include_links=_as_bool(params.get("include_links"), True),
            include_screenshot=_as_bool(params.get("include_screenshot"), False),
            include_visual=_as_bool(params.get("include_visual"), _normalize_javascript_mode(params.get("javascript_mode"), JAVASCRIPT_MODE_BROWSER) == JAVASCRIPT_MODE_BROWSER),
            include_ocr=_as_bool(params.get("include_ocr"), False),
            javascript_mode=_normalize_javascript_mode(params.get("javascript_mode"), JAVASCRIPT_MODE_BROWSER),
            visual_limit=_as_int(params.get("visual_limit"), DEFAULT_VISUAL_ELEMENTS_LIMIT, minimum=1, maximum=2000),
            ocr_language=str(params.get("ocr_language") or DEFAULT_OCR_LANGUAGE),
            tesseract_js_path=str(params.get("tesseract_js_path") or ""),
            tesseract_js_url=str(params.get("tesseract_js_url") or ""),
            ocr_timeout_sec=_as_int(params.get("ocr_timeout_sec"), 60, minimum=5, maximum=600),
            headless_reopen=_as_bool(params.get("headless_reopen"), False),
        )
    if action == "continue_session":
        return _continue_session(
            mode=mode,
            session_id=sid,
            url=url,
            query=query,
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
            tor_auto_start=tor_auto_start,
            tor_data_dir=tor_data_dir,
            tor_start_timeout_sec=tor_start_timeout_sec,
            data_dir=data_dir,
            timeout_sec=timeout_sec,
            max_chars=max_chars,
            allow_read=allow_read,
            params=params,
        )
    if action == "close_session":
        return _close_session(mode, sid, data_dir=data_dir, params=params)
    if action == "clear_session":
        return _clear_session(mode, sid, data_dir=data_dir, params=params)

    return {"ok": False, "error": f"Unhandled action: {action}"}


def interactive_tor(
    action: str,
    url: str = "",
    query: str = "",
    session_id: str = "default_tor",
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    tor_auto_start: bool = True,
    tor_data_dir: str = DEFAULT_TOR_DATA_DIR,
    tor_start_timeout_sec: int = DEFAULT_TOR_START_TIMEOUT_SEC,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_CHARS,
    allow_read: bool = False,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Human-in-the-loop visible browser routed through Tor SOCKS.

    If the configured SOCKS port is closed and tor_auto_start is true, this
    starts tor.exe directly and binds it to tor_socks_url before opening the
    visible Playwright Chromium window through that proxy.
    """
    merged_params = dict(params or {})
    merged_params.setdefault("tor_auto_start", bool(tor_auto_start))
    merged_params.setdefault("tor_data_dir", tor_data_dir)
    merged_params.setdefault("tor_start_timeout_sec", tor_start_timeout_sec)

    return _interactive_browser_dispatch(
        mode="tor",
        action=action,
        url=url,
        query=query,
        session_id=session_id,
        tor_exe_path=tor_exe_path,
        tor_socks_url=tor_socks_url,
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        allow_read=allow_read,
        params=merged_params,
    )


def interactive_search(
    action: str,
    url: str = "",
    query: str = "",
    session_id: str = "default_search",
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_CHARS,
    allow_read: bool = False,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Human-in-the-loop visible normal web browser/search session."""
    return _interactive_browser_dispatch(
        mode="search",
        action=action,
        url=url,
        query=query,
        session_id=session_id,
        tor_exe_path="",
        tor_socks_url="",
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        allow_read=allow_read,
        params=params,
    )


def interactive_browser_status() -> Dict[str, Any]:
    with _SESSION_LOCK:
        sessions = []
        for sid, session in _SESSIONS.items():
            sessions.append(
                {
                    "session_id": sid,
                    "mode": session.mode,
                    "live": session.alive(),
                    "last_url": _redact_url(session.last_url),
                    "last_title": session.last_title,
                    "profile_dir": str(session.profile_dir),
                }
            )
    return {
        "ok": True,
        "sessions": sessions,
        "count": len(sessions),
        "actions": INTERACTIVE_BROWSER_ACTIONS,
    }


def interactive_browser_tool_schema(mode: str = "search") -> Dict[str, Any]:
    props: Dict[str, Any] = {
        "action": {
            "type": "string",
            "enum": INTERACTIVE_BROWSER_ACTIONS,
            "description": "open_user_session/search/wait_for_handoff/open_wait_for_close/open_wait_read/read_session/continue_session/close_session/status/capabilities/clear_session",
        },
        "url": {"type": "string"},
        "query": {"type": "string"},
        "session_id": {"type": "string"},
        "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 86400},
        "max_chars": {"type": "integer", "minimum": 500, "maximum": 2000000},
        "allow_read": {"type": "boolean"},
        "params": {
            "type": "object",
            "additionalProperties": True,
            "description": (
                "Optional browser params. Supported keys include include_links, include_screenshot, "
                "include_visual, include_ocr, javascript_mode ('browser'|'safe'|'disabled'), "
                "visual_limit, ocr_language, tesseract_js_path, tesseract_js_url, ocr_timeout_sec, "
                "wait_for_close, wait_timeout_sec, handoff_file, read_after_close, no_wait_for_close, force_wait_for_close, headless_reopen, data_dir, and snapshot_every_sec. Visible opens block by default until browser close; same session_id reuses the persistent profile/cookies."
            ),
        },
    }
    if mode == "tor":
        props["tor_exe_path"] = {"type": "string", "description": "Path to Tor Browser/Browser/TorBrowser/Tor/tor.exe or standalone tor.exe."}
        props["tor_socks_url"] = {"type": "string", "description": "SOCKS URL, usually socks5h://127.0.0.1:9150."}
        props["tor_auto_start"] = {"type": "boolean", "description": "Start tor.exe automatically if the SOCKS port is closed."}
        props["tor_data_dir"] = {"type": "string", "description": "Dedicated Tor DataDirectory used when launching tor.exe."}
        props["tor_start_timeout_sec"] = {"type": "integer", "minimum": 3, "maximum": 3600}
    return {"type": "object", "properties": props, "required": ["action"], "additionalProperties": False}


def make_interactive_browser_tool_function(mode: str):
    if mode == "tor":
        return interactive_tor
    return interactive_search
