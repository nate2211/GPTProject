# application_engine.py
# Consent-based local application observation engine for PromptChat / GPT tools.
#
# Purpose
# -------
# Lets an authorized local assistant inspect running applications using safe, official-ish
# desktop automation surfaces:
#
#   1. Process/window inventory
#   2. Windows UI Automation / pywinauto readable control tree
#   3. Region screenshots of visible windows
#   4. Optional OCR fallback for what is visibly on screen
#   5. Optional PromptChat-style block registration
#
# It intentionally does NOT implement:
#   - keylogging
#   - credential theft
#   - raw process memory scraping
#   - stealth hooks/injection
#   - browser cookie/token dumping
#   - bypassing OS permission prompts
#
# Dependencies are optional:
#   pip install psutil pywinauto pillow mss pytesseract
#
# On Windows, pywinauto gives the best UI text extraction.
# Screenshot/OCR fallback can work cross-platform if Pillow/mss/Tesseract are installed.

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import datetime as _dt
import io
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# =============================================================================
# Optional imports
# =============================================================================

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore

try:
    from PIL import Image, ImageGrab  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Image = None  # type: ignore
    ImageGrab = None  # type: ignore

try:
    import mss  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    mss = None  # type: ignore

try:
    import pytesseract  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pytesseract = None  # type: ignore

try:
    from pywinauto import Desktop  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Desktop = None  # type: ignore


IS_WINDOWS = platform.system().lower().startswith("win")


# =============================================================================
# Exceptions
# =============================================================================

class ApplicationEngineError(RuntimeError):
    """Base error for the application engine."""


class ConsentRequiredError(ApplicationEngineError):
    """Raised when the requested target has not been explicitly allowed."""


class SensitiveTargetBlockedError(ApplicationEngineError):
    """Raised when the target appears sensitive and allow_sensitive=False."""


class DependencyMissingError(ApplicationEngineError):
    """Raised when an optional dependency is required for an operation."""


class TargetNotFoundError(ApplicationEngineError):
    """Raised when a requested process/window cannot be found."""


# =============================================================================
# Data models
# =============================================================================

@dataclass
class Rect:
    left: int = 0
    top: int = 0
    right: int = 0
    bottom: int = 0

    @property
    def width(self) -> int:
        return max(0, int(self.right) - int(self.left))

    @property
    def height(self) -> int:
        return max(0, int(self.bottom) - int(self.top))

    @property
    def bbox(self) -> Tuple[int, int, int, int]:
        return (int(self.left), int(self.top), int(self.right), int(self.bottom))

    def clamp(self, min_size: int = 1, max_width: int = 8000, max_height: int = 8000) -> "Rect":
        l, t, r, b = self.bbox
        if r < l:
            l, r = r, l
        if b < t:
            t, b = b, t
        if r - l < min_size:
            r = l + min_size
        if b - t < min_size:
            b = t + min_size
        if r - l > max_width:
            r = l + max_width
        if b - t > max_height:
            b = t + max_height
        return Rect(l, t, r, b)


@dataclass
class ProcessInfo:
    pid: int
    name: str = ""
    exe: str = ""
    cmdline: List[str] = field(default_factory=list)
    username: str = ""
    status: str = ""
    create_time: Optional[float] = None


@dataclass
class WindowInfo:
    hwnd: int
    title: str = ""
    class_name: str = ""
    pid: int = 0
    process_name: str = ""
    visible: bool = True
    rect: Rect = field(default_factory=Rect)


@dataclass
class UIElementInfo:
    name: str = ""
    control_type: str = ""
    automation_id: str = ""
    class_name: str = ""
    value: str = ""
    text: str = ""
    rectangle: Optional[Rect] = None
    depth: int = 0
    children: List["UIElementInfo"] = field(default_factory=list)


@dataclass
class ObserveResult:
    ok: bool
    timestamp: str
    target: Optional[WindowInfo] = None
    process: Optional[ProcessInfo] = None
    ui_text: str = ""
    ui_tree: List[UIElementInfo] = field(default_factory=list)
    ocr_text: str = ""
    screenshot_path: str = ""
    screenshot_base64: str = ""
    warnings: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConsentPolicy:
    """
    Safety policy. By default the engine can list windows/processes, but observation
    of contents requires an explicit allow target or allow_all_local=True.

    For your local dev workflow, pass params:
        {"allow_all_local": true}

    For a real assistant UI, call allow_window(hwnd) / allow_process(pid) after a
    user clicks/chooses the target.
    """

    require_consent_for_contents: bool = True
    allow_all_local: bool = False
    allow_sensitive: bool = False

    allowed_hwnds: set[int] = field(default_factory=set)
    allowed_pids: set[int] = field(default_factory=set)
    allowed_process_names: set[str] = field(default_factory=set)

    deny_process_names: set[str] = field(default_factory=lambda: {
        "lsass.exe",
        "winlogon.exe",
        "csrss.exe",
        "services.exe",
        "smss.exe",
        "securityhealthsystray.exe",
    })

    sensitive_title_terms: Tuple[str, ...] = (
        "password",
        "passcode",
        "login",
        "sign in",
        "signin",
        "2fa",
        "mfa",
        "authenticator",
        "bank",
        "wallet",
        "seed phrase",
        "private key",
        "recovery phrase",
        "credit card",
        "card number",
        "ssn",
        "social security",
    )

    redact_patterns: Tuple[Tuple[str, str], ...] = (
        (r"(?i)(password|passcode|secret|token|api[_ -]?key|private[_ -]?key)\s*[:=]\s*\S+", r"\1: [REDACTED]"),
        (r"\b(?:\d[ -]*?){13,19}\b", "[REDACTED_CARD_LIKE_NUMBER]"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        (r"(?i)\b(seed phrase|recovery phrase)\b.*", r"\1: [REDACTED]"),
    )

    def allow_window(self, hwnd: int) -> None:
        self.allowed_hwnds.add(int(hwnd))

    def allow_process(self, pid: int) -> None:
        self.allowed_pids.add(int(pid))

    def allow_process_name(self, name: str) -> None:
        if name:
            self.allowed_process_names.add(name.lower())

    def is_denied_process(self, process_name: str) -> bool:
        return bool(process_name) and process_name.lower() in self.deny_process_names

    def is_sensitive_window(self, win: WindowInfo) -> bool:
        hay = f"{win.title} {win.class_name} {win.process_name}".lower()
        return any(term in hay for term in self.sensitive_title_terms)

    def check_content_access(self, win: WindowInfo) -> None:
        if self.is_denied_process(win.process_name):
            raise ConsentRequiredError(f"Refusing to observe protected process: {win.process_name}")

        if self.is_sensitive_window(win) and not self.allow_sensitive:
            raise SensitiveTargetBlockedError(
                "Window title/process appears sensitive. Pass allow_sensitive=True only for your own authorized target."
            )

        if self.allow_all_local or not self.require_consent_for_contents:
            return

        if int(win.hwnd) in self.allowed_hwnds:
            return
        if int(win.pid) in self.allowed_pids:
            return
        if win.process_name and win.process_name.lower() in self.allowed_process_names:
            return

        raise ConsentRequiredError(
            "Content observation requires explicit consent. Use allow_all_local=True for local dev, "
            "or allow this hwnd/pid/process name first."
        )

    def redact_text(self, text: str) -> str:
        out = text or ""
        for pat, repl in self.redact_patterns:
            try:
                out = re.sub(pat, repl, out)
            except Exception:
                continue
        return out


# =============================================================================
# Windows native helpers
# =============================================================================

class _Win32:
    """Small ctypes wrapper for safe window inventory/capture metadata."""

    if IS_WINDOWS:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

        user32.EnumWindows.argtypes = [EnumWindowsProc, wt.LPARAM]
        user32.EnumWindows.restype = wt.BOOL

        user32.IsWindowVisible.argtypes = [wt.HWND]
        user32.IsWindowVisible.restype = wt.BOOL

        user32.GetWindowTextLengthW.argtypes = [wt.HWND]
        user32.GetWindowTextLengthW.restype = ctypes.c_int

        user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        user32.GetWindowTextW.restype = ctypes.c_int

        user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        user32.GetClassNameW.restype = ctypes.c_int

        user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
        user32.GetWindowRect.restype = wt.BOOL

        user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        user32.GetWindowThreadProcessId.restype = wt.DWORD

        user32.SetForegroundWindow.argtypes = [wt.HWND]
        user32.SetForegroundWindow.restype = wt.BOOL

        user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wt.BOOL

    @staticmethod
    def get_window_text(hwnd: int) -> str:
        if not IS_WINDOWS:
            return ""
        try:
            length = _Win32.user32.GetWindowTextLengthW(wt.HWND(hwnd))
            buff = ctypes.create_unicode_buffer(max(1, length + 2))
            _Win32.user32.GetWindowTextW(wt.HWND(hwnd), buff, len(buff))
            return str(buff.value or "")
        except Exception:
            return ""

    @staticmethod
    def get_class_name(hwnd: int) -> str:
        if not IS_WINDOWS:
            return ""
        try:
            buff = ctypes.create_unicode_buffer(512)
            _Win32.user32.GetClassNameW(wt.HWND(hwnd), buff, len(buff))
            return str(buff.value or "")
        except Exception:
            return ""

    @staticmethod
    def get_window_pid(hwnd: int) -> int:
        if not IS_WINDOWS:
            return 0
        try:
            pid = wt.DWORD(0)
            _Win32.user32.GetWindowThreadProcessId(wt.HWND(hwnd), ctypes.byref(pid))
            return int(pid.value)
        except Exception:
            return 0

    @staticmethod
    def get_window_rect(hwnd: int) -> Rect:
        if not IS_WINDOWS:
            return Rect()
        try:
            r = wt.RECT()
            ok = _Win32.user32.GetWindowRect(wt.HWND(hwnd), ctypes.byref(r))
            if not ok:
                return Rect()
            return Rect(int(r.left), int(r.top), int(r.right), int(r.bottom))
        except Exception:
            return Rect()

    @staticmethod
    def is_visible(hwnd: int) -> bool:
        if not IS_WINDOWS:
            return True
        try:
            return bool(_Win32.user32.IsWindowVisible(wt.HWND(hwnd)))
        except Exception:
            return False

    @staticmethod
    def enum_windows() -> List[int]:
        if not IS_WINDOWS:
            return []
        hwnds: List[int] = []

        @_Win32.EnumWindowsProc
        def callback(hwnd: int, lparam: int) -> bool:
            try:
                hwnds.append(int(hwnd))
            except Exception:
                pass
            return True

        _Win32.user32.EnumWindows(callback, 0)
        return hwnds

    @staticmethod
    def focus_window(hwnd: int) -> bool:
        if not IS_WINDOWS:
            return False
        try:
            # SW_RESTORE = 9
            _Win32.user32.ShowWindow(wt.HWND(hwnd), 9)
            return bool(_Win32.user32.SetForegroundWindow(wt.HWND(hwnd)))
        except Exception:
            return False


# =============================================================================
# Main engine
# =============================================================================

class ApplicationEngine:
    """
    Main local app observation engine.

    Common usage:
        eng = ApplicationEngine({"allow_all_local": True})
        windows = eng.list_windows()
        result = eng.observe_window(query="Notepad", include_screenshot=True, include_ocr=True)
    """

    def __init__(
        self,
        params: Optional[Dict[str, Any]] = None,
        *,
        progress: Optional[Callable[[str], None]] = None,
        policy: Optional[ConsentPolicy] = None,
    ):
        self.params = dict(params or {})
        self.progress = progress or (lambda msg: None)
        self.policy = policy or self._policy_from_params(self.params)
        self._lock = threading.RLock()

    # ---------------------------------------------------------------------
    # Policy/config
    # ---------------------------------------------------------------------

    def _policy_from_params(self, p: Dict[str, Any]) -> ConsentPolicy:
        pol = ConsentPolicy(
            require_consent_for_contents=bool(p.get("require_consent_for_contents", True)),
            allow_all_local=bool(p.get("allow_all_local", False)),
            allow_sensitive=bool(p.get("allow_sensitive", False)),
        )

        for hwnd in _as_int_list(p.get("allowed_hwnds")):
            pol.allow_window(hwnd)
        for pid in _as_int_list(p.get("allowed_pids")):
            pol.allow_process(pid)
        for name in _as_str_list(p.get("allowed_process_names")):
            pol.allow_process_name(name)

        extra_deny = _as_str_list(p.get("deny_process_names"))
        if extra_deny:
            pol.deny_process_names.update(x.lower() for x in extra_deny if x)

        return pol

    def allow_window(self, hwnd: int) -> None:
        self.policy.allow_window(hwnd)

    def allow_process(self, pid: int) -> None:
        self.policy.allow_process(pid)

    def allow_process_name(self, name: str) -> None:
        self.policy.allow_process_name(name)

    # ---------------------------------------------------------------------
    # Inventory
    # ---------------------------------------------------------------------

    def list_processes(self, *, include_cmdline: bool = False, limit: int = 5000) -> List[ProcessInfo]:
        if psutil is not None:
            out: List[ProcessInfo] = []
            attrs = ["pid", "name", "exe", "username", "status", "create_time"]
            if include_cmdline:
                attrs.append("cmdline")
            for proc in psutil.process_iter(attrs=attrs):
                if len(out) >= limit:
                    break
                try:
                    info = proc.info
                    out.append(ProcessInfo(
                        pid=int(info.get("pid") or proc.pid),
                        name=str(info.get("name") or ""),
                        exe=str(info.get("exe") or ""),
                        cmdline=list(info.get("cmdline") or []) if include_cmdline else [],
                        username=str(info.get("username") or ""),
                        status=str(info.get("status") or ""),
                        create_time=info.get("create_time"),
                    ))
                except Exception:
                    continue
            return sorted(out, key=lambda x: (x.name.lower(), x.pid))

        # Fallback without psutil.
        if IS_WINDOWS:
            try:
                cp = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                out: List[ProcessInfo] = []
                for line in cp.stdout.splitlines():
                    cols = _parse_csv_line(line)
                    if len(cols) >= 2:
                        try:
                            out.append(ProcessInfo(pid=int(cols[1]), name=cols[0]))
                        except Exception:
                            pass
                return out
            except Exception:
                return []

        try:
            cp = subprocess.run(["ps", "-eo", "pid=,comm="], text=True, capture_output=True, timeout=10)
            out = []
            for line in cp.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                pid_s, _, name = line.partition(" ")
                try:
                    out.append(ProcessInfo(pid=int(pid_s), name=name.strip()))
                except Exception:
                    pass
            return out
        except Exception:
            return []

    def get_process(self, pid: int) -> Optional[ProcessInfo]:
        pid = int(pid)
        if psutil is not None:
            try:
                proc = psutil.Process(pid)
                return ProcessInfo(
                    pid=pid,
                    name=proc.name() or "",
                    exe=proc.exe() or "",
                    cmdline=proc.cmdline() or [],
                    username=proc.username() or "",
                    status=proc.status() or "",
                    create_time=proc.create_time(),
                )
            except Exception:
                return None
        for p in self.list_processes():
            if p.pid == pid:
                return p
        return None

    def process_name_for_pid(self, pid: int) -> str:
        proc = self.get_process(pid)
        return proc.name if proc else ""

    def list_windows(
        self,
        *,
        visible_only: bool = True,
        include_empty_titles: bool = False,
        limit: int = 2000,
    ) -> List[WindowInfo]:
        if IS_WINDOWS:
            return self._list_windows_win32(
                visible_only=visible_only,
                include_empty_titles=include_empty_titles,
                limit=limit,
            )

        # Cross-platform fallback: pywinauto is Windows-centric, so return processes only.
        windows: List[WindowInfo] = []
        for proc in self.list_processes(limit=limit):
            windows.append(WindowInfo(
                hwnd=0,
                title=proc.name,
                class_name="process",
                pid=proc.pid,
                process_name=proc.name,
                visible=True,
                rect=Rect(),
            ))
        return windows

    def _list_windows_win32(
        self,
        *,
        visible_only: bool = True,
        include_empty_titles: bool = False,
        limit: int = 2000,
    ) -> List[WindowInfo]:
        out: List[WindowInfo] = []
        proc_cache: Dict[int, str] = {}

        for hwnd in _Win32.enum_windows():
            if len(out) >= limit:
                break
            visible = _Win32.is_visible(hwnd)
            if visible_only and not visible:
                continue
            title = _Win32.get_window_text(hwnd)
            if not include_empty_titles and not title.strip():
                continue

            rect = _Win32.get_window_rect(hwnd).clamp()
            if visible_only and (rect.width <= 1 or rect.height <= 1):
                continue

            pid = _Win32.get_window_pid(hwnd)
            if pid not in proc_cache:
                proc_cache[pid] = self.process_name_for_pid(pid)

            out.append(WindowInfo(
                hwnd=int(hwnd),
                title=title,
                class_name=_Win32.get_class_name(hwnd),
                pid=int(pid),
                process_name=proc_cache.get(pid, ""),
                visible=visible,
                rect=rect,
            ))

        return sorted(out, key=lambda w: (w.process_name.lower(), w.title.lower(), w.hwnd))

    def find_windows(
        self,
        query: str = "",
        *,
        pid: Optional[int] = None,
        process_name: str = "",
        visible_only: bool = True,
        include_empty_titles: bool = False,
        limit: int = 50,
    ) -> List[WindowInfo]:
        q = (query or "").strip().lower()
        pname = (process_name or "").strip().lower()

        matches: List[WindowInfo] = []
        for w in self.list_windows(visible_only=visible_only, include_empty_titles=include_empty_titles):
            if pid is not None and int(w.pid) != int(pid):
                continue
            if pname and pname not in (w.process_name or "").lower():
                continue
            if q:
                hay = f"{w.title} {w.class_name} {w.process_name} {w.pid} {w.hwnd}".lower()
                if q not in hay:
                    continue
            matches.append(w)
            if len(matches) >= limit:
                break
        return matches

    def resolve_window(
        self,
        *,
        hwnd: Optional[int] = None,
        pid: Optional[int] = None,
        query: str = "",
        process_name: str = "",
        visible_only: bool = True,
    ) -> WindowInfo:
        if hwnd is not None:
            h = int(hwnd)
            for w in self.list_windows(visible_only=False, include_empty_titles=True):
                if int(w.hwnd) == h:
                    return w
            # If the hwnd is valid but title hidden, still create minimal info.
            if IS_WINDOWS:
                return WindowInfo(
                    hwnd=h,
                    title=_Win32.get_window_text(h),
                    class_name=_Win32.get_class_name(h),
                    pid=_Win32.get_window_pid(h),
                    process_name=self.process_name_for_pid(_Win32.get_window_pid(h)),
                    visible=_Win32.is_visible(h),
                    rect=_Win32.get_window_rect(h).clamp(),
                )
            raise TargetNotFoundError(f"Window handle not found: {h}")

        matches = self.find_windows(query=query, pid=pid, process_name=process_name, visible_only=visible_only, limit=5)
        if not matches:
            raise TargetNotFoundError(f"No matching window found for query={query!r}, pid={pid}, process={process_name!r}")
        return matches[0]

    # ---------------------------------------------------------------------
    # Content observation
    # ---------------------------------------------------------------------

    def observe_window(
        self,
        *,
        hwnd: Optional[int] = None,
        pid: Optional[int] = None,
        query: str = "",
        process_name: str = "",
        include_ui_tree: bool = True,
        include_screenshot: bool = True,
        include_screenshot_base64: bool = False,
        include_ocr: bool = False,
        focus: bool = False,
        out_dir: Union[str, Path] = "out/application_engine",
        max_depth: int = 4,
        max_elements: int = 250,
        visible_only: bool = True,
    ) -> ObserveResult:
        with self._lock:
            win = self.resolve_window(hwnd=hwnd, pid=pid, query=query, process_name=process_name, visible_only=visible_only)
            self.policy.check_content_access(win)

            warnings: List[str] = []
            if focus and win.hwnd and IS_WINDOWS:
                if not _Win32.focus_window(win.hwnd):
                    warnings.append("focus_window failed or was denied by the OS")

            proc = self.get_process(win.pid)
            ui_tree: List[UIElementInfo] = []
            ui_text = ""

            if include_ui_tree:
                try:
                    ui_tree = self.read_ui_tree(win.hwnd, max_depth=max_depth, max_elements=max_elements)
                    ui_text = self.ui_tree_to_text(ui_tree)
                    ui_text = self.policy.redact_text(ui_text)
                except Exception as e:
                    warnings.append(f"UI tree read failed: {type(e).__name__}: {e}")

            screenshot_path = ""
            screenshot_b64 = ""
            if include_screenshot or include_ocr:
                try:
                    image = self.capture_window_image(win)
                    if image is not None:
                        if include_screenshot:
                            screenshot_path = self.save_image(image, out_dir=out_dir, prefix=f"hwnd_{win.hwnd}")
                        if include_screenshot_base64:
                            screenshot_b64 = self.image_to_base64(image)
                        if include_ocr:
                            ocr_text = self.ocr_image(image)
                        else:
                            ocr_text = ""
                    else:
                        ocr_text = ""
                        warnings.append("capture_window_image returned no image")
                except Exception as e:
                    ocr_text = ""
                    warnings.append(f"screenshot/OCR failed: {type(e).__name__}: {e}")
            else:
                ocr_text = ""

            ocr_text = self.policy.redact_text(ocr_text)

            return ObserveResult(
                ok=True,
                timestamp=_dt.datetime.now().isoformat(timespec="seconds"),
                target=win,
                process=proc,
                ui_text=ui_text,
                ui_tree=ui_tree,
                ocr_text=ocr_text,
                screenshot_path=screenshot_path,
                screenshot_base64=screenshot_b64,
                warnings=warnings,
                meta={
                    "engine": "application_engine",
                    "version": "1.0.0",
                    "platform": platform.platform(),
                    "capture_methods": self.available_capture_methods(),
                    "policy": {
                        "require_consent_for_contents": self.policy.require_consent_for_contents,
                        "allow_all_local": self.policy.allow_all_local,
                        "allow_sensitive": self.policy.allow_sensitive,
                    },
                },
            )

    def read_ui_tree(self, hwnd: int, *, max_depth: int = 4, max_elements: int = 250) -> List[UIElementInfo]:
        if not IS_WINDOWS:
            raise DependencyMissingError("UI Automation tree reading is implemented for Windows targets.")
        if Desktop is None:
            raise DependencyMissingError("pywinauto is not installed. Run: pip install pywinauto")

        root = Desktop(backend="uia").window(handle=int(hwnd))
        # Accessing descendants can throw on some apps. Keep bounded.
        items: List[UIElementInfo] = []
        count = 0

        def build(elem: Any, depth: int) -> Optional[UIElementInfo]:
            nonlocal count
            if count >= max_elements:
                return None
            count += 1

            info = self._ui_element_info(elem, depth)
            if depth < max_depth:
                try:
                    children = elem.children()
                except Exception:
                    children = []
                for child in children[: max(0, max_elements - count)]:
                    child_info = build(child, depth + 1)
                    if child_info is not None:
                        info.children.append(child_info)
            return info

        try:
            root_info = build(root, 0)
            if root_info is not None:
                items.append(root_info)
        except Exception:
            # Fallback: flat descendants.
            try:
                descendants = root.descendants()[:max_elements]
            except Exception:
                descendants = []
            for d in descendants:
                info = self._ui_element_info(d, 1)
                items.append(info)

        return items

    def _ui_element_info(self, elem: Any, depth: int) -> UIElementInfo:
        name = _safe_str(lambda: elem.window_text())
        control_type = _safe_str(lambda: elem.element_info.control_type)
        automation_id = _safe_str(lambda: elem.element_info.automation_id)
        class_name = _safe_str(lambda: elem.element_info.class_name)

        value = ""
        text = ""

        # Try common UIA patterns safely.
        for attr in ("legacy_properties",):
            try:
                props = getattr(elem, attr)()
                if isinstance(props, dict):
                    value = value or str(props.get("Value") or props.get("value") or "")
                    text = text or str(props.get("Name") or props.get("name") or "")
            except Exception:
                pass

        try:
            texts = elem.texts()
            if texts:
                text = "\n".join(str(x) for x in texts if str(x).strip())
        except Exception:
            pass

        rect = None
        try:
            r = elem.rectangle()
            rect = Rect(int(r.left), int(r.top), int(r.right), int(r.bottom)).clamp()
        except Exception:
            pass

        return UIElementInfo(
            name=self.policy.redact_text(name),
            control_type=control_type,
            automation_id=automation_id,
            class_name=class_name,
            value=self.policy.redact_text(value),
            text=self.policy.redact_text(text),
            rectangle=rect,
            depth=depth,
            children=[],
        )

    def ui_tree_to_text(self, tree: Sequence[UIElementInfo]) -> str:
        lines: List[str] = []

        def walk(node: UIElementInfo) -> None:
            indent = "  " * max(0, node.depth)
            parts = []
            if node.control_type:
                parts.append(node.control_type)
            if node.name:
                parts.append(f"name={node.name!r}")
            if node.value:
                parts.append(f"value={node.value!r}")
            if node.text and node.text != node.name:
                parts.append(f"text={node.text!r}")
            if node.automation_id:
                parts.append(f"id={node.automation_id!r}")
            if parts:
                lines.append(indent + "- " + " ".join(parts))
            for child in node.children:
                walk(child)

        for item in tree:
            walk(item)

        return "\n".join(lines).strip()

    # ---------------------------------------------------------------------
    # Screenshots/OCR
    # ---------------------------------------------------------------------

    def capture_window_image(self, win: WindowInfo) -> Any:
        rect = win.rect.clamp(max_width=int(self.params.get("max_capture_width", 5000)),
                              max_height=int(self.params.get("max_capture_height", 5000)))

        if rect.width <= 1 or rect.height <= 1:
            raise ApplicationEngineError("Window rectangle is empty or minimized.")

        if ImageGrab is not None:
            # On Windows/macOS Pillow can capture screen regions. On Linux this depends on environment.
            try:
                return ImageGrab.grab(bbox=rect.bbox)
            except Exception:
                pass

        if mss is not None and Image is not None:
            with mss.mss() as sct:
                mon = {
                    "left": int(rect.left),
                    "top": int(rect.top),
                    "width": int(rect.width),
                    "height": int(rect.height),
                }
                raw = sct.grab(mon)
                return Image.frombytes("RGB", raw.size, raw.rgb)

        raise DependencyMissingError("No screenshot backend available. Install pillow or mss.")

    def capture_screen_image(self, monitor_index: int = 1) -> Any:
        if ImageGrab is not None:
            try:
                return ImageGrab.grab()
            except Exception:
                pass

        if mss is not None and Image is not None:
            with mss.mss() as sct:
                monitors = sct.monitors
                idx = max(0, min(int(monitor_index), len(monitors) - 1))
                raw = sct.grab(monitors[idx])
                return Image.frombytes("RGB", raw.size, raw.rgb)

        raise DependencyMissingError("No screenshot backend available. Install pillow or mss.")

    def save_image(self, image: Any, *, out_dir: Union[str, Path], prefix: str = "screenshot") -> str:
        if Image is None:
            raise DependencyMissingError("Pillow is required to save images.")
        path = Path(out_dir)
        path.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        file = path / f"{_safe_filename(prefix)}_{stamp}.png"
        image.save(str(file))
        return str(file)

    def image_to_base64(self, image: Any) -> str:
        if Image is None:
            raise DependencyMissingError("Pillow is required to encode images.")
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")

    def ocr_image(self, image: Any) -> str:
        if pytesseract is None:
            raise DependencyMissingError("pytesseract is not installed. Run: pip install pytesseract")
        text = pytesseract.image_to_string(image) or ""
        return self.policy.redact_text(text.strip())

    def read_screen(
        self,
        *,
        include_screenshot: bool = True,
        include_screenshot_base64: bool = False,
        include_ocr: bool = True,
        out_dir: Union[str, Path] = "out/application_engine",
        monitor_index: int = 1,
    ) -> ObserveResult:
        # Full-screen reading is content observation too.
        pseudo = WindowInfo(hwnd=0, title="Full screen", class_name="screen", pid=0, process_name="screen", visible=True)
        self.policy.check_content_access(pseudo)

        warnings: List[str] = []
        screenshot_path = ""
        screenshot_b64 = ""
        ocr_text = ""

        try:
            img = self.capture_screen_image(monitor_index=monitor_index)
            if include_screenshot:
                screenshot_path = self.save_image(img, out_dir=out_dir, prefix="screen")
            if include_screenshot_base64:
                screenshot_b64 = self.image_to_base64(img)
            if include_ocr:
                ocr_text = self.ocr_image(img)
        except Exception as e:
            warnings.append(f"screen capture/OCR failed: {type(e).__name__}: {e}")

        return ObserveResult(
            ok=True,
            timestamp=_dt.datetime.now().isoformat(timespec="seconds"),
            target=pseudo,
            ocr_text=self.policy.redact_text(ocr_text),
            screenshot_path=screenshot_path,
            screenshot_base64=screenshot_b64,
            warnings=warnings,
            meta={
                "engine": "application_engine",
                "version": "1.0.0",
                "platform": platform.platform(),
                "capture_methods": self.available_capture_methods(),
            },
        )

    def available_capture_methods(self) -> Dict[str, bool]:
        return {
            "windows_win32": bool(IS_WINDOWS),
            "psutil": psutil is not None,
            "pywinauto_uia": Desktop is not None,
            "pillow_imagegrab": ImageGrab is not None,
            "mss": mss is not None,
            "pytesseract": pytesseract is not None,
        }

    # ---------------------------------------------------------------------
    # Tool-like API
    # ---------------------------------------------------------------------

    def execute(self, action: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        p = dict(params or {})
        action = (action or "").strip().lower().replace("-", "_")

        if action in ("capabilities", "info"):
            return {
                "ok": True,
                "engine": "application_engine",
                "version": "1.0.0",
                "capabilities": self.available_capture_methods(),
                "actions": list(APPLICATION_ENGINE_ACTIONS.keys()),
            }

        if action in ("list_processes", "processes"):
            items = self.list_processes(include_cmdline=bool(p.get("include_cmdline", False)),
                                        limit=int(p.get("limit", 5000)))
            return {"ok": True, "processes": [asdict(x) for x in items]}

        if action in ("list_windows", "windows"):
            items = self.list_windows(
                visible_only=bool(p.get("visible_only", True)),
                include_empty_titles=bool(p.get("include_empty_titles", False)),
                limit=int(p.get("limit", 2000)),
            )
            return {"ok": True, "windows": [_as_jsonable_window(x) for x in items]}

        if action in ("find_window", "find_windows"):
            items = self.find_windows(
                query=str(p.get("query", "")),
                pid=_maybe_int(p.get("pid")),
                process_name=str(p.get("process_name", "")),
                visible_only=bool(p.get("visible_only", True)),
                include_empty_titles=bool(p.get("include_empty_titles", False)),
                limit=int(p.get("limit", 50)),
            )
            return {"ok": True, "windows": [_as_jsonable_window(x) for x in items]}

        if action in ("observe", "observe_window", "read_window"):
            result = self.observe_window(
                hwnd=_maybe_int(p.get("hwnd")),
                pid=_maybe_int(p.get("pid")),
                query=str(p.get("query", "")),
                process_name=str(p.get("process_name", "")),
                include_ui_tree=bool(p.get("include_ui_tree", True)),
                include_screenshot=bool(p.get("include_screenshot", True)),
                include_screenshot_base64=bool(p.get("include_screenshot_base64", False)),
                include_ocr=bool(p.get("include_ocr", False)),
                focus=bool(p.get("focus", False)),
                out_dir=p.get("out_dir", "out/application_engine"),
                max_depth=int(p.get("max_depth", 4)),
                max_elements=int(p.get("max_elements", 250)),
                visible_only=bool(p.get("visible_only", True)),
            )
            return _observe_to_dict(result)

        if action in ("read_screen", "observe_screen", "screen"):
            result = self.read_screen(
                include_screenshot=bool(p.get("include_screenshot", True)),
                include_screenshot_base64=bool(p.get("include_screenshot_base64", False)),
                include_ocr=bool(p.get("include_ocr", True)),
                out_dir=p.get("out_dir", "out/application_engine"),
                monitor_index=int(p.get("monitor_index", 1)),
            )
            return _observe_to_dict(result)

        if action in ("allow_window",):
            hwnd = _maybe_int(p.get("hwnd"))
            if hwnd is None:
                raise ValueError("allow_window requires hwnd")
            self.allow_window(hwnd)
            return {"ok": True, "allowed_hwnd": hwnd}

        if action in ("allow_process",):
            pid = _maybe_int(p.get("pid"))
            if pid is None:
                raise ValueError("allow_process requires pid")
            self.allow_process(pid)
            return {"ok": True, "allowed_pid": pid}

        if action in ("allow_process_name",):
            name = str(p.get("process_name") or p.get("name") or "")
            if not name:
                raise ValueError("allow_process_name requires process_name")
            self.allow_process_name(name)
            return {"ok": True, "allowed_process_name": name}

        raise ValueError(f"Unknown application_engine action: {action}")


# =============================================================================
# Tool schema / GPT-facing metadata
# =============================================================================

APPLICATION_ENGINE_ACTIONS: Dict[str, Dict[str, Any]] = {
    "capabilities": {
        "description": "Return installed backends and available actions.",
        "params": {},
    },
    "list_processes": {
        "description": "List local running processes. Does not read screen contents.",
        "params": {"include_cmdline": "bool", "limit": "int"},
    },
    "list_windows": {
        "description": "List visible top-level windows with hwnd, pid, title, class, and rect.",
        "params": {"visible_only": "bool", "include_empty_titles": "bool", "limit": "int"},
    },
    "find_windows": {
        "description": "Find windows by title/process/class substring.",
        "params": {"query": "str", "pid": "int?", "process_name": "str", "limit": "int"},
    },
    "observe_window": {
        "description": "Read an authorized window via UI Automation, screenshot, and optional OCR.",
        "params": {
            "hwnd": "int?",
            "pid": "int?",
            "query": "str",
            "process_name": "str",
            "include_ui_tree": "bool",
            "include_screenshot": "bool",
            "include_ocr": "bool",
            "focus": "bool",
            "allow_all_local": "bool engine param for local dev",
        },
    },
    "read_screen": {
        "description": "Read the whole screen screenshot/OCR. Requires explicit content consent.",
        "params": {"include_screenshot": "bool", "include_ocr": "bool", "monitor_index": "int"},
    },
}


# =============================================================================
# PromptChat-style block adapter
# =============================================================================

@dataclass
class ApplicationEngineBlock:
    """
    PromptChat-style block adapter.

    Signature matches your BaseBlock convention:
        execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]

    Payload forms:
        "list_windows"
        {"action": "observe_window", "query": "Notepad", "include_ocr": true}
        {"tool": "application_engine", "action": "read_screen"}
    """

    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        merged = dict(params or {})
        action = "capabilities"
        call_params: Dict[str, Any] = {}

        if isinstance(payload, dict):
            action = str(payload.get("action") or payload.get("name") or payload.get("tool_action") or "capabilities")
            call_params = {k: v for k, v in payload.items() if k not in {"action", "name", "tool_action", "tool"}}
        elif isinstance(payload, str):
            s = payload.strip()
            if s:
                # Accept "action key=value key=value" quick syntax.
                parts = s.split(None, 1)
                action = parts[0]
                if len(parts) > 1:
                    call_params.update(_parse_key_values(parts[1]))

        call_params.update({k: v for k, v in merged.items() if k not in {"action"}})

        engine = ApplicationEngine(params=merged)
        try:
            result = engine.execute(action, call_params)
            meta = {
                "type": "application-engine",
                "action": action,
                "ok": bool(result.get("ok", False)),
                "capabilities": engine.available_capture_methods(),
            }
            return result, meta
        except Exception as e:
            result = {
                "ok": False,
                "error": str(e),
                "error_type": type(e).__name__,
                "action": action,
            }
            meta = {"type": "application-engine", "action": action, "ok": False, "error_type": type(e).__name__}
            return result, meta

    def get_params_info(self) -> Dict[str, Any]:
        return {
            "allow_all_local": "Set true for local development to allow reading the selected local window/screen.",
            "allow_sensitive": "Set true only for your own authorized sensitive windows.",
            "allowed_hwnds": "Comma-separated/list of window handles allowed for content observation.",
            "allowed_pids": "Comma-separated/list of process ids allowed for content observation.",
            "allowed_process_names": "Comma-separated/list of process names allowed for content observation.",
            "include_ui_tree": "Read UI Automation tree when observing a window.",
            "include_screenshot": "Save screenshot when observing a window/screen.",
            "include_ocr": "OCR screenshot text when pytesseract is installed.",
            "out_dir": "Folder for screenshots. Default: out/application_engine.",
            "max_depth": "Max UI tree depth. Default: 4.",
            "max_elements": "Max UI elements. Default: 250.",
        }


def register_promptchat_blocks() -> bool:
    """
    Optional dynamic registration.

    This does not require your registry at import time. If `registry.BLOCKS` exists,
    this adds app/application block names without changing your existing integration.
    """
    try:
        from registry import BLOCKS  # type: ignore
    except Exception:
        return False

    try:
        block = ApplicationEngineBlock()
        for name in (
            "application_engine",
            "app_engine",
            "application_observer",
            "app_observer",
            "screen_reader_engine",
        ):
            try:
                BLOCKS[name] = block
            except Exception:
                pass
        return True
    except Exception:
        return False


# Register automatically when used inside PromptChat if registry is importable.
register_promptchat_blocks()


# =============================================================================
# JSON helpers
# =============================================================================

def _observe_to_dict(result: ObserveResult) -> Dict[str, Any]:
    d = asdict(result)
    if result.target is not None:
        d["target"] = _as_jsonable_window(result.target)
    if result.process is not None:
        d["process"] = asdict(result.process)
    d["ui_tree"] = [_ui_element_to_dict(x) for x in result.ui_tree]
    return d


def _ui_element_to_dict(x: UIElementInfo) -> Dict[str, Any]:
    d = asdict(x)
    if x.rectangle is not None:
        d["rectangle"] = asdict(x.rectangle)
    d["children"] = [_ui_element_to_dict(c) for c in x.children]
    return d


def _as_jsonable_window(w: WindowInfo) -> Dict[str, Any]:
    return {
        "hwnd": int(w.hwnd),
        "title": w.title,
        "class_name": w.class_name,
        "pid": int(w.pid),
        "process_name": w.process_name,
        "visible": bool(w.visible),
        "rect": asdict(w.rect),
    }


def _safe_str(fn: Callable[[], Any]) -> str:
    try:
        v = fn()
        if v is None:
            return ""
        return str(v)
    except Exception:
        return ""


def _maybe_int(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _as_int_list(v: Any) -> List[int]:
    if v is None or v == "":
        return []
    if isinstance(v, int):
        return [v]
    if isinstance(v, (list, tuple, set)):
        out = []
        for x in v:
            try:
                out.append(int(x))
            except Exception:
                pass
        return out
    out = []
    for part in re.split(r"[,\s]+", str(v)):
        if not part:
            continue
        try:
            out.append(int(part))
        except Exception:
            pass
    return out


def _as_str_list(v: Any) -> List[str]:
    if v is None or v == "":
        return []
    if isinstance(v, str):
        return [x.strip() for x in re.split(r"[,;]", v) if x.strip()]
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v).strip()]


def _safe_filename(s: str) -> str:
    s = str(s or "file")
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "_", s).strip("._")
    return s[:120] or "file"


def _parse_csv_line(line: str) -> List[str]:
    # Enough for tasklist CSV output.
    out: List[str] = []
    cur = []
    quoted = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"':
            if quoted and i + 1 < len(line) and line[i + 1] == '"':
                cur.append('"')
                i += 1
            else:
                quoted = not quoted
        elif ch == "," and not quoted:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    out.append("".join(cur))
    return out


def _parse_key_values(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        import shlex
        parts = shlex.split(text)
    except Exception:
        parts = text.split()

    for part in parts:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = _coerce(v.strip())
    return out


def _coerce(v: str) -> Any:
    low = str(v).strip().lower()
    if low in {"true", "yes", "1", "on"}:
        return True
    if low in {"false", "no", "0", "off"}:
        return False
    if low in {"none", "null"}:
        return None
    try:
        if re.fullmatch(r"[-+]?\d+", str(v)):
            return int(v)
        if re.fullmatch(r"[-+]?\d+\.\d+", str(v)):
            return float(v)
    except Exception:
        pass
    return v


# =============================================================================
# CLI
# =============================================================================

def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Consent-based local application observation engine.")
    p.add_argument("--allow-all-local", action="store_true", help="Allow content observation for local dev.")
    p.add_argument("--allow-sensitive", action="store_true", help="Allow sensitive-looking windows you own/control.")
    p.add_argument("--out-dir", default="out/application_engine", help="Screenshot output folder.")
    p.add_argument("--include-ocr", action="store_true", help="Run OCR if pytesseract is installed.")
    p.add_argument("--include-screenshot-base64", action="store_true", help="Include PNG screenshot base64 in JSON.")
    p.add_argument("--max-depth", type=int, default=4)
    p.add_argument("--max-elements", type=int, default=250)

    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("capabilities")
    sub.add_parser("list-processes")
    sub.add_parser("list-windows")

    f = sub.add_parser("find-window")
    f.add_argument("query", nargs="?", default="")
    f.add_argument("--pid", type=int)
    f.add_argument("--process-name", default="")

    o = sub.add_parser("observe")
    o.add_argument("--hwnd", type=int)
    o.add_argument("--pid", type=int)
    o.add_argument("--query", default="")
    o.add_argument("--process-name", default="")
    o.add_argument("--no-ui-tree", action="store_true")
    o.add_argument("--no-screenshot", action="store_true")
    o.add_argument("--focus", action="store_true")

    s = sub.add_parser("screen")
    s.add_argument("--monitor-index", type=int, default=1)
    s.add_argument("--no-screenshot", action="store_true")

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    params = {
        "allow_all_local": bool(args.allow_all_local),
        "allow_sensitive": bool(args.allow_sensitive),
        "out_dir": args.out_dir,
    }
    engine = ApplicationEngine(params=params)

    try:
        if args.cmd in (None, "capabilities"):
            _print_json(engine.execute("capabilities", {}))
        elif args.cmd == "list-processes":
            _print_json(engine.execute("list_processes", {}))
        elif args.cmd == "list-windows":
            _print_json(engine.execute("list_windows", {}))
        elif args.cmd == "find-window":
            _print_json(engine.execute("find_windows", {
                "query": args.query,
                "pid": args.pid,
                "process_name": args.process_name,
            }))
        elif args.cmd == "observe":
            _print_json(engine.execute("observe_window", {
                "hwnd": args.hwnd,
                "pid": args.pid,
                "query": args.query,
                "process_name": args.process_name,
                "include_ui_tree": not args.no_ui_tree,
                "include_screenshot": not args.no_screenshot,
                "include_screenshot_base64": args.include_screenshot_base64,
                "include_ocr": args.include_ocr,
                "focus": args.focus,
                "out_dir": args.out_dir,
                "max_depth": args.max_depth,
                "max_elements": args.max_elements,
            }))
        elif args.cmd == "screen":
            _print_json(engine.execute("read_screen", {
                "include_screenshot": not args.no_screenshot,
                "include_screenshot_base64": args.include_screenshot_base64,
                "include_ocr": args.include_ocr,
                "monitor_index": args.monitor_index,
                "out_dir": args.out_dir,
            }))
        else:
            raise ValueError(f"Unknown command: {args.cmd}")
        return 0
    except Exception as e:
        _print_json({"ok": False, "error_type": type(e).__name__, "error": str(e)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
