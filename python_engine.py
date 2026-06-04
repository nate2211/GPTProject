# python_engine.py
# ---------------------------------------------------------------------------
# PromptChat Python Engine
#
# Controlled Python file/script execution engine for your local GPT.
#
# The GPT can:
#   - create files inside a workspace
#   - validate generated Python with AST checks
#   - run generated scripts in a subprocess
#   - capture stdout/stderr/return code/runtime
#   - collect artifacts
#   - return structured JSON packets back to the model
#   - create/use a dedicated python_tool/.venv
#   - write python_tool/requirements.txt
#   - pip install python_tool/requirements.txt into that venv
#
# Important:
#   - run_code signature/usage is unchanged.
#   - If python_tool/.venv exists, run_code/run_file automatically use it.
#   - If no venv exists, run_code/run_file still use config.python_executable.
#
# Default safety:
#   - workspace-contained file operations
#   - no shell=True
#   - unrestricted generated-script imports (network/process/native/package imports allowed)
#   - timeout
#   - optional psutil process-tree cleanup
# ---------------------------------------------------------------------------

from __future__ import annotations

import ast
import base64
import dataclasses
import hashlib
import json
import mimetypes
import os
import platform
import re
import subprocess
import sys
import textwrap
import time
import traceback
import venv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

try:
    import psutil  # type: ignore
except Exception:
    psutil = None

try:
    import resource  # type: ignore
except Exception:
    resource = None


ENGINE_NAME = "promptchat_python_engine"
ENGINE_VERSION = "2026.06.04-unrestricted-imports"

DEFAULT_WORKSPACE = Path.home() / ".promptchat" / "python_engine_workspace"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_PIP_TIMEOUT_SECONDS = 900
DEFAULT_MAX_STDOUT_CHARS = 12000
DEFAULT_MAX_STDERR_CHARS = 12000
DEFAULT_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_SOURCE_CHARS = 240_000

PYTHON_TOOL_DIRNAME = "python_tool"
PYTHON_TOOL_VENV_DIRNAME = ".venv"
PYTHON_TOOL_REQUIREMENTS_NAME = "requirements.txt"

TEXT_EXTENSIONS = {
    ".py", ".txt", ".md", ".json", ".csv", ".tsv", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".log", ".html", ".xml", ".svg", ".css", ".js",
}

DEFAULT_ALLOWED_IMPORT_ROOTS: Set[str] = set()

DEFAULT_BLOCKED_IMPORT_ROOTS: Set[str] = set()

DEFAULT_BLOCKED_BUILTIN_CALLS: Set[str] = set()

DEFAULT_BLOCKED_ATTRIBUTE_CALLS: Set[Tuple[str, str]] = set()

DEFAULT_BLOCKED_NAME_PATTERNS: Tuple[str, ...] = tuple()


@dataclass
class PythonEngineConfig:
    workspace: str = str(DEFAULT_WORKSPACE)
    python_executable: str = sys.executable
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    pip_timeout_seconds: int = DEFAULT_PIP_TIMEOUT_SECONDS
    max_stdout_chars: int = DEFAULT_MAX_STDOUT_CHARS
    max_stderr_chars: int = DEFAULT_MAX_STDERR_CHARS
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES
    max_source_chars: int = DEFAULT_MAX_SOURCE_CHARS
    memory_limit_mb: int = 1024

    # python_tool support.
    python_tool_dirname: str = PYTHON_TOOL_DIRNAME
    use_python_tool_venv: bool = True
    auto_create_python_tool_venv: bool = False
    auto_install_python_tool_requirements: bool = False

    # Generated-script safety.
    allow_network_imports: bool = True
    allow_process_imports: bool = True
    allow_native_imports: bool = True
    allow_shell: bool = False
    allow_absolute_paths: bool = True
    allow_path_escape: bool = False
    allow_package_install: bool = True
    enforce_import_allowlist: bool = False
    extra_env: Dict[str, str] = field(default_factory=dict)


@dataclass
class ValidationIssue:
    severity: str
    message: str
    line: int = 0
    column: int = 0
    code: str = "validation"


def _json_safe(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _json_safe(dataclasses.asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return value


def _ok(**kwargs: Any) -> Dict[str, Any]:
    out = {"ok": True, "engine": ENGINE_NAME, "version": ENGINE_VERSION}
    out.update(_json_safe(kwargs))
    return out


def _err(message: str, **kwargs: Any) -> Dict[str, Any]:
    out = {"ok": False, "engine": ENGINE_NAME, "version": ENGINE_VERSION, "error": str(message)}
    out.update(_json_safe(kwargs))
    return out


def _clip(text: Any, limit: int) -> str:
    s = str(text or "")
    if len(s) <= limit:
        return s
    return s[:limit] + "\n...[truncated]"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalize_relative_path(path: str) -> str:
    p = str(path or "").replace("\\", "/").strip()
    p = re.sub(r"/+", "/", p)
    p = p.lstrip("/")
    return p


def _is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    mt, _ = mimetypes.guess_type(str(path))
    return bool(mt and (mt.startswith("text/") or mt in {"application/json", "application/xml"}))


def _module_root(name: str) -> str:
    return (name or "").split(".", 1)[0]


def _safe_generated_slug(value: str, fallback: str = "generated_task") -> str:
    raw = str(value or "").strip().lower()
    raw = re.sub(r"[^a-z0-9_]+", "_", raw).strip("_")
    return (raw or fallback)[:80]


def _truthy_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "y", "on", "create", "write", "run", "install"}


def _normalize_requirements_text(requirements: str) -> str:
    raw = str(requirements or "").strip()
    if not raw:
        return ""
    if "\n" in raw or "\r" in raw:
        return raw.replace("\r\n", "\n").replace("\r", "\n")
    parts = [p.strip() for p in re.split(r"\s+", raw) if p.strip()]
    return "\n".join(parts) + ("\n" if parts else "")


def _infer_action_from_legacy_flags(
    action: str,
    *,
    create_python_tool_venv: Any = False,
    create_file: Any = False,
    write_file_flag: Any = False,
    read_file_flag: Any = False,
    list_files_flag: Any = False,
    delete_file_flag: Any = False,
    validate_code_flag: Any = False,
    run_code_flag: Any = False,
    run_file_flag: Any = False,
    run_task_flag: Any = False,
    collect_artifacts_flag: Any = False,
    read_artifact_flag: Any = False,
    install_requirements_flag: Any = False,
    pip_install_requirements_flag: Any = False,
    install_package_flag: Any = False,
    pip_install_package_flag: Any = False,
    python_tool_status_flag: Any = False,
    extra_flags: Optional[Dict[str, Any]] = None,
) -> str:
    a = str(action or "").strip().lower()
    if a:
        return a

    flags: Dict[str, Any] = dict(extra_flags or {})
    flags.update(
        {
            "create_python_tool_venv": create_python_tool_venv,
            "create_file": create_file,
            "write_file": write_file_flag,
            "read_file": read_file_flag,
            "list_files": list_files_flag,
            "delete_file": delete_file_flag,
            "validate_code": validate_code_flag,
            "run_code": run_code_flag,
            "run_file": run_file_flag,
            "run_task": run_task_flag,
            "collect_artifacts": collect_artifacts_flag,
            "read_artifact": read_artifact_flag,
            "install_requirements": install_requirements_flag,
            "pip_install_requirements": pip_install_requirements_flag,
            "install_package": install_package_flag,
            "pip_install_package": pip_install_package_flag,
            "python_tool_status": python_tool_status_flag,
        }
    )

    ordered = [
        ("create_python_tool_venv", "create_python_tool_venv"),
        ("create_venv", "create_python_tool_venv"),
        ("tool_env_create", "create_python_tool_venv"),
        ("write_requirements", "write_requirements"),
        ("write_python_tool_requirements", "write_requirements"),
        ("pip_install_requirements", "pip_install_requirements"),
        ("install_requirements", "pip_install_requirements"),
        ("pip_install_package", "pip_install_package"),
        ("install_package", "pip_install_package"),
        ("create_file", "write_file"),
        ("write_file", "write_file"),
        ("read_file", "read_file"),
        ("list_files", "list_files"),
        ("delete_file", "delete_file"),
        ("validate_code", "validate_code"),
        ("run_code", "run_code"),
        ("run_file", "run_file"),
        ("run_task", "run_task"),
        ("collect_artifacts", "collect_artifacts"),
        ("read_artifact", "read_artifact"),
        ("python_tool_status", "python_tool_status"),
        ("tool_env_status", "python_tool_status"),
        ("venv_status", "python_tool_status"),
    ]

    for flag_name, inferred in ordered:
        if _truthy_flag(flags.get(flag_name)):
            return inferred

    return "status"


def _normalize_filename_alias(relative_path: str = "", filename: str = "") -> str:
    rp = str(relative_path or "").strip()
    fn = str(filename or "").strip()
    if rp:
        return rp
    if not fn:
        return ""
    clean = _normalize_relative_path(fn)
    if "/" not in clean and clean.endswith(".py"):
        return f"scripts/{clean}"
    return clean



def _default_relative_path_for_action(
    action: str,
    *,
    relative_path: str = "",
    filename: str = "",
    task: str = "",
    content: str = "",
    code: str = "",
) -> str:
    rp = _normalize_relative_path(relative_path or filename or "")
    if rp:
        return rp

    a = str(action or "status").strip().lower()

    if a in {"run_code", "validate_code"}:
        return "scripts/generated_task.py"

    if a == "run_task":
        return f"scripts/{_safe_generated_slug(task)}.py"

    if a == "write_file":
        body = code or content or ""
        if body.lstrip().startswith(("#", "from ", "import ", "def ", "class ")) or ("\n" in body and "import " in body[:500]):
            return "scripts/generated_file.py"
        return "artifacts/generated.txt"

    if a in {"read_artifact", "collect_artifacts"}:
        return "artifacts"

    if a in {"list_files", "read_file"}:
        return "."

    return "scripts/generated_task.py"


class PythonSafetyVisitor(ast.NodeVisitor):
    def __init__(
        self,
        *,
        allowed_imports: Set[str],
        blocked_imports: Set[str],
        blocked_builtin_calls: Set[str],
        blocked_attribute_calls: Set[Tuple[str, str]],
        blocked_name_patterns: Sequence[str],
        allow_absolute_paths: bool,
    ) -> None:
        self.allowed_imports = allowed_imports
        self.blocked_imports = blocked_imports
        self.blocked_builtin_calls = blocked_builtin_calls
        self.blocked_attribute_calls = blocked_attribute_calls
        self.blocked_name_patterns = tuple(re.compile(p) for p in blocked_name_patterns)
        self.allow_absolute_paths = allow_absolute_paths
        self.issues: List[ValidationIssue] = []

    def issue(self, node: ast.AST, message: str, severity: str = "error", code: str = "validation") -> None:
        self.issues.append(
            ValidationIssue(
                severity=severity,
                message=message,
                line=int(getattr(node, "lineno", 0) or 0),
                column=int(getattr(node, "col_offset", 0) or 0),
                code=code,
            )
        )

    def _check_import_name(self, node: ast.AST, name: str) -> None:
        root = _module_root(name)
        if root in self.blocked_imports or name in self.blocked_imports:
            self.issue(node, f"Blocked import: {name}", code="blocked_import")
            return
        if self.allowed_imports and root not in self.allowed_imports and name not in self.allowed_imports:
            self.issue(node, f"Import is not in allowlist: {name}", code="import_not_allowed")

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self._check_import_name(node, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        mod = node.module or ""
        if node.level and node.level > 0:
            self.issue(node, "Relative imports are blocked in generated scripts.", code="relative_import")
        if mod:
            self._check_import_name(node, mod)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> Any:
        for pat in self.blocked_name_patterns:
            if pat.search(node.id):
                self.issue(node, f"Blocked introspection name: {node.id}", code="blocked_name")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        for pat in self.blocked_name_patterns:
            if pat.search(node.attr):
                self.issue(node, f"Blocked introspection attribute: {node.attr}", code="blocked_attribute")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Name) and node.func.id in self.blocked_builtin_calls:
            self.issue(node, f"Blocked builtin call: {node.func.id}", code="blocked_call")

        if isinstance(node.func, ast.Attribute):
            mod_name = None
            if isinstance(node.func.value, ast.Name):
                mod_name = node.func.value.id
            elif isinstance(node.func.value, ast.Attribute):
                parts = []
                cur: Any = node.func.value
                while isinstance(cur, ast.Attribute):
                    parts.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.append(cur.id)
                    mod_name = ".".join(reversed(parts))

            if mod_name:
                pair = (mod_name, node.func.attr)
                root_pair = (_module_root(mod_name), node.func.attr)
                if pair in self.blocked_attribute_calls or root_pair in self.blocked_attribute_calls:
                    self.issue(node, f"Blocked call: {mod_name}.{node.func.attr}", code="blocked_call")

        if not self.allow_absolute_paths:
            values = list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]
            for arg in values:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    s = arg.value
                    if re.match(r"^[A-Za-z]:[\\/]", s) or s.startswith(("/", "\\\\")):
                        self.issue(node, f"Absolute path literal is blocked: {s}", code="absolute_path")

        self.generic_visit(node)


class PythonEngine:
    def __init__(self, config: Optional[PythonEngineConfig] = None) -> None:
        self.config = config or PythonEngineConfig()
        self.workspace = Path(self.config.workspace).expanduser().resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

        for sub in ("artifacts", "scripts", "inputs", "runs"):
            (self.workspace / sub).mkdir(parents=True, exist_ok=True)

        self.python_tool_dir.mkdir(parents=True, exist_ok=True)
        if not self.python_tool_requirements_path.exists():
            self.python_tool_requirements_path.write_text("", encoding="utf-8")

    @property
    def python_tool_dir(self) -> Path:
        dirname = _normalize_relative_path(self.config.python_tool_dirname or PYTHON_TOOL_DIRNAME) or PYTHON_TOOL_DIRNAME
        return (self.workspace / dirname).resolve()

    @property
    def python_tool_venv_dir(self) -> Path:
        return self.python_tool_dir / PYTHON_TOOL_VENV_DIRNAME

    @property
    def python_tool_requirements_path(self) -> Path:
        return self.python_tool_dir / PYTHON_TOOL_REQUIREMENTS_NAME

    @property
    def python_tool_python_path(self) -> Path:
        if os.name == "nt":
            return self.python_tool_venv_dir / "Scripts" / "python.exe"
        return self.python_tool_venv_dir / "bin" / "python"

    @property
    def python_tool_pip_path(self) -> Path:
        if os.name == "nt":
            return self.python_tool_venv_dir / "Scripts" / "pip.exe"
        return self.python_tool_venv_dir / "bin" / "pip"

    def resolve_workspace_path(self, relative_path: str, *, create_parent: bool = False) -> Path:
        rel = _normalize_relative_path(relative_path)
        if not rel:
            raise ValueError("relative_path is empty")
        candidate = (self.workspace / rel).resolve()
        if not self.config.allow_path_escape:
            try:
                candidate.relative_to(self.workspace)
            except ValueError:
                raise ValueError(f"Path escapes workspace: {relative_path}")
        if create_parent:
            candidate.parent.mkdir(parents=True, exist_ok=True)
        return candidate

    def _select_python_executable(self) -> str:
        if self.config.use_python_tool_venv and self.python_tool_python_path.exists():
            return str(self.python_tool_python_path)
        return str(self.config.python_executable or sys.executable)

    def _venv_exists(self) -> bool:
        return self.python_tool_python_path.exists()

    def status(self) -> Dict[str, Any]:
        return _ok(
            status="ready",
            workspace=str(self.workspace),
            python_executable=self.config.python_executable,
            active_python_executable=self._select_python_executable(),
            platform=platform.platform(),
            python_version=sys.version,
            timeout_seconds=self.config.timeout_seconds,
            pip_timeout_seconds=self.config.pip_timeout_seconds,
            memory_limit_mb=self.config.memory_limit_mb,
            psutil_available=psutil is not None,
            resource_available=resource is not None,
            python_tool=self.python_tool_status().get("python_tool", {}),
            packages=self._probe_common_packages(),
            safety={
                "allow_network_imports": self.config.allow_network_imports,
                "allow_process_imports": self.config.allow_process_imports,
                "allow_native_imports": self.config.allow_native_imports,
                "allow_shell": self.config.allow_shell,
                "allow_absolute_paths": self.config.allow_absolute_paths,
                "allow_path_escape": self.config.allow_path_escape,
                "allow_package_install": self.config.allow_package_install,
                "enforce_import_allowlist": self.config.enforce_import_allowlist,
                "use_python_tool_venv": self.config.use_python_tool_venv,
                "auto_create_python_tool_venv": self.config.auto_create_python_tool_venv,
                "auto_install_python_tool_requirements": self.config.auto_install_python_tool_requirements,
            },
        )

    def _probe_common_packages(self) -> Dict[str, Dict[str, Any]]:
        names = [
            "numpy", "scipy", "pandas", "polars", "pyarrow", "duckdb",
            "sympy", "sklearn", "statsmodels", "networkx", "matplotlib",
            "plotly", "PIL", "cv2", "numba", "joblib", "psutil",
        ]
        out: Dict[str, Dict[str, Any]] = {}
        try:
            import importlib.util
            import importlib.metadata
        except Exception:
            return out
        for name in names:
            spec = importlib.util.find_spec(name)
            info: Dict[str, Any] = {"available": spec is not None}
            if spec is not None:
                try:
                    dist_name = "pillow" if name == "PIL" else ("opencv-python" if name == "cv2" else name)
                    info["version"] = importlib.metadata.version(dist_name)
                except Exception:
                    info["version"] = None
            out[name] = info
        return out

    # ------------------------------------------------------------------
    # python_tool venv and requirements
    # ------------------------------------------------------------------

    def python_tool_status(self) -> Dict[str, Any]:
        req_exists = self.python_tool_requirements_path.exists()
        req_text = ""
        req_lines: List[str] = []

        if req_exists:
            try:
                req_text = self.python_tool_requirements_path.read_text(encoding="utf-8", errors="replace")
                req_lines = [
                    line.strip()
                    for line in req_text.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
            except Exception:
                req_text = ""

        return _ok(
            action="python_tool_status",
            python_tool={
                "dir": str(self.python_tool_dir),
                "relative_dir": str(self.python_tool_dir.relative_to(self.workspace)).replace("\\", "/"),
                "venv_dir": str(self.python_tool_venv_dir),
                "venv_exists": self._venv_exists(),
                "venv_python": str(self.python_tool_python_path),
                "venv_pip": str(self.python_tool_pip_path),
                "requirements_path": str(self.python_tool_requirements_path),
                "requirements_exists": req_exists,
                "requirements_count": len(req_lines),
                "requirements": req_lines[:200],
                "active_for_run_code": bool(self.config.use_python_tool_venv and self._venv_exists()),
            },
        )

    def create_python_tool_venv(
        self,
        *,
        clear: bool = False,
        with_pip: bool = True,
        upgrade_deps: bool = False,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        try:
            started = time.time()
            self.python_tool_dir.mkdir(parents=True, exist_ok=True)

            if clear and self.python_tool_venv_dir.exists():
                self._safe_remove_workspace_dir(self.python_tool_venv_dir)

            if not self.python_tool_venv_dir.exists():
                builder = venv.EnvBuilder(with_pip=with_pip, clear=False, upgrade=False)
                builder.create(str(self.python_tool_venv_dir))

            if upgrade_deps:
                upgrade = self._run_pip(
                    ["install", "--upgrade", "pip", "setuptools", "wheel"],
                    timeout_seconds=timeout_seconds,
                )
                if not upgrade.get("ok"):
                    return upgrade

            return _ok(
                action="create_python_tool_venv",
                elapsed_ms=int((time.time() - started) * 1000),
                python_tool=self.python_tool_status().get("python_tool", {}),
            )
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def write_requirements(
        self,
        requirements: str,
        *,
        append: bool = False,
    ) -> Dict[str, Any]:
        try:
            text = str(requirements or "")
            self.python_tool_dir.mkdir(parents=True, exist_ok=True)

            if append and self.python_tool_requirements_path.exists():
                old = self.python_tool_requirements_path.read_text(encoding="utf-8", errors="replace")
                if old and not old.endswith("\n"):
                    old += "\n"
                text = old + text

            self.python_tool_requirements_path.write_text(text, encoding="utf-8")
            data = self.python_tool_requirements_path.read_bytes()
            return _ok(
                action="write_requirements",
                path=str(self.python_tool_requirements_path),
                relative_path=str(self.python_tool_requirements_path.relative_to(self.workspace)).replace("\\", "/"),
                bytes=len(data),
                sha256=_sha256_bytes(data),
                python_tool=self.python_tool_status().get("python_tool", {}),
            )
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def pip_install_requirements(
        self,
        *,
        requirements_path: str = "",
        create_venv: bool = True,
        upgrade: bool = False,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        try:
            if create_venv and not self._venv_exists():
                created = self.create_python_tool_venv(timeout_seconds=timeout_seconds)
                if not created.get("ok"):
                    return created

            if not self._venv_exists():
                return _err("python_tool venv does not exist. Run create_python_tool_venv first.", python_tool=self.python_tool_status().get("python_tool", {}))

            req = self.python_tool_requirements_path
            if requirements_path:
                req = self.resolve_workspace_path(requirements_path)

            try:
                req.relative_to(self.workspace)
            except ValueError:
                return _err("requirements_path escapes workspace", requirements_path=requirements_path)

            if not req.exists() or not req.is_file():
                return _err("requirements file not found", requirements_path=str(req), python_tool=self.python_tool_status().get("python_tool", {}))

            args = ["install"]
            if upgrade:
                args.append("--upgrade")
            args.extend(["-r", str(req)])

            return self._run_pip(args, timeout_seconds=timeout_seconds, action="pip_install_requirements", requirements_path=str(req))
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def pip_install_package(
        self,
        package: str,
        *,
        create_venv: bool = True,
        upgrade: bool = False,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        try:
            pkg = str(package or "").strip()
            if not pkg:
                return _err("package is required")

            if any(x in pkg for x in ("\n", "\r", ";", "&&", "||")):
                return _err("package contains unsafe shell-like characters", package=pkg)

            if create_venv and not self._venv_exists():
                created = self.create_python_tool_venv(timeout_seconds=timeout_seconds)
                if not created.get("ok"):
                    return created

            args = ["install"]
            if upgrade:
                args.append("--upgrade")
            args.append(pkg)
            return self._run_pip(args, timeout_seconds=timeout_seconds, action="pip_install_package", package=pkg)
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def _run_pip(
        self,
        pip_args: Sequence[str],
        *,
        timeout_seconds: Optional[int] = None,
        action: str = "pip",
        **extra: Any,
    ) -> Dict[str, Any]:
        if not self._venv_exists():
            return _err("python_tool venv does not exist", python_tool=self.python_tool_status().get("python_tool", {}))

        cmd = [str(self.python_tool_python_path), "-m", "pip", *[str(x) for x in pip_args]]
        timeout = int(timeout_seconds or self.config.pip_timeout_seconds or DEFAULT_PIP_TIMEOUT_SECONDS)
        started = time.time()

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.python_tool_dir),
                text=True,
                capture_output=True,
                timeout=timeout,
                shell=False,
            )

            return _ok(
                action=action,
                command=cmd,
                cwd=str(self.python_tool_dir),
                returncode=proc.returncode,
                elapsed_ms=int((time.time() - started) * 1000),
                stdout=_clip(proc.stdout, self.config.max_stdout_chars),
                stderr=_clip(proc.stderr, self.config.max_stderr_chars),
                python_tool=self.python_tool_status().get("python_tool", {}),
                **extra,
            ) if proc.returncode == 0 else _err(
                f"pip failed with return code {proc.returncode}",
                action=action,
                command=cmd,
                cwd=str(self.python_tool_dir),
                returncode=proc.returncode,
                elapsed_ms=int((time.time() - started) * 1000),
                stdout=_clip(proc.stdout, self.config.max_stdout_chars),
                stderr=_clip(proc.stderr, self.config.max_stderr_chars),
                python_tool=self.python_tool_status().get("python_tool", {}),
                **extra,
            )
        except subprocess.TimeoutExpired as exc:
            return _err(
                "pip timed out",
                action=action,
                command=cmd,
                timeout_seconds=timeout,
                stdout=_clip(exc.stdout or "", self.config.max_stdout_chars),
                stderr=_clip(exc.stderr or "", self.config.max_stderr_chars),
                python_tool=self.python_tool_status().get("python_tool", {}),
                **extra,
            )

    def _safe_remove_workspace_dir(self, path: Path) -> None:
        target = path.resolve()
        target.relative_to(self.workspace)
        if target == self.workspace:
            raise ValueError("Refusing to remove workspace root")
        if target.exists() and target.is_dir():
            import shutil
            shutil.rmtree(target)

    def _maybe_prepare_python_tool(self) -> Dict[str, Any]:
        if not self.config.use_python_tool_venv:
            return _ok(action="python_tool_prepare", prepared=False, reason="use_python_tool_venv=False")

        if self.config.auto_create_python_tool_venv and not self._venv_exists():
            created = self.create_python_tool_venv()
            if not created.get("ok"):
                return created

        if self.config.auto_install_python_tool_requirements and self._venv_exists() and self.python_tool_requirements_path.exists():
            req_text = self.python_tool_requirements_path.read_text(encoding="utf-8", errors="replace")
            has_requirements = any(line.strip() and not line.strip().startswith("#") for line in req_text.splitlines())
            if has_requirements:
                installed = self.pip_install_requirements(create_venv=False)
                if not installed.get("ok"):
                    return installed

        return _ok(action="python_tool_prepare", prepared=True, python_tool=self.python_tool_status().get("python_tool", {}))

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def write_file(self, relative_path: str, content: str, *, overwrite: bool = True, encoding: str = "utf-8") -> Dict[str, Any]:
        try:
            if len(content) > self.config.max_source_chars:
                return _err("content exceeds max_source_chars", max_source_chars=self.config.max_source_chars)
            path = self.resolve_workspace_path(relative_path, create_parent=True)
            if path.exists() and not overwrite:
                return _err("file already exists and overwrite=False", path=str(path))
            path.write_text(content, encoding=encoding)
            data = path.read_bytes()
            return _ok(action="write_file", relative_path=_normalize_relative_path(relative_path), path=str(path), bytes=len(data), sha256=_sha256_bytes(data))
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def read_file(self, relative_path: str, *, encoding: str = "utf-8", max_chars: int = 12000, as_base64: bool = False) -> Dict[str, Any]:
        try:
            path = self.resolve_workspace_path(relative_path)
            if not path.exists() or not path.is_file():
                return _err("file not found", relative_path=relative_path)
            size = path.stat().st_size
            if as_base64:
                data = path.read_bytes()
                if len(data) > self.config.max_artifact_bytes:
                    return _err("file too large for base64 read", bytes=len(data), max_artifact_bytes=self.config.max_artifact_bytes)
                return _ok(action="read_file", relative_path=_normalize_relative_path(relative_path), path=str(path), bytes=len(data), sha256=_sha256_bytes(data), base64=base64.b64encode(data).decode("ascii"), mime=mimetypes.guess_type(str(path))[0])
            if not _is_text_file(path):
                return _err("file appears binary; use as_base64=True", relative_path=relative_path, bytes=size)
            text = path.read_text(encoding=encoding, errors="replace")
            return _ok(action="read_file", relative_path=_normalize_relative_path(relative_path), path=str(path), bytes=size, sha256=_sha256_file(path), content=_clip(text, max_chars), truncated=len(text) > max_chars)
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def list_files(self, relative_dir: str = ".", *, pattern: str = "*", recursive: bool = True, max_files: int = 200) -> Dict[str, Any]:
        try:
            base = self.resolve_workspace_path(relative_dir or ".")
            if not base.exists():
                return _err("directory not found", relative_dir=relative_dir)
            if not base.is_dir():
                return _err("path is not a directory", relative_dir=relative_dir)
            iterator = base.rglob(pattern) if recursive else base.glob(pattern)
            files: List[Dict[str, Any]] = []
            for path in iterator:
                try:
                    if not path.exists():
                        continue
                    rel = str(path.resolve().relative_to(self.workspace)).replace("\\", "/")
                    stat = path.stat()
                    files.append({"relative_path": rel, "path": str(path), "is_file": path.is_file(), "is_dir": path.is_dir(), "bytes": stat.st_size if path.is_file() else 0, "mtime": stat.st_mtime, "mime": mimetypes.guess_type(str(path))[0]})
                    if len(files) >= max_files:
                        break
                except Exception:
                    continue
            files.sort(key=lambda x: (not x["is_dir"], x["relative_path"]))
            return _ok(action="list_files", relative_dir=relative_dir, count=len(files), files=files)
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def delete_file(self, relative_path: str) -> Dict[str, Any]:
        try:
            path = self.resolve_workspace_path(relative_path)
            if not path.exists():
                return _ok(action="delete_file", relative_path=relative_path, deleted=False)
            if path.is_dir():
                return _err("delete_file refuses to remove directories", relative_path=relative_path)
            path.unlink()
            return _ok(action="delete_file", relative_path=_normalize_relative_path(relative_path), deleted=True)
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_code(
        self,
        code: str,
        *,
        filename: str = "<generated>",
        extra_allowed_imports: Optional[Sequence[str]] = None,
        extra_blocked_imports: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Validate Python for syntax only.

        This unrestricted build intentionally does not block imports, native
        modules, subprocess modules, networking modules, package-management
        imports, introspection names, or attribute calls. The parameters
        ``extra_allowed_imports`` and ``extra_blocked_imports`` are accepted
        for backwards compatibility with the old tool signature, but they do
        not restrict generated code in this build.
        """
        issues: List[ValidationIssue] = []

        if code is None:
            return _err("code is required")

        source = str(code)
        if len(source) > self.config.max_source_chars:
            issues.append(ValidationIssue("error", "source exceeds max_source_chars", code="source_too_large"))

        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as exc:
            issues.append(
                ValidationIssue(
                    "error",
                    f"SyntaxError: {exc.msg}",
                    line=int(exc.lineno or 0),
                    column=int(exc.offset or 0),
                    code="syntax_error",
                )
            )
            return _ok(
                action="validate_code",
                valid=False,
                unrestricted_imports=True,
                issue_count=len(issues),
                error_count=len(issues),
                warning_count=0,
                issues=[dataclasses.asdict(i) for i in issues],
                imports=[],
                calls=[],
                ignored_extra_allowed_imports=list(extra_allowed_imports or []),
                ignored_extra_blocked_imports=list(extra_blocked_imports or []),
            )

        errors = [i for i in issues if i.severity == "error"]
        return _ok(
            action="validate_code",
            valid=not errors,
            unrestricted_imports=True,
            import_policy="syntax_only_no_import_blocklist_no_allowlist",
            issue_count=len(issues),
            error_count=len(errors),
            warning_count=len(issues) - len(errors),
            issues=[dataclasses.asdict(i) for i in issues],
            imports=self._collect_imports(tree),
            calls=self._collect_calls(tree)[:200],
            ignored_extra_allowed_imports=list(extra_allowed_imports or []),
            ignored_extra_blocked_imports=list(extra_blocked_imports or []),
        )

    def _collect_imports(self, tree: ast.AST) -> List[str]:
        imports: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        return sorted(set(imports))

    def _collect_calls(self, tree: ast.AST) -> List[str]:
        calls: List[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                parts = [node.func.attr]
                cur: Any = node.func.value
                while isinstance(cur, ast.Attribute):
                    parts.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.append(cur.id)
                name = ".".join(reversed(parts))
            if name:
                calls.append(name)
        return sorted(set(calls))

    # ------------------------------------------------------------------
    # Running code
    # ------------------------------------------------------------------

    def run_code(
        self,
        code: str,
        *,
        filename: str = "scripts/generated_task.py",
        args: Optional[Sequence[str]] = None,
        timeout_seconds: Optional[int] = None,
        validate: bool = True,
        extra_allowed_imports: Optional[Sequence[str]] = None,
        extra_blocked_imports: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        write_result = self.write_file(filename, code, overwrite=True)
        if not write_result.get("ok"):
            return write_result
        return self.run_file(filename, args=args, timeout_seconds=timeout_seconds, validate=validate, extra_allowed_imports=extra_allowed_imports, extra_blocked_imports=extra_blocked_imports)

    def run_file(
        self,
        relative_path: str,
        *,
        args: Optional[Sequence[str]] = None,
        timeout_seconds: Optional[int] = None,
        validate: bool = True,
        extra_allowed_imports: Optional[Sequence[str]] = None,
        extra_blocked_imports: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        try:
            script = self.resolve_workspace_path(relative_path)
            if not script.exists() or not script.is_file():
                return _err("script file not found", relative_path=relative_path)
            if script.suffix.lower() != ".py":
                return _err("run_file only executes .py files", relative_path=relative_path)

            prep = self._maybe_prepare_python_tool()
            if not prep.get("ok"):
                return prep

            code = script.read_text(encoding="utf-8", errors="replace")
            validation = self.validate_code(code, filename=str(script), extra_allowed_imports=extra_allowed_imports, extra_blocked_imports=extra_blocked_imports)
            if validate and not validation.get("valid", False):
                return _err("validation failed; script was not executed", validation=validation, relative_path=relative_path)

            return self._execute_script(script, args=args or [], timeout_seconds=timeout_seconds, validation=validation)
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def _execute_script(self, script: Path, *, args: Sequence[str], timeout_seconds: Optional[int], validation: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        timeout = int(timeout_seconds or self.config.timeout_seconds)
        run_id = time.strftime("%Y%m%d_%H%M%S") + "_" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]
        run_dir = self.workspace / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        python_exe = self._select_python_executable()

        env = os.environ.copy()
        env.update({
            "PYTHONUNBUFFERED": "1",
            "PROMPTCHAT_PYTHON_ENGINE": "1",
            "PROMPTCHAT_WORKSPACE": str(self.workspace),
            "PROMPTCHAT_RUN_DIR": str(run_dir),
            "PROMPTCHAT_ARTIFACTS_DIR": str(self.workspace / "artifacts"),
            "PROMPTCHAT_PYTHON_TOOL_DIR": str(self.python_tool_dir),
            "PROMPTCHAT_PYTHON_TOOL_VENV": str(self.python_tool_venv_dir),
        })
        env.update({str(k): str(v) for k, v in self.config.extra_env.items()})

        cmd = [python_exe, str(script), *[str(a) for a in args]]

        preexec_fn = None
        if resource is not None and self.config.memory_limit_mb > 0 and os.name != "nt":
            mem_bytes = int(self.config.memory_limit_mb) * 1024 * 1024
            max_file_bytes = int(self.config.max_artifact_bytes) * 4

            def _limit_resources() -> None:
                try:
                    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                except Exception:
                    pass
                try:
                    resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_bytes, max_file_bytes))
                except Exception:
                    pass

            preexec_fn = _limit_resources

        proc: Optional[subprocess.Popen[str]] = None
        timed_out = False
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(self.workspace),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                preexec_fn=preexec_fn,
            )
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._terminate_process_tree(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except Exception:
                    stdout, stderr = "", "process timed out and output could not be collected"

            elapsed_ms = int((time.time() - started) * 1000)
            artifacts = self.collect_artifacts(since=started).get("artifacts", [])
            process_ok = (proc.returncode == 0 and not timed_out)
            return _ok(
                action="run_file",
                run_id=run_id,
                run_dir=str(run_dir),
                process_ok=process_ok,
                returncode=int(proc.returncode if proc.returncode is not None else -999),
                elapsed_ms=elapsed_ms,
                stdout=_clip(stdout, self.config.max_stdout_chars),
                stderr=_clip(stderr, self.config.max_stderr_chars),
                command=cmd,
                python_executable=python_exe,
                using_python_tool_venv=bool(self.config.use_python_tool_venv and self._venv_exists()),
                cwd=str(self.workspace),
                timed_out=timed_out,
                validation=validation,
                artifacts=artifacts,
                error=("process timed out" if timed_out else ""),
                python_tool=self.python_tool_status().get("python_tool", {}),
            ) if process_ok else _err(
                "process failed" if not timed_out else "process timed out",
                action="run_file",
                run_id=run_id,
                run_dir=str(run_dir),
                process_ok=process_ok,
                returncode=int(proc.returncode if proc.returncode is not None else -999),
                elapsed_ms=elapsed_ms,
                stdout=_clip(stdout, self.config.max_stdout_chars),
                stderr=_clip(stderr, self.config.max_stderr_chars),
                command=cmd,
                python_executable=python_exe,
                using_python_tool_venv=bool(self.config.use_python_tool_venv and self._venv_exists()),
                cwd=str(self.workspace),
                timed_out=timed_out,
                validation=validation,
                artifacts=artifacts,
                python_tool=self.python_tool_status().get("python_tool", {}),
            )
        except Exception as exc:
            if proc is not None:
                self._terminate_process_tree(proc)
            return _err(str(exc), traceback=traceback.format_exc(), command=cmd, cwd=str(self.workspace))

    def _terminate_process_tree(self, proc: subprocess.Popen[Any]) -> None:
        try:
            if psutil is not None and proc.pid:
                parent = psutil.Process(proc.pid)
                children = parent.children(recursive=True)
                for child in children:
                    try:
                        child.terminate()
                    except Exception:
                        pass
                try:
                    parent.terminate()
                except Exception:
                    pass
                _, alive = psutil.wait_procs([parent, *children], timeout=2)
                for p in alive:
                    try:
                        p.kill()
                    except Exception:
                        pass
                return
        except Exception:
            pass
        try:
            proc.terminate()
            time.sleep(0.5)
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass

    def run_task(
        self,
        task: str,
        *,
        code: str = "",
        filename: str = "",
        args: Optional[Sequence[str]] = None,
        timeout_seconds: Optional[int] = None,
        validate: bool = True,
        extra_allowed_imports: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        task = str(task or "").strip()
        if code:
            safe_name = filename or self._task_to_filename(task)
            return self.run_code(code, filename=safe_name, args=args, timeout_seconds=timeout_seconds, validate=validate, extra_allowed_imports=extra_allowed_imports)
        if filename:
            return self.run_file(filename, args=args, timeout_seconds=timeout_seconds, validate=validate, extra_allowed_imports=extra_allowed_imports)

        template_name = self._task_to_filename(task)
        template = self._make_task_template(task)
        return self.write_file(template_name, template, overwrite=False)

    def _task_to_filename(self, task: str) -> str:
        return f"scripts/{_safe_generated_slug(task)}.py"

    def _make_task_template(self, task: str) -> str:
        return textwrap.dedent(f"""
            # Generated by PromptChat Python Engine
            # Task: {task}

            from __future__ import annotations

            import json
            from pathlib import Path

            WORKSPACE = Path.cwd()
            ARTIFACTS = WORKSPACE / "artifacts"
            ARTIFACTS.mkdir(parents=True, exist_ok=True)


            def main() -> dict:
                result = {{
                    "task": {json.dumps(task)},
                    "status": "template_created",
                    "message": "Replace this template with generated task code, then run again.",
                }}
                output_path = ARTIFACTS / "result.json"
                output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
                return result


            if __name__ == "__main__":
                print(json.dumps(main(), indent=2))
        """).lstrip()

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def collect_artifacts(self, *, since: Optional[float] = None, max_files: int = 80) -> Dict[str, Any]:
        try:
            roots = [self.workspace / "artifacts", self.workspace / "runs"]
            artifacts: List[Dict[str, Any]] = []
            for root in roots:
                if not root.exists():
                    continue
                for path in root.rglob("*"):
                    if not path.is_file():
                        continue
                    stat = path.stat()
                    if since is not None and stat.st_mtime < since:
                        continue
                    too_large = stat.st_size > self.config.max_artifact_bytes
                    sha = "" if too_large else _sha256_file(path)
                    rel = str(path.resolve().relative_to(self.workspace)).replace("\\", "/")
                    artifacts.append({
                        "relative_path": rel,
                        "path": str(path),
                        "bytes": stat.st_size,
                        "sha256": sha,
                        "mime": mimetypes.guess_type(str(path))[0],
                        "too_large": too_large,
                        "text": _is_text_file(path),
                        "mtime": stat.st_mtime,
                    })
                    if len(artifacts) >= max_files:
                        break
            artifacts.sort(key=lambda x: x.get("mtime", 0), reverse=True)
            return _ok(action="collect_artifacts", count=len(artifacts), artifacts=artifacts)
        except Exception as exc:
            return _err(str(exc), traceback=traceback.format_exc())

    def read_artifact(self, relative_path: str, *, max_chars: int = 12000, as_base64: bool = False) -> Dict[str, Any]:
        return self.read_file(relative_path, max_chars=max_chars, as_base64=as_base64)


_DEFAULT_ENGINE: Optional[PythonEngine] = None


def get_default_python_engine(config: Optional[PythonEngineConfig] = None) -> PythonEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None or config is not None:
        _DEFAULT_ENGINE = PythonEngine(config=config)
    return _DEFAULT_ENGINE


def python_engine(
    action: str = "",
    relative_path: str = "",
    content: str = "",
    code: str = "",
    task: str = "",
    filename: str = "",
    args: Optional[List[str]] = None,
    timeout_seconds: Optional[int] = None,
    validate: bool = True,
    recursive: bool = True,
    pattern: str = "*",
    max_files: int = 200,
    max_chars: int = 12000,
    as_base64: bool = False,
    overwrite: bool = True,
    extra_allowed_imports: Optional[List[str]] = None,
    requirements: str = "",
    append: bool = False,
    package: str = "",
    create_venv: bool = True,
    clear_venv: bool = False,
    upgrade: bool = False,
    upgrade_deps: bool = False,
    create_python_tool_venv: Any = False,
    create_file: Any = False,
    write_file: Any = False,
    read_file: Any = False,
    list_files: Any = False,
    delete_file: Any = False,
    validate_code: Any = False,
    run_code: Any = False,
    run_file: Any = False,
    run_task: Any = False,
    collect_artifacts: Any = False,
    read_artifact: Any = False,
    install_requirements: Any = False,
    install_package: Any = False,
    pip_install_package_flag: Any = False,
    python_tool_status: Any = False,
    config: Optional[PythonEngineConfig] = None,
    **extra_flags: Any,
) -> Dict[str, Any]:
    eng = get_default_python_engine(config)
    relative_path = _normalize_filename_alias(relative_path, filename)
    a = _infer_action_from_legacy_flags(
        action,
        create_python_tool_venv=create_python_tool_venv,
        create_file=create_file,
        write_file_flag=write_file,
        read_file_flag=read_file,
        list_files_flag=list_files,
        delete_file_flag=delete_file,
        validate_code_flag=validate_code,
        run_code_flag=run_code,
        run_file_flag=run_file,
        run_task_flag=run_task,
        collect_artifacts_flag=collect_artifacts,
        read_artifact_flag=read_artifact,
        install_requirements_flag=install_requirements,
        pip_install_requirements_flag=extra_flags.get("pip_install_requirements", False),
        install_package_flag=install_package,
        pip_install_package_flag=pip_install_package_flag or extra_flags.get("pip_install_package", False),
        python_tool_status_flag=python_tool_status,
        extra_flags=extra_flags,
    )

    if a == "status":
        return eng.status()

    if a in {"python_tool_status", "tool_env_status", "venv_status"}:
        return eng.python_tool_status()

    if a in {"create_python_tool_venv", "create_venv", "tool_env_create"}:
        created = eng.create_python_tool_venv(clear=clear_venv, upgrade_deps=upgrade_deps, timeout_seconds=timeout_seconds)
        if not created.get("ok"):
            return created
        if requirements or content:
            wrote = eng.write_requirements(_normalize_requirements_text(requirements or content), append=append)
            if not wrote.get("ok"):
                return wrote
            installed = eng.pip_install_requirements(create_venv=False, upgrade=upgrade, timeout_seconds=timeout_seconds)
            created["requirements_write"] = wrote
            created["requirements_install"] = installed
        return created

    if a in {"write_requirements", "write_python_tool_requirements"}:
        return eng.write_requirements(_normalize_requirements_text(requirements or content), append=append)

    if a in {"pip_install_requirements", "install_requirements"}:
        return eng.pip_install_requirements(
            requirements_path=relative_path or filename,
            create_venv=create_venv,
            upgrade=upgrade,
            timeout_seconds=timeout_seconds,
        )

    if a in {"pip_install_package", "install_package"}:
        return eng.pip_install_package(
            package=package or content,
            create_venv=create_venv,
            upgrade=upgrade,
            timeout_seconds=timeout_seconds,
        )

    resolved_path = _default_relative_path_for_action(
        a,
        relative_path=relative_path,
        filename=filename,
        task=task,
        content=content,
        code=code,
    )

    if a == "write_file":
        return eng.write_file(resolved_path, content or code, overwrite=overwrite)

    if a == "read_file":
        if resolved_path == ".":
            listing = eng.list_files(".", pattern=pattern, recursive=recursive, max_files=max_files)
            listing["hint"] = "read_file needs a workspace-relative file path. Returned workspace listing because no path was supplied."
            return listing
        return eng.read_file(resolved_path, max_chars=max_chars, as_base64=as_base64)

    if a == "list_files":
        return eng.list_files(resolved_path or ".", pattern=pattern, recursive=recursive, max_files=max_files)

    if a == "delete_file":
        if not resolved_path:
            return _err("delete_file requires a workspace-relative file path.")
        return eng.delete_file(resolved_path)

    if a == "validate_code":
        return eng.validate_code(
            code or content,
            filename=filename or relative_path or resolved_path or "<generated>",
            extra_allowed_imports=extra_allowed_imports,
        )

    if a == "run_code":
        return eng.run_code(
            code or content,
            filename=resolved_path or "scripts/generated_task.py",
            args=args,
            timeout_seconds=timeout_seconds,
            validate=validate,
            extra_allowed_imports=extra_allowed_imports,
        )

    if a == "run_file":
        if not (relative_path or filename) and (code or content):
            return eng.run_code(
                code or content,
                filename=resolved_path or "scripts/generated_task.py",
                args=args,
                timeout_seconds=timeout_seconds,
                validate=validate,
                extra_allowed_imports=extra_allowed_imports,
            )

        if not (relative_path or filename):
            listing = eng.list_files("scripts", pattern="*.py", recursive=True, max_files=max_files)
            listing["hint"] = "run_file needs an existing workspace-relative .py path. Returned scripts listing because no path was supplied."
            return listing

        return eng.run_file(
            resolved_path,
            args=args,
            timeout_seconds=timeout_seconds,
            validate=validate,
            extra_allowed_imports=extra_allowed_imports,
        )

    if a == "run_task":
        return eng.run_task(
            task=task,
            code=code or content,
            filename=filename or relative_path or "",
            args=args,
            timeout_seconds=timeout_seconds,
            validate=validate,
            extra_allowed_imports=extra_allowed_imports,
        )

    if a == "collect_artifacts":
        return eng.collect_artifacts(max_files=max_files)

    if a == "read_artifact":
        if resolved_path == "artifacts":
            listing = eng.list_files("artifacts", pattern=pattern, recursive=recursive, max_files=max_files)
            listing["hint"] = "read_artifact needs a workspace-relative artifact path. Returned artifacts listing because no path was supplied."
            return listing
        return eng.read_artifact(resolved_path, max_chars=max_chars, as_base64=as_base64)

    return _err("unknown action", action=action, available_actions=[
        "status",
        "python_tool_status",
        "create_python_tool_venv",
        "write_requirements",
        "pip_install_requirements",
        "pip_install_package",
        "write_file",
        "read_file",
        "list_files",
        "delete_file",
        "validate_code",
        "run_code",
        "run_file",
        "run_task",
        "collect_artifacts",
        "read_artifact",
    ])


def python_engine_tool_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "status",
                    "python_tool_status",
                    "create_python_tool_venv",
                    "write_requirements",
                    "pip_install_requirements",
                    "pip_install_package",
                    "write_file",
                    "read_file",
                    "list_files",
                    "delete_file",
                    "validate_code",
                    "run_code",
                    "run_file",
                    "run_task",
                    "collect_artifacts",
                    "read_artifact",
                ],
                "default": "status", "description": "Python engine operation. Defaults to status when omitted or blank.",
            },
            "relative_path": {"type": "string", "default": "", "description": "Workspace-relative path. Blank is allowed for run_code/run_task/list_files and will use a safe default."},
            "content": {"type": "string", "default": ""},
            "code": {"type": "string", "default": ""},
            "task": {"type": "string", "default": ""},
            "filename": {"type": "string", "default": "", "description": "Optional workspace-relative Python filename, such as scripts/task.py."},
            "args": {"type": "array", "items": {"type": "string"}, "default": []},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": DEFAULT_TIMEOUT_SECONDS},
            "validate": {"type": "boolean", "default": True},
            "recursive": {"type": "boolean", "default": True},
            "pattern": {"type": "string", "default": "*"},
            "max_files": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 200},
            "max_chars": {"type": "integer", "minimum": 1, "maximum": 200000, "default": 12000},
            "as_base64": {"type": "boolean", "default": False},
            "overwrite": {"type": "boolean", "default": True},
            "extra_allowed_imports": {"type": "array", "items": {"type": "string"}, "default": []},
            "requirements": {"type": "string", "default": "", "description": "Requirements text written to python_tool/requirements.txt."},
            "append": {"type": "boolean", "default": False},
            "package": {"type": "string", "default": "", "description": "Single package spec for pip_install_package."},
            "create_venv": {"type": "boolean", "default": True},
            "clear_venv": {"type": "boolean", "default": False},
            "upgrade": {"type": "boolean", "default": False},
            "upgrade_deps": {"type": "boolean", "default": False},
            "python_tool_status": {"type": "boolean", "default": False},
            "create_python_tool_venv": {"type": "boolean", "default": False},
            "create_file": {"type": "boolean", "default": False},
            "write_file": {"type": "boolean", "default": False},
            "read_file": {"type": "boolean", "default": False},
            "list_files": {"type": "boolean", "default": False},
            "delete_file": {"type": "boolean", "default": False},
            "validate_code": {"type": "boolean", "default": False},
            "run_code": {"type": "boolean", "default": False},
            "run_file": {"type": "boolean", "default": False},
            "run_task": {"type": "boolean", "default": False},
            "collect_artifacts": {"type": "boolean", "default": False},
            "read_artifact": {"type": "boolean", "default": False},
            "install_requirements": {"type": "boolean", "default": False},
            "install_package": {"type": "boolean", "default": False},
            "pip_install_package_flag": {"type": "boolean", "default": False},
        },
        "required": [],
        "additionalProperties": True,
    }


def make_python_engine_tool_function(config: Optional[PythonEngineConfig] = None) -> Callable[..., Dict[str, Any]]:
    engine = PythonEngine(config=config)

    def _tool(
        action: str = "",
        relative_path: str = "",
        content: str = "",
        code: str = "",
        task: str = "",
        filename: str = "",
        args: Optional[List[str]] = None,
        timeout_seconds: Optional[int] = None,
        validate: bool = True,
        recursive: bool = True,
        pattern: str = "*",
        max_files: int = 200,
        max_chars: int = 12000,
        as_base64: bool = False,
        overwrite: bool = True,
        extra_allowed_imports: Optional[List[str]] = None,
        requirements: str = "",
        append: bool = False,
        package: str = "",
        create_venv: bool = True,
        clear_venv: bool = False,
        upgrade: bool = False,
        upgrade_deps: bool = False,
        create_python_tool_venv: Any = False,
        create_file: Any = False,
        write_file: Any = False,
        read_file: Any = False,
        list_files: Any = False,
        delete_file: Any = False,
        validate_code: Any = False,
        run_code: Any = False,
        run_file: Any = False,
        run_task: Any = False,
        collect_artifacts: Any = False,
        read_artifact: Any = False,
        install_requirements: Any = False,
        install_package: Any = False,
        pip_install_package_flag: Any = False,
        python_tool_status: Any = False,
        **extra_flags: Any,
    ) -> Dict[str, Any]:
        return python_engine(
            action=action,
            relative_path=relative_path,
            content=content,
            code=code,
            task=task,
            filename=filename,
            args=args,
            timeout_seconds=timeout_seconds,
            validate=validate,
            recursive=recursive,
            pattern=pattern,
            max_files=max_files,
            max_chars=max_chars,
            as_base64=as_base64,
            overwrite=overwrite,
            extra_allowed_imports=extra_allowed_imports,
            requirements=requirements,
            append=append,
            package=package,
            create_venv=create_venv,
            clear_venv=clear_venv,
            upgrade=upgrade,
            upgrade_deps=upgrade_deps,
            create_python_tool_venv=create_python_tool_venv,
            create_file=create_file,
            write_file=write_file,
            read_file=read_file,
            list_files=list_files,
            delete_file=delete_file,
            validate_code=validate_code,
            run_code=run_code,
            run_file=run_file,
            run_task=run_task,
            collect_artifacts=collect_artifacts,
            read_artifact=read_artifact,
            install_requirements=install_requirements,
            install_package=install_package,
            pip_install_package_flag=pip_install_package_flag,
            python_tool_status=python_tool_status,
            config=engine.config,
            **extra_flags,
        )

    return _tool


def register_python_engine_tool(registry: Any, ToolSpec: Any, config: Optional[PythonEngineConfig] = None) -> bool:
    if registry is None or ToolSpec is None:
        return False

    registry.register(
        ToolSpec(
            name="python_engine",
            description=(
                "Controlled Python coding engine with unrestricted generated-script imports. Creates files, syntax-checks generated Python, "
                "runs scripts in a workspace subprocess, captures stdout/stderr/artifacts, allows normal Python imports, "
                "creates/uses python_tool/.venv, installs python_tool/requirements.txt, "
                "and returns structured JSON."
            ),
            parameters=python_engine_tool_schema(),
            fn=make_python_engine_tool_function(config=config),
        )
    )
    return True


if __name__ == "__main__":
    eng = PythonEngine()
    print(json.dumps(eng.status(), indent=2))
    demo_code = """
import json
import math
from pathlib import Path

artifacts = Path.cwd() / "artifacts"
artifacts.mkdir(exist_ok=True)
result = {"sqrt_2": math.sqrt(2)}
(artifacts / "demo_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result))
"""
    print(json.dumps(eng.run_code(demo_code, filename="scripts/demo.py"), indent=2))
