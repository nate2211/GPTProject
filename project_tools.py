from __future__ import annotations

import ast
import configparser
import difflib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    import tomllib
except Exception:  # pragma: no cover - Python < 3.11 fallback only
    tomllib = None


TEXT_SUFFIXES = {
    ".py", ".pyi", ".txt", ".md", ".rst", ".json", ".toml", ".yaml", ".yml",
    ".ini", ".cfg", ".conf", ".html", ".css", ".js", ".ts", ".tsx", ".jsx",
    ".sql", ".sh", ".bat", ".ps1", ".xml", ".csv", ".log", ".env.example",
}

SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development", ".envrc",
    "id_rsa", "id_ed25519", "known_hosts", "authorized_keys",
}

UNRESTRICTED_TOKENS = {"*", "any", "all"}
SHELL_TOKENS = {"shell", "shell=true", "cmd", "powershell", "pwsh"}


@dataclass
class ProjectToolConfig:
    root: Path
    run_enabled: bool = True
    write_enabled: bool = False
    command_timeout_sec: int = 30
    max_output_chars: int = 14000
    max_file_chars: int = 160000
    max_scan_files: int = 3000

    allowed_commands: Sequence[str] = (
        "python", "py", "pytest", "ruff", "mypy", "pyright", "pip",
    )

    unrestricted_commands: bool = False
    shell_enabled: bool = False
    delete_enabled: bool = False
    sensitive_file_access_enabled: bool = False
    outside_root_enabled: bool = False

    ignore_dirs: Iterable[str] = (
        ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox",
        ".venv", "venv", "env", "node_modules", "dist", "build", "site-packages",
    )


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _split_command_text(command: str) -> List[str]:
    text = str(command or "").strip()
    if not text:
        return []
    return shlex.split(text, posix=(os.name != "nt"))


class LocalPythonProjectTools:
    """
    Safe local Python project scanner/runner for GPTProject.

    The model can use this workflow:
      1. project_status()
      2. learn_project_for_execution()
      3. infer_project_run_commands()
      4. run_inferred_project(...) or run_project_command(...)

    It does not actually activate a shell. Instead, it discovers the project's .venv
    and runs commands with that interpreter plus VIRTUAL_ENV/PATH set correctly.
    """

    def __init__(self, config: ProjectToolConfig):
        self.config = config
        self.root = Path(config.root).expanduser().resolve()
        self.ignore_dirs = {str(x).lower() for x in config.ignore_dirs}
        self.allowed_commands = {
            str(x).lower().strip()
            for x in config.allowed_commands
            if str(x).strip()
        }

        if self.allowed_commands & UNRESTRICTED_TOKENS:
            self.config.unrestricted_commands = True

        if self.allowed_commands & SHELL_TOKENS:
            self.config.shell_enabled = True

    @classmethod
    def from_app_config(cls, app_config: Any) -> Optional["LocalPythonProjectTools"]:
        root = getattr(app_config, "resolved_project_dir", None)
        if root is None:
            root = getattr(app_config, "local_project_dir", None)

        if root is None or not str(root).strip():
            return None

        root_path = Path(root).expanduser().resolve()
        if not root_path.exists() or not root_path.is_dir():
            return None

        allowed = tuple(getattr(app_config, "project_command_names", None) or [])
        if not allowed:
            raw_allowlist = getattr(
                app_config,
                "project_command_allowlist",
                "python,py,pytest,ruff,mypy,pyright,pip",
            )
            allowed = tuple(
                x.strip().lower()
                for x in str(raw_allowlist).split(",")
                if x.strip()
            )

        allowed_lower = {str(x).lower().strip() for x in allowed if str(x).strip()}
        unrestricted = _as_bool(getattr(app_config, "project_unrestricted_commands_enabled", False))
        shell_enabled = _as_bool(getattr(app_config, "project_shell_enabled", False))

        if allowed_lower & UNRESTRICTED_TOKENS:
            unrestricted = True
        if allowed_lower & SHELL_TOKENS:
            shell_enabled = True

        ignore_dirs = getattr(app_config, "project_ignore_dir_names", None)
        if ignore_dirs is None:
            base_ignore = set(ProjectToolConfig(root_path).ignore_dirs)
            extra = {
                x.strip()
                for x in str(getattr(app_config, "project_extra_ignore_dirs", "") or "").split(",")
                if x.strip()
            }
            ignore_dirs = base_ignore | extra

        return cls(
            ProjectToolConfig(
                root=root_path,
                run_enabled=_as_bool(getattr(app_config, "project_run_enabled", True), True),
                write_enabled=_as_bool(getattr(app_config, "project_write_enabled", False), False),
                command_timeout_sec=_as_int(getattr(app_config, "project_command_timeout_sec", 30), 30),
                max_output_chars=_as_int(getattr(app_config, "project_max_output_chars", 14000), 14000),
                max_file_chars=_as_int(getattr(app_config, "project_max_file_chars", 160000), 160000),
                max_scan_files=_as_int(getattr(app_config, "project_max_scan_files", 3000), 3000),
                allowed_commands=allowed,
                unrestricted_commands=unrestricted,
                shell_enabled=shell_enabled,
                delete_enabled=_as_bool(getattr(app_config, "project_delete_enabled", False), False),
                sensitive_file_access_enabled=_as_bool(
                    getattr(app_config, "project_sensitive_file_access_enabled", False), False
                ),
                outside_root_enabled=_as_bool(getattr(app_config, "project_outside_root_enabled", False), False),
                ignore_dirs=ignore_dirs,
            )
        )

    def _ok(self, **kw: Any) -> Dict[str, Any]:
        return {"ok": True, "project_root": str(self.root), **kw}

    def _fail(self, error: str, **kw: Any) -> Dict[str, Any]:
        return {"ok": False, "project_root": str(self.root), "error": str(error), **kw}

    def _truncate(self, text: Any, max_chars: Optional[int] = None) -> str:
        s = str(text or "")
        limit = int(max_chars or self.config.max_output_chars)
        if len(s) <= limit:
            return s
        return s[:limit] + f"\n\n[TRUNCATED to {limit} chars]"

    def _relpath(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except Exception:
            return path.as_posix()

    def _resolve(self, rel_path: str = ".") -> Path:
        raw = str(rel_path or ".").replace("\\", "/").strip()
        if not raw:
            raw = "."

        if re.match(r"^[a-zA-Z]:", raw) or raw.startswith("/"):
            candidate = Path(raw).expanduser().resolve()
        else:
            candidate = (self.root / raw).resolve()

        if not self.config.outside_root_enabled:
            try:
                candidate.relative_to(self.root)
            except Exception as exc:
                raise ValueError(f"path escapes project root: {rel_path}") from exc

        return candidate

    def _is_sensitive(self, path: Path) -> bool:
        if self.config.sensitive_file_access_enabled:
            return False
        lower_name = path.name.lower()
        lower_parts = {p.lower() for p in path.parts}
        return (
            lower_name in SENSITIVE_NAMES
            or bool(lower_parts & SENSITIVE_NAMES)
            or lower_name.endswith((".pem", ".key", ".pfx", ".p12", ".crt", ".cer"))
        )

    def _is_ignored_dir(self, path: Path) -> bool:
        return any(part.lower() in self.ignore_dirs for part in path.parts)

    def _is_text_file(self, path: Path) -> bool:
        if self._is_sensitive(path):
            return False
        lower_name = path.name.lower()
        return path.suffix.lower() in TEXT_SUFFIXES or lower_name.endswith(".env.example")

    def _read_text(self, path: Path, max_chars: Optional[int] = None) -> str:
        limit = int(max_chars or self.config.max_file_chars)
        data = path.read_bytes()
        if len(data) > limit * 4:
            data = data[: limit * 4]
        text = data.decode("utf-8", errors="replace")
        if len(text) > limit:
            text = text[:limit] + "\n\n[TRUNCATED]"
        return text

    def _iter_files(self, suffix: str = "", include_hidden: bool = False) -> Iterable[Path]:
        count = 0
        suffix = str(suffix or "").lower().strip()

        for dirpath, dirnames, filenames in os.walk(self.root):
            dir_path = Path(dirpath)
            dirnames[:] = [
                d
                for d in dirnames
                if d.lower() not in self.ignore_dirs and (include_hidden or not d.startswith("."))
            ]

            if self._is_ignored_dir(dir_path):
                continue

            for filename in filenames:
                if count >= self.config.max_scan_files:
                    return
                if not include_hidden and filename.startswith("."):
                    continue

                path = dir_path / filename
                if self._is_ignored_dir(path) or self._is_sensitive(path):
                    continue
                if suffix and path.suffix.lower() != suffix:
                    continue

                count += 1
                yield path

    def _find_venv_dir(self) -> Optional[Path]:
        candidates = [self.root / ".venv", self.root / "venv", self.root / "env", self.root / "virtualenv"]
        for candidate in candidates:
            if candidate.is_dir() and (candidate / "pyvenv.cfg").exists():
                return candidate.resolve()

        for child in self.root.iterdir() if self.root.exists() else []:
            try:
                if child.is_dir() and child.name.lower() not in self.ignore_dirs and (child / "pyvenv.cfg").exists():
                    return child.resolve()
            except Exception:
                continue
        return None

    def _venv_python(self) -> Optional[Path]:
        venv = self._find_venv_dir()
        if not venv:
            return None
        candidates = [
            venv / "Scripts" / "python.exe",
            venv / "Scripts" / "python",
            venv / "bin" / "python",
            venv / "bin" / "python3",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate.resolve()
        return None

    def _project_python(self) -> str:
        venv_py = self._venv_python()
        if venv_py:
            return str(venv_py)
        return sys.executable or shutil.which("python") or "python"

    def _venv_info(self) -> Dict[str, Any]:
        venv_dir = self._find_venv_dir()
        py = self._venv_python()
        return {
            "found": bool(venv_dir and py),
            "venv_dir": str(venv_dir) if venv_dir else "",
            "python": str(py) if py else "",
            "activation_hint_windows": str(venv_dir / "Scripts" / "activate") if venv_dir else "",
            "activation_hint_posix": f"source {venv_dir / 'bin' / 'activate'}" if venv_dir else "",
        }

    def _env_for_subprocess(self) -> Dict[str, str]:
        env = os.environ.copy()
        venv = self._find_venv_dir()
        if venv:
            env["VIRTUAL_ENV"] = str(venv)
            script_dir = venv / ("Scripts" if os.name == "nt" else "bin")
            env["PATH"] = str(script_dir) + os.pathsep + env.get("PATH", "")
        env.setdefault("PYTHONUTF8", "1")
        return env

    def _command_name(self, args: List[str]) -> str:
        if not args:
            return ""
        exe = Path(str(args[0]).strip('"')).name.lower()
        if exe.endswith(".exe"):
            exe = exe[:-4]
        return exe

    def _command_allowed(self, args: List[str]) -> bool:
        if self.config.unrestricted_commands:
            return True
        return self._command_name(args) in self.allowed_commands

    def _normalize_command(self, command: Any, use_project_python: bool = True) -> List[str]:
        if isinstance(command, str):
            args = _split_command_text(command)
        elif isinstance(command, (list, tuple)):
            args = [str(x) for x in command if str(x) != ""]
        else:
            raise ValueError("command must be a list of strings or a command string")

        if not args:
            raise ValueError("command is empty")

        first_name = self._command_name(args)
        if use_project_python and first_name in {"python", "python3", "py"}:
            if first_name == "py" and len(args) > 1 and re.fullmatch(r"-?3(?:\.\d+)?", args[1]):
                args = [self._project_python(), *args[2:]]
            else:
                args = [self._project_python(), *args[1:]]
        elif use_project_python and first_name == "pip":
            args = [self._project_python(), "-m", "pip", *args[1:]]

        return args

    def _display_command(self, args: List[str]) -> str:
        if os.name == "nt":
            return subprocess.list2cmdline(args)
        return " ".join(shlex.quote(x) for x in args)

    def _safe_cwd(self, cwd: str = ".") -> Path:
        path = self._resolve(cwd or ".")
        if not path.exists():
            raise ValueError(f"cwd does not exist: {cwd}")
        if not path.is_dir():
            raise ValueError(f"cwd is not a directory: {cwd}")
        return path

    def _run_args(
        self,
        args: List[str],
        *,
        cwd: str = ".",
        timeout_sec: Optional[int] = None,
        stdin_text: str = "",
    ) -> Dict[str, Any]:
        if not self.config.run_enabled:
            return self._fail("project command execution is disabled")

        if not args:
            return self._fail("command is empty")

        if self._command_name(args) in SHELL_TOKENS and not self.config.shell_enabled:
            return self._fail("shell commands are disabled; pass argv lists instead")

        if not self._command_allowed(args):
            return self._fail(
                "command_not_allowlisted",
                command=args,
                command_name=self._command_name(args),
                allowed_commands=sorted(self.allowed_commands),
                hint="Add the command name to GPTPROJECT_PROJECT_COMMAND_ALLOWLIST or the GUI allowlist.",
            )

        try:
            cwd_path = self._safe_cwd(cwd)
        except Exception as exc:
            return self._fail(str(exc), cwd=cwd)

        timeout = int(timeout_sec or self.config.command_timeout_sec)
        started = time.time()

        try:
            proc = subprocess.run(
                args,
                cwd=str(cwd_path),
                env=self._env_for_subprocess(),
                input=stdin_text if stdin_text else None,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                shell=False,
            )
            elapsed = time.time() - started
            return self._ok(
                returncode=int(proc.returncode),
                success=proc.returncode == 0,
                timed_out=False,
                duration_sec=round(elapsed, 3),
                cwd=self._relpath(cwd_path),
                command=args,
                command_display=self._display_command(args),
                venv=self._venv_info(),
                stdout=self._truncate(proc.stdout),
                stderr=self._truncate(proc.stderr),
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.time() - started
            return self._fail(
                "command_timeout",
                timed_out=True,
                duration_sec=round(elapsed, 3),
                timeout_sec=timeout,
                cwd=self._relpath(cwd_path),
                command=args,
                command_display=self._display_command(args),
                stdout=self._truncate(getattr(exc, "stdout", "") or ""),
                stderr=self._truncate(getattr(exc, "stderr", "") or ""),
            )
        except FileNotFoundError as exc:
            return self._fail(
                "command_not_found",
                command=args,
                command_display=self._display_command(args),
                error_detail=str(exc),
            )
        except Exception as exc:
            return self._fail(
                "command_failed_to_start",
                command=args,
                command_display=self._display_command(args),
                error_detail=str(exc),
            )

    def project_status(self) -> Dict[str, Any]:
        markers: Dict[str, bool] = {}
        for name in (
            "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements-dev.txt",
            "pytest.ini", "tox.ini", "noxfile.py", "main.py", "app.py", "manage.py",
            "server.py", "cli.py", "bot.py", "Pipfile", "poetry.lock", "uv.lock",
        ):
            markers[name] = (self.root / name).exists()

        return self._ok(
            exists=self.root.exists(),
            is_dir=self.root.is_dir(),
            run_enabled=self.config.run_enabled,
            write_enabled=self.config.write_enabled,
            unrestricted_commands=self.config.unrestricted_commands,
            shell_enabled=self.config.shell_enabled,
            delete_enabled=self.config.delete_enabled,
            outside_root_enabled=self.config.outside_root_enabled,
            sensitive_file_access_enabled=self.config.sensitive_file_access_enabled,
            allowed_commands=sorted(self.allowed_commands),
            ignored_dirs=sorted(self.ignore_dirs),
            venv=self._venv_info(),
            markers=markers,
        )

    def project_tree(
        self,
        max_files: int = 350,
        suffix: str = "",
        include_hidden: bool = False,
    ) -> Dict[str, Any]:
        files: List[Dict[str, Any]] = []
        for path in self._iter_files(suffix=suffix, include_hidden=include_hidden):
            try:
                st = path.stat()
                files.append(
                    {
                        "path": self._relpath(path),
                        "bytes": int(st.st_size),
                        "suffix": path.suffix.lower(),
                        "modified": int(st.st_mtime),
                    }
                )
            except Exception:
                continue
            if len(files) >= int(max_files):
                break
        return self._ok(count=len(files), files=files)

    def read_project_file(self, path: str, max_chars: Optional[int] = None) -> Dict[str, Any]:
        try:
            target = self._resolve(path)
            if not target.exists():
                return self._fail("file_not_found", path=path)
            if not target.is_file():
                return self._fail("not_a_file", path=path)
            if not self._is_text_file(target):
                return self._fail("unsupported_or_sensitive_file_type", path=path)
            content = self._read_text(target, max_chars=max_chars)
            return self._ok(path=self._relpath(target), chars=len(content), content=content)
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def search_project(
        self,
        query: str,
        max_results: int = 25,
        context_chars: int = 700,
        suffix: str = "",
    ) -> Dict[str, Any]:
        query = str(query or "").strip()
        if not query:
            return self._fail("query_required")

        literal = query.lower()
        terms = [t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", query)]
        results: List[Dict[str, Any]] = []

        for path in self._iter_files(suffix=suffix):
            if not self._is_text_file(path):
                continue
            try:
                text = self._read_text(path)
            except Exception:
                continue

            low = text.lower()
            path_low = self._relpath(path).lower()
            score = 0
            idx = low.find(literal)
            if idx >= 0:
                score += 12
            else:
                hits = [term for term in terms if term in low or term in path_low]
                if not hits:
                    continue
                score += len(hits)
                positions = [low.find(term) for term in hits if low.find(term) >= 0]
                idx = min(positions) if positions else 0

            for term in terms:
                if term in path_low:
                    score += 3

            start = max(0, idx - int(context_chars))
            end = min(len(text), idx + int(context_chars))
            results.append(
                {
                    "path": self._relpath(path),
                    "score": int(score),
                    "line": text[:idx].count("\n") + 1 if idx >= 0 else None,
                    "excerpt": text[start:end],
                }
            )

        results.sort(key=lambda row: (-row["score"], row["path"]))
        final = results[: int(max_results)]
        return self._ok(query=query, count=len(final), results=final)

    def summarize_project(self, max_files: int = 1000) -> Dict[str, Any]:
        files = list(self._iter_files())[: int(max_files)]
        by_suffix: Dict[str, int] = {}
        packages: List[str] = []
        classes: List[Dict[str, Any]] = []
        functions: List[Dict[str, Any]] = []
        imports: Dict[str, int] = {}
        entrypoints: List[Dict[str, Any]] = []

        for path in files:
            suffix = path.suffix.lower() or "<none>"
            by_suffix[suffix] = by_suffix.get(suffix, 0) + 1
            if path.name == "__init__.py":
                packages.append(self._relpath(path.parent))
            if path.suffix.lower() != ".py":
                continue

            try:
                text = self._read_text(path, max_chars=200000)
                tree = ast.parse(text)
            except Exception:
                continue

            if re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", text):
                entrypoints.append({"path": self._relpath(path), "type": "python_main_guard"})

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(
                        {
                            "name": node.name,
                            "path": self._relpath(path),
                            "line": int(getattr(node, "lineno", 0)),
                            "async": isinstance(node, ast.AsyncFunctionDef),
                        }
                    )
                elif isinstance(node, ast.ClassDef):
                    classes.append(
                        {"name": node.name, "path": self._relpath(path), "line": int(getattr(node, "lineno", 0))}
                    )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".", 1)[0]
                        imports[root] = imports.get(root, 0) + 1
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".", 1)[0]
                    imports[root] = imports.get(root, 0) + 1

        top_imports = [
            {"name": name, "count": count}
            for name, count in sorted(imports.items(), key=lambda kv: (-kv[1], kv[0]))[:80]
        ]
        return self._ok(
            file_count=len(files),
            by_suffix=dict(sorted(by_suffix.items())),
            packages=packages[:120],
            classes=classes[:180],
            functions=functions[:220],
            imports=top_imports,
            entrypoints=entrypoints[:120],
        )

    def _module_name_from_path(self, path: Path) -> str:
        rel = path.resolve().relative_to(self.root)
        if rel.name == "__main__.py":
            rel = rel.parent
        elif rel.suffix == ".py":
            rel = rel.with_suffix("")
        parts = list(rel.parts)
        if parts and parts[0] == "src" and len(parts) > 1:
            parts = parts[1:]
        return ".".join(p for p in parts if p and p != "__init__")

    def _candidate(
        self,
        *,
        kind: str,
        title: str,
        command: List[str],
        reason: str,
        confidence: float = 0.5,
        cwd: str = ".",
        long_running: bool = False,
        source: str = "",
    ) -> Dict[str, Any]:
        return {
            "kind": kind,
            "title": title,
            "command": [str(x) for x in command],
            "cwd": cwd,
            "reason": reason,
            "confidence": round(float(confidence), 3),
            "long_running": bool(long_running),
            "source": source,
        }

    def _dedupe_candidates(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set[tuple[str, ...]] = set()
        out: List[Dict[str, Any]] = []
        for item in candidates:
            key = tuple(item.get("command") or [])
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(item)
        out.sort(key=lambda x: (-float(x.get("confidence", 0.0)), bool(x.get("long_running", False)), x.get("title", "")))
        for idx, item in enumerate(out):
            item["index"] = idx
        return out

    def _load_pyproject(self) -> Dict[str, Any]:
        path = self.root / "pyproject.toml"
        if not path.exists() or tomllib is None:
            return {}
        try:
            return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return {}

    def _load_setup_cfg(self) -> configparser.ConfigParser:
        parser = configparser.ConfigParser()
        path = self.root / "setup.cfg"
        if path.exists():
            try:
                parser.read(path, encoding="utf-8")
            except Exception:
                pass
        return parser

    def _detect_argparse_flags(self, text: str) -> List[Dict[str, Any]]:
        flags: List[Dict[str, Any]] = []
        for match in re.finditer(r"add_argument\((.*?)\)", text, flags=re.S):
            call_text = match.group(1)
            option_names = re.findall(r"['\"](--?[A-Za-z0-9_][A-Za-z0-9_\-]*)['\"]", call_text)
            if not option_names:
                continue
            flags.append(
                {
                    "names": option_names,
                    "action_store_true": "store_true" in call_text,
                    "required_hint": "required=True" in call_text,
                    "snippet": re.sub(r"\s+", " ", call_text).strip()[:260],
                }
            )
        return flags[:80]

    def inspect_python_entrypoints(self, max_files: int = 1000) -> Dict[str, Any]:
        entrypoints: List[Dict[str, Any]] = []
        for path in list(self._iter_files(suffix=".py"))[: int(max_files)]:
            rel = self._relpath(path)
            try:
                text = self._read_text(path, max_chars=250000)
                tree = ast.parse(text)
            except Exception as exc:
                entrypoints.append({"path": rel, "type": "parse_error", "error": str(exc)})
                continue

            imports: set[str] = set()
            functions: List[str] = []
            classes: List[str] = []
            has_main_guard = bool(re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", text))
            argparse_flags = self._detect_argparse_flags(text)
            has_argparse = "argparse" in text and "add_argument" in text

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".", 1)[0])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".", 1)[0])
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(node.name)
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)

            framework = ""
            low = text.lower()
            if "fastapi" in imports or "fastapi(" in low:
                framework = "fastapi"
            elif "flask" in imports or "flask(" in low:
                framework = "flask"
            elif "streamlit" in imports:
                framework = "streamlit"
            elif "django" in imports or rel == "manage.py":
                framework = "django"
            elif {"pyqt5", "pyqt6", "pyside6", "pyside2"} & {x.lower() for x in imports}:
                framework = "qt_gui"

            important_name = path.name in {"main.py", "app.py", "server.py", "cli.py", "bot.py", "manage.py", "__main__.py"}
            if has_main_guard or has_argparse or framework or important_name:
                entrypoints.append(
                    {
                        "path": rel,
                        "module": self._module_name_from_path(path),
                        "type": "python_entrypoint",
                        "has_main_guard": has_main_guard,
                        "has_argparse": has_argparse,
                        "argparse_flags": argparse_flags,
                        "framework": framework,
                        "functions": functions[:40],
                        "classes": classes[:40],
                        "imports": sorted(imports)[:80],
                    }
                )
        return self._ok(count=len(entrypoints), entrypoints=entrypoints)

    def _extract_doc_commands(self, max_files: int = 8) -> List[Dict[str, Any]]:
        docs: List[Path] = []
        for name in ("README.md", "README.rst", "README.txt", "docs/README.md", "INSTALL.md", "USAGE.md"):
            p = self.root / name
            if p.exists() and p.is_file():
                docs.append(p)
        docs.extend([p for p in self._iter_files(suffix=".md") if p not in docs][:max(0, max_files - len(docs))])

        command_lines: List[Dict[str, Any]] = []
        cmd_re = re.compile(
            r"(?im)^\s*(?:[$>]\s*)?((?:python|py|pytest|ruff|mypy|pyright|pip|flask|uvicorn|streamlit)\b[^\n`]+)"
        )
        for path in docs[:max_files]:
            try:
                text = self._read_text(path, max_chars=60000)
            except Exception:
                continue
            for m in cmd_re.finditer(text):
                line = m.group(1).strip()
                if not line or any(bad in line.lower() for bad in [" rm ", " del ", "sudo "]):
                    continue
                command_lines.append({"path": self._relpath(path), "command_text": line[:500]})
        return command_lines[:50]

    def infer_project_run_commands(self, max_files: int = 1000) -> Dict[str, Any]:
        candidates: List[Dict[str, Any]] = []
        py = "python"

        pyproject = self._load_pyproject()
        project_scripts = (pyproject.get("project") or {}).get("scripts") or {}
        poetry_scripts = ((pyproject.get("tool") or {}).get("poetry") or {}).get("scripts") or {}
        for script_name, target in {**project_scripts, **poetry_scripts}.items():
            target_str = str(target)
            if ":" in target_str:
                module = target_str.split(":", 1)[0]
                candidates.append(
                    self._candidate(
                        kind="pyproject_script",
                        title=f"Run pyproject script module for {script_name}",
                        command=[py, "-m", module],
                        reason=f"pyproject script {script_name} points at {target_str}",
                        confidence=0.84,
                        source="pyproject.toml",
                    )
                )

        setup_cfg = self._load_setup_cfg()
        if setup_cfg.has_section("options.entry_points"):
            for key, value in setup_cfg.items("options.entry_points"):
                if key == "console_scripts":
                    for line in value.splitlines():
                        if "=" not in line or ":" not in line:
                            continue
                        name, target = [x.strip() for x in line.split("=", 1)]
                        module = target.split(":", 1)[0]
                        candidates.append(
                            self._candidate(
                                kind="setup_cfg_script",
                                title=f"Run console script module for {name}",
                                command=[py, "-m", module],
                                reason=f"setup.cfg console_scripts maps {name} to {target}",
                                confidence=0.76,
                                source="setup.cfg",
                            )
                        )

        if (self.root / "manage.py").exists():
            candidates.append(
                self._candidate(
                    kind="django_check",
                    title="Django system check",
                    command=[py, "manage.py", "check"],
                    reason="manage.py exists; this is a safe Django diagnostic.",
                    confidence=0.94,
                    source="manage.py",
                )
            )
            candidates.append(
                self._candidate(
                    kind="django_runserver",
                    title="Django development server",
                    command=[py, "manage.py", "runserver"],
                    reason="manage.py exists; runserver starts the Django app.",
                    confidence=0.88,
                    long_running=True,
                    source="manage.py",
                )
            )

        entry_data = self.inspect_python_entrypoints(max_files=max_files)
        for ep in entry_data.get("entrypoints", []):
            if ep.get("type") != "python_entrypoint":
                continue
            rel = str(ep.get("path") or "")
            module = str(ep.get("module") or "")
            framework = str(ep.get("framework") or "")
            flags = ep.get("argparse_flags") or []
            flag_names = {name for item in flags for name in item.get("names", [])}

            base_conf = 0.72
            if Path(rel).name in {"main.py", "app.py", "cli.py", "server.py", "bot.py"}:
                base_conf += 0.12
            if ep.get("has_main_guard"):
                base_conf += 0.08
            if ep.get("has_argparse"):
                base_conf += 0.03

            if rel:
                candidates.append(
                    self._candidate(
                        kind="python_file",
                        title=f"Run {rel}",
                        command=[py, rel],
                        reason="Python file looks like an entrypoint.",
                        confidence=min(base_conf, 0.95),
                        source=rel,
                    )
                )

            if "--gui" in flag_names and rel:
                candidates.append(
                    self._candidate(
                        kind="python_gui",
                        title=f"Run {rel} in GUI mode",
                        command=[py, rel, "--gui"],
                        reason="argparse declares a --gui flag.",
                        confidence=min(base_conf + 0.1, 0.98),
                        long_running=True,
                        source=rel,
                    )
                )

            if module and rel.endswith("__main__.py"):
                candidates.append(
                    self._candidate(
                        kind="python_module",
                        title=f"Run module {module}",
                        command=[py, "-m", module],
                        reason="Package contains __main__.py.",
                        confidence=0.9,
                        source=rel,
                    )
                )

            if framework == "fastapi" and rel:
                module_name = module or Path(rel).with_suffix("").as_posix().replace("/", ".")
                candidates.append(
                    self._candidate(
                        kind="fastapi_uvicorn",
                        title=f"Run FastAPI app from {rel}",
                        command=[py, "-m", "uvicorn", f"{module_name}:app", "--reload"],
                        reason="FastAPI import/app detected; uvicorn module runs inside the project venv.",
                        confidence=0.86,
                        long_running=True,
                        source=rel,
                    )
                )
            elif framework == "flask" and rel:
                module_name = module or Path(rel).with_suffix("").as_posix().replace("/", ".")
                candidates.append(
                    self._candidate(
                        kind="flask_run",
                        title=f"Run Flask app from {rel}",
                        command=[py, "-m", "flask", "--app", module_name, "run"],
                        reason="Flask import/app detected; flask module runs inside the project venv.",
                        confidence=0.82,
                        long_running=True,
                        source=rel,
                    )
                )
            elif framework == "streamlit" and rel:
                candidates.append(
                    self._candidate(
                        kind="streamlit_run",
                        title=f"Run Streamlit app {rel}",
                        command=[py, "-m", "streamlit", "run", rel],
                        reason="streamlit import detected.",
                        confidence=0.82,
                        long_running=True,
                        source=rel,
                    )
                )

        if (self.root / "pytest.ini").exists() or (self.root / "tests").exists() or any(self.root.glob("test_*.py")):
            candidates.append(
                self._candidate(
                    kind="tests",
                    title="Run pytest quietly",
                    command=[py, "-m", "pytest", "-q"],
                    reason="pytest config/tests detected.",
                    confidence=0.78,
                    source="pytest/tests",
                )
            )

        for doc_cmd in self._extract_doc_commands():
            args = _split_command_text(doc_cmd["command_text"])
            if not args:
                continue
            first = Path(args[0]).name.lower().removesuffix(".exe")
            if first in {"flask", "uvicorn", "streamlit", "pytest", "ruff", "mypy", "pyright", "pip"}:
                args = [py, "-m", *args]
            candidates.append(
                self._candidate(
                    kind="documented_command",
                    title=f"Documented command: {doc_cmd['command_text'][:70]}",
                    command=args,
                    reason=f"Found in {doc_cmd['path']}",
                    confidence=0.62,
                    source=doc_cmd["path"],
                    long_running=any(x in args for x in ["runserver", "uvicorn", "flask", "streamlit"]),
                )
            )

        if not candidates:
            candidates.append(
                self._candidate(
                    kind="compileall",
                    title="Compile all Python files",
                    command=[py, "-m", "compileall", "."],
                    reason="No obvious entrypoint found; compileall is a safe syntax/import bytecode check.",
                    confidence=0.4,
                    source="fallback",
                )
            )

        return self._ok(venv=self._venv_info(), candidates=self._dedupe_candidates(candidates))

    def learn_project_for_execution(self, max_files: int = 1000) -> Dict[str, Any]:
        return self._ok(
            status=self.project_status(),
            summary=self.summarize_project(max_files=max_files),
            entrypoints=self.inspect_python_entrypoints(max_files=max_files),
            documented_commands=self._extract_doc_commands(),
            inferred_commands=self.infer_project_run_commands(max_files=max_files),
            recommendation=(
                "Use run_inferred_project with a candidate index. Commands are executed with shell=False; "
                "python/pip are redirected into the detected project .venv when present."
            ),
        )

    def run_project_command(
        self,
        command: Any,
        cwd: str = ".",
        timeout_sec: Optional[int] = None,
        stdin_text: str = "",
        use_project_python: bool = True,
    ) -> Dict[str, Any]:
        try:
            args = self._normalize_command(command, use_project_python=use_project_python)
        except Exception as exc:
            return self._fail(str(exc), command=command)
        return self._run_args(args, cwd=cwd, timeout_sec=timeout_sec, stdin_text=stdin_text)

    def run_python_file(
        self,
        path: str,
        args: Optional[List[str]] = None,
        timeout_sec: Optional[int] = None,
        cwd: str = ".",
    ) -> Dict[str, Any]:
        try:
            target = self._resolve(path)
            if not target.exists() or not target.is_file():
                return self._fail("file_not_found", path=path)
            if target.suffix.lower() != ".py":
                return self._fail("not_a_python_file", path=path)
            rel = self._relpath(target)
            return self._run_args([self._project_python(), rel, *[str(x) for x in (args or [])]], cwd=cwd, timeout_sec=timeout_sec)
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def run_python_module(
        self,
        module: str,
        args: Optional[List[str]] = None,
        timeout_sec: Optional[int] = None,
        cwd: str = ".",
    ) -> Dict[str, Any]:
        module = str(module or "").strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", module):
            return self._fail("invalid_module_name", module=module)
        return self._run_args([self._project_python(), "-m", module, *[str(x) for x in (args or [])]], cwd=cwd, timeout_sec=timeout_sec)

    def run_inferred_project(
        self,
        candidate_index: int = 0,
        extra_args: Optional[List[str]] = None,
        timeout_sec: Optional[int] = None,
        max_files: int = 1000,
        prefer_long_running: bool = False,
    ) -> Dict[str, Any]:
        inferred = self.infer_project_run_commands(max_files=max_files)
        candidates = list(inferred.get("candidates") or [])
        if not candidates:
            return self._fail("no_inferred_commands", inferred=inferred)

        if prefer_long_running:
            long_candidates = [c for c in candidates if c.get("long_running")]
            if long_candidates and int(candidate_index) == 0:
                candidate = long_candidates[0]
            else:
                candidate = candidates[min(max(int(candidate_index), 0), len(candidates) - 1)]
        else:
            candidate = candidates[min(max(int(candidate_index), 0), len(candidates) - 1)]

        command = [str(x) for x in candidate.get("command") or []] + [str(x) for x in (extra_args or [])]
        result = self.run_project_command(
            command=command,
            cwd=str(candidate.get("cwd") or "."),
            timeout_sec=timeout_sec,
            use_project_python=True,
        )
        result["selected_candidate"] = candidate
        result["candidate_count"] = len(candidates)
        return result

    def scan_and_run_project(
        self,
        user_request: str = "",
        candidate_index: int = 0,
        extra_args: Optional[List[str]] = None,
        timeout_sec: Optional[int] = None,
        max_files: int = 1000,
        prefer_long_running: bool = False,
    ) -> Dict[str, Any]:
        learned = self.learn_project_for_execution(max_files=max_files)
        inferred = learned.get("inferred_commands") or {}
        candidates = list(inferred.get("candidates") or [])
        if not candidates:
            return self._fail("no_inferred_commands", learned=learned)

        request_terms = [t.lower() for t in re.findall(r"[A-Za-z0-9_]{3,}", user_request or "")]
        if request_terms and int(candidate_index) == 0:
            def score(c: Dict[str, Any]) -> float:
                hay = " ".join([
                    str(c.get("kind", "")), str(c.get("title", "")), str(c.get("reason", "")),
                    " ".join(str(x) for x in c.get("command") or []),
                ]).lower()
                return float(c.get("confidence", 0.0)) + sum(0.08 for t in request_terms if t in hay)

            candidates = sorted(candidates, key=score, reverse=True)

        if prefer_long_running:
            longs = [c for c in candidates if c.get("long_running")]
            if longs:
                candidates = longs

        idx = min(max(int(candidate_index), 0), len(candidates) - 1)
        candidate = candidates[idx]
        result = self.run_project_command(
            command=[*candidate.get("command", []), *[str(x) for x in (extra_args or [])]],
            cwd=str(candidate.get("cwd") or "."),
            timeout_sec=timeout_sec,
            use_project_python=True,
        )
        return self._ok(
            learned_summary={
                "venv": learned.get("status", {}).get("venv", {}),
                "candidate_count": len(candidates),
                "selected_candidate": candidate,
            },
            run_result=result,
        )

    def compile_python_file(self, path: str, timeout_sec: Optional[int] = None) -> Dict[str, Any]:
        try:
            target = self._resolve(path)
            if not target.exists() or not target.is_file():
                return self._fail("file_not_found", path=path)
            if target.suffix.lower() != ".py":
                return self._fail("not_a_python_file", path=path)
            return self._run_args([self._project_python(), "-m", "py_compile", self._relpath(target)], timeout_sec=timeout_sec)
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def run_pytest(
        self,
        target: str = "",
        timeout_sec: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        args = [self._project_python(), "-m", "pytest", "-q"]
        if target:
            args.append(str(target))
        args.extend(str(x) for x in (extra_args or []))
        return self._run_args(args, timeout_sec=timeout_sec)

    def run_ruff(
        self,
        target: str = ".",
        fix: bool = False,
        timeout_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        if fix and not self.config.write_enabled:
            return self._fail("ruff_fix_requires_project_write_enabled")
        args = [self._project_python(), "-m", "ruff", "check", str(target or ".")]
        if fix:
            args.append("--fix")
        return self._run_args(args, timeout_sec=timeout_sec)

    def _require_write(self) -> Optional[Dict[str, Any]]:
        if not self.config.write_enabled:
            return self._fail("project file writes are disabled")
        return None

    def write_project_file(self, path: str, content: str, create_dirs: bool = True) -> Dict[str, Any]:
        fail = self._require_write()
        if fail:
            return fail
        try:
            target = self._resolve(path)
            if self._is_sensitive(target):
                return self._fail("refusing_to_write_sensitive_file", path=path)
            if create_dirs:
                target.parent.mkdir(parents=True, exist_ok=True)
            if not target.parent.exists():
                return self._fail("parent_directory_missing", path=path)
            target.write_text(str(content), encoding="utf-8")
            return self._ok(path=self._relpath(target), bytes=target.stat().st_size)
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def create_project_file(
        self,
        path: str,
        content: str = "",
        overwrite: bool = False,
        create_dirs: bool = True,
    ) -> Dict[str, Any]:
        fail = self._require_write()
        if fail:
            return fail
        try:
            target = self._resolve(path)
            if target.exists() and not overwrite:
                return self._fail("file_already_exists", path=path)
            return self.write_project_file(path=path, content=content, create_dirs=create_dirs)
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def append_project_file(self, path: str, content: str, create_dirs: bool = True) -> Dict[str, Any]:
        fail = self._require_write()
        if fail:
            return fail
        try:
            target = self._resolve(path)
            if self._is_sensitive(target):
                return self._fail("refusing_to_write_sensitive_file", path=path)
            if create_dirs:
                target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as f:
                f.write(str(content))
            return self._ok(path=self._relpath(target), bytes=target.stat().st_size)
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def replace_in_project_file(self, path: str, old: str, new: str, count: int = 1) -> Dict[str, Any]:
        fail = self._require_write()
        if fail:
            return fail
        try:
            target = self._resolve(path)
            if not target.exists() or not target.is_file():
                return self._fail("file_not_found", path=path)
            if not self._is_text_file(target):
                return self._fail("unsupported_or_sensitive_file_type", path=path)
            text = self._read_text(target, max_chars=max(self.config.max_file_chars, target.stat().st_size + 1))
            if old not in text:
                return self._fail("old_text_not_found", path=path)
            n = max(1, int(count))
            updated = text.replace(old, new, n)
            target.write_text(updated, encoding="utf-8")
            return self._ok(path=self._relpath(target), replacements=text.count(old) if count <= 0 else min(text.count(old), n))
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def patch_project_file(self, path: str, replacements: List[Dict[str, Any]]) -> Dict[str, Any]:
        fail = self._require_write()
        if fail:
            return fail
        try:
            target = self._resolve(path)
            if not target.exists() or not target.is_file():
                return self._fail("file_not_found", path=path)
            if not self._is_text_file(target):
                return self._fail("unsupported_or_sensitive_file_type", path=path)
            before = self._read_text(target, max_chars=max(self.config.max_file_chars, target.stat().st_size + 1))
            text = before
            applied: List[Dict[str, Any]] = []
            for item in replacements or []:
                old = str(item.get("old", ""))
                new = str(item.get("new", ""))
                count = int(item.get("count", 1) or 1)
                if not old:
                    applied.append({"ok": False, "error": "empty_old_text"})
                    continue
                found = text.count(old)
                if not found:
                    applied.append({"ok": False, "error": "old_text_not_found", "old_preview": old[:120]})
                    continue
                text = text.replace(old, new, max(1, count))
                applied.append({"ok": True, "found": found, "replaced": min(found, max(1, count))})
            if text == before:
                return self._fail("no_changes_applied", path=path, applied=applied)
            target.write_text(text, encoding="utf-8")
            diff = "".join(
                difflib.unified_diff(
                    before.splitlines(True),
                    text.splitlines(True),
                    fromfile=f"a/{self._relpath(target)}",
                    tofile=f"b/{self._relpath(target)}",
                    n=3,
                )
            )
            return self._ok(path=self._relpath(target), applied=applied, diff=self._truncate(diff))
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def make_project_dir(self, path: str) -> Dict[str, Any]:
        fail = self._require_write()
        if fail:
            return fail
        try:
            target = self._resolve(path)
            target.mkdir(parents=True, exist_ok=True)
            return self._ok(path=self._relpath(target), created=True)
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def delete_project_path(self, path: str, recursive: bool = False) -> Dict[str, Any]:
        fail = self._require_write()
        if fail:
            return fail
        if not self.config.delete_enabled:
            return self._fail("delete is disabled; set project_delete_enabled=True to allow it")
        try:
            target = self._resolve(path)
            if not target.exists():
                return self._fail("path_not_found", path=path)
            if self._is_sensitive(target):
                return self._fail("refusing_to_delete_sensitive_file", path=path)
            if target.is_dir():
                if not recursive:
                    return self._fail("directory_requires_recursive_true", path=path)
                shutil.rmtree(target)
            else:
                target.unlink()
            return self._ok(path=path, deleted=True)
        except Exception as exc:
            return self._fail(str(exc), path=path)