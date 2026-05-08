from __future__ import annotations

import ast
import difflib
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".txt",
    ".md",
    ".rst",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
    ".html",
    ".css",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".sql",
    ".sh",
    ".bat",
    ".ps1",
}


SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
}


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
        "python",
        "py",
        "pytest",
        "ruff",
        "mypy",
        "pyright",
        "pip",
    )
    ignore_dirs: Iterable[str] = (
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        "site-packages",
    )


class LocalPythonProjectTools:
    """
    Config-driven local Python project scanner/runner.

    Safety behavior:
    - Never uses shell=True.
    - Blocks paths that escape the configured project root.
    - Blocks sensitive files like .env and private keys.
    - Runs only allowlisted commands.
    - Truncates command output.
    - Writes are disabled unless project_write_enabled=True.
    """

    def __init__(self, config: ProjectToolConfig):
        self.config = config
        self.root = Path(config.root).expanduser().resolve()
        self.ignore_dirs = {str(x) for x in config.ignore_dirs}
        self.allowed_commands = {str(x).lower() for x in config.allowed_commands}

    @classmethod
    def from_app_config(cls, app_config: Any) -> Optional["LocalPythonProjectTools"]:
        root = getattr(app_config, "resolved_project_dir", None)
        if root is None:
            return None

        root = Path(root)
        if not root.exists() or not root.is_dir():
            return None

        return cls(
            ProjectToolConfig(
                root=root,
                run_enabled=bool(getattr(app_config, "project_run_enabled", True)),
                write_enabled=bool(getattr(app_config, "project_write_enabled", False)),
                command_timeout_sec=int(getattr(app_config, "project_command_timeout_sec", 30)),
                max_output_chars=int(getattr(app_config, "project_max_output_chars", 14000)),
                max_file_chars=int(getattr(app_config, "project_max_file_chars", 160000)),
                max_scan_files=int(getattr(app_config, "project_max_scan_files", 3000)),
                allowed_commands=tuple(getattr(app_config, "project_command_names", ["python", "pytest"])),
                ignore_dirs=getattr(app_config, "project_ignore_dir_names", set()),
            )
        )

    def _ok(self, **kw: Any) -> Dict[str, Any]:
        return {"ok": True, "project_root": str(self.root), **kw}

    def _fail(self, error: str, **kw: Any) -> Dict[str, Any]:
        return {"ok": False, "project_root": str(self.root), "error": error, **kw}

    def _relpath(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except Exception:
            return path.as_posix()

    def _resolve(self, rel_path: str = ".") -> Path:
        raw = str(rel_path or ".").replace("\\", "/").strip()

        if re.match(r"^[a-zA-Z]:", raw) or raw.startswith("/"):
            candidate = Path(raw).expanduser().resolve()
        else:
            candidate = (self.root / raw).resolve()

        try:
            candidate.relative_to(self.root)
        except Exception as exc:
            raise ValueError(f"path escapes project root: {rel_path}") from exc

        return candidate

    def _is_sensitive(self, path: Path) -> bool:
        lower = path.name.lower()
        if lower in SENSITIVE_NAMES:
            return True
        if lower.endswith(".pem") or lower.endswith(".key") or lower.endswith(".pfx"):
            return True
        return False

    def _is_ignored_dir(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _is_text_file(self, path: Path) -> bool:
        if self._is_sensitive(path):
            return False
        if path.suffix.lower() in TEXT_SUFFIXES:
            return True
        return path.name.lower().endswith(".env.example")

    def _read_text(self, path: Path, max_chars: Optional[int] = None) -> str:
        limit = int(max_chars or self.config.max_file_chars)
        data = path.read_bytes()

        if len(data) > limit * 4:
            data = data[: limit * 4]

        text = data.decode("utf-8", errors="replace")

        if len(text) > limit:
            text = text[:limit] + "\n\n[TRUNCATED]"

        return text

    def _truncate(self, text: Any, max_chars: Optional[int] = None) -> str:
        s = str(text or "")
        limit = int(max_chars or self.config.max_output_chars)
        if len(s) > limit:
            return s[:limit] + f"\n\n[TRUNCATED to {limit} chars]"
        return s

    def _iter_files(self, suffix: str = "", include_hidden: bool = False) -> Iterable[Path]:
        count = 0
        suffix = str(suffix or "").lower().strip()

        for dirpath, dirnames, filenames in os.walk(self.root):
            dir_path = Path(dirpath)

            dirnames[:] = [
                d
                for d in dirnames
                if d not in self.ignore_dirs and (include_hidden or not d.startswith("."))
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

    def project_status(self) -> Dict[str, Any]:
        markers = {}
        for name in (
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
            "pytest.ini",
            "tox.ini",
            "main.py",
            "app.py",
        ):
            markers[name] = (self.root / name).exists()

        return self._ok(
            exists=self.root.exists(),
            is_dir=self.root.is_dir(),
            run_enabled=self.config.run_enabled,
            write_enabled=self.config.write_enabled,
            allowed_commands=sorted(self.allowed_commands),
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
                        "bytes": st.st_size,
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
        terms = [
            t.lower()
            for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", query)
        ]

        results: List[Dict[str, Any]] = []

        for path in self._iter_files(suffix=suffix):
            if not self._is_text_file(path):
                continue

            try:
                text = self._read_text(path)
            except Exception:
                continue

            low = text.lower()
            score = 0
            idx = low.find(literal)

            if idx >= 0:
                score += 12
            else:
                term_hits = [term for term in terms if term in low]
                if not term_hits:
                    continue

                score += len(term_hits)
                positions = [low.find(term) for term in term_hits if low.find(term) >= 0]
                idx = min(positions) if positions else 0

            path_low = self._relpath(path).lower()
            for term in terms:
                if term in path_low:
                    score += 2

            start = max(0, idx - int(context_chars))
            end = min(len(text), idx + int(context_chars))
            excerpt = text[start:end]
            line = text[:idx].count("\n") + 1 if idx >= 0 else None

            results.append(
                {
                    "path": self._relpath(path),
                    "score": score,
                    "line": line,
                    "excerpt": excerpt,
                }
            )

        results.sort(key=lambda row: (-row["score"], row["path"]))
        return self._ok(query=query, count=len(results[:max_results]), results=results[:max_results])

    def summarize_project(self, max_files: int = 1000) -> Dict[str, Any]:
        files = list(self._iter_files())[: int(max_files)]
        by_suffix: Dict[str, int] = {}
        packages: List[str] = []
        classes: List[Dict[str, Any]] = []
        functions: List[Dict[str, Any]] = []
        imports: Dict[str, int] = {}

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

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(
                        {
                            "name": node.name,
                            "path": self._relpath(path),
                            "line": node.lineno,
                            "async": isinstance(node, ast.AsyncFunctionDef),
                        }
                    )
                elif isinstance(node, ast.ClassDef):
                    classes.append(
                        {
                            "name": node.name,
                            "path": self._relpath(path),
                            "line": node.lineno,
                        }
                    )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".", 1)[0]
                        imports[root] = imports.get(root, 0) + 1
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
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
        )

    def run_project_command(
        self,
        command: Any,
        timeout_sec: Optional[int] = None,
        cwd: str = ".",
    ) -> Dict[str, Any]:
        if not self.config.run_enabled:
            return self._fail("project_run_disabled")

        if isinstance(command, str):
            try:
                args = shlex.split(command)
            except Exception as exc:
                return self._fail(f"could_not_parse_command: {exc}")
        elif isinstance(command, list):
            args = [str(x) for x in command]
        else:
            return self._fail("command_must_be_string_or_list")

        if not args:
            return self._fail("empty_command")

        exe = Path(args[0]).name.lower()
        if exe.endswith(".exe"):
            exe = exe[:-4]

        if exe not in self.allowed_commands:
            return self._fail(
                "command_not_allowlisted",
                command=args,
                allowed_commands=sorted(self.allowed_commands),
            )

        try:
            workdir = self._resolve(cwd)
            if not workdir.exists() or not workdir.is_dir():
                return self._fail("cwd_not_directory", cwd=cwd)

            started = time.time()
            proc = subprocess.run(
                args,
                cwd=str(workdir),
                text=True,
                capture_output=True,
                timeout=int(timeout_sec or self.config.command_timeout_sec),
                shell=False,
            )
            elapsed = time.time() - started

            return self._ok(
                command=args,
                cwd=self._relpath(workdir),
                returncode=proc.returncode,
                elapsed_sec=round(elapsed, 3),
                stdout=self._truncate(proc.stdout),
                stderr=self._truncate(proc.stderr),
            )

        except subprocess.TimeoutExpired as exc:
            return self._fail(
                "command_timeout",
                command=args,
                timeout_sec=int(timeout_sec or self.config.command_timeout_sec),
                stdout=self._truncate(exc.stdout or ""),
                stderr=self._truncate(exc.stderr or ""),
            )
        except Exception as exc:
            return self._fail(str(exc), command=args)

    def run_python_file(
        self,
        path: str,
        args: Optional[List[str]] = None,
        timeout_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        try:
            target = self._resolve(path)

            if not target.exists() or not target.is_file():
                return self._fail("file_not_found", path=path)

            if target.suffix.lower() != ".py":
                return self._fail("not_python_file", path=path)

            rel = self._relpath(target)
            return self.run_project_command(
                [sys.executable, rel, *(args or [])],
                timeout_sec=timeout_sec,
                cwd=".",
            )

        except Exception as exc:
            return self._fail(str(exc), path=path)

    def run_pytest(
        self,
        target: str = "",
        timeout_sec: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        args = ["pytest", "-q"]
        if target:
            args.append(target)
        if extra_args:
            args.extend(str(x) for x in extra_args)
        return self.run_project_command(args, timeout_sec=timeout_sec)

    def run_ruff(
        self,
        target: str = ".",
        fix: bool = False,
        timeout_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        args = ["ruff", "check", target or "."]
        if fix:
            if not self.config.write_enabled:
                return self._fail("write_disabled_for_ruff_fix")
            args.append("--fix")
        return self.run_project_command(args, timeout_sec=timeout_sec)

    def compile_python_file(self, path: str, timeout_sec: Optional[int] = None) -> Dict[str, Any]:
        try:
            target = self._resolve(path)
            if not target.exists() or not target.is_file():
                return self._fail("file_not_found", path=path)
            if target.suffix.lower() != ".py":
                return self._fail("not_python_file", path=path)

            rel = self._relpath(target)
            return self.run_project_command(
                [sys.executable, "-m", "py_compile", rel],
                timeout_sec=timeout_sec,
                cwd=".",
            )
        except Exception as exc:
            return self._fail(str(exc), path=path)

    def write_project_file(self, path: str, content: str, create_dirs: bool = True) -> Dict[str, Any]:
        if not self.config.write_enabled:
            return self._fail("project_write_disabled", path=path)

        try:
            target = self._resolve(path)

            if target.exists() and not target.is_file():
                return self._fail("not_a_file", path=path)

            if self._is_sensitive(target):
                return self._fail("refusing_to_write_sensitive_file", path=path)

            if target.suffix and target.suffix.lower() not in TEXT_SUFFIXES:
                return self._fail("unsupported_file_type", path=path)

            old = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""
            new = str(content or "")

            if create_dirs:
                target.parent.mkdir(parents=True, exist_ok=True)

            target.write_text(new, encoding="utf-8")

            diff = "\n".join(
                difflib.unified_diff(
                    old.splitlines(),
                    new.splitlines(),
                    fromfile=f"a/{self._relpath(target)}",
                    tofile=f"b/{self._relpath(target)}",
                    lineterm="",
                )
            )

            return self._ok(
                path=self._relpath(target),
                bytes=len(new.encode("utf-8")),
                diff=self._truncate(diff),
            )

        except Exception as exc:
            return self._fail(str(exc), path=path)