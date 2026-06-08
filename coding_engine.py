# coding_engine.py
# ---------------------------------------------------------------------------
# Standalone GPTProject Coding Engine
#
# Local-first code-generation support brain for GPT.  This engine gathers code
# tokens, snippets, imports, symbols, signatures, style signals, and syntax
# patterns, then builds compact context packs for stronger code generation.
# It does not execute user/project code.  It only reads text, parses syntax,
# formats generated text, and creates prompt/template output.
#
# Public exports:
#   coding_engine
#   coding_engine_tool_schema
#   make_coding_engine_tool_function
#   register_coding_engine_tool
#   CodingEngine
#   CodingEngineConfig
#   CODE_GENERATION_ACTIONS
# ---------------------------------------------------------------------------
from __future__ import annotations

import ast
import builtins
import dataclasses
import difflib
import hashlib
import io
import json
import keyword
import os
import re
import textwrap
import tokenize
import traceback
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from loggers import DEBUG_LOGGER  # type: ignore
except Exception:
    class _FallbackDebugLogger:
        def log_message(self, msg: str) -> None:
            try:
                print(msg)
            except Exception:
                pass
    DEBUG_LOGGER = _FallbackDebugLogger()

ENGINE_VERSION = "2026.06.07-finish-actions-codegen-brain"
DEFAULT_MAX_CHARS = 120_000
DEFAULT_MAX_SNIPPETS = 24
DEFAULT_MAX_TOKENS = 8_000
DEFAULT_PROJECT_FILE_LIMIT = 220
DEFAULT_MAX_FILE_BYTES = 500_000

SAFE_TEXT_SUFFIXES = {
    ".py", ".pyw", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".cs", ".java",
    ".c", ".h", ".hpp", ".cpp", ".cc", ".cxx", ".go", ".rs", ".swift",
    ".kt", ".kts", ".html", ".css", ".scss", ".sass", ".json", ".toml",
    ".yaml", ".yml", ".ini", ".cfg", ".md", ".txt", ".rst", ".sql", ".sh", ".ps1", ".bat",
}
IGNORED_DIR_NAMES = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".venv", "venv", "env", "node_modules", "dist", "build", ".idea", ".vscode", "target", "bin", "obj",
}
LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".pyw": "python", ".pyi": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".cs": "csharp", ".java": "java",
    ".c": "c", ".h": "c", ".hpp": "cpp", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".go": "go", ".rs": "rust", ".swift": "swift", ".kt": "kotlin", ".kts": "kotlin",
    ".html": "html", ".css": "css", ".scss": "scss", ".sass": "sass", ".json": "json", ".toml": "toml",
    ".yaml": "yaml", ".yml": "yaml", ".md": "markdown", ".rst": "rst", ".sql": "sql", ".sh": "bash", ".ps1": "powershell",
}
PY_BUILTINS = set(dir(builtins))
PY_KEYWORDS = set(keyword.kwlist) | set(getattr(keyword, "softkwlist", []))


def _log(msg: str) -> None:
    try:
        DEBUG_LOGGER.log_message(f"[coding_engine] {msg}")
    except Exception:
        pass


def _coerce_int(value: Any, default: int, min_value: int = 0, max_value: Optional[int] = None) -> int:
    try:
        out = int(value)
    except Exception:
        out = default
    out = max(min_value, out)
    if max_value is not None:
        out = min(out, max_value)
    return out


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _safe_text(value: Any, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "ignore")
    text = str(value)
    return text[:max_chars] if len(text) > max_chars else text


def _dedent_clean(code: str) -> str:
    return textwrap.dedent(code or "").strip("\n") + "\n"


def _estimate_tokens(text: str) -> int:
    return 0 if not text else max(1, int(len(text) / 4))


def _hash_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "ignore")).hexdigest()[:16]


def _word_set(text: str) -> set[str]:
    return {w.lower() for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", text or "")}


def detect_language(source: str = "", path: str = "") -> str:
    suffix = Path(path or "").suffix.lower()
    if suffix in LANGUAGE_BY_SUFFIX:
        return LANGUAGE_BY_SUFFIX[suffix]
    s = (source or "")[:5000]
    if re.search(r"^\s*(from\s+\S+\s+import|import\s+\S+|def\s+\w+|class\s+\w+)\b", s, re.M):
        return "python"
    if re.search(r"\b(function|const|let|var|import\s+.*from|export\s+)\b", s):
        return "javascript"
    if re.search(r"\b(public|private|protected|namespace|using\s+System|class\s+\w+)\b", s):
        return "csharp"
    if re.search(r"#include\s*<|int\s+main\s*\(", s):
        return "cpp"
    return "unknown"


@dataclass
class CodeToken:
    text: str
    kind: str
    language: str = "unknown"
    source: str = ""
    line: int = 0
    column: int = 0
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CodeSymbol:
    name: str
    kind: str
    language: str = "python"
    source: str = ""
    line: int = 0
    signature: str = ""
    docstring: str = ""
    parent: str = ""
    decorators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CodeSnippet:
    code: str
    language: str = "unknown"
    source: str = ""
    title: str = ""
    start_line: int = 0
    end_line: int = 0
    symbols: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    signatures: List[str] = field(default_factory=list)
    docstrings: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    token_count: int = 0
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if len(d.get("code", "")) > 20_000:
            d["code"] = d["code"][:20_000] + "\n# ... [truncated]"
        return d


@dataclass
class SyntaxPack:
    task: str = ""
    language: str = "python"
    intent: str = "build_context_pack"
    snippets: List[CodeSnippet] = field(default_factory=list)
    tokens: List[CodeToken] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    signatures: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    guidance: List[str] = field(default_factory=list)
    estimated_tokens: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task": self.task,
            "language": self.language,
            "intent": self.intent,
            "snippets": [s.to_dict() for s in self.snippets],
            "tokens": [t.to_dict() for t in self.tokens],
            "symbols": self.symbols,
            "imports": self.imports,
            "signatures": self.signatures,
            "patterns": self.patterns,
            "constraints": self.constraints,
            "guidance": self.guidance,
            "estimated_tokens": self.estimated_tokens,
        }


@dataclass
class CodingEngineConfig:
    project_root: str = ""
    max_chars: int = DEFAULT_MAX_CHARS
    max_snippets: int = DEFAULT_MAX_SNIPPETS
    max_tokens: int = DEFAULT_MAX_TOKENS
    max_project_files: int = DEFAULT_PROJECT_FILE_LIMIT
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    include_tests: bool = True
    include_docs: bool = True
    include_markdown_fences: bool = True
    safe_read_only: bool = True
    allow_absolute_paths: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Python AST / regex extractors
# ---------------------------------------------------------------------------
def _annotation_to_str(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _decorator_name(node: ast.AST) -> str:
    try:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Call):
            return _decorator_name(node.func)
        if isinstance(node, ast.Attribute):
            return ast.unparse(node)
        return ast.unparse(node)
    except Exception:
        return "decorator"


def _function_signature(node: ast.AST) -> str:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ""
    args: List[str] = []
    normal_args = list(node.args.posonlyargs) + list(node.args.args)
    defaults = [None] * (len(normal_args) - len(node.args.defaults)) + list(node.args.defaults)
    for arg, default in zip(normal_args, defaults):
        piece = arg.arg
        ann = _annotation_to_str(arg.annotation)
        if ann:
            piece += f": {ann}"
        if default is not None:
            try:
                piece += f" = {ast.unparse(default)}"
            except Exception:
                piece += " = ..."
        args.append(piece)
    if node.args.vararg:
        piece = "*" + node.args.vararg.arg
        ann = _annotation_to_str(node.args.vararg.annotation)
        if ann:
            piece += f": {ann}"
        args.append(piece)
    elif node.args.kwonlyargs:
        args.append("*")
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        piece = arg.arg
        ann = _annotation_to_str(arg.annotation)
        if ann:
            piece += f": {ann}"
        if default is not None:
            try:
                piece += f" = {ast.unparse(default)}"
            except Exception:
                piece += " = ..."
        args.append(piece)
    if node.args.kwarg:
        piece = "**" + node.args.kwarg.arg
        ann = _annotation_to_str(node.args.kwarg.annotation)
        if ann:
            piece += f": {ann}"
        args.append(piece)
    ret = _annotation_to_str(node.returns)
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    sig = f"{prefix} {node.name}({', '.join(args)})"
    if ret:
        sig += f" -> {ret}"
    return sig + ":"


def _class_signature(node: ast.ClassDef) -> str:
    bases = []
    for base in node.bases:
        try:
            bases.append(ast.unparse(base))
        except Exception:
            pass
    return f"class {node.name}({', '.join(bases)}):" if bases else f"class {node.name}:"


def extract_python_imports(code: str) -> List[str]:
    imports: List[str] = []
    try:
        tree = ast.parse(code or "")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""))
            elif isinstance(node, ast.ImportFrom):
                mod = "." * int(node.level or 0) + (node.module or "")
                names = ", ".join(a.name + (f" as {a.asname}" if a.asname else "") for a in node.names)
                imports.append(f"from {mod} import {names}")
    except Exception:
        for line in (code or "").splitlines():
            if re.match(r"\s*(import\s+\S+|from\s+\S+\s+import\s+.+)", line):
                imports.append(line.strip())
    return sorted(dict.fromkeys(imports))


def extract_python_symbols(code: str, source: str = "") -> List[CodeSymbol]:
    symbols: List[CodeSymbol] = []
    try:
        tree = ast.parse(code or "")
    except Exception:
        return symbols

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: List[str] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> Any:
            parent = ".".join(self.stack)
            symbols.append(CodeSymbol(
                name=node.name, kind="class", source=source, line=getattr(node, "lineno", 0),
                signature=_class_signature(node), docstring=ast.get_docstring(node) or "",
                parent=parent, decorators=[_decorator_name(d) for d in node.decorator_list],
            ))
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
            self._visit_func(node, "function")

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
            self._visit_func(node, "async_function")

        def _visit_func(self, node: ast.AST, kind: str) -> None:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return
            parent = ".".join(self.stack)
            symbols.append(CodeSymbol(
                name=node.name, kind="method" if parent else kind, source=source,
                line=getattr(node, "lineno", 0), signature=_function_signature(node),
                docstring=ast.get_docstring(node) or "", parent=parent,
                decorators=[_decorator_name(d) for d in node.decorator_list],
            ))
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

    Visitor().visit(tree)
    return symbols


def extract_python_dependencies(code: str) -> List[str]:
    deps = []
    for imp in extract_python_imports(code):
        m = re.match(r"import\s+([A-Za-z_][\w.]*)", imp) or re.match(r"from\s+([A-Za-z_][\w.]*)\s+import", imp)
        if m:
            top = m.group(1).split(".")[0]
            if top and top not in deps:
                deps.append(top)
    return sorted(deps)


def extract_python_patterns(code: str) -> List[str]:
    try:
        tree = ast.parse(code or "")
    except Exception:
        return []
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            found.add("try_except")
        if isinstance(node, (ast.With, ast.AsyncWith)):
            found.add("context_manager")
        if isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
            found.add("comprehension")
        if isinstance(node, ast.Await):
            found.add("async_await")
        if isinstance(node, ast.AnnAssign):
            found.add("type_annotations")
        if isinstance(node, ast.Call):
            try:
                call = ast.unparse(node.func)
            except Exception:
                call = ""
            if call.endswith(".add_argument"):
                found.add("argparse")
            if call in {"dataclass", "dataclasses.dataclass"}:
                found.add("dataclass")
            if call.endswith(".register"):
                found.add("registry_pattern")
            if call.endswith(".append"):
                found.add("list_accumulator")
    if re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", code or ""):
        found.add("main_guard")
    if "@dataclass" in code:
        found.add("dataclass")
    if "ToolSpec" in code and ".register" in code:
        found.add("gpt_tool_registration")
    return sorted(found)


def extract_generic_imports(code: str, language: str = "unknown") -> List[str]:
    lines = []
    for line in (code or "").splitlines():
        s = line.strip()
        if re.match(r"^(import|from|using|#include|require\(|const\s+\w+\s*=\s*require\(|export\s+|package\s+)", s):
            lines.append(s)
    return sorted(dict.fromkeys(lines))


def extract_generic_signatures(code: str, language: str = "unknown") -> List[str]:
    signatures: List[str] = []
    patterns = [
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_][\w$]*\s*\([^)]*\)",
        r"^\s*(?:public|private|protected|static|async|virtual|override|sealed|internal|extern|partial|\s)+\s*[A-Za-z_][\w<>?,\s\[\]]+\s+[A-Za-z_][\w]*\s*\([^)]*\)",
        r"^\s*(?:class|interface|struct|enum|record)\s+[A-Za-z_][\w]*[^\n{;]*",
        r"^\s*[A-Za-z_][\w<>?,\s\[\]]+\s+[A-Za-z_][\w]*\s*\([^)]*\)\s*(?:\{|;)",
        r"^\s*(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?\([^)]*\)\s*=>",
    ]
    for rx in patterns:
        for m in re.finditer(rx, code or "", re.M):
            signatures.append(m.group(0).strip().rstrip("{"))
    return sorted(dict.fromkeys(signatures))[:200]


def extract_generic_symbols(code: str, language: str = "unknown", source: str = "") -> List[CodeSymbol]:
    out: List[CodeSymbol] = []
    for sig in extract_generic_signatures(code, language):
        name = ""
        kind = "symbol"
        m = re.search(r"\b(class|interface|struct|enum|record)\s+([A-Za-z_][\w]*)", sig)
        if m:
            kind, name = m.group(1), m.group(2)
        else:
            m = re.search(r"\bfunction\s+([A-Za-z_$][\w$]*)", sig) or re.search(r"\s+([A-Za-z_][\w]*)\s*\(", sig)
            if m:
                kind, name = "function", m.group(1)
        if name:
            line = (code or "")[: (code or "").find(sig)].count("\n") + 1 if sig in (code or "") else 0
            out.append(CodeSymbol(name=name, kind=kind, language=language, source=source, line=line, signature=sig))
    return out


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------
def tokenize_python(code: str, source: str = "") -> List[CodeToken]:
    out: List[CodeToken] = []
    try:
        reader = io.StringIO(code or "").readline
        for tok in tokenize.generate_tokens(reader):
            kind_name = tokenize.tok_name.get(tok.type, str(tok.type))
            text = tok.string
            if not text or kind_name in {"ENCODING", "ENDMARKER", "NL"}:
                continue
            score = 1.0
            if kind_name == "NAME":
                score = 2.0 if text in PY_KEYWORDS else (1.5 if text not in PY_BUILTINS else 0.7)
            elif kind_name in {"STRING", "COMMENT"}:
                score = 0.4
            out.append(CodeToken(text=text, kind=kind_name, language="python", source=source, line=tok.start[0], column=tok.start[1], score=score))
    except Exception:
        out.extend(tokenize_generic(code, language="python", source=source))
    return out


def tokenize_generic(code: str, language: str = "unknown", source: str = "") -> List[CodeToken]:
    out: List[CodeToken] = []
    rx = re.compile(
        r"(?P<comment>//.*?$|#.*?$|/\*.*?\*/)|"
        r"(?P<string>'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")|"
        r"(?P<number>\b\d+(?:\.\d+)?\b)|"
        r"(?P<identifier>\b[A-Za-z_][A-Za-z0-9_]*\b)|"
        r"(?P<operator>==|!=|<=|>=|=>|->|::|&&|\|\||[+\-*/%=<>!&|^~]+)|"
        r"(?P<punctuation>[{}\[\]();:,.])",
        re.S | re.M,
    )
    for m in rx.finditer(code or ""):
        kind = m.lastgroup or "token"
        text = m.group(0)
        line = (code or "")[:m.start()].count("\n") + 1
        col = m.start() - ((code or "").rfind("\n", 0, m.start()) + 1)
        out.append(CodeToken(text=text, kind=kind, language=language, source=source, line=line, column=col, score=1.5 if kind == "identifier" else 0.8))
    return out


def tokenize_code(code: str, language: str = "", source: str = "", max_tokens: int = 5000) -> List[CodeToken]:
    lang = (language or detect_language(code)).lower()
    out = tokenize_python(code, source=source) if lang == "python" else tokenize_generic(code, language=lang, source=source)
    return out[:max(1, max_tokens)]


# ---------------------------------------------------------------------------
# Snippets and ranking
# ---------------------------------------------------------------------------
def _window_around_lines(lines: List[str], line_no: int, radius: int = 28) -> Tuple[str, int, int]:
    if not lines:
        return "", 0, 0
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start - 1:end]), start, end


def extract_markdown_code_fences(text: str, source: str = "markdown") -> List[CodeSnippet]:
    snippets: List[CodeSnippet] = []
    pattern = re.compile(r"```(?P<lang>[A-Za-z0-9_+\-.#]*)\s*\n(?P<code>.*?)```", re.S)
    for idx, m in enumerate(pattern.finditer(text or ""), start=1):
        lang = (m.group("lang") or "").strip().lower().replace("py", "python") or "unknown"
        code = (m.group("code") or "").strip("\n")
        if not code.strip():
            continue
        start_line = text[:m.start()].count("\n") + 1
        snippets.append(CodeSnippet(
            code=code,
            language=detect_language(code, path=f"snippet.{lang}") if lang == "unknown" else lang,
            source=source,
            title=f"markdown fence {idx}",
            start_line=start_line,
            end_line=start_line + code.count("\n"),
            token_count=_estimate_tokens(code),
        ))
    return snippets


def create_snippets_from_code(code: str, language: str = "", source: str = "", max_snippets: int = 80) -> List[CodeSnippet]:
    code = code or ""
    lang = (language or detect_language(code, path=source)).lower()
    snippets: List[CodeSnippet] = []
    if lang == "python":
        lines = code.splitlines()
        imports = extract_python_imports(code)
        symbols = extract_python_symbols(code, source=source)
        for sym in symbols:
            chunk, start, end = _window_around_lines(lines, sym.line, radius=32)
            if not chunk.strip():
                continue
            local_symbols = extract_python_symbols(chunk, source=source)
            snippets.append(CodeSnippet(
                code=chunk,
                language=lang,
                source=source,
                title=f"{sym.kind} {sym.name}",
                start_line=start,
                end_line=end,
                symbols=[x.name for x in local_symbols] or [sym.name],
                imports=imports,
                signatures=[x.signature for x in local_symbols if x.signature],
                docstrings=[x.docstring for x in local_symbols if x.docstring][:4],
                patterns=extract_python_patterns(chunk),
                token_count=_estimate_tokens(chunk),
            ))
            if len(snippets) >= max_snippets:
                break
        if not snippets and code.strip():
            snippets.append(CodeSnippet(
                code=code[:20_000], language=lang, source=source, title=Path(source).name or "python code",
                start_line=1, end_line=code.count("\n") + 1, imports=imports,
                symbols=[x.name for x in symbols], signatures=[x.signature for x in symbols if x.signature],
                patterns=extract_python_patterns(code), token_count=_estimate_tokens(code[:20_000]),
            ))
    else:
        imports = extract_generic_imports(code, lang)
        signatures = extract_generic_signatures(code, lang)
        lines = code.splitlines()
        for sig in signatures[:max_snippets]:
            line_no = next((i + 1 for i, line in enumerate(lines) if sig.strip() in line.strip()), 1)
            chunk, start, end = _window_around_lines(lines, line_no, radius=32)
            snippets.append(CodeSnippet(
                code=chunk, language=lang, source=source, title=sig[:120], start_line=start, end_line=end,
                imports=imports, signatures=[sig], symbols=[x.name for x in extract_generic_symbols(chunk, lang, source)], token_count=_estimate_tokens(chunk),
            ))
        if not snippets and code.strip():
            snippets.append(CodeSnippet(
                code=code[:20_000], language=lang, source=source, title=Path(source).name or "code",
                start_line=1, end_line=code.count("\n") + 1, imports=imports, signatures=signatures[:20],
                symbols=[x.name for x in extract_generic_symbols(code, lang, source)[:50]], token_count=_estimate_tokens(code[:20_000]),
            ))
    return snippets[:max_snippets]


def dedupe_snippets(snippets: Sequence[CodeSnippet]) -> List[CodeSnippet]:
    seen: set[str] = set()
    out: List[CodeSnippet] = []
    for sn in snippets:
        normalized = re.sub(r"\s+", " ", sn.code.strip())[:4000]
        h = _hash_text(normalized)
        if h in seen:
            continue
        seen.add(h)
        out.append(sn)
    return out


def rank_snippets(snippets: Sequence[CodeSnippet], query: str = "", language: str = "", max_snippets: int = DEFAULT_MAX_SNIPPETS) -> List[CodeSnippet]:
    terms = _word_set(query)
    lang = (language or "").lower()
    ranked: List[CodeSnippet] = []
    for sn in snippets:
        hay = " ".join([sn.title, sn.source, " ".join(sn.symbols), " ".join(sn.signatures), " ".join(sn.patterns), sn.code[:4000]]).lower()
        score = 0.0
        for term in terms:
            if term in hay:
                score += 2.0
            if term in {s.lower() for s in sn.symbols}:
                score += 3.0
        if lang and sn.language.lower() == lang:
            score += 2.5
        if sn.signatures:
            score += 1.25
        if sn.imports:
            score += 0.75
        if "main_guard" in sn.patterns:
            score += 0.4
        if sn.token_count > 0:
            score += min(2.0, 6000.0 / max(500.0, float(sn.token_count)))
        ranked.append(dataclasses.replace(sn, score=round(score, 3)))
    ranked.sort(key=lambda s: s.score, reverse=True)
    return ranked[:max(1, max_snippets)]


def _iter_project_files(root: str, *, max_files: int, max_file_bytes: int, include_tests: bool, include_docs: bool) -> Iterable[Path]:
    base = Path(root or os.getcwd()).resolve()
    count = 0
    for path in base.rglob("*"):
        if count >= max_files:
            break
        try:
            if not path.is_file():
                continue
            if set(path.parts) & IGNORED_DIR_NAMES:
                continue
            if path.suffix.lower() not in SAFE_TEXT_SUFFIXES:
                continue
            name = path.name.lower()
            if not include_tests and (name.startswith("test_") or name.endswith("_test.py") or "tests" in path.parts):
                continue
            if not include_docs and path.suffix.lower() in {".md", ".rst", ".txt"}:
                continue
            if path.stat().st_size > max_file_bytes:
                continue
            count += 1
            yield path
        except Exception:
            continue


def _read_text_file(path: Path, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> str:
    size = path.stat().st_size
    if size > max_file_bytes:
        raise ValueError(f"File too large: {path} ({size} bytes)")
    return path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
def _module_header(title: str = "Generated module", description: str = "") -> str:
    return (
        f"# {title}\n"
        "# ---------------------------------------------------------------------------\n"
        f"# {description or title}\n"
        "# Generated by coding_engine.py context/template support.\n"
        "# ---------------------------------------------------------------------------\n"
        "from __future__ import annotations\n\n"
    )


def template_script(task: str, name: str = "generated_script") -> str:
    return _dedent_clean(f'''
    {_module_header(name, task)}import argparse
    import json
    from typing import Any, Dict


    def run(args: argparse.Namespace) -> Dict[str, Any]:
        """Main script logic for: {task}"""
        return {{
            "ok": True,
            "task": {task!r},
            "input": getattr(args, "input", ""),
        }}


    def build_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description={task!r})
        parser.add_argument("input", nargs="?", default="", help="Optional input text or path")
        parser.add_argument("--json", action="store_true", help="Print JSON output")
        return parser


    def main() -> int:
        parser = build_parser()
        args = parser.parse_args()
        result = run(args)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(result)
        return 0 if result.get("ok") else 1


    if __name__ == "__main__":
        raise SystemExit(main())
    ''')


def template_function(task: str, name: str = "generated_function") -> str:
    return _dedent_clean(f'''
    from __future__ import annotations

    from typing import Any, Dict, Optional


    def {name}(payload: Any, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """{task}"""
        options = options or {{}}
        return {{
            "ok": True,
            "task": {task!r},
            "payload": payload,
            "options": options,
        }}
    ''')


def template_class(task: str, name: str = "GeneratedWorker") -> str:
    return _dedent_clean(f'''
    from __future__ import annotations

    from dataclasses import dataclass, field
    from typing import Any, Dict


    @dataclass
    class {name}Config:
        enabled: bool = True
        max_items: int = 100


    @dataclass
    class {name}:
        """{task}"""
        config: {name}Config = field(default_factory={name}Config)

        def status(self) -> Dict[str, Any]:
            return {{"ok": True, "enabled": self.config.enabled}}

        def run(self, payload: Any = None, **kwargs: Any) -> Dict[str, Any]:
            if not self.config.enabled:
                return {{"ok": False, "error": "Worker is disabled."}}
            return {{"ok": True, "task": {task!r}, "payload": payload, "kwargs": kwargs}}
    ''')


def template_gui(task: str, name: str = "GeneratedWindow") -> str:
    return _dedent_clean(f'''
    from __future__ import annotations

    import sys
    from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget, QPushButton


    class {name}(QMainWindow):
        """{task}"""
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle({task!r})
            self.resize(900, 600)
            self.text = QTextEdit()
            self.button = QPushButton("Run")
            self.button.clicked.connect(self.on_run)
            layout = QVBoxLayout()
            layout.addWidget(self.text)
            layout.addWidget(self.button)
            root = QWidget()
            root.setLayout(layout)
            self.setCentralWidget(root)

        def on_run(self) -> None:
            self.text.setPlainText(self.text.toPlainText() + "\\n\\nRan GUI action.")


    def main() -> int:
        app = QApplication(sys.argv)
        win = {name}()
        win.show()
        return app.exec()


    if __name__ == "__main__":
        raise SystemExit(main())
    ''')


def template_engine(task: str, engine_name: str = "generated_engine") -> str:
    fn_name = re.sub(r"\W+", "_", engine_name.strip().lower()).strip("_") or "generated_engine"
    cls_name = "".join(part.capitalize() for part in fn_name.split("_")) or "GeneratedEngine"
    return _dedent_clean(f'''
    # {fn_name}.py
    from __future__ import annotations

    from dataclasses import dataclass, field, asdict
    from typing import Any, Callable, Dict, Optional


    @dataclass
    class {cls_name}Config:
        max_items: int = 100


    @dataclass
    class {cls_name}:
        config: {cls_name}Config = field(default_factory={cls_name}Config)

        def status(self) -> Dict[str, Any]:
            return {{"ok": True, "engine": {fn_name!r}, "config": asdict(self.config)}}

        def run(self, action: str, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            params = params or {{}}
            action = (action or "status").strip().lower()
            if action == "status":
                return self.status()
            if action == "help":
                return {{"ok": True, "actions": ["status", "help", "echo"]}}
            if action == "echo":
                return {{"ok": True, "payload": payload, "params": params}}
            return {{"ok": False, "error": f"Unknown action: {{action}}", "actions": ["status", "help", "echo"]}}


    _ENGINE = {cls_name}()


    def {fn_name}(action: str = "status", payload: Any = None, params: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        if kwargs:
            params = dict(params or {{}})
            params.update(kwargs)
        return _ENGINE.run(action, payload, params)


    def {fn_name}_tool_schema() -> Dict[str, Any]:
        return {{
            "type": "object",
            "properties": {{"action": {{"type": "string"}}, "payload": {{}}, "params": {{"type": "object"}}}},
            "required": ["action"],
        }}


    def make_{fn_name}_tool_function() -> Callable[..., Dict[str, Any]]:
        return {fn_name}
    ''')


def template_tool_wrapper(engine_module: str = "coding_engine") -> str:
    return _dedent_clean(f'''
    # ======================= Coding Engine Import ==============================
    try:
        from {engine_module} import (
            coding_engine as engine_coding_engine,
            coding_engine_tool_schema as engine_coding_engine_tool_schema,
            make_coding_engine_tool_function as engine_make_coding_engine_tool_function,
            register_coding_engine_tool as engine_register_coding_engine_tool,
        )
    except Exception:
        engine_coding_engine = None
        engine_coding_engine_tool_schema = None
        engine_make_coding_engine_tool_function = None
        engine_register_coding_engine_tool = None


    def _coding_engine_unavailable_result() -> Dict[str, Any]:
        return {{"ok": False, "coding_engine_available": False, "error": "coding_engine.py is not importable. Put coding_engine.py beside tools.py."}}


    def coding_engine(action: str = "status", payload: Any = None, params: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        if engine_coding_engine is None:
            return _coding_engine_unavailable_result()
        if kwargs:
            params = dict(params or {{}})
            params.update(kwargs)
        return engine_coding_engine(action=action, payload=payload, params=params or {{}})


    def _coding_engine_schema() -> Dict[str, Any]:
        if engine_coding_engine_tool_schema is not None:
            return engine_coding_engine_tool_schema()
        return {{"type": "object", "properties": {{"action": {{"type": "string"}}, "payload": {{}}, "params": {{"type": "object"}}}}, "required": ["action"]}}


    # Register near your other tools:
    # tools.register(ToolSpec(
    #     name="coding_engine",
    #     description="Code-generation support brain: extracts tokens, snippets, symbols, syntax packs, and generation prompts.",
    #     parameters=_coding_engine_schema(),
    #     fn=coding_engine,
    # ))
    ''')


def template_tests(task: str, module_name: str = "generated_module") -> str:
    return _dedent_clean(f'''
    import {module_name}


    def test_module_imports():
        assert {module_name} is not None


    def test_placeholder_behavior():
        assert True, {task!r}
    ''')


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class CodingEngine:
    def __init__(self, config: Optional[CodingEngineConfig] = None) -> None:
        self.config = config or CodingEngineConfig()
        self._last_pack: Optional[SyntaxPack] = None

    def status(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "engine": "coding_engine",
            "version": ENGINE_VERSION,
            "config": self.config.to_dict(),
            "actions": CODE_GENERATION_ACTIONS,
            "safe_read_only": True,
            "executes_user_code": False,
            "optional_black_available": self._black_available(),
        }

    @staticmethod
    def _black_available() -> bool:
        try:
            import black  # noqa: F401
            return True
        except Exception:
            return False

    def _collect_code_inputs(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> List[CodeSnippet]:
        params = params or {}
        snippets: List[CodeSnippet] = []
        language = str(params.get("language") or params.get("lang") or "").strip().lower()
        max_snippets = _coerce_int(params.get("max_snippets"), self.config.max_snippets, 1, 500)
        max_chars = _coerce_int(params.get("max_chars"), self.config.max_chars, 1_000, 2_000_000)

        def add_text(text: str, source: str) -> None:
            if not text.strip():
                return
            lang = language or detect_language(text, source)
            snippets.extend(create_snippets_from_code(text, language=lang, source=source, max_snippets=max_snippets))
            if self.config.include_markdown_fences:
                snippets.extend(extract_markdown_code_fences(text, source=source))

        if isinstance(payload, dict):
            add_text(_safe_text(payload.get("code") or payload.get("text") or payload.get("source") or "", max_chars), str(payload.get("source_name") or payload.get("path") or "payload"))
            for row in payload.get("snippets") or []:
                if isinstance(row, dict):
                    add_text(_safe_text(row.get("code") or row.get("text") or "", max_chars), str(row.get("source") or "payload.snippet"))
        elif isinstance(payload, str):
            add_text(_safe_text(payload, max_chars), "payload")

        for key in ("code", "text", "source", "docs", "apidocs"):
            if params.get(key):
                add_text(_safe_text(params.get(key), max_chars), f"params.{key}")

        root = str(params.get("project_root") or params.get("root") or self.config.project_root or "").strip()
        if root:
            file_limit = _coerce_int(params.get("max_project_files"), self.config.max_project_files, 1, 5000)
            max_file_bytes = _coerce_int(params.get("max_file_bytes"), self.config.max_file_bytes, 1024, 5_000_000)
            include_tests = _coerce_bool(params.get("include_tests"), self.config.include_tests)
            include_docs = _coerce_bool(params.get("include_docs"), self.config.include_docs)
            base = Path(root).resolve()
            for path in _iter_project_files(root, max_files=file_limit, max_file_bytes=max_file_bytes, include_tests=include_tests, include_docs=include_docs):
                try:
                    rel = str(path.relative_to(base)) if base.exists() else str(path)
                    add_text(_read_text_file(path, max_file_bytes), rel)
                    if len(snippets) >= max_snippets * 4:
                        break
                except Exception:
                    continue
        return dedupe_snippets(snippets)[:max_snippets * 4]

    # Extraction actions
    def action_tokenize_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "", _coerce_int(params.get("max_chars"), self.config.max_chars, 1000, 2_000_000))
        language = str(params.get("language") or detect_language(code)).lower()
        max_tokens = _coerce_int(params.get("max_tokens"), 5000, 1, 200_000)
        tokens = tokenize_code(code, language=language, source=str(params.get("source") or "payload"), max_tokens=max_tokens)
        return {"ok": True, "language": language, "count": len(tokens), "tokens": [t.to_dict() for t in tokens]}

    def action_parse_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        if language != "python":
            return {"ok": True, "language": language, "note": "Generic parse uses regex extraction only.", "signatures": extract_generic_signatures(code, language)}
        try:
            tree = ast.parse(code)
            counts = Counter(type(n).__name__ for n in ast.walk(tree))
            return {"ok": True, "language": "python", "node_counts": dict(counts), "body_count": len(tree.body)}
        except SyntaxError as exc:
            return {"ok": False, "language": "python", "error": "SyntaxError", "message": str(exc), "line": exc.lineno, "offset": exc.offset, "text": exc.text}
        except Exception as exc:
            return {"ok": False, "language": "python", "error": str(exc)}

    def action_extract_symbols(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        source = str(params.get("source") or "payload")
        syms = extract_python_symbols(code, source) if language == "python" else extract_generic_symbols(code, language, source)
        return {"ok": True, "language": language, "count": len(syms), "symbols": [s.to_dict() for s in syms]}

    def action_extract_imports(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        imports = extract_python_imports(code) if language == "python" else extract_generic_imports(code, language)
        return {"ok": True, "language": language, "count": len(imports), "imports": imports}

    def action_extract_signatures(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        signatures = [s.signature for s in extract_python_symbols(code) if s.signature] if language == "python" else extract_generic_signatures(code, language)
        return {"ok": True, "language": language, "count": len(signatures), "signatures": signatures}

    def action_extract_docstrings(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        docs: List[Dict[str, Any]] = []
        if language == "python":
            try:
                module_doc = ast.get_docstring(ast.parse(code))
                if module_doc:
                    docs.append({"name": "<module>", "kind": "module", "line": 1, "docstring": module_doc})
            except Exception:
                pass
            for sym in extract_python_symbols(code):
                if sym.docstring:
                    docs.append({"name": sym.name, "kind": sym.kind, "line": sym.line, "docstring": sym.docstring})
        else:
            for m in re.finditer(r"(?s)/\*\*(.*?)\*/|'''(.*?)'''|\"\"\"(.*?)\"\"\"", code or ""):
                docs.append({"name": "comment", "kind": "doc", "line": code[:m.start()].count("\n") + 1, "docstring": next(g for g in m.groups() if g)})
        return {"ok": True, "language": language, "count": len(docs), "docstrings": docs}

    def action_extract_dependencies(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        if language == "python":
            deps = extract_python_dependencies(code)
        else:
            deps = sorted(set(x for imp in extract_generic_imports(code, language) for x in re.findall(r"[A-Za-z_][\w.\-/@]*", imp)))
        return {"ok": True, "language": language, "count": len(deps), "dependencies": deps}

    def action_extract_style(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        lines = code.splitlines()
        indent_counts = Counter()
        quote_counts = Counter()
        for line in lines:
            m = re.match(r"^(\s+)", line)
            if m:
                indent_counts[len(m.group(1).replace("\t", "    "))] += 1
            quote_counts["single"] += line.count("'")
            quote_counts["double"] += line.count('"')
        return {
            "ok": True,
            "line_count": len(lines),
            "avg_line_len": round(sum(len(x) for x in lines) / max(1, len(lines)), 2),
            "max_line_len": max([len(x) for x in lines] or [0]),
            "indent_counts": dict(indent_counts.most_common(10)),
            "preferred_quote": "double" if quote_counts["double"] >= quote_counts["single"] else "single",
            "has_type_hints": bool(re.search(r"def\s+\w+\([^)]*:\s*[^)]+\).*?(?:->|:)", code or "")),
            "has_dataclasses": "@dataclass" in code or "dataclass(" in code,
            "has_main_guard": "if __name__" in code,
        }

    def action_extract_patterns(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        patterns = extract_python_patterns(code) if language == "python" else []
        if "try" in code and "except" in code:
            patterns.append("try_except")
        if re.search(r"class\s+\w+", code):
            patterns.append("class_definition")
        if re.search(r"def\s+\w+|function\s+\w+|=>", code):
            patterns.append("function_definition")
        return {"ok": True, "language": language, "patterns": sorted(dict.fromkeys(patterns))}

    # Snippet/context actions
    def action_search_snippets(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        query = str(params.get("query") or params.get("task") or payload or "")
        language = str(params.get("language") or "").lower()
        snippets = self._collect_code_inputs(None if isinstance(payload, str) else payload, params)
        ranked = rank_snippets(dedupe_snippets(snippets), query=query, language=language, max_snippets=_coerce_int(params.get("max_snippets"), self.config.max_snippets, 1, 200))
        return {"ok": True, "query": query, "count": len(ranked), "snippets": [s.to_dict() for s in ranked]}

    def action_rank_snippets(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.action_search_snippets(payload, params)

    def action_dedupe_snippets(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        snippets = self._collect_code_inputs(payload, params or {})
        deduped = dedupe_snippets(snippets)
        return {"ok": True, "before": len(snippets), "after": len(deduped), "snippets": [s.to_dict() for s in deduped]}

    def _make_pack(self, payload: Any = None, params: Optional[Dict[str, Any]] = None, intent: str = "build_context_pack") -> SyntaxPack:
        params = params or {}
        task = str(params.get("task") or params.get("query") or (payload if isinstance(payload, str) else "") or "Generate code")
        language = str(params.get("language") or params.get("lang") or "python").lower()
        max_snippets = _coerce_int(params.get("max_snippets"), self.config.max_snippets, 1, 200)
        max_tokens = _coerce_int(params.get("max_tokens"), self.config.max_tokens, 200, 100_000)
        snippets = self._collect_code_inputs(None if isinstance(payload, str) else payload, params)
        if not snippets:
            snippets = [
                CodeSnippet(code=template_script(task), language="python", source="builtin.template", title="script template", patterns=["main_guard", "argparse"], token_count=_estimate_tokens(template_script(task))),
                CodeSnippet(code=template_engine(task), language="python", source="builtin.template", title="engine template", patterns=["tool_schema", "registry_pattern"], token_count=_estimate_tokens(template_engine(task))),
            ]
        ranked = rank_snippets(dedupe_snippets(snippets), query=task, language=language, max_snippets=max_snippets)
        selected: List[CodeSnippet] = []
        used_tokens = 0
        for sn in ranked:
            need = _estimate_tokens(sn.code) + 80
            if selected and used_tokens + need > max_tokens:
                continue
            selected.append(sn)
            used_tokens += need
            if used_tokens >= max_tokens:
                break
        all_code = "\n\n".join(s.code for s in selected)
        toks = tokenize_code(all_code, language=language, source="context_pack", max_tokens=min(max_tokens, 10_000))
        counter = Counter(t.text for t in toks if t.kind in {"NAME", "identifier", "keyword"} and len(t.text) > 1)
        high_tokens = [CodeToken(text=k, kind="keyword_or_identifier", language=language, score=float(v)) for k, v in counter.most_common(120)]
        imports = sorted(dict.fromkeys(x for s in selected for x in s.imports))[:80]
        symbols = sorted(dict.fromkeys(x for s in selected for x in s.symbols))[:120]
        signatures = sorted(dict.fromkeys(x for s in selected for x in s.signatures))[:120]
        patterns = sorted(dict.fromkeys(x for s in selected for x in s.patterns))[:80]
        constraints = list(params.get("constraints") or []) if isinstance(params.get("constraints"), list) else []
        constraints.extend([
            "Generate complete, runnable code unless the user asks for a fragment.",
            "Prefer explicit imports and typed function signatures for Python.",
            "Do not execute user/project code; only parse or validate syntax.",
            "Keep generated code self-contained and include a main guard for scripts.",
        ])
        guidance = [
            f"Task: {task}", f"Language: {language}",
            "Use snippets as syntax/style patterns, not mandatory exact code.",
            "Preserve old public signatures when generating GPTProject engine wrappers.",
        ]
        pack = SyntaxPack(task=task, language=language, intent=intent, snippets=selected, tokens=high_tokens, symbols=symbols, imports=imports, signatures=signatures, patterns=patterns, constraints=constraints, guidance=guidance, estimated_tokens=used_tokens)
        self._last_pack = pack
        return pack

    def action_build_context_pack(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"ok": True, "pack": self._make_pack(payload, params, "build_context_pack").to_dict()}

    def action_build_token_pack(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        pack = self._make_pack(payload, params, "build_token_pack")
        return {"ok": True, "task": pack.task, "language": pack.language, "tokens": [t.to_dict() for t in pack.tokens], "estimated_tokens": pack.estimated_tokens}

    def action_build_syntax_pack(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        pack = self._make_pack(payload, params, "build_syntax_pack")
        return {"ok": True, "task": pack.task, "language": pack.language, "imports": pack.imports, "symbols": pack.symbols, "signatures": pack.signatures, "patterns": pack.patterns, "snippets": [s.to_dict() for s in pack.snippets]}

    def action_make_generation_prompt(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        pack = self._make_pack(payload, params, "make_generation_prompt")
        max_chars = _coerce_int(params.get("max_prompt_chars"), 32_000, 4_000, 200_000)
        prompt = self._render_generation_prompt(pack)
        if len(prompt) > max_chars:
            prompt = prompt[:max_chars] + "\n\n[TRUNCATED BY coding_engine max_prompt_chars]\n"
        return {"ok": True, "prompt": prompt, "pack": pack.to_dict()}

    def _render_generation_prompt(self, pack: SyntaxPack) -> str:
        parts = [
            "You are generating code using this local context pack.",
            f"Task: {pack.task}", f"Language: {pack.language}", "", "Constraints:",
            *[f"- {c}" for c in pack.constraints], "", "High-value imports:",
            *[f"- {x}" for x in pack.imports[:40]], "", "High-value signatures:",
            *[f"- {x}" for x in pack.signatures[:60]], "", "Detected patterns:",
            *[f"- {x}" for x in pack.patterns[:60]], "", "Selected syntax snippets:",
        ]
        for i, sn in enumerate(pack.snippets, start=1):
            parts.append(f"\n--- snippet {i}: {sn.title} ({sn.source}:{sn.start_line}-{sn.end_line}) score={sn.score} ---")
            parts.append(f"```{sn.language}\n{sn.code.strip()}\n```")
        parts.append("\nNow generate the requested code. Return complete code only unless explanation is requested.")
        return "\n".join(parts)

    # Generation actions
    def _generation_params(self, payload: Any, params: Optional[Dict[str, Any]]) -> Tuple[str, str, str]:
        params = params or {}
        task = str(params.get("task") or params.get("query") or (payload if isinstance(payload, str) else "") or "Generate code")
        language = str(params.get("language") or "python").lower()
        name = re.sub(r"\W+", "_", str(params.get("name") or params.get("module_name") or "generated_code")).strip("_") or "generated_code"
        return task, language, name

    def _generated_result(self, action: str, code: str, language: str, task: str) -> Dict[str, Any]:
        return {"ok": True, "action": action, "language": language, "task": task, "code": code, "validation": self.action_validate_syntax(code, {"language": language})}

    def action_generate_script(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        task, language, name = self._generation_params(payload, params)
        code = template_script(task, name=name) if language == "python" else self._generic_comment_template(task, language, "script")
        return self._generated_result("generate_script", code, language, task)

    def action_generate_module(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        task, language, name = self._generation_params(payload, params)
        if language == "python":
            cls = "".join(p.capitalize() for p in name.split("_")) or "Generated"
            code = _dedent_clean(f'''
            {_module_header(name, task)}from dataclasses import dataclass
            from typing import Any, Dict, Optional


            @dataclass
            class {cls}Config:
                max_items: int = 100


            def process(payload: Any = None, config: Optional[{cls}Config] = None) -> Dict[str, Any]:
                """{task}"""
                config = config or {cls}Config()
                return {{"ok": True, "payload": payload, "max_items": config.max_items}}
            ''')
        else:
            code = self._generic_comment_template(task, language, "module")
        return self._generated_result("generate_module", code, language, task)

    def action_generate_class(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        task, language, name = self._generation_params(payload, params)
        class_name = str((params or {}).get("class_name") or name or "GeneratedWorker")
        class_name = "".join(p.capitalize() for p in re.split(r"\W+|_+", class_name) if p) or "GeneratedWorker"
        code = template_class(task, class_name) if language == "python" else self._generic_comment_template(task, language, "class")
        return self._generated_result("generate_class", code, language, task)

    def action_generate_function(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        task, language, name = self._generation_params(payload, params)
        fn = re.sub(r"\W+", "_", str((params or {}).get("function_name") or name or "generated_function")).strip("_") or "generated_function"
        code = template_function(task, fn) if language == "python" else self._generic_comment_template(task, language, "function")
        return self._generated_result("generate_function", code, language, task)

    def action_generate_cli(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.action_generate_script(payload, params)

    def action_generate_gui(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        task, language, _ = self._generation_params(payload, params)
        class_name = str((params or {}).get("class_name") or "GeneratedWindow")
        code = template_gui(task, class_name) if language == "python" else self._generic_comment_template(task, language, "gui")
        return self._generated_result("generate_gui", code, language, task)

    def action_generate_engine(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        task, language, name = self._generation_params(payload, params)
        code = template_engine(task, name) if language == "python" else self._generic_comment_template(task, language, "engine")
        return self._generated_result("generate_engine", code, language, task)

    def action_generate_tool_wrapper(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        code = template_tool_wrapper(str((params or {}).get("engine_module") or "coding_engine"))
        return self._generated_result("generate_tool_wrapper", code, "python", "tools.py integration wrapper for coding_engine")

    def action_generate_tests(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        task, _, name = self._generation_params(payload, params)
        module = re.sub(r"\W+", "_", str((params or {}).get("module_name") or name or "generated_module")).strip("_") or "generated_module"
        return self._generated_result("generate_tests", template_tests(task, module), "python", task)

    def action_generate_requirements(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        deps = extract_python_dependencies(code) if code else list(params.get("dependencies") or [])
        import sys
        stdlib = set(getattr(sys, "stdlib_module_names", set()))
        reqs = []
        for dep in deps:
            top = str(dep).split(".")[0].replace("-", "_")
            if top and top not in stdlib and top not in PY_BUILTINS and not top.startswith("_"):
                reqs.append(top.replace("_", "-"))
        reqs = sorted(dict.fromkeys(reqs))
        return {"ok": True, "count": len(reqs), "requirements": reqs, "text": "\n".join(reqs) + ("\n" if reqs else "")}

    def _generic_comment_template(self, task: str, language: str, kind: str) -> str:
        comment = "#" if language in {"python", "bash", "yaml", "toml"} else "//"
        return f"{comment} {kind} template for: {task}\n{comment} Language: {language}\n{comment} Add language-specific implementation here.\n"

    # Validation/repair/format/score
    def action_validate_syntax(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        if language != "python":
            return {"ok": True, "language": language, "syntax_checked": False, "note": "Only Python syntax validation is built in."}
        try:
            ast.parse(code)
            compile(code, str(params.get("filename") or "<coding_engine>"), "exec")
            return {"ok": True, "language": "python", "syntax_checked": True}
        except SyntaxError as exc:
            return {"ok": False, "language": "python", "syntax_checked": True, "error": "SyntaxError", "message": str(exc), "line": exc.lineno, "offset": exc.offset, "text": exc.text}
        except Exception as exc:
            return {"ok": False, "language": "python", "syntax_checked": True, "error": type(exc).__name__, "message": str(exc)}

    def action_explain_code_error(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        error = str((params or {}).get("error") or payload or "")
        lower = error.lower()
        notes = []
        if "nonetype" in lower and "attribute" in lower:
            notes.append("A dependency/object is None before attribute access; add import/dependency checks and clearer error messages.")
        if "syntaxerror" in lower or "invalid syntax" in lower:
            notes.append("Python syntax failed; run validate_syntax and inspect line/offset.")
        if "nameerror" in lower or "not defined" in lower:
            notes.append("A symbol is referenced before import/assignment; inspect imports and local names.")
        if "modulenotfounderror" in lower or "no module named" in lower:
            notes.append("Missing dependency or wrong interpreter; add requirement and install it in the running Python environment.")
        if "unexpected keyword" in lower:
            notes.append("Function/tool signature mismatch; inspect schema and wrapper parameter names.")
        if not notes:
            notes.append("Collect traceback, related source snippet, imports, and signatures, then build a context pack for repair.")
        return {"ok": True, "error": error, "notes": notes}

    def action_explain_syntax(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        validation = self.action_validate_syntax(payload, params)
        if validation.get("ok"):
            return {"ok": True, "syntax_ok": True, "explanation": "Python syntax parses and compiles."}
        text = validation.get("text") or ""
        offset = validation.get("offset") or 0
        pointer = text.rstrip("\n") + "\n" + " " * max(0, int(offset) - 1) + "^" if text and offset else ""
        msg = str(validation.get("message") or "").lower()
        suggestions = []
        if "expected ':'" in msg or "invalid syntax" in msg:
            suggestions.append("Check missing colon after def/class/if/for/while/try/except/with/match/case.")
        if "was never closed" in msg or "unexpected eof" in msg:
            suggestions.append("Check unclosed parentheses, brackets, braces, or triple-quoted strings.")
        if "indent" in msg:
            suggestions.append("Check indentation consistency and ensure blocks contain at least pass/return/body statements.")
        if not suggestions:
            suggestions.append("Inspect the reported line plus three lines above it.")
        return {"ok": True, "syntax_ok": False, "validation": validation, "pointer": pointer, "suggestions": suggestions}

    def action_repair_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        if language != "python":
            return {"ok": False, "error": "repair_code currently supports Python only.", "language": language}
        before = self.action_validate_syntax(code, {"language": "python"})
        repaired = code
        changes: List[str] = []
        if not before.get("ok"):
            lines = repaired.splitlines()
            block_rx = re.compile(r"^(\s*)(def|class|if|elif|else|for|while|try|except|finally|with|match|case)\b(.*?)(?<!:)\s*$")
            for i, line in enumerate(lines):
                if block_rx.match(line) and not line.strip().endswith(":"):
                    lines[i] = line.rstrip() + ":"
                    changes.append(f"added colon on line {i + 1}")
            out_lines: List[str] = []
            for i, line in enumerate(lines):
                out_lines.append(line)
                if line.rstrip().endswith(":"):
                    next_line = lines[i + 1] if i + 1 < len(lines) else ""
                    indent = len(line) - len(line.lstrip())
                    next_indent = len(next_line) - len(next_line.lstrip()) if next_line.strip() else -1
                    if i + 1 >= len(lines) or (next_line.strip() and next_indent <= indent):
                        out_lines.append(" " * (indent + 4) + "pass")
                        changes.append(f"inserted pass after line {i + 1}")
            repaired = "\n".join(out_lines) + "\n"
        after = self.action_validate_syntax(repaired, {"language": "python"})
        diff = "\n".join(difflib.unified_diff(code.splitlines(), repaired.splitlines(), fromfile="before.py", tofile="after.py", lineterm=""))
        return {"ok": bool(after.get("ok")), "language": "python", "before": before, "after": after, "changes": changes, "code": repaired, "diff": diff}

    def action_format_generated_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        formatted = _dedent_clean(code)
        formatter = "dedent"
        if language == "python":
            try:
                import black  # type: ignore
                formatted = black.format_str(formatted, mode=black.FileMode())
                formatter = "black"
            except Exception:
                pass
        return {"ok": True, "language": language, "formatter": formatter, "code": formatted, "validation": self.action_validate_syntax(formatted, {"language": language})}

    def action_score_generated_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        language = str(params.get("language") or detect_language(code)).lower()
        validation = self.action_validate_syntax(code, {"language": language})
        imports = extract_python_imports(code) if language == "python" else extract_generic_imports(code, language)
        sigs = [s.signature for s in extract_python_symbols(code) if s.signature] if language == "python" else extract_generic_signatures(code, language)
        score = 50.0 + (25 if validation.get("ok") else -30) + min(10, len(imports)) + min(15, len(sigs) * 2)
        if "TODO" in code:
            score -= 5
        if "if __name__" in code:
            score += 5
        score = max(0, min(100, score))
        notes = []
        if not validation.get("ok"):
            notes.append("Syntax validation failed; repair before use.")
        if not imports:
            notes.append("No imports detected; verify dependencies or self-contained behavior.")
        if not sigs:
            notes.append("No reusable function/class signatures detected.")
        if score >= 85:
            notes.append("Strong structural quality signals.")
        return {"ok": True, "language": language, "score": round(score, 2), "validation": validation, "imports_count": len(imports), "signatures_count": len(sigs), "notes": notes}

    def action_complete_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        prefix = _safe_text(params.get("prefix") or params.get("code") or payload or "", 240_000)
        completion = _safe_text(params.get("completion") or params.get("suffix") or params.get("append") or "", 240_000)
        task = str(params.get("task") or "complete this code")
        language = str(params.get("language") or detect_language(prefix)).lower()
        code = (prefix.rstrip() + "\n" + completion.lstrip()) if completion else prefix.rstrip()

        changes: List[str] = []
        if language == "python" and code:
            # Make incomplete Python fragments syntactically finishable without leaving TODO loops.
            lines = code.splitlines()
            if lines and lines[-1].rstrip().endswith(":"):
                indent = len(lines[-1]) - len(lines[-1].lstrip()) + 4
                lines.append(" " * indent + "pass")
                changes.append("inserted pass for trailing block header")
            code = "\n".join(lines).rstrip() + "\n"
            repaired = self.action_repair_code(code, {"language": "python"})
            if repaired.get("ok") and repaired.get("code"):
                code = str(repaired.get("code"))
                changes.extend(repaired.get("changes") or [])

        validation = self.action_validate_syntax(code, {"language": language})
        pack = self._make_pack({"code": code}, {**params, "task": task}, "complete_code")
        result = {
            "ok": bool(validation.get("ok", True)),
            "code": code,
            "final_code": code,
            "language": language,
            "validation": validation,
            "changes": changes,
            "pack": pack.to_dict(),
            "finished": True,
            "done": True,
            "action_complete": True,
            "should_continue": False,
            "requires_more_tool_calls": False,
            "stop_tool_loop": True,
            "next_action": "final_answer",
            "final_answer": code,
            "answer": code,
            "response": code,
        }
        return result

    def action_rewrite_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        instructions = str(params.get("instructions") or params.get("task") or "Rewrite for clarity without changing behavior.")
        pack = self._make_pack({"code": code}, {**params, "task": instructions}, "rewrite_code")
        prompt = self._render_generation_prompt(pack) + "\n\nOriginal code to rewrite:\n```\n" + code + "\n```"
        return {"ok": True, "prompt": prompt, "pack": pack.to_dict(), "note": "Use this prompt with GPT to produce rewritten code."}

    def action_convert_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        code = _safe_text(params.get("code") or payload or "")
        source_language = str(params.get("source_language") or detect_language(code)).lower()
        target_language = str(params.get("target_language") or params.get("language") or "python").lower()
        task = f"Convert code from {source_language} to {target_language}."
        pack = self._make_pack({"code": code}, {**params, "task": task, "language": target_language}, "convert_code")
        prompt = self._render_generation_prompt(pack) + f"\n\nConvert this {source_language} code to {target_language}:\n```{source_language}\n{code}\n```"
        return {"ok": True, "source_language": source_language, "target_language": target_language, "prompt": prompt, "pack": pack.to_dict()}


    # -----------------------------------------------------------------------
    # Finish/finalization actions
    # -----------------------------------------------------------------------
    def _payload_get(self, payload: Any, *keys: str, default: Any = None) -> Any:
        if isinstance(payload, dict):
            for key in keys:
                if key in payload and payload.get(key) is not None:
                    return payload.get(key)
        return default

    def _finalize_payload(
        self,
        *,
        final_answer: str = "",
        code: str = "",
        language: str = "",
        data: Optional[Dict[str, Any]] = None,
        note: str = "",
    ) -> Dict[str, Any]:
        """Create a result shape that tells a GPT/tool runtime the action is done."""
        language = (language or detect_language(code) if code else language or "text").lower()
        final_answer = _safe_text(final_answer or code or note or "Action completed.", 240_000)
        result: Dict[str, Any] = {
            "ok": True,
            "finished": True,
            "done": True,
            "action_complete": True,
            "should_continue": False,
            "requires_more_tool_calls": False,
            "requires_followup": False,
            "stop_tool_loop": True,
            "next_action": "final_answer",
            "tool_status": "complete",
            "final_answer": final_answer,
            "answer": final_answer,
            "response": final_answer,
            "assistant_message": final_answer,
            "language": language,
        }
        if code:
            result["code"] = code
            result["final_code"] = code
            result["validation"] = self.action_validate_syntax(code, {"language": language})
            try:
                result["score"] = self.action_score_generated_code(code, {"language": language}).get("score")
            except Exception:
                pass
        if note:
            result["note"] = note
        if data:
            result.update(data)
        return result

    def _normalize_finish_params(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Tuple[str, str, str]:
        params = params or {}
        code = _safe_text(
            params.get("final_code")
            or params.get("code")
            or params.get("generated_code")
            or self._payload_get(payload, "final_code", "code", "generated_code", default="")
            or "",
            240_000,
        )
        final_answer = _safe_text(
            params.get("final_answer")
            or params.get("answer")
            or params.get("message")
            or params.get("text")
            or self._payload_get(payload, "final_answer", "answer", "message", "text", default="")
            or (payload if isinstance(payload, str) and not code else "")
            or "",
            240_000,
        )
        language = str(params.get("language") or self._payload_get(payload, "language", default="") or detect_language(code) or "text").lower()
        return final_answer, code, language

    def action_finish_action(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Mark a coding-engine action as complete and return final-answer fields.

        This is intentionally redundant: many tool runtimes look for different
        keys.  Returning all of them prevents GPT from calling another tool just
        to say the action is finished.
        """
        params = params or {}
        final_answer, code, language = self._normalize_finish_params(payload, params)
        auto_format = _coerce_bool(params.get("auto_format"), True)
        if code and auto_format:
            formatted = self.action_format_generated_code(code, {"language": language})
            if formatted.get("ok") and formatted.get("code"):
                code = str(formatted.get("code"))
        note = str(params.get("note") or "Coding action finished; return final_answer to the user.")
        return self._finalize_payload(final_answer=final_answer, code=code, language=language, note=note)

    def action_finalize_result(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.action_finish_action(payload, params)

    def action_finish(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.action_finish_action(payload, params)

    def action_done(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.action_finish_action(payload, params)

    def action_final(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.action_finish_action(payload, params)

    def action_complete_action(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate or accept code, validate it, and return a final tool result.

        If `code`/`final_code` is supplied, it finalizes that code.  Otherwise it
        generates a script/module/class/function/engine template from `kind` and
        finalizes the generated result so GPT can stop using tools and answer.
        """
        params = dict(params or {})
        final_answer, code, language = self._normalize_finish_params(payload, params)
        if code or final_answer:
            return self.action_finish_action(payload, params)

        kind = str(params.get("kind") or params.get("template") or params.get("type") or "script").strip().lower()
        kind_aliases = {
            "code": "script", "cli": "script", "command": "script", "cmd": "script",
            "tool": "tool_wrapper", "wrapper": "tool_wrapper", "test": "tests", "requirements.txt": "requirements",
        }
        kind = kind_aliases.get(kind, kind)
        generate_action = f"generate_{kind}"
        method = getattr(self, f"action_{generate_action}", None)
        if method is None:
            method = self.action_generate_script
            generate_action = "generate_script"
        generated = method(payload=payload, params=params)
        gen_code = str(generated.get("code") or generated.get("text") or "") if isinstance(generated, dict) else str(generated)
        return self._finalize_payload(
            final_answer=gen_code or f"Completed action: {generate_action}",
            code=gen_code,
            language=str(generated.get("language") or language or "python") if isinstance(generated, dict) else language,
            data={"generated": generated, "completed_from_action": generate_action},
            note="Generated output was finalized so the GPT runtime can stop calling tools.",
        )

    def action_finish_generated_code(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.action_complete_action(payload, params)

    def action_plan_next_action(self, payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Small decision helper for GPT: choose whether to call another tool or finish."""
        params = params or {}
        has_code = bool(params.get("code") or self._payload_get(payload, "code", "final_code", default=""))
        has_answer = bool(params.get("answer") or params.get("final_answer") or self._payload_get(payload, "answer", "final_answer", default=""))
        if has_code or has_answer:
            return self._finalize_payload(
                final_answer="The available result is ready. Call finish_action/finalize_result or answer the user now.",
                data={"recommended_action": "finish_action", "should_call_tool": False},
            )
        return {
            "ok": True,
            "finished": False,
            "should_continue": True,
            "recommended_action": "build_context_pack",
            "reason": "No code or final answer was supplied yet.",
            "actions": CODE_GENERATION_ACTIONS,
        }

    def run(self, action: str = "status", payload: Any = None, params: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        if kwargs:
            params = dict(params or {})
            params.update(kwargs)
        params = params or {}
        action = (action or "status").strip().lower()
        aliases = {
            "help": "status",
            "actions": "status",
            "search_syntax": "search_snippets",
            "search_api_usage": "search_snippets",
            "build_context": "build_context_pack",
            "context_pack": "build_context_pack",
            "syntax_pack": "build_syntax_pack",
            "token_pack": "build_token_pack",
            "make_prompt": "make_generation_prompt",
            "prompt": "make_generation_prompt",
            "generate_code": "generate_script",
            "generate": "generate_script",
            "validate": "validate_syntax",
            "format_code": "format_generated_code",
            "score_code": "score_generated_code",
            "finish": "finish_action",
            "final": "finish_action",
            "done": "finish_action",
            "complete": "complete_action",
            "complete_task": "complete_action",
            "finalize": "finalize_result",
            "finalize_action": "finalize_result",
            "finish_code": "finish_generated_code",
            "final_code": "finish_generated_code",
        }
        action = aliases.get(action, action)
        if action == "status":
            return self.status()
        method = getattr(self, f"action_{action}", None)
        if method is None:
            return {"ok": False, "error": f"Unknown coding_engine action: {action}", "actions": CODE_GENERATION_ACTIONS}
        try:
            result = method(payload=payload, params=params)
            if isinstance(result, dict):
                result.setdefault("ok", True)
                result.setdefault("engine", "coding_engine")
                result.setdefault("action", action)
                # These fields let a GPT tool runtime stop cleanly after a successful action.
                result.setdefault("finished", True)
                result.setdefault("done", True)
                result.setdefault("action_complete", True)
                result.setdefault("should_continue", False)
                result.setdefault("requires_more_tool_calls", False)
                result.setdefault("requires_followup", False)
                result.setdefault("stop_tool_loop", True)
                result.setdefault("next_action", "final_answer")
                if "code" in result and "final_answer" not in result:
                    result["final_answer"] = result.get("code")
                if "prompt" in result and "assistant_instruction" not in result:
                    result["assistant_instruction"] = "Use this prompt/context internally, then answer the user directly without another tool call."
                if "final_answer" in result:
                    result.setdefault("answer", result.get("final_answer"))
                    result.setdefault("response", result.get("final_answer"))
                    result.setdefault("assistant_message", result.get("final_answer"))
                return result
            return {
                "ok": True,
                "engine": "coding_engine",
                "action": action,
                "result": result,
                "finished": True,
                "done": True,
                "action_complete": True,
                "should_continue": False,
                "requires_more_tool_calls": False,
                "stop_tool_loop": True,
                "next_action": "final_answer",
                "final_answer": str(result),
            }
        except Exception as exc:
            return {"ok": False, "engine": "coding_engine", "action": action, "error": str(exc), "traceback": traceback.format_exc()[-6000:]}


CODE_GENERATION_ACTIONS = [
    "status",
    "tokenize_code", "parse_code", "extract_symbols", "extract_imports", "extract_signatures",
    "extract_docstrings", "extract_dependencies", "extract_style", "extract_patterns",
    "search_snippets", "search_syntax", "search_api_usage", "rank_snippets", "dedupe_snippets",
    "build_token_pack", "build_syntax_pack", "build_context_pack", "make_generation_prompt",
    "generate_script", "generate_module", "generate_class", "generate_function", "generate_cli",
    "generate_gui", "generate_engine", "generate_tool_wrapper", "generate_tests", "generate_requirements",
    "complete_code", "complete_action", "finish_action", "finish_generated_code", "finalize_result",
    "finish", "done", "final", "plan_next_action",
    "repair_code", "rewrite_code", "convert_code", "explain_code_error", "explain_syntax",
    "validate_syntax", "format_generated_code", "score_generated_code",
]

_DEFAULT_ENGINE = CodingEngine()


def coding_engine(action: str = "status", payload: Any = None, params: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return _DEFAULT_ENGINE.run(action=action, payload=payload, params=params, **kwargs)


def coding_engine_tool_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action": {"type": "string", "description": "Coding engine action.", "enum": CODE_GENERATION_ACTIONS, "default": "build_context_pack"},
            "payload": {"description": "Code/text/snippets/task payload. May be a string or object."},
            "params": {
                "type": "object",
                "description": "Optional params: task, language, code, project_root, max_snippets, max_tokens, constraints, etc.",
                "properties": {
                    "task": {"type": "string"}, "query": {"type": "string"}, "language": {"type": "string", "default": "python"},
                    "code": {"type": "string"}, "text": {"type": "string"}, "project_root": {"type": "string"},
                    "max_snippets": {"type": "integer", "default": DEFAULT_MAX_SNIPPETS}, "max_tokens": {"type": "integer", "default": DEFAULT_MAX_TOKENS},
                    "constraints": {"type": "array", "items": {"type": "string"}}, "name": {"type": "string"},
                    "module_name": {"type": "string"}, "function_name": {"type": "string"}, "class_name": {"type": "string"},
                    "instructions": {"type": "string"}, "source_language": {"type": "string"}, "target_language": {"type": "string"},
                    "final_answer": {"type": "string"}, "final_code": {"type": "string"}, "kind": {"type": "string"},
                    "auto_format": {"type": "boolean", "default": True},
                },
            },
        },
        "required": ["action"],
    }


def make_coding_engine_tool_function() -> Callable[..., Dict[str, Any]]:
    return coding_engine


def register_coding_engine_tool(registry: Any) -> None:
    try:
        registry.register(ToolSpec(name="coding_engine", description="Code-generation support brain: extracts code tokens, snippets, symbols, syntax packs, and generation prompts.", parameters=coding_engine_tool_schema(), fn=coding_engine))  # type: ignore[name-defined]
    except NameError:
        registry.register({"name": "coding_engine", "description": "Code-generation support brain: extracts code tokens, snippets, symbols, syntax packs, and generation prompts.", "parameters": coding_engine_tool_schema(), "fn": coding_engine})


def coding_status() -> Dict[str, Any]:
    return coding_engine("status")


def coding_build_context_pack(task: str, language: str = "python", code: str = "", project_root: str = "", max_snippets: int = DEFAULT_MAX_SNIPPETS, max_tokens: int = DEFAULT_MAX_TOKENS) -> Dict[str, Any]:
    return coding_engine("build_context_pack", payload={"code": code}, params={"task": task, "language": language, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens})


def coding_make_generation_prompt(task: str, language: str = "python", code: str = "", project_root: str = "", max_snippets: int = DEFAULT_MAX_SNIPPETS, max_tokens: int = DEFAULT_MAX_TOKENS) -> Dict[str, Any]:
    return coding_engine("make_generation_prompt", payload={"code": code}, params={"task": task, "language": language, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens})


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Standalone coding_engine.py")
    parser.add_argument("action", nargs="?", default="status")
    parser.add_argument("payload", nargs="?", default="")
    parser.add_argument("--params", default="{}", help="JSON params object")
    ns = parser.parse_args()
    try:
        params = json.loads(ns.params or "{}")
    except Exception as exc:
        params = {"_params_error": str(exc)}
    print(json.dumps(coding_engine(ns.action, ns.payload, params), indent=2, ensure_ascii=False))
