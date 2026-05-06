from __future__ import annotations

import html
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from PyQt5.QtCore import QObject, QThread, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QDragEnterEvent, QDropEvent, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QDoubleSpinBox,
    QSpinBox,
)

from config import AppConfig
from memory import MemoryStore
from runtime import build_runtime, load_system_prompt

try:
    from provider_local import ProviderError
except Exception:
    class ProviderError(RuntimeError):
        pass

try:
    from provider_local import detect_ollama_host_from_env as _detect_ollama_host_from_env
except Exception:
    _detect_ollama_host_from_env = None

try:
    from provider_local import discover_ollama_models as _discover_ollama_models
except Exception:
    _discover_ollama_models = None


DARK_STYLESHEET = """
QWidget {
    background-color: #111827;
    color: #e5e7eb;
    font-family: Segoe UI, Inter, Arial;
    font-size: 13px;
}
QMainWindow, QTabWidget::pane, QFrame {
    background-color: #111827;
}
QLabel#TitleLabel {
    font-size: 22px;
    font-weight: 700;
    color: #f9fafb;
}
QLabel#MutedLabel {
    color: #94a3b8;
}
QLabel#SectionLabel {
    font-size: 16px;
    font-weight: 700;
    color: #f9fafb;
}
QLineEdit, QTextEdit, QPlainTextEdit, QListWidget, QComboBox, QSpinBox, QDoubleSpinBox, QTextBrowser {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 8px;
    selection-background-color: #2563eb;
}
QCheckBox {
    spacing: 8px;
    color: #e5e7eb;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
}
QPushButton {
    background-color: #2563eb;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 10px 14px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #1d4ed8;
}
QPushButton:disabled {
    background-color: #475569;
    color: #cbd5e1;
}
QPushButton#Secondary {
    background-color: #1f2937;
    border: 1px solid #334155;
}
QPushButton#Danger {
    background-color: #b91c1c;
}
QPushButton#Danger:hover {
    background-color: #991b1b;
}
QListWidget::item {
    border-radius: 8px;
    padding: 8px;
    margin: 2px 0;
}
QListWidget::item:selected {
    background-color: #1d4ed8;
}
QSplitter::handle {
    background-color: #1f2937;
}
QStatusBar {
    background-color: #0b1220;
    color: #cbd5e1;
}
QTabBar::tab {
    background: #0f172a;
    color: #cbd5e1;
    padding: 10px 14px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 4px;
}
QTabBar::tab:selected {
    background: #1d4ed8;
    color: white;
}
"""


ATTACHMENT_BEGIN = "<<GPTPROJECT_ATTACHMENTS>>"
ATTACHMENT_END = "<<END_GPTPROJECT_ATTACHMENTS>>"

SUPPORTED_TEXT_SUFFIXES = {
    ".txt", ".md", ".py", ".json", ".js", ".ts", ".tsx", ".jsx", ".html", ".css",
    ".scss", ".sql", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".log",
    ".csv", ".sh", ".bat", ".ps1", ".cs", ".cpp", ".c", ".h", ".hpp", ".java",
    ".kt", ".go", ".rs", ".php", ".rb", ".lua", ".swift", ".dart", ".toml",
}

MAX_FILE_CHARS = 120_000
MAX_TOTAL_ATTACHMENT_CHARS = 350_000

DISPLAY_BLOCK_RE = re.compile(
    r"(?is)^### Thinking\s*\n\n(?P<thinking>.*?)\n\n---\n\n### Answer\s*\n\n(?P<answer>.*)$"
)

TOOL_TRACE_SPLIT_RE = re.compile(
    r"(?is)\n\n---\n\n### Tool Trace\s*\n\n(?P<trace>.*)$"
)

FENCED_CODE_BLOCK_RE = re.compile(r"```([^\n`]*)\n(.*?)```", re.DOTALL)

COMPACT_THINKING_REPAIRS = [
    ("Theuserwants", "The user wants"),
    ("Theuser", "The user"),
    ("theuserwants", "the user wants"),
    ("theuser", "the user"),
    ("userwants", "user wants"),
    ("wantsreal", "wants real"),
    ("realWhatsApp", "real WhatsApp"),
    ("WhatsAppandTelegram", "WhatsApp and Telegram"),
    ("Telegramcommunities", "Telegram communities"),
    ("communities/groupsfor", "communities/groups for"),
    ("groupsfor", "groups for"),
    ("Theywant", "They want"),
    ("theywant", "they want"),
    ("wantjust", "want just"),
    ("theinvitelinks", "the invite links"),
    ("tothegroup", "to the group"),
    ("alsoinclude", "also include"),
    ("andtheywant", "and they want"),
    ("touseTor", "to use Tor"),
    ("useTor", "use Tor"),
    ("forthesearch", "for the search"),
    ("Letmesearch", "Let me search"),
    ("letmesearch", "let me search"),
    ("thesecommunities", "these communities"),
    ("usingboth", "using both"),
    ("bothregular", "both regular"),
    ("websearchandTorsearch", "web search and Tor search"),
    ("Torsearch", "Tor search"),
    ("toget", "to get"),
    ("comprehensiveresults", "comprehensive results"),
    ("results.I'llsearch", "results. I'll search"),
    ("I'llsearch", "I'll search"),
    ("forWhatsAppgroupsandTelegramgroups", "for WhatsApp groups and Telegram groups"),
    ("WhatsAppgroups", "WhatsApp groups"),
    ("Telegramgroups", "Telegram groups"),
    ("foreachcategory", "for each category"),
    ("Letmestart", "Let me start"),
    ("withmultiplesearches", "with multiple searches"),
    ("tofindreal", "to find real"),
    ("activegroups", "active groups"),
    ("resaleing", "reselling"),
    ("communties", "communities"),
    ("communitiesdealing", "communities dealing"),
    ("groupsdealing", "groups dealing"),
    ("gettingconnections", "getting connections"),
    ("networkingandgetting", "networking and getting"),
    ("fashionreselling", "fashion reselling"),
]


@dataclass
class AttachmentPayload:
    path: str
    name: str
    content: str
    warning: str = ""


def _cfg_get(config: AppConfig, name: str, default):
    return getattr(config, name, default)


def _cfg_bool(config: AppConfig, name: str, default: bool = False) -> bool:
    value = getattr(config, name, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return default


def normalize_native_ollama_base_url(base_url: str) -> str:
    raw = (base_url or "").strip().rstrip("/")
    if not raw:
        raw = "http://127.0.0.1:11434"

    lowered = raw.lower()
    if lowered.endswith("/api"):
        return raw[:-4]
    if lowered.endswith("/v1"):
        return raw[:-3]
    return raw


def detect_ollama_host_from_env(default: str = "http://127.0.0.1:11434") -> str:
    if callable(_detect_ollama_host_from_env):
        try:
            detected = _detect_ollama_host_from_env(default)
            return normalize_native_ollama_base_url(str(detected))
        except Exception:
            pass
    return normalize_native_ollama_base_url(default)


def discover_ollama_models(base_url: str) -> list[str]:
    if callable(_discover_ollama_models):
        models = _discover_ollama_models(base_url)
        return [str(m) for m in models]
    raise RuntimeError("discover_ollama_models is not available in provider_local.py")


def _apply_compact_repair_table(text: str) -> str:
    out = text or ""
    for before, after in sorted(COMPACT_THINKING_REPAIRS, key=lambda pair: len(pair[0]), reverse=True):
        out = out.replace(before, after)
    return out


def repair_compacted_thinking_text(text: str) -> str:
    raw = text or ""
    if not raw.strip():
        return ""

    out = raw.replace("\r\n", "\n").replace("\r", "\n")
    out = out.replace("\u200b", "").replace("\ufeff", "")
    out = re.sub(r"[ \t\f\v]+", " ", out)

    compact_score = 0
    if len(out) > 80:
        whitespace_count = len(re.findall(r"\s", out))
        if whitespace_count < max(3, len(out) // 45):
            compact_score += 1

    if re.search(
        r"(Theuser|userwants|WhatsAppandTelegram|Telegramcommunities|Letmesearch|foreachcategory)",
        out,
    ):
        compact_score += 2

    out = _apply_compact_repair_table(out)

    if compact_score:
        out = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", out)
        out = re.sub(r"(?<=[A-Za-z])(?=\d+[.)])", "\n", out)
        out = re.sub(r"(?<=[0-9])(?=[A-Za-z])", " ", out)

    brand_repairs = {
        "Whats App": "WhatsApp",
        "Whats app": "WhatsApp",
        "Tele Gram": "Telegram",
        "Tele gram": "Telegram",
        "Tor Search": "Tor search",
        "T Or": "Tor",
    }
    for before, after in brand_repairs.items():
        out = out.replace(before, after)

    out = _apply_compact_repair_table(out)

    out = re.sub(r":\s*(?=\d+[.)])", ":\n", out)
    out = re.sub(r"(?<!\n)(?=\b\d+[.)]\s*)", "\n", out)
    out = re.sub(r"\b(\d+)[.)]\s*", r"\1. ", out)
    out = re.sub(r"([.!?])\s*(?=[A-Z])", r"\1\n", out)
    out = re.sub(r"([.!?])\s*(?=I['’]ll\b)", r"\1\n", out)
    out = re.sub(r"([,;:])(?=\S)", r"\1 ", out)
    out = re.sub(r"\n{3,}", "\n\n", out)
    out = re.sub(r"[ \t]+\n", "\n", out)
    out = re.sub(r"\n[ \t]+", "\n", out)

    out = _apply_compact_repair_table(out)
    return out.strip()


def normalize_plain_text(text: str) -> str:
    out = text or ""
    out = out.replace("\r\n", "\n").replace("\r", "\n")
    out = re.sub(r"[ \t\f\v]+", " ", out)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


def parse_fenced_code_blocks(text: str) -> list[tuple[str, str, str]]:
    parts: list[tuple[str, str, str]] = []
    last_end = 0

    for match in FENCED_CODE_BLOCK_RE.finditer(text or ""):
        if match.start() > last_end:
            plain = text[last_end:match.start()]
            if plain:
                parts.append(("text", "", plain))

        language = (match.group(1) or "").strip()
        code = match.group(2).rstrip("\n")
        parts.append(("code", language, code))
        last_end = match.end()

    if last_end < len(text or ""):
        tail = text[last_end:]
        if tail:
            parts.append(("text", "", tail))

    if not parts:
        parts.append(("text", "", text or ""))

    return parts


def build_message_payload(user_text: str, attachments: list[AttachmentPayload]) -> str:
    base_text = user_text.strip() or "(attached files only)"
    if not attachments:
        return base_text

    parts = [base_text, "", ATTACHMENT_BEGIN]
    for attachment in attachments:
        parts.append(f"=== FILE: {attachment.name} ===")
        parts.append(f"PATH: {attachment.path}")
        if attachment.warning:
            parts.append(f"WARNING: {attachment.warning}")
        parts.append("CONTENT:")
        parts.append(attachment.content)
        parts.append("=== END FILE ===")
        parts.append("")
    parts.append(ATTACHMENT_END)
    return "\n".join(parts)


def extract_display_text_and_files(raw_text: str) -> tuple[str, list[str]]:
    if ATTACHMENT_BEGIN not in raw_text or ATTACHMENT_END not in raw_text:
        return raw_text, []

    before, _, remainder = raw_text.partition(ATTACHMENT_BEGIN)
    block, _, _ = remainder.partition(ATTACHMENT_END)
    files = re.findall(r"=== FILE: (.+?) ===", block)
    return before.strip(), files


def read_attachment_file(path_str: str) -> AttachmentPayload:
    path = Path(path_str)
    warning = ""

    if not path.exists():
        return AttachmentPayload(
            path=str(path),
            name=path.name or str(path),
            content="[File could not be found at send time.]",
            warning="Missing file",
        )

    suffix = path.suffix.lower()
    if suffix and suffix not in SUPPORTED_TEXT_SUFFIXES:
        warning = f"Extension {suffix} is not in the text/code allowlist; attempting text read anyway."

    raw = path.read_bytes()
    decoded = raw.decode("utf-8", errors="replace")

    if len(decoded) > MAX_FILE_CHARS:
        decoded = decoded[:MAX_FILE_CHARS]
        warning = (warning + " " if warning else "") + f"Truncated to {MAX_FILE_CHARS} characters."

    return AttachmentPayload(
        path=str(path.resolve()),
        name=path.name,
        content=decoded,
        warning=warning,
    )


def _text_to_html(text: str) -> str:
    return html.escape(text or "").replace("\n", "<br>")


def _render_text_and_code_chunks(
    text: str,
    text_color: str = "#f8fafc",
    *,
    thinking: bool = False,
) -> str:
    parts: list[str] = []

    for kind, language, chunk in parse_fenced_code_blocks(text or ""):
        if kind == "text":
            normalized = repair_compacted_thinking_text(chunk) if thinking else normalize_plain_text(chunk)
            if not normalized.strip():
                continue

            parts.append(
                f"""
                <div style="color:{text_color}; line-height:1.55; margin-bottom:8px; white-space:normal;">
                    {_text_to_html(normalized)}
                </div>
                """
            )
        else:
            lang = html.escape(language or "code")
            code_html = html.escape(chunk)

            parts.append(
                f"""
                <div style="
                    margin:8px 0;
                    background:#020617;
                    border:1px solid #334155;
                    border-radius:12px;
                    overflow:hidden;
                ">
                    <div style="
                        background:#0f172a;
                        color:#93c5fd;
                        font-weight:700;
                        padding:8px 12px;
                        border-bottom:1px solid #334155;
                    ">{lang}</div>
                    <pre style="
                        margin:0;
                        padding:10px 12px;
                        color:#e2e8f0;
                        white-space:pre-wrap;
                        word-wrap:break-word;
                        font-family:Consolas, 'Courier New', monospace;
                        font-size:12px;
                    ">{code_html}</pre>
                </div>
                """
            )

    return "".join(parts)


def _split_answer_and_trace(answer_text: str) -> tuple[str, str]:
    m = TOOL_TRACE_SPLIT_RE.search(answer_text or "")
    if not m:
        return answer_text or "", ""

    trace = (m.group("trace") or "").strip()
    answer = (answer_text[:m.start()] or "").strip()
    return answer, trace


def _render_tool_trace_panel(trace: str) -> str:
    if not trace.strip():
        return ""

    return f"""
    <div style="
        background:#020617;
        border:1px solid #334155;
        border-radius:12px;
        padding:10px 12px;
        margin:10px 0 4px 0;
    ">
        <div style="
            color:#a78bfa;
            font-size:12px;
            font-weight:800;
            letter-spacing:0.3px;
            margin-bottom:8px;
        ">Tool / Status</div>
        <div style="
            color:#cbd5e1;
            line-height:1.45;
            font-size:12px;
        ">
            {_render_text_and_code_chunks(trace, text_color="#cbd5e1")}
        </div>
    </div>
    """


def _render_thinking_panel(thinking: str) -> str:
    repaired = repair_compacted_thinking_text(thinking)
    if not repaired.strip():
        return ""

    return f"""
    <div style="
        background:#111827;
        border:1px solid #475569;
        border-radius:12px;
        padding:10px 12px;
        margin:4px 0 10px 0;
    ">
        <div style="
            color:#fbbf24;
            font-size:12px;
            font-weight:800;
            letter-spacing:0.3px;
            margin-bottom:8px;
        ">Thinking</div>
        <div style="
            color:#cbd5e1;
            line-height:1.55;
            font-size:12px;
        ">
            {_render_text_and_code_chunks(repaired, text_color="#cbd5e1", thinking=True)}
        </div>
    </div>
    """


def _render_answer_header() -> str:
    return """
    <div style="
        color:#93c5fd;
        font-size:12px;
        font-weight:800;
        letter-spacing:0.3px;
        margin:2px 0 8px 0;
    ">Answer</div>
    """


def _render_assistant_display_content(content: str, text_color: str) -> str:
    raw = content or ""
    m = DISPLAY_BLOCK_RE.match(raw.strip())

    if not m:
        answer, trace = _split_answer_and_trace(raw)
        rendered = _render_text_and_code_chunks(answer, text_color=text_color)
        if trace:
            rendered += _render_tool_trace_panel(trace)
        return rendered

    thinking = (m.group("thinking") or "").strip()
    answer_all = (m.group("answer") or "").strip()
    answer, trace = _split_answer_and_trace(answer_all)

    parts: list[str] = []
    parts.append(_render_thinking_panel(thinking))
    parts.append(_render_answer_header())
    parts.append(_render_text_and_code_chunks(answer, text_color=text_color))

    if trace:
        parts.append(_render_tool_trace_panel(trace))

    return "".join(parts)


def _format_live_assistant_text(
    thinking: str,
    answer: str,
    status: str,
    show_thinking: bool,
    show_tool_trace: bool,
) -> str:
    repaired_thinking = repair_compacted_thinking_text(thinking or "")
    answer = answer or ""
    status = status or ""

    parts: list[str] = []

    if show_thinking and repaired_thinking.strip():
        parts.append(
            "### Thinking\n\n"
            f"{repaired_thinking.strip()}\n\n"
            "---\n\n"
            "### Answer\n\n"
            f"{answer.strip() or '...'}"
        )
    else:
        parts.append(answer.strip() or "...")

    if show_tool_trace and status.strip():
        parts.append(f"\n\n---\n\n### Tool Trace\n\n{status.strip()}")

    return "\n".join(parts).strip()


def _message_to_html(speaker: str, raw_text: str, mine: bool, subtle: bool = False) -> str:
    display_text, attached_files = extract_display_text_and_files(raw_text or "")

    if subtle:
        bubble_bg = "#111827"
        border = "#475569"
        speaker_color = "#94a3b8"
        text_color = "#cbd5e1"
    else:
        bubble_bg = "#1d4ed8" if mine else "#0f172a"
        border = "#1d4ed8" if mine else "#334155"
        speaker_color = "#bfdbfe" if mine else "#cbd5e1"
        text_color = "#f8fafc"

    align = "right" if mine else "left"
    max_width = "860px" if mine else "940px"

    parts: list[str] = []

    parts.append(
        f"""
        <div style="text-align:{align}; margin:0 0 12px 0;">
          <div style="
              display:inline-block;
              max-width:{max_width};
              width:fit-content;
              text-align:left;
              background:{bubble_bg};
              border:1px solid {border};
              border-radius:14px;
              padding:12px;
              box-sizing:border-box;
          ">
            <div style="color:{speaker_color}; font-size:11px; font-weight:800; margin-bottom:8px;">
              {html.escape(speaker)}
            </div>
        """
    )

    if attached_files:
        parts.append(
            f"""
            <div style="
                color:#bfdbfe;
                background:#0b1220;
                border:1px solid #334155;
                border-radius:10px;
                padding:8px;
                font-weight:600;
                margin-bottom:8px;
            ">
                Attached: {html.escape(", ".join(attached_files))}
            </div>
            """
        )

    content = display_text.strip()
    if not content and attached_files:
        content = "(files attached)"

    if speaker == "Assistant" and not mine:
        parts.append(_render_assistant_display_content(content, text_color=text_color))
    else:
        parts.append(_render_text_and_code_chunks(content, text_color=text_color))

    parts.append("</div></div>")
    return "".join(parts)


class ChatWorker(QObject):
    snapshot = pyqtSignal(str, str)
    status = pyqtSignal(str)
    finished = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, config: AppConfig, session_id: str, user_text: str) -> None:
        super().__init__()
        self.config = config
        self.session_id = session_id
        self.user_text = user_text

    def run(self) -> None:
        try:
            runtime = build_runtime(self.config)

            if hasattr(runtime, "ask_stream") and getattr(self.config, "stream_chat", True):
                final_text = ""

                for event in runtime.ask_stream(self.session_id, self.user_text):
                    kind = event.get("type")

                    if kind == "snapshot":
                        self.snapshot.emit(
                            event.get("thinking", "") or "",
                            event.get("answer", "") or "",
                        )

                    elif kind == "status":
                        self.status.emit(event.get("text", "") or "")

                    elif kind == "tool_result":
                        name = event.get("name", "") or "tool"
                        self.status.emit(f"Tool finished: {name}")

                    elif kind == "final":
                        final_text = event.get("text", "") or ""

                self.finished.emit(final_text)
            else:
                reply = runtime.ask(self.session_id, self.user_text)
                self.finished.emit(reply)

        except ProviderError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Unexpected error: {exc}")


class ModelDiscoveryWorker(QObject):
    finished = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url

    def run(self) -> None:
        try:
            models = discover_ollama_models(self.base_url)
            self.finished.emit(models)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    RENDER_DEBOUNCE_MS = 120

    def __init__(self) -> None:
        super().__init__()

        self.config = AppConfig.load()
        self.config.base_url = normalize_native_ollama_base_url(self.config.base_url)
        self.memory = MemoryStore(self.config.db_path)
        self.current_session_id = self.config.default_session

        self._thread: Optional[QThread] = None
        self._worker: Optional[ChatWorker] = None
        self._model_thread: Optional[QThread] = None
        self._model_worker: Optional[ModelDiscoveryWorker] = None

        self._request_running = False
        self._show_loading_placeholder = False

        self._chat_cache_key: Optional[tuple] = None
        self._last_rendered_html = ""
        self._pending_render_force_bottom = False
        self._pending_render_preserve_scroll = True

        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.timeout.connect(self._flush_scheduled_render)

        self.pending_attachments: list[AttachmentPayload] = []
        self.pending_user_payload: str = ""

        self.live_thinking_text = ""
        self.live_answer_text = ""
        self.live_status_text = ""

        self.setAcceptDrops(True)
        self.setWindowTitle("GPTProject Pro - Streaming Ollama Chat")
        self.resize(self.config.window_width, self.config.window_height)
        self.setStyleSheet(DARK_STYLESHEET)

        self._build_ui()
        self.refresh_session_list(select_session=self.current_session_id)
        self.load_session_into_chat(self.current_session_id)
        self.reload_prompt_editor()
        self.update_status_banner("Ready.")

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)

        header = QHBoxLayout()

        title = QLabel("GPTProject Pro")
        title.setObjectName("TitleLabel")

        subtitle = QLabel(
            "Streaming Ollama-style local chat with stable QTextBrowser layout, readable thinking, and no scroll jumping."
        )
        subtitle.setObjectName("MutedLabel")
        subtitle.setWordWrap(True)

        title_box = QVBoxLayout()
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box, 1)

        self.detect_button = QPushButton("Detect Ollama")
        self.detect_button.setObjectName("Secondary")
        self.detect_button.clicked.connect(self.detect_ollama)
        header.addWidget(self.detect_button)

        self.save_config_button = QPushButton("Save Config")
        self.save_config_button.clicked.connect(self.save_settings)
        header.addWidget(self.save_config_button)

        root_layout.addLayout(header)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_sidebar())
        splitter.addWidget(self._build_main_tabs())
        splitter.setSizes([300, 980])

        root_layout.addWidget(splitter, 1)

        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())

    def _build_sidebar(self) -> QWidget:
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        label = QLabel("Sessions")
        label.setObjectName("SectionLabel")
        layout.addWidget(label)

        self.session_list = QListWidget()
        self.session_list.itemSelectionChanged.connect(self.on_session_selected)
        layout.addWidget(self.session_list, 1)

        row1 = QHBoxLayout()

        self.new_session_button = QPushButton("New")
        self.new_session_button.setObjectName("Secondary")
        self.new_session_button.clicked.connect(self.new_session)

        self.refresh_sessions_button = QPushButton("Refresh")
        self.refresh_sessions_button.setObjectName("Secondary")
        self.refresh_sessions_button.clicked.connect(self.refresh_session_list)

        row1.addWidget(self.new_session_button)
        row1.addWidget(self.refresh_sessions_button)
        layout.addLayout(row1)

        row2 = QHBoxLayout()

        self.load_session_button = QPushButton("Reload")
        self.load_session_button.setObjectName("Secondary")
        self.load_session_button.clicked.connect(lambda: self.load_session_into_chat(self.current_session_id))

        self.clear_session_button = QPushButton("Clear")
        self.clear_session_button.setObjectName("Danger")
        self.clear_session_button.clicked.connect(self.clear_current_session)

        row2.addWidget(self.load_session_button)
        row2.addWidget(self.clear_session_button)
        layout.addLayout(row2)

        help_text = QLabel("Drop text/code files into the window or use Attach Files.")
        help_text.setObjectName("MutedLabel")
        help_text.setWordWrap(True)
        layout.addWidget(help_text)

        return panel

    def _build_main_tabs(self) -> QWidget:
        tabs = QTabWidget()
        tabs.addTab(self._build_chat_tab(), "Chat")
        tabs.addTab(self._build_settings_tab(), "Settings")
        return tabs

    def _build_chat_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        info_row = QHBoxLayout()

        self.session_badge = QLabel()
        self.session_badge.setStyleSheet("font-size: 14px; font-weight: 700;")

        self.backend_badge = QLabel()
        self.backend_badge.setObjectName("MutedLabel")

        info_row.addWidget(self.session_badge)
        info_row.addStretch(1)
        info_row.addWidget(self.backend_badge)

        layout.addLayout(info_row)

        self.chat_view = QTextBrowser()
        self.chat_view.setOpenExternalLinks(False)
        self.chat_view.setReadOnly(True)
        self.chat_view.setUndoRedoEnabled(False)
        self.chat_view.document().setDocumentMargin(12)
        self.chat_view.setStyleSheet("""
            QTextBrowser {
                background: #0b1220;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 4px;
                color: #e5e7eb;
                selection-background-color: #2563eb;
            }
        """)
        layout.addWidget(self.chat_view, 1)

        attachments_label = QLabel("Pending attachments")
        attachments_label.setStyleSheet("font-size: 14px; font-weight: 700;")
        layout.addWidget(attachments_label)

        self.attachment_list = QListWidget()
        self.attachment_list.setFixedHeight(96)
        layout.addWidget(self.attachment_list)

        attach_row = QHBoxLayout()

        self.attach_files_button = QPushButton("Attach Files")
        self.attach_files_button.setObjectName("Secondary")
        self.attach_files_button.clicked.connect(self.attach_files)

        self.remove_attachment_button = QPushButton("Remove Selected")
        self.remove_attachment_button.setObjectName("Secondary")
        self.remove_attachment_button.clicked.connect(self.remove_selected_attachment)

        self.clear_attachments_button = QPushButton("Clear Attachments")
        self.clear_attachments_button.setObjectName("Secondary")
        self.clear_attachments_button.clicked.connect(self.clear_attachments)

        attach_row.addWidget(self.attach_files_button)
        attach_row.addWidget(self.remove_attachment_button)
        attach_row.addWidget(self.clear_attachments_button)
        attach_row.addStretch(1)

        layout.addLayout(attach_row)

        self.prompt_input = QTextEdit()
        self.prompt_input.setPlaceholderText("Message the assistant... You can attach files before sending.")
        self.prompt_input.setFixedHeight(150)
        layout.addWidget(self.prompt_input)

        button_row = QHBoxLayout()
        button_row.addStretch(1)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        button_row.addWidget(self.send_button)

        layout.addLayout(button_row)

        return page

    def _build_settings_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)

        form_panel = QFrame()
        form_layout = QFormLayout(form_panel)
        form_layout.setContentsMargins(10, 10, 10, 10)
        form_layout.setSpacing(10)

        self.base_url_input = QLineEdit(self.config.base_url)

        self.model_input = QComboBox()
        self.model_input.setEditable(True)
        self.model_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.model_input.setEditText(self.config.model)

        self.api_key_input = QLineEdit(self.config.api_key)
        self.api_key_input.setPlaceholderText("Unused for native Ollama unless your gateway needs it")

        self.temperature_input = QDoubleSpinBox()
        self.temperature_input.setRange(0.0, 2.0)
        self.temperature_input.setSingleStep(0.05)
        self.temperature_input.setValue(float(self.config.temperature))

        self.max_history_input = QSpinBox()
        self.max_history_input.setRange(1, 200)
        self.max_history_input.setValue(int(self.config.max_history))

        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(5, 100000)
        self.timeout_input.setValue(int(self.config.request_timeout_sec))

        self.db_path_input = QLineEdit(self.config.db_path)
        self.prompt_path_input = QLineEdit(self.config.prompt_path)
        self.default_session_input = QLineEdit(self.config.default_session)

        self.tor_socks_url_input = QLineEdit(
            str(_cfg_get(self.config, "tor_socks_url", "socks5h://127.0.0.1:9150"))
        )

        self.prefer_tor_for_web_checkbox = QCheckBox("Route normal web/search tools through Tor")
        self.prefer_tor_for_web_checkbox.setChecked(_cfg_bool(self.config, "prefer_tor_for_web", False))

        self.show_thinking_checkbox = QCheckBox("Show model thinking in chat")
        self.show_thinking_checkbox.setChecked(_cfg_bool(self.config, "show_thinking", True))

        self.show_tool_trace_checkbox = QCheckBox("Show tool-call trace/status in chat")
        self.show_tool_trace_checkbox.setChecked(_cfg_bool(self.config, "show_tool_trace", False))

        self.stream_chat_checkbox = QCheckBox("Stream chat like Ollama")
        self.stream_chat_checkbox.setChecked(_cfg_bool(self.config, "stream_chat", True))

        form_layout.addRow("Base URL", self.base_url_input)
        form_layout.addRow("Model", self.model_input)
        form_layout.addRow("API Key", self.api_key_input)
        form_layout.addRow("Temperature", self.temperature_input)
        form_layout.addRow("Max History", self.max_history_input)
        form_layout.addRow("Timeout (sec)", self.timeout_input)
        form_layout.addRow("DB Path", self.db_path_input)
        form_layout.addRow("Prompt Path", self.prompt_path_input)
        form_layout.addRow("Default Session", self.default_session_input)
        form_layout.addRow("Tor SOCKS URL", self.tor_socks_url_input)
        form_layout.addRow("Prefer Tor", self.prefer_tor_for_web_checkbox)
        form_layout.addRow("Visible Thinking", self.show_thinking_checkbox)
        form_layout.addRow("Tool Trace / Status", self.show_tool_trace_checkbox)
        form_layout.addRow("Streaming", self.stream_chat_checkbox)

        outer.addWidget(form_panel)

        button_row = QHBoxLayout()

        self.load_models_button = QPushButton("Load Installed Models")
        self.load_models_button.setObjectName("Secondary")
        self.load_models_button.clicked.connect(self.load_models_from_ollama)

        self.reload_config_button = QPushButton("Reload Saved Config")
        self.reload_config_button.setObjectName("Secondary")
        self.reload_config_button.clicked.connect(self.reload_settings_from_disk)

        self.save_prompt_button = QPushButton("Save Prompt")
        self.save_prompt_button.setObjectName("Secondary")
        self.save_prompt_button.clicked.connect(self.save_prompt)

        button_row.addWidget(self.load_models_button)
        button_row.addWidget(self.reload_config_button)
        button_row.addWidget(self.save_prompt_button)

        outer.addLayout(button_row)

        prompt_label = QLabel("System Prompt")
        prompt_label.setObjectName("SectionLabel")
        outer.addWidget(prompt_label)

        prompt_hint = QLabel(
            "This keeps the original chat-window layout, but throttles streamed updates so thinking text does not flash or force-scroll."
        )
        prompt_hint.setObjectName("MutedLabel")
        prompt_hint.setWordWrap(True)
        outer.addWidget(prompt_hint)

        self.prompt_editor = QPlainTextEdit()
        self.prompt_editor.setPlaceholderText("Edit the system prompt used for every chat call.")
        outer.addWidget(self.prompt_editor, 1)

        return page

    def update_status_banner(self, message: str) -> None:
        self.session_badge.setText(f"Session: {self.current_session_id or '(none)'}")

        thinking_state = "thinking:on" if _cfg_bool(self.config, "show_thinking", True) else "thinking:off"
        trace_state = "trace:on" if _cfg_bool(self.config, "show_tool_trace", False) else "trace:off"
        stream_state = "stream:on" if _cfg_bool(self.config, "stream_chat", True) else "stream:off"
        tor_state = "tor:web" if _cfg_bool(self.config, "prefer_tor_for_web", False) else "tor:manual"

        self.backend_badge.setText(
            f"{self.config.model} | {normalize_native_ollama_base_url(self.config.base_url)} | "
            f"{stream_state} | {thinking_state} | {trace_state} | {tor_state}"
        )

        self.statusBar().showMessage(message)

    def build_config_from_form(self) -> AppConfig:
        return AppConfig(
            base_url=normalize_native_ollama_base_url(self.base_url_input.text().strip() or self.config.base_url),
            model=self.model_input.currentText().strip() or self.config.model,
            api_key=self.api_key_input.text().strip() or "ollama",
            temperature=float(self.temperature_input.value()),
            max_history=int(self.max_history_input.value()),
            db_path=self.db_path_input.text().strip() or self.config.db_path,
            prompt_path=self.prompt_path_input.text().strip() or self.config.prompt_path,
            request_timeout_sec=int(self.timeout_input.value()),
            settings_path=self.config.settings_path,
            default_session=self.default_session_input.text().strip() or "default-session",
            window_width=self.width(),
            window_height=self.height(),
            tor_socks_url=self.tor_socks_url_input.text().strip() or "socks5h://127.0.0.1:9150",
            prefer_tor_for_web=bool(self.prefer_tor_for_web_checkbox.isChecked()),
            show_thinking=bool(self.show_thinking_checkbox.isChecked()),
            show_tool_trace=bool(self.show_tool_trace_checkbox.isChecked()),
            stream_chat=bool(self.stream_chat_checkbox.isChecked()),
        )

    def apply_config_to_form(self, config: AppConfig) -> None:
        self.base_url_input.setText(normalize_native_ollama_base_url(config.base_url))
        self.model_input.setEditText(config.model)
        self.api_key_input.setText(config.api_key)
        self.temperature_input.setValue(float(config.temperature))
        self.max_history_input.setValue(int(config.max_history))
        self.timeout_input.setValue(int(config.request_timeout_sec))
        self.db_path_input.setText(config.db_path)
        self.prompt_path_input.setText(config.prompt_path)
        self.default_session_input.setText(config.default_session)
        self.tor_socks_url_input.setText(str(_cfg_get(config, "tor_socks_url", "socks5h://127.0.0.1:9150")))
        self.prefer_tor_for_web_checkbox.setChecked(_cfg_bool(config, "prefer_tor_for_web", False))
        self.show_thinking_checkbox.setChecked(_cfg_bool(config, "show_thinking", True))
        self.show_tool_trace_checkbox.setChecked(_cfg_bool(config, "show_tool_trace", False))
        self.stream_chat_checkbox.setChecked(_cfg_bool(config, "stream_chat", True))

    def save_settings(self) -> None:
        self.config = self.build_config_from_form()
        self.config.save()

        self.memory = MemoryStore(self.config.db_path)
        self.current_session_id = self.default_session_input.text().strip() or self.current_session_id

        self.update_status_banner(f"Saved config to {self.config.settings_path}")
        self.refresh_session_list(select_session=self.current_session_id)
        self._invalidate_render_cache()
        self.render_chat(force=True, force_bottom=False, preserve_scroll=True)

    def reload_settings_from_disk(self) -> None:
        self.config = AppConfig.load(self.config.settings_path)
        self.config.base_url = normalize_native_ollama_base_url(self.config.base_url)

        self.apply_config_to_form(self.config)

        self.memory = MemoryStore(self.config.db_path)
        self.current_session_id = self.config.default_session

        self.reload_prompt_editor()
        self.refresh_session_list(select_session=self.current_session_id)
        self.load_session_into_chat(self.current_session_id)
        self.update_status_banner("Reloaded saved config.")

    def reload_prompt_editor(self) -> None:
        try:
            self.prompt_editor.setPlainText(load_system_prompt(self.config.prompt_path))
        except Exception as exc:
            self.prompt_editor.setPlainText("")
            self.update_status_banner(f"Could not load prompt: {exc}")

    def save_prompt(self) -> None:
        cfg = self.build_config_from_form()

        prompt_path = cfg.prompt_file
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(self.prompt_editor.toPlainText(), encoding="utf-8")

        self.config = cfg
        self.config.save()

        self.update_status_banner(f"Saved prompt to {prompt_path}")

    def detect_ollama(self) -> None:
        detected = detect_ollama_host_from_env(self.base_url_input.text().strip() or self.config.base_url)
        self.base_url_input.setText(normalize_native_ollama_base_url(detected))
        self.update_status_banner(f"Detected Ollama base URL: {detected}")
        self.load_models_from_ollama()

    def _cleanup_model_thread_refs(self) -> None:
        self._model_worker = None
        self._model_thread = None
        self.detect_button.setEnabled(True)
        self.load_models_button.setEnabled(True)

    def load_models_from_ollama(self) -> None:
        if self._model_thread is not None and self._model_thread.isRunning():
            return

        base_url = normalize_native_ollama_base_url(self.base_url_input.text().strip() or self.config.base_url)

        self.detect_button.setEnabled(False)
        self.load_models_button.setEnabled(False)
        self.update_status_banner("Checking Ollama models in the background...")

        self._model_thread = QThread(self)
        self._model_worker = ModelDiscoveryWorker(base_url)
        self._model_worker.moveToThread(self._model_thread)

        self._thread_connect(self._model_thread.started, self._model_worker.run)
        self._thread_connect(self._model_worker.finished, self.on_models_loaded)
        self._thread_connect(self._model_worker.failed, self.on_models_failed)
        self._thread_connect(self._model_worker.finished, self._model_thread.quit)
        self._thread_connect(self._model_worker.failed, self._model_thread.quit)
        self._thread_connect(self._model_thread.finished, self._cleanup_model_thread_refs)

        self._model_thread.start()

    def on_models_loaded(self, models: list) -> None:
        current = self.model_input.currentText().strip()

        self.model_input.clear()
        self.model_input.addItems([str(m) for m in models])

        if current:
            if current not in models:
                self.model_input.addItem(current)
            self.model_input.setCurrentText(current)

        self.update_status_banner(f"Loaded {len(models)} installed model(s) from Ollama.")

    def on_models_failed(self, message: str) -> None:
        self.update_status_banner("Failed to load models from Ollama.")
        QMessageBox.warning(self, "Ollama Detection", f"Could not load installed models.\n\n{message}")

    def attach_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Attach files")
        if not paths:
            return
        self.add_attachments(paths)

    def add_attachments(self, paths: list[str]) -> None:
        total_chars = sum(len(a.content) for a in self.pending_attachments)

        for path in paths:
            try:
                attachment = read_attachment_file(path)
            except Exception as exc:
                QMessageBox.warning(self, "Attachment Error", f"Could not read:\n{path}\n\n{exc}")
                continue

            if total_chars + len(attachment.content) > MAX_TOTAL_ATTACHMENT_CHARS:
                attachment.warning = (
                    (attachment.warning + " " if attachment.warning else "")
                    + f"Skipped because total attachment budget is {MAX_TOTAL_ATTACHMENT_CHARS} characters."
                )
                attachment.content = "[Skipped due to total attachment budget.]"

            total_chars += len(attachment.content)
            self.pending_attachments.append(attachment)

        self.refresh_attachment_list()
        self.update_status_banner(f"Attached {len(self.pending_attachments)} file(s).")

    def remove_selected_attachment(self) -> None:
        selected_rows = sorted({item.row() for item in self.attachment_list.selectedIndexes()}, reverse=True)
        if not selected_rows:
            return

        for row in selected_rows:
            if 0 <= row < len(self.pending_attachments):
                self.pending_attachments.pop(row)

        self.refresh_attachment_list()
        self.update_status_banner("Removed selected attachment(s).")

    def clear_attachments(self) -> None:
        self.pending_attachments.clear()
        self.refresh_attachment_list()
        self.update_status_banner("Cleared pending attachments.")

    def refresh_attachment_list(self) -> None:
        self.attachment_list.clear()
        for attachment in self.pending_attachments:
            text = attachment.name
            if attachment.warning:
                text += f"  ·  {attachment.warning}"
            self.attachment_list.addItem(text)

    def refresh_session_list(self, select_session: Optional[str] = None) -> None:
        select_session = select_session or self.current_session_id
        sessions = self.memory.list_sessions()

        self.session_list.blockSignals(True)
        self.session_list.clear()

        seen = False

        for entry in sessions:
            session_id = entry["session_id"]
            preview = entry["preview"].replace("\n", " ").strip()
            count = int(entry["message_count"])

            item = QListWidgetItem(f"{session_id}\n{preview[:56]}  ·  {count} msgs")
            item.setData(Qt.UserRole, session_id)
            self.session_list.addItem(item)

            if session_id == select_session:
                self.session_list.setCurrentItem(item)
                seen = True

        if not sessions and select_session:
            item = QListWidgetItem(f"{select_session}\n(empty session)")
            item.setData(Qt.UserRole, select_session)
            self.session_list.addItem(item)
            self.session_list.setCurrentItem(item)
            seen = True

        if sessions and not seen:
            self.session_list.setCurrentRow(0)
            current_item = self.session_list.currentItem()
            if current_item:
                self.current_session_id = current_item.data(Qt.UserRole)

        self.session_list.blockSignals(False)

    def on_session_selected(self) -> None:
        item = self.session_list.currentItem()
        if not item:
            return

        if self._request_is_active():
            return

        self.current_session_id = item.data(Qt.UserRole)
        self.load_session_into_chat(self.current_session_id)

    def _last_stored_message_matches_pending_user(self) -> bool:
        if not self.pending_user_payload:
            return False

        messages = self.memory.get_session_messages(self.current_session_id)
        if not messages:
            return False

        last = messages[-1]
        return last.get("role") == "user" and (last.get("content") or "") == self.pending_user_payload

    def _get_scroll_state(self) -> tuple[int, int]:
        bar = self.chat_view.verticalScrollBar()
        return bar.value(), bar.maximum()

    def _restore_scroll_state(
        self,
        old_value: int,
        old_maximum: int,
        *,
        force_bottom: bool = False,
        preserve_exact_position: bool = True,
    ) -> None:
        bar = self.chat_view.verticalScrollBar()

        if force_bottom:
            QTimer.singleShot(0, lambda: bar.setValue(bar.maximum()))
            return

        if preserve_exact_position:
            QTimer.singleShot(0, lambda: bar.setValue(min(old_value, bar.maximum())))
            return

        delta = bar.maximum() - old_maximum
        QTimer.singleShot(0, lambda: bar.setValue(max(0, old_value + delta)))

    def _invalidate_render_cache(self) -> None:
        self._chat_cache_key = None
        self._last_rendered_html = ""

    def _schedule_render_chat(self, *, force_bottom: bool = False, preserve_scroll: bool = True) -> None:
        self._pending_render_force_bottom = self._pending_render_force_bottom or force_bottom
        self._pending_render_preserve_scroll = preserve_scroll

        if not self._render_timer.isActive():
            self._render_timer.start(self.RENDER_DEBOUNCE_MS)

    def _flush_scheduled_render(self) -> None:
        force_bottom = self._pending_render_force_bottom
        preserve_scroll = self._pending_render_preserve_scroll

        self._pending_render_force_bottom = False
        self._pending_render_preserve_scroll = True

        self.render_chat(force=True, force_bottom=force_bottom, preserve_scroll=preserve_scroll)

    def _build_chat_html(self) -> str:
        messages = self.memory.get_session_messages(self.current_session_id)

        html_parts: list[str] = [
            """
            <html>
            <head>
            <meta charset="utf-8">
            <style>
                body {
                    background:#0b1220;
                    color:#e5e7eb;
                    font-family:'Segoe UI', Arial, sans-serif;
                    font-size:13px;
                    margin:0;
                    padding:0;
                }
                a {
                    color:#93c5fd;
                }
                pre {
                    tab-size:4;
                }
            </style>
            </head>
            <body>
            """
        ]

        for entry in messages:
            role = entry["role"]
            text = entry["content"]

            if role == "user":
                html_parts.append(_message_to_html("You", text, mine=True))
            elif role == "assistant":
                html_parts.append(_message_to_html("Assistant", text, mine=False))
            else:
                html_parts.append(_message_to_html(role.capitalize(), text, mine=False, subtle=True))

        if self.pending_user_payload and not self._last_stored_message_matches_pending_user():
            html_parts.append(_message_to_html("You", self.pending_user_payload, mine=True))

        if self._request_running and self._show_loading_placeholder:
            live_text = _format_live_assistant_text(
                self.live_thinking_text,
                self.live_answer_text,
                self.live_status_text,
                self.show_thinking_checkbox.isChecked(),
                self.show_tool_trace_checkbox.isChecked(),
            )

            html_parts.append(
                _message_to_html(
                    "Assistant",
                    live_text or "Assistant is thinking...",
                    mine=False,
                    subtle=False,
                )
            )

        html_parts.append("</body></html>")
        return "".join(html_parts)

    def render_chat(self, force: bool = False, *, force_bottom: bool = False, preserve_scroll: bool = True) -> None:
        message_count = self.memory.count_messages(self.current_session_id)

        cache_key = (
            self.current_session_id,
            message_count,
            self._request_running,
            self.pending_user_payload,
            self.show_thinking_checkbox.isChecked(),
            self.show_tool_trace_checkbox.isChecked(),
            self.stream_chat_checkbox.isChecked(),
            len(self.live_thinking_text),
            len(self.live_answer_text),
            self.live_thinking_text[-180:],
            self.live_answer_text[-180:],
            self.live_status_text,
        )

        if not force and cache_key == self._chat_cache_key:
            return

        old_value, old_maximum = self._get_scroll_state()
        html_doc = self._build_chat_html()

        if html_doc == self._last_rendered_html and not force_bottom:
            self._chat_cache_key = cache_key
            return

        self._chat_cache_key = cache_key
        self._last_rendered_html = html_doc

        self.chat_view.setUpdatesEnabled(False)
        self.chat_view.viewport().setUpdatesEnabled(False)

        try:
            self.chat_view.setHtml(html_doc)
        finally:
            self.chat_view.viewport().setUpdatesEnabled(True)
            self.chat_view.setUpdatesEnabled(True)

        self._restore_scroll_state(
            old_value,
            old_maximum,
            force_bottom=force_bottom,
            preserve_exact_position=preserve_scroll,
        )

    def load_session_into_chat(self, session_id: str) -> None:
        self.current_session_id = session_id
        self.pending_user_payload = ""
        self._request_running = False
        self._show_loading_placeholder = False

        self.live_thinking_text = ""
        self.live_answer_text = ""
        self.live_status_text = ""

        self._invalidate_render_cache()
        self.render_chat(force=True, force_bottom=True, preserve_scroll=False)

        count = self.memory.count_messages(session_id)
        self.update_status_banner(f"Loaded session '{session_id}' with {count} message(s).")

    def _start_loading(self) -> None:
        self._request_running = True
        self._show_loading_placeholder = True
        self._invalidate_render_cache()

        self.render_chat(force=True, force_bottom=True, preserve_scroll=False)

    def _stop_loading(self) -> None:
        if self._render_timer.isActive():
            self._render_timer.stop()

        self._request_running = False
        self._show_loading_placeholder = False
        self._invalidate_render_cache()

        self.render_chat(force=True, force_bottom=False, preserve_scroll=True)

    def _request_is_active(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def _cleanup_thread_refs(self) -> None:
        self._worker = None
        self._thread = None

    def _set_request_ui_enabled(self, enabled: bool) -> None:
        self.prompt_input.setEnabled(enabled)
        self.send_button.setEnabled(enabled)
        self.attach_files_button.setEnabled(enabled)
        self.remove_attachment_button.setEnabled(enabled)
        self.clear_attachments_button.setEnabled(enabled)
        self.new_session_button.setEnabled(enabled)
        self.clear_session_button.setEnabled(enabled)
        self.load_session_button.setEnabled(enabled)
        self.refresh_sessions_button.setEnabled(enabled)
        self.detect_button.setEnabled(enabled)
        self.save_config_button.setEnabled(enabled)
        self.reload_config_button.setEnabled(enabled)
        self.save_prompt_button.setEnabled(enabled)
        self.load_models_button.setEnabled(enabled)

    def _thread_connect(self, signal: Callable, slot: Callable) -> None:
        signal.connect(slot)

    def send_message(self) -> None:
        if self._request_is_active():
            return

        user_text = self.prompt_input.toPlainText().strip()
        if not user_text and not self.pending_attachments:
            return

        if not self.current_session_id:
            self.current_session_id = self.default_session_input.text().strip() or "default-session"

        self.config = self.build_config_from_form()

        self.pending_user_payload = build_message_payload(user_text, self.pending_attachments)

        self.live_thinking_text = ""
        self.live_answer_text = ""
        self.live_status_text = "Connecting to Ollama stream..."

        self.prompt_input.clear()
        self._set_request_ui_enabled(False)

        self.pending_attachments.clear()
        self.refresh_attachment_list()

        self.update_status_banner("Streaming request from local Ollama model...")
        self._start_loading()

        self._thread = QThread(self)
        self._worker = ChatWorker(
            config=self.config,
            session_id=self.current_session_id,
            user_text=self.pending_user_payload,
        )
        self._worker.moveToThread(self._thread)

        self._thread_connect(self._thread.started, self._worker.run)
        self._thread_connect(self._worker.snapshot, self.on_stream_snapshot)
        self._thread_connect(self._worker.status, self.on_stream_status)
        self._thread_connect(self._worker.finished, self.on_response)
        self._thread_connect(self._worker.failed, self.on_error)
        self._thread_connect(self._worker.finished, self._thread.quit)
        self._thread_connect(self._worker.failed, self._thread.quit)
        self._thread_connect(self._thread.finished, self._cleanup_thread_refs)

        self._thread.start()

    def on_stream_snapshot(self, thinking: str, answer: str) -> None:
        new_thinking = thinking or ""
        new_answer = answer or self.live_answer_text

        if new_thinking == self.live_thinking_text and new_answer == self.live_answer_text:
            return

        self.live_thinking_text = new_thinking
        self.live_answer_text = new_answer

        self._schedule_render_chat(force_bottom=False, preserve_scroll=True)

    def on_stream_status(self, text: str) -> None:
        if not text:
            return

        if text == self.live_status_text:
            return

        self.live_status_text = text
        self.update_status_banner(text)

        self._schedule_render_chat(force_bottom=False, preserve_scroll=True)

    def on_response(self, _text: str) -> None:
        if self._render_timer.isActive():
            self._render_timer.stop()
            self._flush_scheduled_render()

        self._set_request_ui_enabled(True)
        self.pending_user_payload = ""

        self.live_thinking_text = ""
        self.live_answer_text = ""
        self.live_status_text = ""

        self.memory = MemoryStore(self.config.db_path)

        self.refresh_session_list(select_session=self.current_session_id)
        self._stop_loading()
        self.update_status_banner("Response received.")

    def on_error(self, message: str) -> None:
        if self._render_timer.isActive():
            self._render_timer.stop()

        self._set_request_ui_enabled(True)
        self.pending_user_payload = ""

        self.live_thinking_text = ""
        self.live_answer_text = ""
        self.live_status_text = ""

        self.memory = MemoryStore(self.config.db_path)
        self._stop_loading()

        current_html = self.chat_view.toHtml()
        error_html = _message_to_html("Error", message, mine=False, subtle=True)

        if "</body>" in current_html:
            current_html = current_html.replace("</body>", error_html + "</body>")
            self.chat_view.setHtml(current_html)
            self._last_rendered_html = current_html
        else:
            self.chat_view.setHtml(error_html)
            self._last_rendered_html = error_html

        self.update_status_banner("Request failed.")
        QMessageBox.warning(self, "GPTProject Error", message)

    def new_session(self) -> None:
        if self._request_is_active():
            QMessageBox.information(
                self,
                "Request Running",
                "Wait for the current request to finish before creating a new session.",
            )
            return

        session_id, ok = QInputDialog.getText(self, "New Session", "Session ID:")
        session_id = (session_id or "").strip()

        if not ok or not session_id:
            return

        self.current_session_id = session_id
        self.pending_user_payload = ""
        self.pending_attachments.clear()
        self.live_thinking_text = ""
        self.live_answer_text = ""
        self.live_status_text = ""

        self.refresh_attachment_list()
        self.refresh_session_list(select_session=session_id)

        self._invalidate_render_cache()
        self.load_session_into_chat(session_id)
        self.update_status_banner(f"Created session '{session_id}'.")

    def clear_current_session(self) -> None:
        if self._request_is_active():
            QMessageBox.information(
                self,
                "Request Running",
                "Wait for the current request to finish before clearing the session.",
            )
            return

        if not self.current_session_id:
            return

        confirm = QMessageBox.question(
            self,
            "Clear Session",
            f"Delete all saved messages for '{self.current_session_id}'?",
        )

        if confirm != QMessageBox.Yes:
            return

        self.memory.clear_session(self.current_session_id)

        self.pending_user_payload = ""
        self.pending_attachments.clear()
        self.live_thinking_text = ""
        self.live_answer_text = ""
        self.live_status_text = ""

        self.refresh_attachment_list()
        self.refresh_session_list(select_session=self.current_session_id)

        self._invalidate_render_cache()
        self.load_session_into_chat(self.current_session_id)
        self.update_status_banner(f"Cleared session '{self.current_session_id}'.")

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # type: ignore[override]
        mime = event.mimeData()
        if mime.hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:  # type: ignore[override]
        mime = event.mimeData()

        if not mime.hasUrls():
            super().dropEvent(event)
            return

        paths = []
        for url in mime.urls():
            if url.isLocalFile():
                paths.append(url.toLocalFile())

        if paths:
            self.add_attachments(paths)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._request_is_active():
            QMessageBox.warning(
                self,
                "Request Still Running",
                "A model request is still running.\n\nWait for it to finish before closing the window.",
            )
            event.ignore()
            return

        if self._render_timer.isActive():
            self._render_timer.stop()

        self.config = self.build_config_from_form()
        self.config.window_width = self.width()
        self.config.window_height = self.height()
        self.config.default_session = self.current_session_id or self.config.default_session
        self.config.save()

        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())