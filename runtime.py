# ========================================================
# ================  runtime.py  ==========================
# ========================================================
from __future__ import annotations

import base64
import io
import json
import re
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from config import AppConfig
from memory import MemoryStore
from provider_local import LocalModelProvider
from tools import ToolRegistry, build_default_tool_registry

MAX_TOOL_ROUNDS = 6
MAX_TOOL_RESULT_CHARS = 5000
MAX_TOOL_TRACE_RESULT_CHARS = 900

THINK_BLOCK_RE = re.compile(r"(?is)<think>\s*(.*?)\s*</think>")
UNCLOSED_THINK_RE = re.compile(r"(?is)<think>\s*(.*)$")

DISPLAY_TOOL_TRACE_RE = re.compile(r"(?is)\n---\n\n### Tool Trace\n\n.*$")
DISPLAY_THINKING_ANSWER_RE = re.compile(
    r"(?is)^### Thinking\n\n.*?\n\n---\n\n### Answer\n\n(.*)$"
)


ATTACHMENT_BEGIN = "<<GPTPROJECT_ATTACHMENTS>>"
ATTACHMENT_END = "<<END_GPTPROJECT_ATTACHMENTS>>"

SUPPORTED_IMAGE_SUFFIXES = {
    ".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff",
}

SUPPORTED_VIDEO_SUFFIXES = {
    ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm", ".wmv", ".flv", ".mpeg", ".mpg",
}

MAX_MEDIA_IMAGES_PER_MESSAGE = 12
MAX_VIDEO_FRAMES_PER_FILE = 6
MAX_MEDIA_DIMENSION = 1280
MAX_MEDIA_BYTES = 80 * 1024 * 1024


def _parse_attachment_blocks(text: str) -> List[Dict[str, str]]:
    if ATTACHMENT_BEGIN not in (text or "") or ATTACHMENT_END not in (text or ""):
        return []

    _, _, remainder = text.partition(ATTACHMENT_BEGIN)
    block, _, _ = remainder.partition(ATTACHMENT_END)

    attachments: List[Dict[str, str]] = []

    for raw_item in re.split(r"(?m)^=== FILE: ", block):
        item = raw_item.strip()
        if not item:
            continue

        if " ===" in item:
            name, _, rest = item.partition(" ===")
        else:
            name, rest = "", item

        data: Dict[str, str] = {"name": name.strip()}

        for key in ("PATH", "KIND", "MIME", "SIZE_BYTES", "WARNING"):
            m = re.search(rf"(?m)^{key}:\s*(.*)$", rest)
            if m:
                data[key.lower()] = (m.group(1) or "").strip()

        if data.get("path"):
            attachments.append(data)

    return attachments


def _strip_media_attachment_block_for_model(text: str) -> str:
    """
    Keep the user's visible text and text attachments, but reduce image/video
    attachment bodies to short summaries. The actual visual data is sent through
    Ollama's message.images field.
    """
    raw = text or ""
    if ATTACHMENT_BEGIN not in raw or ATTACHMENT_END not in raw:
        return raw

    before, _, remainder = raw.partition(ATTACHMENT_BEGIN)
    block, _, after = remainder.partition(ATTACHMENT_END)

    rebuilt: List[str] = [before.strip(), "", ATTACHMENT_BEGIN]

    for part in re.split(r"(?m)^=== FILE: ", block):
        item = part.strip()
        if not item:
            continue

        content = "=== FILE: " + item
        kind_match = re.search(r"(?m)^KIND:\s*(.*)$", content)
        kind = (kind_match.group(1).strip().lower() if kind_match else "")

        if kind in {"image", "video"}:
            name_match = re.search(r"(?m)^=== FILE:\s*(.*?)\s*===", content)
            path_match = re.search(r"(?m)^PATH:\s*(.*)$", content)
            mime_match = re.search(r"(?m)^MIME:\s*(.*)$", content)
            size_match = re.search(r"(?m)^SIZE_BYTES:\s*(.*)$", content)

            rebuilt.append(f"=== FILE: {(name_match.group(1).strip() if name_match else 'media')} ===")
            if path_match:
                rebuilt.append(f"PATH: {path_match.group(1).strip()}")
            rebuilt.append(f"KIND: {kind}")
            if mime_match:
                rebuilt.append(f"MIME: {mime_match.group(1).strip()}")
            if size_match:
                rebuilt.append(f"SIZE_BYTES: {size_match.group(1).strip()}")
            rebuilt.append("CONTENT:")
            if kind == "image":
                rebuilt.append("[Image is attached as model vision input.]")
            else:
                rebuilt.append("[Video is sampled into image frames and attached as model vision input.]")
            rebuilt.append("=== END FILE ===")
            rebuilt.append("")
        else:
            rebuilt.append(content)
            if not content.endswith("\n"):
                rebuilt.append("")

    rebuilt.append(ATTACHMENT_END)
    if after.strip():
        rebuilt.append(after.strip())

    return "\n".join(rebuilt).strip()


def _file_size_ok(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size <= MAX_MEDIA_BYTES
    except Exception:
        return False


def _image_file_to_base64(path: Path, max_dimension: int = MAX_MEDIA_DIMENSION) -> Optional[str]:
    try:
        if not _file_size_ok(path):
            return None

        try:
            from PIL import Image, ImageOps
        except Exception:
            raw = path.read_bytes()
            return base64.b64encode(raw).decode("ascii")

        with Image.open(path) as img:
            img = ImageOps.exif_transpose(img)
            if img.mode == "RGBA":
                bg = Image.new("RGB", img.size, (255, 255, 255))
                bg.paste(img, mask=img.getchannel("A"))
                img = bg
            elif img.mode != "RGB":
                img = img.convert("RGB")

            if max(img.size) > max_dimension:
                img.thumbnail((max_dimension, max_dimension))

            out = io.BytesIO()
            img.save(out, format="JPEG", quality=90, optimize=True)
            return base64.b64encode(out.getvalue()).decode("ascii")
    except Exception:
        return None


def _video_file_to_frame_base64(
    path: Path,
    max_frames: int = MAX_VIDEO_FRAMES_PER_FILE,
    max_dimension: int = MAX_MEDIA_DIMENSION,
) -> Tuple[List[str], str]:
    """
    Sample a small number of video frames and return them as JPEG base64 strings.
    Requires opencv-python. This keeps Ollama-compatible vision input because
    Ollama accepts images, not raw video blobs.
    """
    frames: List[str] = []

    try:
        if not _file_size_ok(path):
            return [], "Video is missing or larger than the media byte limit."

        try:
            import cv2
        except Exception:
            return [], "opencv-python is not installed, so video frames could not be sampled."

        cap = cv2.VideoCapture(str(path))
        if not cap.isOpened():
            return [], "OpenCV could not open the video."

        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        if frame_count <= 0:
            sample_indices = list(range(max_frames))
        else:
            if max_frames <= 1:
                sample_indices = [max(0, frame_count // 2)]
            else:
                sample_indices = [
                    int(round(i * (frame_count - 1) / float(max_frames - 1)))
                    for i in range(max_frames)
                ]

        for idx in sample_indices:
            if frame_count > 0:
                cap.set(cv2.CAP_PROP_POS_FRAMES, max(0, min(idx, frame_count - 1)))

            ok, frame = cap.read()
            if not ok or frame is None:
                continue

            h, w = frame.shape[:2]
            largest = max(w, h)
            if largest > max_dimension:
                scale = max_dimension / float(largest)
                frame = cv2.resize(frame, (max(1, int(w * scale)), max(1, int(h * scale))))

            ok, encoded = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 90])
            if not ok:
                continue

            frames.append(base64.b64encode(encoded.tobytes()).decode("ascii"))

        cap.release()

        if not frames:
            return [], "No frames could be sampled from the video."

        return frames, f"Sampled {len(frames)} frame(s) from video."
    except Exception as exc:
        return frames, f"Video frame sampling failed: {exc}"


def _extract_model_images_from_payload(text: str) -> Tuple[List[str], List[str]]:
    images: List[str] = []
    notes: List[str] = []

    for item in _parse_attachment_blocks(text):
        if len(images) >= MAX_MEDIA_IMAGES_PER_MESSAGE:
            break

        path_text = item.get("path", "")
        kind = (item.get("kind", "") or "").strip().lower()
        path = Path(path_text).expanduser()

        if not path.exists():
            notes.append(f"{item.get('name', path.name)}: file missing at send time.")
            continue

        suffix = path.suffix.lower()
        if not kind:
            if suffix in SUPPORTED_IMAGE_SUFFIXES:
                kind = "image"
            elif suffix in SUPPORTED_VIDEO_SUFFIXES:
                kind = "video"

        if kind == "image" or suffix in SUPPORTED_IMAGE_SUFFIXES:
            encoded = _image_file_to_base64(path)
            if encoded:
                images.append(encoded)
                notes.append(f"{item.get('name', path.name)}: attached as image input.")
            else:
                notes.append(f"{item.get('name', path.name)}: image could not be encoded.")
            continue

        if kind == "video" or suffix in SUPPORTED_VIDEO_SUFFIXES:
            remaining = MAX_MEDIA_IMAGES_PER_MESSAGE - len(images)
            frame_count = max(1, min(MAX_VIDEO_FRAMES_PER_FILE, remaining))
            frame_images, note = _video_file_to_frame_base64(path, max_frames=frame_count)
            images.extend(frame_images[:remaining])
            notes.append(f"{item.get('name', path.name)}: {note}")
            continue

    return images[:MAX_MEDIA_IMAGES_PER_MESSAGE], notes


def _message_content_and_images_for_model(
    role: str,
    content: str,
    *,
    include_media: bool,
) -> Dict[str, Any]:
    model_content = _strip_media_attachment_block_for_model(content)
    msg: Dict[str, Any] = {"role": role, "content": model_content}

    if include_media and role == "user":
        images, notes = _extract_model_images_from_payload(content)
        if images:
            msg["images"] = images

        if notes:
            extra = "\n\nMedia processing notes:\n" + "\n".join(f"- {n}" for n in notes)
            msg["content"] = (msg.get("content", "") or "").strip() + extra

    return msg



def _safe_json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(obj)


def _clip_text(text: Any, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    s = str(text or "")
    if len(s) <= limit:
        return s
    return s[:limit] + "\n...[truncated]"


def _normalize_tool_calls(message: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = message.get("tool_calls", []) or []
    if not isinstance(raw, list):
        return []

    normalized: List[Dict[str, Any]] = []

    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            continue

        fn = item.get("function", {})
        if isinstance(fn, dict):
            name = fn.get("name")
            arguments = fn.get("arguments", {})
        else:
            name = item.get("name")
            arguments = item.get("arguments", {})

        if not name or not isinstance(name, str):
            continue

        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments or "{}")
            except Exception:
                arguments = {}

        if not isinstance(arguments, dict):
            arguments = {}

        normalized.append(
            {
                "id": item.get("id", f"toolcall-{idx}"),
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": arguments,
                },
            }
        )

    return normalized


def _extract_message(resp: Dict[str, Any]) -> Dict[str, Any]:
    choices = resp.get("choices", []) or []
    if not choices:
        return {
            "role": "assistant",
            "content": "",
            "thinking": "",
            "tool_calls": [],
        }

    msg = choices[0].get("message", {}) or {}
    if not isinstance(msg, dict):
        return {
            "role": "assistant",
            "content": "",
            "thinking": "",
            "tool_calls": [],
        }

    thinking = (
        msg.get("thinking", "")
        or msg.get("reasoning", "")
        or msg.get("reasoning_content", "")
        or msg.get("thinking_content", "")
        or msg.get("analysis", "")
        or ""
    )

    return {
        "role": msg.get("role", "assistant"),
        "content": msg.get("content", "") or "",
        "thinking": thinking,
        "tool_calls": _normalize_tool_calls(msg),
    }


def _split_thinking_from_content(
    content: str,
    explicit_thinking: str = "",
) -> tuple[str, str]:
    text = content or ""
    thinking_parts: List[str] = []

    if explicit_thinking and explicit_thinking.strip():
        thinking_parts.append(explicit_thinking.strip())

    def collect_closed(match: re.Match[str]) -> str:
        thinking = (match.group(1) or "").strip()
        if thinking:
            thinking_parts.append(thinking)
        return ""

    clean_content = THINK_BLOCK_RE.sub(collect_closed, text).strip()

    unclosed = UNCLOSED_THINK_RE.search(clean_content)
    if unclosed:
        thinking = (unclosed.group(1) or "").strip()
        if thinking:
            thinking_parts.append(thinking)
        clean_content = clean_content[: unclosed.start()].strip()

    thinking_text = "\n\n".join(part for part in thinking_parts if part.strip()).strip()
    return clean_content, thinking_text


def _strip_display_metadata_for_history(text: str) -> str:
    s = text or ""
    s = DISPLAY_TOOL_TRACE_RE.sub("", s).strip()

    m = DISPLAY_THINKING_ANSWER_RE.match(s)
    if m:
        return (m.group(1) or "").strip()

    return s.strip()


def _format_tool_trace(
    tool_trace: List[Dict[str, Any]],
    *,
    max_tool_trace_result_chars: int = MAX_TOOL_TRACE_RESULT_CHARS,
) -> str:
    if not tool_trace:
        return ""

    parts: List[str] = []

    for idx, item in enumerate(tool_trace, start=1):
        name = item.get("name", "")
        arguments = item.get("arguments", {})
        result = item.get("result", "")

        parts.append(
            f"{idx}. `{name}`\n"
            f"   args: `{_clip_text(_safe_json_dumps(arguments), 600)}`\n"
            f"   result: `{_clip_text(result, max_tool_trace_result_chars)}`"
        )

    return "\n\n".join(parts).strip()


def _format_display_response(
    *,
    answer: str,
    thinking: str,
    tool_trace: List[Dict[str, Any]],
    show_thinking: bool,
    show_tool_trace: bool,
    max_tool_trace_result_chars: int = MAX_TOOL_TRACE_RESULT_CHARS,
) -> str:
    final_answer = (answer or "").strip() or "Model failed to produce a response."
    thinking_text = (thinking or "").strip()

    sections: List[str] = []

    if show_thinking and thinking_text:
        sections.append(
            "### Thinking\n\n"
            f"{thinking_text}\n\n"
            "---\n\n"
            "### Answer\n\n"
            f"{final_answer}"
        )
    else:
        sections.append(final_answer)

    if show_tool_trace and tool_trace:
        trace = _format_tool_trace(
            tool_trace,
            max_tool_trace_result_chars=max_tool_trace_result_chars,
        )
        if trace:
            sections.append("---\n\n### Tool Trace\n\n" + trace)

    return "\n\n".join(sections).strip()


def load_system_prompt(prompt_path: str) -> str:
    path = Path(prompt_path)

    default_prompt = """You are a practical local coding assistant.

Core rules:
- Be helpful and direct.
- Use tools when they clearly help produce a better answer.
- Never invent tool results.
- When a tool fails, say so briefly and keep helping if possible.
- You may use multiple tool calls when needed.
- Prefer local project tools first when the user asks about their code/project.
- For web questions, search first, then summarize accurately.
- Return a normal final answer after tools complete.

Local project tool rules:
- If the user asks about this local codebase, project files, imports, errors, tests, syntax, runtime failures, or requested patches, use the project tools.
- Start with project_status before project scanning or running commands.
- Use project_tree to inspect the file layout.
- Use search_project to locate relevant files/classes/functions/errors.
- Use read_project_file before making claims about exact code.
- Use run_project_command for safe diagnostics such as py_compile, pytest, ruff, mypy, or pyright.
- Do not claim a command passed unless the tool result says it passed.
- If write_project_file is disabled, provide copy/paste patches instead of pretending to edit files.
- If write_project_file is enabled, only write files the user clearly asked to change.

Thinking display rules:
- If the model supports a visible thinking field, keep it concise and useful.
- If the model uses <think>...</think> tags, put brief useful reasoning inside <think>...</think>.
- After thinking, provide the final answer normally.
- Never invent tool results inside thinking or final answers.

Tor/tool rules:
- Use check_tor_proxy before browse_tor/search_tor when Tor status is unknown.
- Use browse_tor, search_tor, or extract_links_tor when the user explicitly asks for Tor-routed browsing.
- Use browse_web/search_web for normal web requests unless Tor is explicitly requested or config prefers Tor.
- If a Tor tool fails, say the proxy may not be running and include the configured proxy address from the tool result.
- Do not help with illegal markets, credential theft, malware, evasion, or abuse.
"""

    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(default_prompt, encoding="utf-8")

    try:
        text = path.read_text(encoding="utf-8").strip()
    except Exception:
        text = default_prompt

    return text or default_prompt


class AssistantRuntime:
    def __init__(
        self,
        *,
        provider: LocalModelProvider,
        tools: ToolRegistry,
        memory: MemoryStore,
        system_prompt: str,
        temperature: float = 0.2,
        max_history: int = 24,
        show_thinking: bool = True,
        show_tool_trace: bool = False,
        stream_chat: bool = True,
        max_tool_rounds: int = MAX_TOOL_ROUNDS,
        max_tool_result_chars: int = MAX_TOOL_RESULT_CHARS,
        max_tool_trace_result_chars: int = MAX_TOOL_TRACE_RESULT_CHARS,
    ) -> None:
        self.provider = provider
        self.tools = tools
        self.memory = memory
        self.system_prompt = system_prompt
        self.temperature = temperature
        self.max_history = max_history
        self.show_thinking = bool(show_thinking)
        self.show_tool_trace = bool(show_tool_trace)
        self.stream_chat = bool(stream_chat)
        self.max_tool_rounds = max(1, int(max_tool_rounds))
        self.max_tool_result_chars = max(100, int(max_tool_result_chars))
        self.max_tool_trace_result_chars = max(50, int(max_tool_trace_result_chars))

    def _build_messages_from_memory(self, session_id: str) -> List[Dict[str, Any]]:
        history = self.memory.recent_messages(session_id, limit=self.max_history)

        messages: List[Dict[str, Any]] = [
            {
                "role": "system",
                "content": (
                    self.system_prompt
                    + "\n\nMedia attachment rules:\n"
                    "- When the latest user message includes images, they are supplied in Ollama's message.images field.\n"
                    "- When the latest user message includes video, sampled frames are supplied as images.\n"
                    "- Use the attached visual inputs directly when answering.\n"
                    "- If no images arrive, say the selected model may not support vision or the media could not be encoded."
                ),
            }
        ]

        last_user_index = -1
        for idx, item in enumerate(history):
            if item.get("role", "") == "user":
                last_user_index = idx

        for idx, item in enumerate(history):
            role = item.get("role", "")
            content = item.get("content", "")

            if role == "assistant":
                content = _strip_display_metadata_for_history(content)

            if role in {"system", "user", "assistant", "tool"}:
                include_media = role == "user" and idx == last_user_index
                messages.append(
                    _message_content_and_images_for_model(
                        role,
                        content,
                        include_media=include_media,
                    )
                )

        return messages

    def _store_and_return(self, session_id: str, text: str) -> str:
        final = (text or "").strip() or "Model failed to produce a response."
        self.memory.add(session_id, "assistant", final)
        return final

    def _call_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        raw = self.tools.call(name, arguments)
        try:
            parsed = json.loads(raw)
            return _clip_text(_safe_json_dumps(parsed), self.max_tool_result_chars)
        except Exception:
            return _clip_text(raw, self.max_tool_result_chars)

    def ask(self, session_id: str, user_text: str) -> str:
        final_text = ""
        for event in self.ask_stream(session_id, user_text):
            if event.get("type") == "final":
                final_text = event.get("text", "") or ""
        return final_text or "Model failed to produce a response."

    def ask_stream(
        self,
        session_id: str,
        user_text: str,
    ) -> Generator[Dict[str, Any], None, None]:
        clean_user_text = (user_text or "").strip()
        if not clean_user_text:
            final = self._store_and_return(session_id, "Please send a message.")
            yield {"type": "final", "text": final}
            return

        self.memory.add(session_id, "user", clean_user_text)

        messages = self._build_messages_from_memory(session_id)
        tool_schemas = self.tools.schemas()

        full_thinking = ""
        full_answer = ""
        tool_trace: List[Dict[str, Any]] = []

        if not tool_schemas:
            yield {
                "type": "status",
                "text": (
                    "No tools are registered. Check GPTPROJECT_LOCAL_PROJECT_DIR "
                    "and GPTPROJECT_PROJECT_TOOLS_ENABLED."
                ),
            }

        for round_idx in range(self.max_tool_rounds):
            yield {
                "type": "status",
                "text": f"Streaming from Ollama... round {round_idx + 1}",
            }

            raw_content = ""
            raw_thinking = ""
            current_tool_calls: List[Dict[str, Any]] = []

            if self.stream_chat and hasattr(self.provider, "chat_stream"):
                stream_iter = self.provider.chat_stream(
                    messages=messages,
                    tools=tool_schemas,
                    temperature=self.temperature,
                )

                for ev in stream_iter:
                    ev_type = ev.get("type")

                    if ev_type == "thinking":
                        raw_thinking += ev.get("text", "") or ""
                        answer_now, thinking_now = _split_thinking_from_content(
                            raw_content,
                            raw_thinking,
                        )
                        full_thinking = thinking_now
                        full_answer = answer_now

                        yield {
                            "type": "snapshot",
                            "thinking": full_thinking,
                            "answer": full_answer,
                        }

                    elif ev_type == "content":
                        raw_content += ev.get("text", "") or ""

                        answer_now, thinking_now = _split_thinking_from_content(
                            raw_content,
                            raw_thinking,
                        )
                        full_thinking = thinking_now
                        full_answer = answer_now

                        yield {
                            "type": "snapshot",
                            "thinking": full_thinking,
                            "answer": full_answer,
                        }

                    elif ev_type == "tool_calls":
                        tool_calls_raw = ev.get("tool_calls", []) or []
                        current_tool_calls = _normalize_tool_calls(
                            {"tool_calls": tool_calls_raw}
                        )

                    elif ev_type == "done":
                        break

            else:
                response = self.provider.chat(
                    messages=messages,
                    tools=tool_schemas,
                    temperature=self.temperature,
                    stream=False,
                )
                assistant_msg = _extract_message(response)
                raw_content = (assistant_msg.get("content") or "").strip()
                raw_thinking = (assistant_msg.get("thinking") or "").strip()
                current_tool_calls = assistant_msg.get("tool_calls", []) or []

                full_answer, full_thinking = _split_thinking_from_content(
                    raw_content,
                    raw_thinking,
                )

                yield {
                    "type": "snapshot",
                    "thinking": full_thinking,
                    "answer": full_answer,
                }

            if current_tool_calls:
                answer_for_tool_message, thinking_from_content = _split_thinking_from_content(
                    raw_content,
                    raw_thinking,
                )

                if thinking_from_content:
                    full_thinking = thinking_from_content
                full_answer = answer_for_tool_message

                messages.append(
                    {
                        "role": "assistant",
                        "content": answer_for_tool_message,
                        "tool_calls": current_tool_calls,
                    }
                )

                for call in current_tool_calls:
                    fn = call.get("function", {})
                    name = fn.get("name", "")
                    arguments = fn.get("arguments", {}) or {}

                    if not name:
                        continue

                    yield {
                        "type": "status",
                        "text": f"Calling tool: {name}",
                    }

                    tool_result = self._call_tool(name, arguments)

                    tool_trace.append(
                        {
                            "round": round_idx + 1,
                            "name": name,
                            "arguments": arguments,
                            "result": tool_result,
                        }
                    )

                    messages.append(
                        {
                            "role": "tool",
                            "tool_name": name,
                            "content": tool_result,
                        }
                    )

                    yield {
                        "type": "tool_result",
                        "name": name,
                        "result": tool_result,
                    }

                continue

            display = _format_display_response(
                answer=full_answer,
                thinking=full_thinking,
                tool_trace=tool_trace,
                show_thinking=self.show_thinking,
                show_tool_trace=self.show_tool_trace,
                max_tool_trace_result_chars=self.max_tool_trace_result_chars,
            )

            stored = self._store_and_return(session_id, display)

            yield {
                "type": "final",
                "text": stored,
                "thinking": full_thinking,
                "answer": full_answer,
            }
            return

        yield {
            "type": "status",
            "text": "Maximum tool rounds reached. Asking Ollama for final answer.",
        }

        final_messages = messages + [
            {
                "role": "system",
                "content": (
                    "You have reached the maximum number of tool rounds. "
                    "Using the conversation and tool results already available, "
                    "give the best final answer you can. "
                    "Do not call any more tools."
                ),
            }
        ]

        response = self.provider.chat(
            messages=final_messages,
            tools=[],
            temperature=self.temperature,
            stream=False,
        )

        final_msg = _extract_message(response)
        final_raw_content = (final_msg.get("content") or "").strip()
        final_raw_thinking = (final_msg.get("thinking") or "").strip()

        final_answer, final_thinking = _split_thinking_from_content(
            final_raw_content,
            final_raw_thinking,
        )

        display = _format_display_response(
            answer=final_answer
            or "I could not complete more tool calls, but here is the best answer from the information already gathered.",
            thinking=final_thinking or full_thinking,
            tool_trace=tool_trace,
            show_thinking=self.show_thinking,
            show_tool_trace=self.show_tool_trace,
        )

        stored = self._store_and_return(session_id, display)

        yield {
            "type": "final",
            "text": stored,
            "thinking": final_thinking or full_thinking,
            "answer": final_answer,
        }


def _build_tools_for_config(cfg: AppConfig) -> ToolRegistry:
    """
    IMPORTANT FIX:
    Pass app_config=cfg into build_default_tool_registry.

    Without this, tools.py receives app_config=None, so _register_project_tools()
    returns early and none of the local project tools are exposed to the model.
    """
    try:
        return build_default_tool_registry(
            tor_socks_url=cfg.tor_socks_url,
            prefer_tor_for_web=cfg.prefer_tor_for_web,
            app_config=cfg,
        )
    except TypeError:
        # Backward compatibility for older tools.py versions.
        return build_default_tool_registry()


def build_runtime(config: AppConfig | None = None) -> AssistantRuntime:
    cfg = config or AppConfig.load()

    provider = LocalModelProvider(
        base_url=cfg.base_url,
        model=cfg.model,
        api_key=cfg.api_key,
        request_timeout_sec=cfg.request_timeout_sec,
    )

    memory = MemoryStore(cfg.db_path)
    tools = _build_tools_for_config(cfg)
    prompt = load_system_prompt(cfg.prompt_path)

    return AssistantRuntime(
        provider=provider,
        tools=tools,
        memory=memory,
        system_prompt=prompt,
        temperature=cfg.temperature,
        max_history=cfg.max_history,
        show_thinking=cfg.show_thinking,
        show_tool_trace=cfg.show_tool_trace,
        stream_chat=cfg.stream_chat,
        max_tool_rounds=cfg.max_tool_rounds,
        max_tool_result_chars=cfg.max_tool_result_chars,
        max_tool_trace_result_chars=cfg.max_tool_trace_result_chars,
    )