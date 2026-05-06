from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Generator, List

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


def _format_tool_trace(tool_trace: List[Dict[str, Any]]) -> str:
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
            f"   result: `{_clip_text(result, MAX_TOOL_TRACE_RESULT_CHARS)}`"
        )

    return "\n\n".join(parts).strip()


def _format_display_response(
    *,
    answer: str,
    thinking: str,
    tool_trace: List[Dict[str, Any]],
    show_thinking: bool,
    show_tool_trace: bool,
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
        trace = _format_tool_trace(tool_trace)
        if trace:
            sections.append("---\n\n### Tool Trace\n\n" + trace)

    return "\n\n".join(sections).strip()


def load_system_prompt(prompt_path: str) -> str:
    path = Path(prompt_path)

    default_prompt = """You are a practical local assistant.

Rules:
- Be helpful and direct.
- Use tools when they clearly help produce a better answer.
- Never invent tool results.
- When a tool fails, say so briefly and keep helping if possible.
- You may use multiple tool calls when needed.
- Prefer local tools first when they can answer the question.
- For web questions, search first, then summarize accurately.
- Return a normal final answer after tools complete.

Thinking display rules:
- If the model supports a visible thinking channel, use it naturally.
- If the model uses <think>...</think> tags, put visible reasoning inside <think>...</think>.
- After thinking, provide the final answer normally.
- Keep visible thinking concise and useful.
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

    def _build_messages_from_memory(self, session_id: str) -> List[Dict[str, Any]]:
        history = self.memory.recent_messages(session_id, limit=self.max_history)

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt}
        ]

        for item in history:
            role = item.get("role", "")
            content = item.get("content", "")

            if role == "assistant":
                content = _strip_display_metadata_for_history(content)

            messages.append(
                {
                    "role": role,
                    "content": content,
                }
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
            return _clip_text(_safe_json_dumps(parsed))
        except Exception:
            return _clip_text(raw)

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

        for round_idx in range(MAX_TOOL_ROUNDS):
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
    try:
        return build_default_tool_registry(
            tor_socks_url=cfg.tor_socks_url,
            prefer_tor_for_web=cfg.prefer_tor_for_web,
        )
    except TypeError:
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
    )