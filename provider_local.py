from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Optional

import requests


class ProviderError(RuntimeError):
    """Raised when the local model server cannot be reached or returns a bad response."""


def _build_session(api_key: str = "ollama") -> requests.Session:
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=4,
        pool_maxsize=8,
        max_retries=0,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if api_key and api_key != "ollama":
        headers["Authorization"] = f"Bearer {api_key}"

    session.headers.update(headers)
    return session


def normalize_base_url(base_url: str) -> str:
    raw = (base_url or "").strip().rstrip("/")
    if not raw:
        raw = "http://127.0.0.1:11434"

    lowered = raw.lower()
    if lowered.endswith("/v1"):
        raw = raw[:-3]
    elif lowered.endswith("/api"):
        raw = raw[:-4]

    return raw.rstrip("/")


def ollama_api_root_from_base_url(base_url: str) -> str:
    return f"{normalize_base_url(base_url)}/api"


def _clip(s: str, n: int = 2000) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else (s[:n] + "...(clipped)")


def _safe_response_text(response: requests.Response, limit: int = 2000) -> str:
    try:
        return _clip(response.text, limit)
    except Exception:
        return ""


def _extract_thinking_from_message(msg: Dict[str, Any]) -> str:
    parts: List[str] = []

    for key in (
        "thinking",
        "reasoning",
        "reasoning_content",
        "thinking_content",
        "analysis",
    ):
        value = msg.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())

    return "\n\n".join(parts).strip()


def _extract_message_from_response_obj(data: Dict[str, Any]) -> Dict[str, Any]:
    msg = data.get("message")
    if isinstance(msg, dict):
        return msg

    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            choice_msg = first.get("message")
            if isinstance(choice_msg, dict):
                return choice_msg

    raise ProviderError(f"Unexpected model response shape: {data}")


def _normalize_response_to_openai_shape(data: Dict[str, Any]) -> Dict[str, Any]:
    msg = _extract_message_from_response_obj(data)
    thinking = _extract_thinking_from_message(msg)

    return {
        "choices": [
            {
                "message": {
                    "role": msg.get("role", "assistant"),
                    "content": msg.get("content", "") or "",
                    "thinking": thinking,
                    "reasoning": thinking,
                    "tool_calls": msg.get("tool_calls", []) or [],
                }
            }
        ]
    }


def _parse_ollama_ndjson_text(text: str) -> Dict[str, Any]:
    content_parts: List[str] = []
    thinking_parts: List[str] = []
    last_obj: Optional[Dict[str, Any]] = None
    last_tool_calls: Any = []

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except Exception:
            continue

        if not isinstance(obj, dict):
            continue

        last_obj = obj
        msg = obj.get("message") or {}

        if isinstance(msg, dict):
            content = msg.get("content")
            if isinstance(content, str) and content:
                content_parts.append(content)

            thinking = _extract_thinking_from_message(msg)
            if thinking:
                thinking_parts.append(thinking)

            tc = msg.get("tool_calls")
            if tc:
                last_tool_calls = tc

        if obj.get("done") is True:
            break

    if last_obj is None:
        raise ProviderError(
            "Model server returned NDJSON/streaming, but no JSON objects were parseable."
        )

    merged_content = "".join(content_parts)
    merged_thinking = "\n\n".join(part for part in thinking_parts if part.strip()).strip()

    msg = last_obj.get("message") or {}
    if not isinstance(msg, dict):
        msg = {}

    msg["content"] = merged_content

    if merged_thinking:
        msg["thinking"] = merged_thinking

    if last_tool_calls:
        msg["tool_calls"] = last_tool_calls

    last_obj["message"] = msg
    return last_obj


@dataclass
class LocalModelProvider:
    base_url: str
    model: str
    api_key: str = "ollama"
    request_timeout_sec: int = 360

    def chat(
        self,
        *,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
        stream: bool = False,
    ) -> Dict[str, Any]:
        url = f"{ollama_api_root_from_base_url(self.base_url)}/chat"

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": bool(stream),
            "options": {
                "temperature": float(temperature),
            },
        }

        if tools:
            payload["tools"] = tools

        session = _build_session(self.api_key)

        try:
            response = session.post(
                url,
                json=payload,
                timeout=(2.0, float(self.request_timeout_sec)),
                stream=bool(stream),
            )

            if not response.ok:
                raise ProviderError(
                    "Local model server rejected the request.\n\n"
                    f"URL: {url}\n"
                    f"Status: {response.status_code}\n"
                    f"Response:\n{_safe_response_text(response)}\n\n"
                    f"Payload model: {self.model}"
                )

            if stream:
                data = _parse_ollama_ndjson_text(response.text or "")
            else:
                try:
                    data = response.json()
                except requests.exceptions.JSONDecodeError:
                    data = _parse_ollama_ndjson_text(response.text or "")

        except ProviderError:
            raise
        except requests.RequestException as exc:
            raise ProviderError(
                f"Could not reach the local model server at {url}. Details: {exc}"
            ) from exc
        finally:
            session.close()

        return _normalize_response_to_openai_shape(data)

    def chat_stream(
        self,
        *,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Streams Ollama /api/chat NDJSON events.

        Yields:
          {"type": "content", "text": "..."}
          {"type": "thinking", "text": "..."}
          {"type": "tool_calls", "tool_calls": [...]}
          {"type": "done"}
        """
        url = f"{ollama_api_root_from_base_url(self.base_url)}/chat"

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": float(temperature),
            },
        }

        if tools:
            payload["tools"] = tools

        session = _build_session(self.api_key)

        try:
            with session.post(
                url,
                json=payload,
                timeout=(2.0, float(self.request_timeout_sec)),
                stream=True,
            ) as response:
                if not response.ok:
                    raise ProviderError(
                        "Local model server rejected the streaming request.\n\n"
                        f"URL: {url}\n"
                        f"Status: {response.status_code}\n"
                        f"Response:\n{_safe_response_text(response)}\n\n"
                        f"Payload model: {self.model}"
                    )

                last_tool_calls: Any = None

                for raw_line in response.iter_lines(decode_unicode=True):
                    if not raw_line:
                        continue

                    line = raw_line.strip()
                    if not line:
                        continue

                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    if not isinstance(obj, dict):
                        continue

                    msg = obj.get("message") or {}
                    if isinstance(msg, dict):
                        thinking = _extract_thinking_from_message(msg)
                        if thinking:
                            yield {"type": "thinking", "text": thinking}

                        content = msg.get("content")
                        if isinstance(content, str) and content:
                            yield {"type": "content", "text": content}

                        tool_calls = msg.get("tool_calls")
                        if tool_calls:
                            last_tool_calls = tool_calls
                            yield {"type": "tool_calls", "tool_calls": tool_calls}

                    if obj.get("done") is True:
                        if last_tool_calls:
                            yield {"type": "tool_calls", "tool_calls": last_tool_calls}
                        yield {"type": "done"}
                        break

        except ProviderError:
            raise
        except requests.RequestException as exc:
            raise ProviderError(
                f"Could not reach the local model server at {url}. Details: {exc}"
            ) from exc
        finally:
            session.close()


def detect_ollama_host_from_env(default: str = "http://127.0.0.1:11434") -> str:
    return normalize_base_url(default)


def discover_ollama_models(base_url: str) -> list[str]:
    root = ollama_api_root_from_base_url(base_url)
    url = f"{root}/tags"

    session = _build_session()
    try:
        response = session.get(url, timeout=(2.0, 20.0))
        if not response.ok:
            raise ProviderError(
                "Could not list Ollama models.\n\n"
                f"URL: {url}\n"
                f"Status: {response.status_code}\n"
                f"Response:\n{_safe_response_text(response)}"
            )

        data = response.json()
    except ProviderError:
        raise
    except requests.RequestException as exc:
        raise ProviderError(f"Could not reach Ollama model list at {url}. Details: {exc}") from exc
    except Exception as exc:
        raise ProviderError(f"Could not parse Ollama model list from {url}. Details: {exc}") from exc
    finally:
        session.close()

    models = data.get("models", [])
    if not isinstance(models, list):
        return []

    names: list[str] = []
    for item in models:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("model")
        if isinstance(name, str) and name.strip():
            names.append(name.strip())

    return sorted(set(names))