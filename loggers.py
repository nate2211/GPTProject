from __future__ import annotations

"""
PromptChat loggers.py

Shared debug logger used by tracker_engine.py, tools.py, GUI code, and any
other local engine.

Usage:
    from loggers import DEBUG_LOGGER

    DEBUG_LOGGER.log_message("hello from my block")

The GUI subscribes to DEBUG_LOGGER and displays every message in its Debug tab.
The logger itself does not import PyQt, so engines can use it safely from
worker threads or non-GUI scripts.
"""

import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Deque, List, Optional


class DebugLogger:
    """
    Thread-safe debug logger.

    The only method engines need is:
        log_message(message: str) -> None

    Extra helper methods are for the GUI:
        subscribe(callback, replay=True)
        get_messages()
        clear()
    """

    def __init__(
        self,
        *,
        max_lines: int = 10000,
        echo_to_stdout: bool = True,
        log_file: str = "data/debug.log",
    ) -> None:
        self.max_lines = max(100, int(max_lines or 10000))
        self.echo_to_stdout = bool(echo_to_stdout)
        self.log_file = str(log_file or "")
        self._messages: Deque[str] = deque(maxlen=self.max_lines)
        self._callbacks: List[Callable[[str], None]] = []
        self._lock = threading.RLock()

    def _timestamp(self) -> str:
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        except Exception:
            return "0000-00-00 00:00:00"

    def _format(self, message: str) -> str:
        text = str(message or "")
        if text.startswith("[") and re_like_timestamp_prefix(text):
            return text
        return f"[{self._timestamp()}] {text}"

    def _write_file(self, line: str) -> None:
        if not self.log_file:
            return

        try:
            path = Path(self.log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8", errors="replace") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def log_message(self, message: str) -> None:
        """
        Log one debug message.

        Keep this signature simple on purpose: it accepts just a string.
        """
        line = self._format(str(message))

        with self._lock:
            self._messages.append(line)
            callbacks = list(self._callbacks)

        if self.echo_to_stdout:
            try:
                print(line, file=sys.stderr)
            except Exception:
                pass

        self._write_file(line)

        for callback in callbacks:
            try:
                callback(line)
            except Exception:
                # A bad GUI subscriber should not break tracker/tools logging.
                pass

    def subscribe(self, callback: Callable[[str], None], replay: bool = True) -> Callable[[], None]:
        """
        Subscribe a callback that accepts one string.

        Returns an unsubscribe function.
        """
        if not callable(callback):
            raise TypeError("DebugLogger.subscribe requires a callable callback.")

        replay_lines: List[str] = []
        with self._lock:
            self._callbacks.append(callback)
            if replay:
                replay_lines = list(self._messages)

        for line in replay_lines:
            try:
                callback(line)
            except Exception:
                pass

        def unsubscribe() -> None:
            with self._lock:
                try:
                    self._callbacks.remove(callback)
                except ValueError:
                    pass

        return unsubscribe

    def get_messages(self) -> List[str]:
        with self._lock:
            return list(self._messages)

    def clear(self) -> None:
        with self._lock:
            self._messages.clear()

    def set_log_file(self, path: str) -> None:
        with self._lock:
            self.log_file = str(path or "")


def re_like_timestamp_prefix(text: str) -> bool:
    # Avoid importing re just for this tiny check.
    # Matches rough form: [2026-06-04 12:34:56]
    if len(text) < 21:
        return False
    if text[0] != "[" or text[5] != "-" or text[8] != "-" or text[11] != " ":
        return False
    return text[14] == ":" and text[17] == ":" and text[20] == "]"


DEBUG_LOGGER = DebugLogger()


def log_message(message: str) -> None:
    """Convenience module-level wrapper."""
    DEBUG_LOGGER.log_message(message)
