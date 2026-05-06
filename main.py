from __future__ import annotations

import argparse
import sys

from config import AppConfig
from provider_local import ProviderError
from runtime import build_runtime


def run_console(session_id: str) -> int:
    runtime = build_runtime(AppConfig.load())

    print("GPTProject console chat")
    print("Type 'exit' or 'quit' to stop. Type '/clear' to wipe this session's memory.")

    while True:
        try:
            text = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            return 0

        if not text:
            continue
        if text.lower() in {"exit", "quit"}:
            print("Goodbye.")
            return 0
        if text.lower() == "/clear":
            runtime.memory.clear_session(session_id)
            print("Session cleared.")
            continue

        try:
            reply = runtime.ask(session_id, text)
        except ProviderError as exc:
            print(f"[Provider error] {exc}")
            continue
        except Exception as exc:
            print(f"[Unexpected error] {exc}")
            continue

        print(f"Assistant: {reply}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local GPTProject console chat.")
    parser.add_argument(
        "--session",
        default=AppConfig.load().default_session,
        help="Session ID used for local memory.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sys.exit(run_console(args.session))