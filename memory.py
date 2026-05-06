from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, List


class MemoryStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._local = threading.local()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn

        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
        self._local.conn = conn
        return conn

    def _initialize(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_session_id_id "
                "ON messages(session_id, id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_session_id_created_at "
                "ON messages(session_id, created_at)"
            )
            conn.commit()

    def add(self, session_id: str, role: str, content: str) -> None:
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO messages (session_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                (session_id, role, content, time.time()),
            )
            conn.commit()

    def recent_messages(self, session_id: str, limit: int = 20) -> List[Dict[str, str]]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                """
                SELECT role, content
                FROM messages
                WHERE session_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()

        rows = list(reversed(rows))
        return [{"role": row["role"], "content": row["content"]} for row in rows]

    def get_session_messages(self, session_id: str) -> List[Dict[str, str]]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                """
                SELECT role, content, created_at
                FROM messages
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (session_id,),
            ).fetchall()

        return [
            {
                "role": row["role"],
                "content": row["content"],
                "created_at": str(row["created_at"]),
            }
            for row in rows
        ]

    def count_messages(self, session_id: str) -> int:
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM messages WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return int(row["c"] if row else 0)

    def list_sessions(self) -> List[Dict[str, str]]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                """
                SELECT
                    session_id,
                    COUNT(*) AS message_count,
                    MAX(created_at) AS last_at,
                    COALESCE(
                        (
                            SELECT substr(m2.content, 1, 80)
                            FROM messages m2
                            WHERE m2.session_id = m1.session_id
                            ORDER BY m2.id DESC
                            LIMIT 1
                        ),
                        ''
                    ) AS preview
                FROM messages m1
                GROUP BY session_id
                ORDER BY last_at DESC
                """
            ).fetchall()

        return [
            {
                "session_id": row["session_id"],
                "message_count": str(row["message_count"]),
                "last_at": str(row["last_at"] or ""),
                "preview": row["preview"] or "",
            }
            for row in rows
        ]

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            conn = self._connect()
            conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            conn.commit()