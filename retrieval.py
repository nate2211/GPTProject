from __future__ import annotations

import math
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


DEFAULT_TEXT_EXTENSIONS = {
    ".txt", ".md", ".py", ".json", ".js", ".ts", ".tsx", ".jsx", ".html", ".css",
    ".scss", ".sql", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".log",
    ".csv", ".sh", ".bat", ".ps1", ".cs", ".cpp", ".c", ".h", ".hpp", ".java",
    ".kt", ".go", ".rs", ".php", ".rb", ".lua", ".swift", ".dart", ".toml",
}

STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "if", "to", "for", "of", "in", "on",
    "at", "by", "with", "from", "as", "is", "are", "was", "were", "be", "been",
    "being", "do", "does", "did", "this", "that", "these", "those", "it", "its",
    "how", "what", "when", "where", "why", "which", "who", "whom", "can", "could",
    "should", "would", "will", "about", "into", "than", "then", "also", "just",
    "over", "under", "more", "most", "less", "very",
}

TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_\-.:/]*")
PHRASE_RE = re.compile(r'"([^"]+)"')
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
WHITESPACE_RE = re.compile(r"\s+")


@dataclass
class ChunkRecord:
    file_path: str
    file_name: str
    rel_path: str
    chunk_id: int
    text: str
    normalized_text: str
    tokens: List[str]
    unique_tokens: set[str]
    char_start: int
    char_end: int
    modified_at: float
    file_size: int


@dataclass
class FileRecord:
    path: Path
    modified_at: float
    size: int
    chunks: List[ChunkRecord]


def _normalize_whitespace(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text or "").strip()


def _read_text_file(path: Path, max_chars: int) -> str:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    if len(raw) > max_chars:
        return raw[:max_chars]
    return raw


def _tokenize(text: str) -> List[str]:
    return [m.group(0).lower() for m in TOKEN_RE.finditer(text or "")]


def _normalize_token(token: str) -> str:
    t = (token or "").strip().lower()
    if not t:
        return ""

    # very light stemming/normalization
    if len(t) > 5 and t.endswith("ing"):
        t = t[:-3]
    elif len(t) > 4 and t.endswith("ed"):
        t = t[:-2]
    elif len(t) > 4 and t.endswith("es"):
        t = t[:-2]
    elif len(t) > 3 and t.endswith("s"):
        t = t[:-1]

    return t


def _normalize_tokens(tokens: Iterable[str]) -> List[str]:
    out: List[str] = []
    for token in tokens:
        norm = _normalize_token(token)
        if norm and norm not in STOPWORDS:
            out.append(norm)
    return out


def _extract_query_parts(query: str) -> tuple[List[str], List[str]]:
    raw = _normalize_whitespace(query)
    if not raw:
        return [], []

    phrases = [_normalize_whitespace(p).lower() for p in PHRASE_RE.findall(raw) if p.strip()]
    stripped = PHRASE_RE.sub(" ", raw)
    tokens = _normalize_tokens(_tokenize(stripped.lower()))

    # If no quoted phrases were given, also build 2-3 word phrases from the query.
    if not phrases and len(tokens) >= 2:
        auto_phrases: List[str] = []
        for i in range(len(tokens) - 1):
            auto_phrases.append(f"{tokens[i]} {tokens[i + 1]}")
        phrases.extend(auto_phrases[:4])

    return tokens, phrases


def _sentencize(text: str) -> List[str]:
    parts = SENTENCE_SPLIT_RE.split(text.strip())
    return [p.strip() for p in parts if p.strip()]


def _chunk_text(
    text: str,
    *,
    chunk_size: int,
    overlap: int,
) -> List[tuple[str, int, int]]:
    text = text.strip()
    if not text:
        return []

    sentences = _sentencize(text)
    if not sentences:
        return [(text[:chunk_size], 0, min(len(text), chunk_size))]

    chunks: List[tuple[str, int, int]] = []
    current_sentences: List[str] = []
    current_len = 0
    approx_start = 0

    running_char = 0
    sentence_positions: List[tuple[str, int, int]] = []
    for sentence in sentences:
        start = text.find(sentence, running_char)
        if start < 0:
            start = running_char
        end = start + len(sentence)
        sentence_positions.append((sentence, start, end))
        running_char = end

    i = 0
    while i < len(sentence_positions):
        current_sentences = []
        current_len = 0
        start_char = sentence_positions[i][1]
        j = i

        while j < len(sentence_positions):
            sentence = sentence_positions[j][0]
            extra = len(sentence) + (1 if current_sentences else 0)
            if current_sentences and current_len + extra > chunk_size:
                break
            current_sentences.append(sentence)
            current_len += extra
            j += 1

        if not current_sentences:
            sentence = sentence_positions[i][0]
            clipped = sentence[:chunk_size]
            chunks.append((clipped, sentence_positions[i][1], sentence_positions[i][1] + len(clipped)))
            i += 1
            continue

        end_char = sentence_positions[j - 1][2]
        chunk_text = " ".join(current_sentences).strip()
        chunks.append((chunk_text, start_char, end_char))

        if j >= len(sentence_positions):
            break

        if overlap <= 0:
            i = j
            continue

        carried = 0
        back = j - 1
        while back > i and carried < overlap:
            carried += len(sentence_positions[back][0]) + 1
            back -= 1
        i = max(i + 1, back + 1)

    return chunks


def _safe_stat(path: Path) -> Optional[os.stat_result]:
    try:
        return path.stat()
    except OSError:
        return None


class SimpleFileRetrieval:
    """
    Smarter local retrieval over text/code files using:
    - chunked indexing
    - token + phrase scoring
    - path and filename boosts
    - lightweight recency boost
    - cached file index for fast repeated queries
    """

    def __init__(
        self,
        root_dir: str = "data/knowledge",
        *,
        allowed_extensions: Optional[set[str]] = None,
        chunk_size: int = 1200,
        chunk_overlap: int = 220,
        max_file_chars: int = 250_000,
        reindex_interval_sec: float = 5.0,
    ) -> None:
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)

        self.allowed_extensions = allowed_extensions or set(DEFAULT_TEXT_EXTENSIONS)
        self.chunk_size = max(300, int(chunk_size))
        self.chunk_overlap = max(0, int(chunk_overlap))
        self.max_file_chars = max(10_000, int(max_file_chars))
        self.reindex_interval_sec = max(0.0, float(reindex_interval_sec))

        self._lock = threading.RLock()
        self._files: Dict[str, FileRecord] = {}
        self._token_doc_freq: Dict[str, int] = {}
        self._total_chunks = 0
        self._last_index_at = 0.0

    def _should_reindex(self) -> bool:
        if not self._files:
            return True
        return (time.time() - self._last_index_at) >= self.reindex_interval_sec

    def _iter_candidate_files(self) -> Iterable[Path]:
        for path in self.root_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in self.allowed_extensions:
                continue
            yield path

    def _build_chunk_record(
        self,
        path: Path,
        rel_path: str,
        chunk_id: int,
        chunk_text: str,
        char_start: int,
        char_end: int,
        modified_at: float,
        file_size: int,
    ) -> ChunkRecord:
        lowered = chunk_text.lower()
        raw_tokens = _tokenize(lowered)
        normalized_tokens = _normalize_tokens(raw_tokens)
        return ChunkRecord(
            file_path=str(path),
            file_name=path.name,
            rel_path=rel_path,
            chunk_id=chunk_id,
            text=chunk_text,
            normalized_text=" ".join(normalized_tokens),
            tokens=normalized_tokens,
            unique_tokens=set(normalized_tokens),
            char_start=char_start,
            char_end=char_end,
            modified_at=modified_at,
            file_size=file_size,
        )

    def _index_file(self, path: Path) -> Optional[FileRecord]:
        st = _safe_stat(path)
        if st is None:
            return None

        try:
            text = _read_text_file(path, self.max_file_chars)
        except OSError:
            return None

        rel_path = str(path.relative_to(self.root_dir))
        chunk_specs = _chunk_text(
            text,
            chunk_size=self.chunk_size,
            overlap=self.chunk_overlap,
        )

        chunks: List[ChunkRecord] = []
        for idx, (chunk_text, start, end) in enumerate(chunk_specs):
            chunk_text = _normalize_whitespace(chunk_text)
            if not chunk_text:
                continue
            chunks.append(
                self._build_chunk_record(
                    path=path,
                    rel_path=rel_path,
                    chunk_id=idx,
                    chunk_text=chunk_text,
                    char_start=start,
                    char_end=end,
                    modified_at=st.st_mtime,
                    file_size=st.st_size,
                )
            )

        return FileRecord(
            path=path,
            modified_at=st.st_mtime,
            size=st.st_size,
            chunks=chunks,
        )

    def _rebuild_index(self) -> None:
        files: Dict[str, FileRecord] = {}
        token_doc_freq: Dict[str, int] = {}
        total_chunks = 0

        for path in self._iter_candidate_files():
            record = self._index_file(path)
            if record is None:
                continue

            files[str(path)] = record
            for chunk in record.chunks:
                total_chunks += 1
                for token in chunk.unique_tokens:
                    token_doc_freq[token] = token_doc_freq.get(token, 0) + 1

        self._files = files
        self._token_doc_freq = token_doc_freq
        self._total_chunks = max(1, total_chunks)
        self._last_index_at = time.time()

    def refresh_index(self, force: bool = False) -> None:
        with self._lock:
            if not force and not self._should_reindex():
                return
            self._rebuild_index()

    def _idf(self, token: str) -> float:
        df = self._token_doc_freq.get(token, 0)
        return math.log((1.0 + self._total_chunks) / (1.0 + df)) + 1.0

    def _score_chunk(
        self,
        chunk: ChunkRecord,
        query_tokens: List[str],
        query_phrases: List[str],
    ) -> float:
        if not query_tokens and not query_phrases:
            return 0.0

        score = 0.0
        text_lower = chunk.text.lower()
        file_name_lower = chunk.file_name.lower()
        rel_path_lower = chunk.rel_path.lower()

        # token scoring
        if query_tokens:
            token_counts: Dict[str, int] = {}
            for token in chunk.tokens:
                token_counts[token] = token_counts.get(token, 0) + 1

            matched_unique = 0
            for token in query_tokens:
                count = token_counts.get(token, 0)
                if count <= 0:
                    continue

                matched_unique += 1
                tf = 1.0 + math.log(1.0 + count)
                score += tf * self._idf(token)

                if token in file_name_lower:
                    score += 2.2
                elif token in rel_path_lower:
                    score += 1.0

            coverage = matched_unique / max(1, len(set(query_tokens)))
            score += coverage * 4.0

        # phrase boosts
        for phrase in query_phrases:
            if not phrase:
                continue
            if phrase in text_lower:
                score += 6.0
            if phrase in file_name_lower:
                score += 4.0
            if phrase in rel_path_lower:
                score += 2.5

        # small recency boost
        age_seconds = max(0.0, time.time() - chunk.modified_at)
        age_days = age_seconds / 86400.0
        score += 1.5 / (1.0 + age_days / 30.0)

        # slight preference for medium-size chunks over tiny or huge ones
        length = len(chunk.text)
        if 250 <= length <= 1600:
            score += 0.75
        elif length < 120:
            score -= 0.5

        return score

    def _make_excerpt(
        self,
        chunk_text: str,
        query_tokens: List[str],
        query_phrases: List[str],
        max_chars: int = 800,
    ) -> str:
        text = _normalize_whitespace(chunk_text)
        if len(text) <= max_chars:
            return text

        lower = text.lower()
        hit_positions: List[int] = []

        for phrase in query_phrases:
            pos = lower.find(phrase)
            if pos >= 0:
                hit_positions.append(pos)

        for token in query_tokens:
            pos = lower.find(token)
            if pos >= 0:
                hit_positions.append(pos)

        if not hit_positions:
            return text[:max_chars].rstrip() + "..."

        center = min(hit_positions)
        start = max(0, center - max_chars // 3)
        end = min(len(text), start + max_chars)

        if end - start < max_chars and start > 0:
            start = max(0, end - max_chars)

        excerpt = text[start:end].strip()
        if start > 0:
            excerpt = "..." + excerpt
        if end < len(text):
            excerpt = excerpt + "..."
        return excerpt

    def search(
        self,
        query: str,
        limit: int = 5,
        *,
        per_file_limit: int = 2,
        excerpt_chars: int = 800,
    ) -> List[Dict[str, str]]:
        query = _normalize_whitespace(query)
        if not query:
            return []

        self.refresh_index()

        query_tokens, query_phrases = _extract_query_parts(query)
        if not query_tokens and not query_phrases:
            return []

        ranked: List[tuple[float, ChunkRecord]] = []

        with self._lock:
            for record in self._files.values():
                for chunk in record.chunks:
                    score = self._score_chunk(chunk, query_tokens, query_phrases)
                    if score > 0:
                        ranked.append((score, chunk))

        ranked.sort(key=lambda item: item[0], reverse=True)

        results: List[Dict[str, str]] = []
        per_file_counts: Dict[str, int] = {}
        seen_chunk_keys: set[tuple[str, int]] = set()

        for score, chunk in ranked:
            file_key = chunk.file_path
            chunk_key = (chunk.file_path, chunk.chunk_id)

            if chunk_key in seen_chunk_keys:
                continue
            if per_file_counts.get(file_key, 0) >= per_file_limit:
                continue

            excerpt = self._make_excerpt(
                chunk.text,
                query_tokens=query_tokens,
                query_phrases=query_phrases,
                max_chars=excerpt_chars,
            )

            results.append(
                {
                    "file": chunk.file_path,
                    "file_name": chunk.file_name,
                    "relative_path": chunk.rel_path,
                    "chunk_id": str(chunk.chunk_id),
                    "score": f"{score:.4f}",
                    "excerpt": excerpt,
                    "char_range": f"{chunk.char_start}:{chunk.char_end}",
                    "modified_at": str(chunk.modified_at),
                    "file_size": str(chunk.file_size),
                }
            )

            seen_chunk_keys.add(chunk_key)
            per_file_counts[file_key] = per_file_counts.get(file_key, 0) + 1

            if len(results) >= limit:
                break

        return results