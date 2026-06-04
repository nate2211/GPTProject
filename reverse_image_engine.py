from __future__ import annotations

"""
PromptChat reverse_image_engine.py

Drop-in smarter reverse image + media matching engine.

Compatibility goals:
- Keeps the public reverse_image_tool(...) signature unchanged.
- Keeps old actions working: init_db, stats, add_path, add_url, import_folder, search.
- Keeps old DB columns, while adding additive migrations for better matching.
- Accepts local paths even when an LLM mistakenly passes them in image_url.

New capabilities:
- More robust image matching with multiple perceptual hashes, mirrored-hash matching,
  color/shape/entropy/aspect penalties, and clearer match evidence.
- Optional video handling. If OpenCV is installed, video files/URLs are sampled into
  frame fingerprints. Existing actions automatically route videos for add/search.
- Better file input coercion, URL/path handling, and safer bounded downloads.
"""

import hashlib
import io
import json
import math
import os
import re
import shutil
import sqlite3
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote, urlparse

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    from PIL import Image, ImageEnhance, ImageFilter, ImageOps, ImageStat
except Exception:  # pragma: no cover
    Image = None
    ImageEnhance = None
    ImageFilter = None
    ImageOps = None
    ImageStat = None

try:
    import imagehash
except Exception:  # pragma: no cover
    imagehash = None

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None


DEFAULT_DB_PATH = "data/reverse_image/reverse_images.sqlite3"
DEFAULT_STORE_DIR = "data/reverse_image/images"
DEFAULT_TIMEOUT_SEC = 20
DEFAULT_MAX_IMAGE_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_VIDEO_BYTES = 180 * 1024 * 1024
DEFAULT_MAX_DIMENSION = 1600
DEFAULT_VIDEO_FRAME_COUNT = 18
DEFAULT_VIDEO_SAMPLE_SECONDS = 90.0

SUPPORTED_IMAGE_SUFFIXES = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".bmp",
    ".gif",
    ".tif",
    ".tiff",
}

SUPPORTED_VIDEO_SUFFIXES = {
    ".mp4",
    ".m4v",
    ".mov",
    ".mkv",
    ".webm",
    ".avi",
    ".wmv",
    ".flv",
    ".mpeg",
    ".mpg",
}

IMAGE_ACCEPT_HEADER = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
MEDIA_ACCEPT_HEADER = "image/*,video/*,application/octet-stream,*/*;q=0.7"


@dataclass
class ImageFingerprint:
    width: int
    height: int
    sha256: str
    phash: str = ""
    dhash: str = ""
    ahash: str = ""
    whash: str = ""
    colorhash: str = ""
    avg_red: float = 0.0
    avg_green: float = 0.0
    avg_blue: float = 0.0
    # Additive, backward-compatible fields.
    edgehash: str = ""
    mirror_phash: str = ""
    mirror_dhash: str = ""
    aspect_ratio: float = 0.0
    entropy: float = 0.0
    avg_luma: float = 0.0
    std_luma: float = 0.0
    hist_sig: str = ""
    crop_phash: str = ""


@dataclass
class IndexedImage:
    id: int
    sha256: str
    source_type: str
    source: str
    stored_path: str
    width: int
    height: int
    phash: str
    dhash: str
    ahash: str
    whash: str
    colorhash: str
    title: str
    notes: str
    created_at: float
    updated_at: float


@dataclass
class VideoFrameFingerprint:
    frame_index: int
    time_sec: float
    fingerprint: ImageFingerprint


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------
def _now() -> float:
    return float(time.time())


def _ensure_deps() -> Optional[str]:
    missing = []
    if Image is None or ImageOps is None or ImageStat is None:
        missing.append("Pillow")
    if missing:
        return (
            "Missing required package(s): "
            + ", ".join(missing)
            + ". Install with: python -m pip install pillow"
        )
    return None


def _ensure_video_deps() -> Optional[str]:
    if cv2 is None:
        return "Video support requires OpenCV. Install with: python -m pip install opencv-python"
    return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _hex_to_int(value: str) -> Optional[int]:
    try:
        value = (value or "").strip().lower()
        if not value:
            return None
        # ImageHash strings are normally hex. Keep only hex chars so odd formatted
        # hash strings get a graceful penalty instead of crashing the match.
        value = re.sub(r"[^0-9a-f]", "", value)
        if not value:
            return None
        return int(value, 16)
    except Exception:
        return None


def hamming_hex(a: str, b: str) -> int:
    """
    SQLite-safe Hamming distance between two hex image hashes.
    Missing or malformed hashes get a large penalty instead of crashing.
    """
    ai = _hex_to_int(a)
    bi = _hex_to_int(b)
    if ai is None or bi is None:
        return 9999
    return int((ai ^ bi).bit_count())


def _hash_distance_min(query_hash: str, *candidate_hashes: str) -> int:
    distances = [hamming_hex(query_hash, c) for c in candidate_hashes if c]
    return min(distances) if distances else 9999


def _strip_wrapping_quotes(value: str) -> str:
    text = (value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1].strip()
    return text


def _is_http_url(value: str) -> bool:
    text = _strip_wrapping_quotes(value)
    try:
        parsed = urlparse(text)
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def _is_http_image_url(value: str) -> bool:
    return _is_http_url(value)


def _is_file_url(value: str) -> bool:
    text = _strip_wrapping_quotes(value)
    try:
        return urlparse(text).scheme.lower() == "file"
    except Exception:
        return False


def _file_url_to_local_path(value: str) -> str:
    """
    Convert file:///C:/x/y.jpg, file:/C:/x/y.jpg, and file:///home/x/y.jpg
    into a normal local path string.
    """
    text = _strip_wrapping_quotes(value)
    parsed = urlparse(text)

    if parsed.scheme.lower() != "file":
        return text

    if parsed.netloc and parsed.path:
        raw_path = f"//{parsed.netloc}{parsed.path}"
    else:
        raw_path = parsed.path or ""

    raw_path = unquote(raw_path)

    if re.match(r"^/[A-Za-z]:/", raw_path):
        raw_path = raw_path[1:]

    return raw_path.replace("/", os.sep) if os.name == "nt" else raw_path


def _looks_like_windows_path(value: str) -> bool:
    text = _strip_wrapping_quotes(value)
    return bool(re.match(r"^[A-Za-z]:[\\/]", text)) or text.startswith("\\\\")


def _suffix_of_url_or_path(value: str) -> str:
    text = _strip_wrapping_quotes(value)
    try:
        parsed = urlparse(text)
        if parsed.scheme in {"http", "https", "file"}:
            return Path(unquote(parsed.path)).suffix.lower()
    except Exception:
        pass
    return Path(text).suffix.lower()


def _looks_like_video_path_or_url(value: str) -> bool:
    return _suffix_of_url_or_path(value) in SUPPORTED_VIDEO_SUFFIXES


def _looks_like_image_path_or_url(value: str) -> bool:
    return _suffix_of_url_or_path(value) in SUPPORTED_IMAGE_SUFFIXES


def _looks_like_local_media_path(value: str) -> bool:
    text = _strip_wrapping_quotes(value)

    if not text:
        return False

    if _is_file_url(text):
        return True

    if _is_http_url(text):
        return False

    parsed = urlparse(text)
    if parsed.scheme and parsed.scheme.lower() not in {"file"}:
        return False

    if _looks_like_windows_path(text):
        return True

    if text.startswith(("./", "../", "~/", "/", ".\\", "..\\")):
        return True

    try:
        if Path(text).expanduser().exists():
            return True
    except Exception:
        pass

    suffix = Path(text).suffix.lower()
    if suffix in SUPPORTED_IMAGE_SUFFIXES or suffix in SUPPORTED_VIDEO_SUFFIXES:
        return True

    return False


def _looks_like_local_image_path(value: str) -> bool:
    text = _strip_wrapping_quotes(value)
    if not _looks_like_local_media_path(text):
        return False
    if _looks_like_video_path_or_url(text):
        return False
    return True


def _coerce_local_media_path(value: str) -> str:
    text = _strip_wrapping_quotes(value)
    if _is_file_url(text):
        return _file_url_to_local_path(text)
    return text


def _resolve_media_input(
    *,
    image_input: str = "",
    image_path: str = "",
    image_url: str = "",
) -> Tuple[str, str, str]:
    """
    Return (location_kind, value, media_kind).

    location_kind: "path" or "url"
    media_kind: "image", "video", or "unknown"

    This intentionally accepts local paths in image_url because LLMs often put a
    Windows path into the URL field when calling tools.
    """
    candidates = [
        ("image_path", image_path),
        ("image_input", image_input),
        ("image_url", image_url),
    ]

    for field_name, value in candidates:
        text = _strip_wrapping_quotes(value)
        if not text:
            continue

        if _is_http_url(text):
            if _looks_like_video_path_or_url(text):
                return "url", text, "video"
            if _looks_like_image_path_or_url(text):
                return "url", text, "image"
            return "url", text, "unknown"

        if _looks_like_local_media_path(text):
            path_value = _coerce_local_media_path(text)
            if _looks_like_video_path_or_url(path_value):
                return "path", path_value, "video"
            if _looks_like_image_path_or_url(path_value):
                return "path", path_value, "image"
            return "path", path_value, "unknown"

        if field_name in {"image_path", "image_input"}:
            path_value = _coerce_local_media_path(text)
            if _looks_like_video_path_or_url(path_value):
                return "path", path_value, "video"
            return "path", path_value, "image"

    return "", "", ""


def _resolve_image_input(
    *,
    image_input: str = "",
    image_path: str = "",
    image_url: str = "",
) -> Tuple[str, str]:
    location_kind, value, _media_kind = _resolve_media_input(
        image_input=image_input,
        image_path=image_path,
        image_url=image_url,
    )
    return location_kind, value


# ---------------------------------------------------------------------------
# Downloads and media opening
# ---------------------------------------------------------------------------
def _download_bytes(
    url: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
    accept: str = MEDIA_ACCEPT_HEADER,
) -> bytes:
    if requests is None:
        raise RuntimeError("requests is unavailable. Install with: python -m pip install requests")

    clean_url = (url or "").strip()
    if not clean_url:
        raise ValueError("URL is required.")

    parsed = urlparse(clean_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(
            "URL must be HTTP/HTTPS. For local files, use image_path, image_input, or pass the local path anyway and reverse_image_tool will route it before download."
        )

    headers = {
        "User-Agent": "GPTProject-ReverseImageEngine/2.0 (+local user tool)",
        "Accept": accept,
    }

    with requests.get(clean_url, timeout=int(timeout_sec), stream=True, headers=headers) as resp:
        resp.raise_for_status()
        chunks: List[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"Downloaded media exceeded max_bytes={max_bytes}.")
            chunks.append(chunk)

    return b"".join(chunks)


def _download_image(
    url: str,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
) -> bytes:
    return _download_bytes(
        url,
        timeout_sec=timeout_sec,
        max_bytes=max_bytes,
        accept=IMAGE_ACCEPT_HEADER,
    )


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _normalized_png_bytes(image: Any) -> bytes:
    out = io.BytesIO()
    image.save(out, format="PNG", optimize=True)
    return out.getvalue()


def _normalize_image_for_hash(image: Any, max_dimension: int = DEFAULT_MAX_DIMENSION) -> Any:
    if ImageOps is None:
        raise RuntimeError("Pillow ImageOps is unavailable.")

    image = ImageOps.exif_transpose(image)

    if getattr(image, "mode", "") not in ("RGB", "RGBA"):
        image = image.convert("RGB")
    elif image.mode == "RGBA":
        background = Image.new("RGB", image.size, (255, 255, 255))
        background.paste(image, mask=image.getchannel("A"))
        image = background
    else:
        image = image.convert("RGB")

    max_dimension = max(64, int(max_dimension or DEFAULT_MAX_DIMENSION))
    if max(image.size) > max_dimension:
        image.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else 1)

    return image


def _open_image_from_bytes(raw: bytes, max_dimension: int = DEFAULT_MAX_DIMENSION) -> Any:
    missing = _ensure_deps()
    if missing:
        raise RuntimeError(missing)

    if not raw:
        raise ValueError("Image bytes are empty.")

    if len(raw) > DEFAULT_MAX_IMAGE_BYTES:
        raise ValueError(
            f"Image is too large: {len(raw)} bytes > {DEFAULT_MAX_IMAGE_BYTES} bytes."
        )

    with Image.open(io.BytesIO(raw)) as img:
        return _normalize_image_for_hash(img, max_dimension=max_dimension).copy()


def _open_image_from_path(path: str, max_dimension: int = DEFAULT_MAX_DIMENSION) -> Tuple[Any, bytes]:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"Image path does not exist: {p}")
    if not p.is_file():
        raise ValueError(f"Image path is not a file: {p}")

    raw = p.read_bytes()
    return _open_image_from_bytes(raw, max_dimension=max_dimension), raw


def _temp_file_from_url(url: str, suffix: str, timeout_sec: int, max_bytes: int) -> Tuple[str, bytes]:
    raw = _download_bytes(url, timeout_sec=timeout_sec, max_bytes=max_bytes, accept=MEDIA_ACCEPT_HEADER)
    suffix = suffix or _suffix_of_url_or_path(url) or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as fh:
        fh.write(raw)
        return fh.name, raw


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------
def _image_entropy(gray_image: Any) -> float:
    try:
        histogram = gray_image.histogram()
        total = float(sum(histogram)) or 1.0
        entropy = 0.0
        for count in histogram:
            if count:
                p = count / total
                entropy -= p * math.log2(p)
        return float(entropy)
    except Exception:
        return 0.0


def _histogram_signature(image: Any, bins_per_channel: int = 4) -> str:
    """Compact RGB histogram signature for color-aware matching."""
    try:
        small = image.resize((64, 64))
        pixels = list(small.getdata())
        bins = [0] * (bins_per_channel ** 3)
        step = 256 // bins_per_channel
        for r, g, b in pixels:
            ri = min(bins_per_channel - 1, int(r) // step)
            gi = min(bins_per_channel - 1, int(g) // step)
            bi = min(bins_per_channel - 1, int(b) // step)
            bins[(ri * bins_per_channel * bins_per_channel) + (gi * bins_per_channel) + bi] += 1
        total = max(1, sum(bins))
        # Quantize to 0..15 and encode as hex characters.
        return "".join(format(min(15, int(round((v / total) * 15))), "x") for v in bins)
    except Exception:
        return ""


def _histogram_distance(a: str, b: str) -> float:
    if not a or not b or len(a) != len(b):
        return 12.0
    try:
        vals_a = [int(ch, 16) for ch in a]
        vals_b = [int(ch, 16) for ch in b]
        return float(sum(abs(x - y) for x, y in zip(vals_a, vals_b)) / max(1, len(vals_a)))
    except Exception:
        return 12.0


def _crop_center(image: Any, ratio: float = 0.78) -> Any:
    try:
        w, h = image.size
        nw = max(16, int(w * ratio))
        nh = max(16, int(h * ratio))
        left = max(0, (w - nw) // 2)
        top = max(0, (h - nh) // 2)
        return image.crop((left, top, left + nw, top + nh))
    except Exception:
        return image


def _edge_image(image: Any) -> Any:
    try:
        if ImageFilter is None:
            return image.convert("L")
        return image.convert("L").filter(ImageFilter.FIND_EDGES)
    except Exception:
        return image.convert("L")




def _bits_to_hex(bits: Iterable[bool]) -> str:
    value = 0
    count = 0
    for bit in bits:
        value = (value << 1) | (1 if bit else 0)
        count += 1
    width = max(1, (count + 3) // 4)
    return f"{value:0{width}x}"


def _fallback_average_hash(image: Any, hash_size: int = 8) -> str:
    gray = image.convert("L").resize((hash_size, hash_size))
    pixels = list(gray.getdata())
    avg = sum(pixels) / max(1, len(pixels))
    return _bits_to_hex(p >= avg for p in pixels)


def _fallback_dhash(image: Any, hash_size: int = 8) -> str:
    gray = image.convert("L").resize((hash_size + 1, hash_size))
    pixels = list(gray.getdata())
    bits = []
    for y in range(hash_size):
        row = pixels[y * (hash_size + 1):(y + 1) * (hash_size + 1)]
        for x in range(hash_size):
            bits.append(row[x] > row[x + 1])
    return _bits_to_hex(bits)


def _fallback_phash(image: Any, hash_size: int = 8, highfreq_factor: int = 4) -> str:
    # Lightweight DCT pHash if numpy is present; otherwise average hash.
    try:
        import numpy as _np  # type: ignore
        size = hash_size * highfreq_factor
        gray = image.convert("L").resize((size, size))
        arr = _np.asarray(gray, dtype=float)
        # Slow but dependency-light 2D DCT using matrix multiplication.
        n = arr.shape[0]
        k = _np.arange(n).reshape(-1, 1)
        i = _np.arange(n).reshape(1, -1)
        mat = _np.cos((_np.pi / n) * (i + 0.5) * k)
        dct = mat @ arr @ mat.T
        low = dct[:hash_size, :hash_size].flatten()
        med = _np.median(low[1:]) if low.size > 1 else _np.median(low)
        return _bits_to_hex(v >= med for v in low)
    except Exception:
        return _fallback_average_hash(image, hash_size=hash_size)


def _fallback_colorhash(image: Any) -> str:
    return _histogram_signature(image, bins_per_channel=4)[:64]


def _hash_average(image: Any) -> str:
    if imagehash is not None:
        try:
            return str(imagehash.average_hash(image))
        except Exception:
            pass
    return _fallback_average_hash(image)


def _hash_dhash(image: Any) -> str:
    if imagehash is not None:
        try:
            return str(imagehash.dhash(image))
        except Exception:
            pass
    return _fallback_dhash(image)


def _hash_phash(image: Any) -> str:
    if imagehash is not None:
        try:
            return str(imagehash.phash(image))
        except Exception:
            pass
    return _fallback_phash(image)


def _hash_whash(image: Any) -> str:
    if imagehash is not None:
        try:
            return str(imagehash.whash(image))
        except Exception:
            pass
    return _fallback_average_hash(image)


def _hash_color(image: Any) -> str:
    if imagehash is not None:
        try:
            return str(imagehash.colorhash(image))
        except Exception:
            pass
    return _fallback_colorhash(image)

def _compute_fingerprint(image: Any, original_raw: Optional[bytes] = None) -> ImageFingerprint:
    missing = _ensure_deps()
    if missing:
        raise RuntimeError(missing)

    width, height = image.size
    normalized_raw = _normalized_png_bytes(image)
    sha = _sha256_bytes(original_raw or normalized_raw)

    # Main perceptual hashes. Uses ImageHash when installed, otherwise built-in Pillow/numpy fallbacks.
    phash = _hash_phash(image)
    dhash = _hash_dhash(image)
    ahash = _hash_average(image)
    whash = _hash_whash(image)
    colorhash = _hash_color(image)

    # Mirrored hashes make matches more robust for flipped screenshots/photos.
    mirror = ImageOps.mirror(image)
    try:
        mirror_phash = _hash_phash(mirror)
        mirror_dhash = _hash_dhash(mirror)
    except Exception:
        mirror_phash = ""
        mirror_dhash = ""

    # Edge hash handles cases where colors shift but structure stays similar.
    try:
        edgehash = _hash_dhash(_edge_image(image))
    except Exception:
        edgehash = ""

    # Center crop hash handles thumbnails/crops better than full-frame only.
    try:
        crop_phash = _hash_phash(_crop_center(image))
    except Exception:
        crop_phash = ""

    avg_red = avg_green = avg_blue = avg_luma = std_luma = entropy = 0.0
    try:
        stat = ImageStat.Stat(image)
        means = stat.mean or [0, 0, 0]
        avg_red = float(means[0])
        avg_green = float(means[1])
        avg_blue = float(means[2])
    except Exception:
        pass

    try:
        gray = image.convert("L")
        gstat = ImageStat.Stat(gray)
        avg_luma = float((gstat.mean or [0.0])[0])
        std_luma = float((gstat.stddev or [0.0])[0])
        entropy = _image_entropy(gray)
    except Exception:
        pass

    hist_sig = _histogram_signature(image)
    aspect_ratio = float(width) / float(height) if height else 0.0

    return ImageFingerprint(
        width=int(width),
        height=int(height),
        sha256=sha,
        phash=phash,
        dhash=dhash,
        ahash=ahash,
        whash=whash,
        colorhash=colorhash,
        avg_red=avg_red,
        avg_green=avg_green,
        avg_blue=avg_blue,
        edgehash=edgehash,
        mirror_phash=mirror_phash,
        mirror_dhash=mirror_dhash,
        aspect_ratio=aspect_ratio,
        entropy=entropy,
        avg_luma=avg_luma,
        std_luma=std_luma,
        hist_sig=hist_sig,
        crop_phash=crop_phash,
    )


def _fingerprint_to_db_values(fp: ImageFingerprint) -> Dict[str, Any]:
    return asdict(fp)


# ---------------------------------------------------------------------------
# Video frame extraction
# ---------------------------------------------------------------------------
def _frame_to_image(frame: Any, max_dimension: int) -> Any:
    if cv2 is None:
        raise RuntimeError(_ensure_video_deps() or "OpenCV unavailable")
    if Image is None:
        raise RuntimeError("Pillow unavailable")
    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    img = Image.fromarray(rgb)
    return _normalize_image_for_hash(img, max_dimension=max_dimension)


def _extract_video_frame_fingerprints(
    video_path: str,
    *,
    frame_count: int = DEFAULT_VIDEO_FRAME_COUNT,
    max_sample_seconds: float = DEFAULT_VIDEO_SAMPLE_SECONDS,
    max_dimension: int = DEFAULT_MAX_DIMENSION,
) -> Dict[str, Any]:
    missing = _ensure_deps() or _ensure_video_deps()
    if missing:
        raise RuntimeError(missing)

    p = Path(video_path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"Video path does not exist: {p}")

    cap = cv2.VideoCapture(str(p))
    if not cap.isOpened():
        raise ValueError(f"Could not open video: {p}")

    try:
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        fps = float(cap.get(cv2.CAP_PROP_FPS) or 0.0)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        duration = float(total_frames / fps) if total_frames > 0 and fps > 0 else 0.0

        frame_count = max(1, min(int(frame_count or DEFAULT_VIDEO_FRAME_COUNT), 80))
        sample_duration = duration if duration > 0 else max_sample_seconds
        if max_sample_seconds and max_sample_seconds > 0:
            sample_duration = min(sample_duration, float(max_sample_seconds))

        if total_frames > 0 and fps > 0 and sample_duration > 0:
            end_frame = max(0, min(total_frames - 1, int(sample_duration * fps)))
            if frame_count == 1:
                targets = [min(end_frame, max(0, int(end_frame / 2)))]
            else:
                targets = [int(round(i * end_frame / max(1, frame_count - 1))) for i in range(frame_count)]
        elif total_frames > 0:
            targets = [int(round(i * (total_frames - 1) / max(1, frame_count - 1))) for i in range(frame_count)]
        else:
            targets = list(range(frame_count))

        seen_targets: set[int] = set()
        frames: List[VideoFrameFingerprint] = []
        failed_frames = 0

        for target in targets:
            if target in seen_targets:
                continue
            seen_targets.add(target)
            try:
                if total_frames > 0:
                    cap.set(cv2.CAP_PROP_POS_FRAMES, target)
                ok, frame = cap.read()
                if not ok or frame is None:
                    failed_frames += 1
                    continue
                img = _frame_to_image(frame, max_dimension=max_dimension)
                raw = _normalized_png_bytes(img)
                fp = _compute_fingerprint(img, original_raw=raw)
                time_sec = float(target / fps) if fps > 0 else 0.0
                frames.append(VideoFrameFingerprint(frame_index=int(target), time_sec=time_sec, fingerprint=fp))
            except Exception:
                failed_frames += 1

        return {
            "ok": True,
            "path": str(p),
            "width": width,
            "height": height,
            "fps": fps,
            "frame_count_total": total_frames,
            "duration_sec": duration,
            "sampled_count": len(frames),
            "failed_frames": failed_frames,
            "frames": frames,
        }
    finally:
        cap.release()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
class ReverseImageDatabase:
    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        store_dir: str = DEFAULT_STORE_DIR,
    ) -> None:
        self.db_path = Path(db_path).expanduser()
        self.store_dir = Path(store_dir).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(self.db_path))
        con.row_factory = sqlite3.Row
        con.create_function("hamming_hex", 2, hamming_hex)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA temp_store=MEMORY")
        return con

    def _table_columns(self, con: sqlite3.Connection, table: str) -> set[str]:
        try:
            return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
        except Exception:
            return set()

    def _add_column_if_missing(self, con: sqlite3.Connection, table: str, name: str, ddl_type: str) -> None:
        cols = self._table_columns(con, table)
        if name not in cols:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl_type}")

    def init_db(self) -> Dict[str, Any]:
        with self.connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS images (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256 TEXT NOT NULL UNIQUE,
                    source_type TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    stored_path TEXT NOT NULL DEFAULT '',
                    width INTEGER NOT NULL DEFAULT 0,
                    height INTEGER NOT NULL DEFAULT 0,
                    phash TEXT NOT NULL DEFAULT '',
                    dhash TEXT NOT NULL DEFAULT '',
                    ahash TEXT NOT NULL DEFAULT '',
                    whash TEXT NOT NULL DEFAULT '',
                    colorhash TEXT NOT NULL DEFAULT '',
                    avg_red REAL NOT NULL DEFAULT 0,
                    avg_green REAL NOT NULL DEFAULT 0,
                    avg_blue REAL NOT NULL DEFAULT 0,
                    title TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS media (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256 TEXT NOT NULL UNIQUE,
                    media_type TEXT NOT NULL DEFAULT 'video',
                    source_type TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    stored_path TEXT NOT NULL DEFAULT '',
                    width INTEGER NOT NULL DEFAULT 0,
                    height INTEGER NOT NULL DEFAULT 0,
                    fps REAL NOT NULL DEFAULT 0,
                    duration_sec REAL NOT NULL DEFAULT 0,
                    frame_count_total INTEGER NOT NULL DEFAULT 0,
                    sampled_count INTEGER NOT NULL DEFAULT 0,
                    title TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_images_sha256 ON images(sha256);
                CREATE INDEX IF NOT EXISTS idx_images_phash ON images(phash);
                CREATE INDEX IF NOT EXISTS idx_images_dhash ON images(dhash);
                CREATE INDEX IF NOT EXISTS idx_images_ahash ON images(ahash);
                CREATE INDEX IF NOT EXISTS idx_images_whash ON images(whash);
                CREATE INDEX IF NOT EXISTS idx_images_source ON images(source);
                CREATE INDEX IF NOT EXISTS idx_media_sha256 ON media(sha256);
                CREATE INDEX IF NOT EXISTS idx_media_source ON media(source);
                """
            )

            # Additive migrations for smarter matching and video frame provenance.
            migrations = {
                "edgehash": "TEXT NOT NULL DEFAULT ''",
                "mirror_phash": "TEXT NOT NULL DEFAULT ''",
                "mirror_dhash": "TEXT NOT NULL DEFAULT ''",
                "aspect_ratio": "REAL NOT NULL DEFAULT 0",
                "entropy": "REAL NOT NULL DEFAULT 0",
                "avg_luma": "REAL NOT NULL DEFAULT 0",
                "std_luma": "REAL NOT NULL DEFAULT 0",
                "hist_sig": "TEXT NOT NULL DEFAULT ''",
                "crop_phash": "TEXT NOT NULL DEFAULT ''",
                "media_kind": "TEXT NOT NULL DEFAULT 'image'",
                "source_media_id": "INTEGER NOT NULL DEFAULT 0",
                "frame_index": "INTEGER NOT NULL DEFAULT -1",
                "frame_time_sec": "REAL NOT NULL DEFAULT 0",
            }
            for name, ddl in migrations.items():
                self._add_column_if_missing(con, "images", name, ddl)

            con.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_images_edgehash ON images(edgehash);
                CREATE INDEX IF NOT EXISTS idx_images_mirror_phash ON images(mirror_phash);
                CREATE INDEX IF NOT EXISTS idx_images_media_kind ON images(media_kind);
                CREATE INDEX IF NOT EXISTS idx_images_source_media_id ON images(source_media_id);
                CREATE INDEX IF NOT EXISTS idx_images_frame_index ON images(frame_index);
                """
            )
            con.commit()

        return {
            "ok": True,
            "db_path": str(self.db_path),
            "store_dir": str(self.store_dir),
            "video_support": cv2 is not None,
            "schema_version": 2,
        }

    def stats(self) -> Dict[str, Any]:
        self.init_db()
        with self.connect() as con:
            row = con.execute(
                """
                SELECT
                    COUNT(*) AS count,
                    SUM(CASE WHEN media_kind = 'image' THEN 1 ELSE 0 END) AS image_count,
                    SUM(CASE WHEN media_kind = 'video_frame' THEN 1 ELSE 0 END) AS video_frame_count,
                    MIN(created_at) AS first_created_at,
                    MAX(updated_at) AS last_updated_at
                FROM images
                """
            ).fetchone()
            media_row = con.execute("SELECT COUNT(*) AS count FROM media").fetchone()

        return {
            "ok": True,
            "db_path": str(self.db_path),
            "store_dir": str(self.store_dir),
            "count": int(row["count"] or 0),
            "image_count": int(row["image_count"] or 0),
            "video_count": int(media_row["count"] or 0),
            "video_frame_count": int(row["video_frame_count"] or 0),
            "first_created_at": float(row["first_created_at"] or 0),
            "last_updated_at": float(row["last_updated_at"] or 0),
            "video_support": cv2 is not None,
        }

    def _stored_path_for_sha(self, sha256: str, suffix: str = ".png", subdir: str = "") -> Path:
        safe_suffix = suffix if suffix.startswith(".") else "." + suffix
        if safe_suffix.lower() not in SUPPORTED_IMAGE_SUFFIXES and safe_suffix.lower() not in SUPPORTED_VIDEO_SUFFIXES and safe_suffix.lower() != ".png":
            safe_suffix = ".png"
        root = self.store_dir / subdir if subdir else self.store_dir
        return root / f"{sha256[:2]}" / f"{sha256}{safe_suffix.lower()}"

    def upsert_image(
        self,
        fingerprint: ImageFingerprint,
        raw_bytes: bytes,
        source_type: str,
        source: str,
        title: str = "",
        notes: str = "",
        copy_store: bool = True,
        original_suffix: str = ".png",
        media_kind: str = "image",
        source_media_id: int = 0,
        frame_index: int = -1,
        frame_time_sec: float = 0.0,
    ) -> Dict[str, Any]:
        self.init_db()
        now = _now()

        stored_path = ""
        if copy_store:
            dest = self._stored_path_for_sha(fingerprint.sha256, original_suffix, subdir="frames" if media_kind == "video_frame" else "")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                dest.write_bytes(raw_bytes)
            stored_path = str(dest)

        fpv = _fingerprint_to_db_values(fingerprint)

        with self.connect() as con:
            existing = con.execute(
                "SELECT id FROM images WHERE sha256 = ?",
                (fingerprint.sha256,),
            ).fetchone()

            values = {
                "source_type": source_type,
                "source": source,
                "stored_path": stored_path,
                "width": fingerprint.width,
                "height": fingerprint.height,
                "phash": fingerprint.phash,
                "dhash": fingerprint.dhash,
                "ahash": fingerprint.ahash,
                "whash": fingerprint.whash,
                "colorhash": fingerprint.colorhash,
                "avg_red": fingerprint.avg_red,
                "avg_green": fingerprint.avg_green,
                "avg_blue": fingerprint.avg_blue,
                "edgehash": fingerprint.edgehash,
                "mirror_phash": fingerprint.mirror_phash,
                "mirror_dhash": fingerprint.mirror_dhash,
                "aspect_ratio": fingerprint.aspect_ratio,
                "entropy": fingerprint.entropy,
                "avg_luma": fingerprint.avg_luma,
                "std_luma": fingerprint.std_luma,
                "hist_sig": fingerprint.hist_sig,
                "crop_phash": fingerprint.crop_phash,
                "media_kind": media_kind,
                "source_media_id": int(source_media_id or 0),
                "frame_index": int(frame_index),
                "frame_time_sec": float(frame_time_sec or 0.0),
                "title": title,
                "notes": notes,
                "updated_at": now,
            }

            if existing:
                image_id = int(existing["id"])
                con.execute(
                    """
                    UPDATE images
                    SET
                        source_type = COALESCE(NULLIF(:source_type, ''), source_type),
                        source = COALESCE(NULLIF(:source, ''), source),
                        stored_path = COALESCE(NULLIF(:stored_path, ''), stored_path),
                        width = :width,
                        height = :height,
                        phash = :phash,
                        dhash = :dhash,
                        ahash = :ahash,
                        whash = :whash,
                        colorhash = :colorhash,
                        avg_red = :avg_red,
                        avg_green = :avg_green,
                        avg_blue = :avg_blue,
                        edgehash = :edgehash,
                        mirror_phash = :mirror_phash,
                        mirror_dhash = :mirror_dhash,
                        aspect_ratio = :aspect_ratio,
                        entropy = :entropy,
                        avg_luma = :avg_luma,
                        std_luma = :std_luma,
                        hist_sig = :hist_sig,
                        crop_phash = :crop_phash,
                        media_kind = COALESCE(NULLIF(:media_kind, ''), media_kind),
                        source_media_id = CASE WHEN :source_media_id > 0 THEN :source_media_id ELSE source_media_id END,
                        frame_index = CASE WHEN :frame_index >= 0 THEN :frame_index ELSE frame_index END,
                        frame_time_sec = CASE WHEN :frame_time_sec > 0 THEN :frame_time_sec ELSE frame_time_sec END,
                        title = COALESCE(NULLIF(:title, ''), title),
                        notes = COALESCE(NULLIF(:notes, ''), notes),
                        updated_at = :updated_at
                    WHERE id = :id
                    """,
                    {**values, "id": image_id},
                )
                inserted = False
            else:
                cur = con.execute(
                    """
                    INSERT INTO images (
                        sha256, source_type, source, stored_path,
                        width, height,
                        phash, dhash, ahash, whash, colorhash,
                        avg_red, avg_green, avg_blue,
                        edgehash, mirror_phash, mirror_dhash,
                        aspect_ratio, entropy, avg_luma, std_luma, hist_sig, crop_phash,
                        media_kind, source_media_id, frame_index, frame_time_sec,
                        title, notes, created_at, updated_at
                    )
                    VALUES (
                        :sha256, :source_type, :source, :stored_path,
                        :width, :height,
                        :phash, :dhash, :ahash, :whash, :colorhash,
                        :avg_red, :avg_green, :avg_blue,
                        :edgehash, :mirror_phash, :mirror_dhash,
                        :aspect_ratio, :entropy, :avg_luma, :std_luma, :hist_sig, :crop_phash,
                        :media_kind, :source_media_id, :frame_index, :frame_time_sec,
                        :title, :notes, :created_at, :updated_at
                    )
                    """,
                    {**values, "sha256": fingerprint.sha256, "created_at": now},
                )
                image_id = int(cur.lastrowid)
                inserted = True

            con.commit()

        return {
            "ok": True,
            "inserted": inserted,
            "id": image_id,
            "sha256": fingerprint.sha256,
            "stored_path": stored_path,
            "media_kind": media_kind,
            "source_media_id": int(source_media_id or 0),
            "frame_index": int(frame_index),
            "frame_time_sec": float(frame_time_sec or 0.0),
            "fingerprint": fpv,
        }

    def _upsert_media(
        self,
        *,
        sha256: str,
        raw_bytes: bytes,
        source_type: str,
        source: str,
        title: str = "",
        notes: str = "",
        copy_store: bool = True,
        original_suffix: str = ".mp4",
        width: int = 0,
        height: int = 0,
        fps: float = 0.0,
        duration_sec: float = 0.0,
        frame_count_total: int = 0,
        sampled_count: int = 0,
    ) -> Dict[str, Any]:
        self.init_db()
        now = _now()
        stored_path = ""
        if copy_store:
            dest = self._stored_path_for_sha(sha256, original_suffix, subdir="videos")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                dest.write_bytes(raw_bytes)
            stored_path = str(dest)

        with self.connect() as con:
            existing = con.execute("SELECT id FROM media WHERE sha256 = ?", (sha256,)).fetchone()
            vals = {
                "sha256": sha256,
                "source_type": source_type,
                "source": source,
                "stored_path": stored_path,
                "width": int(width or 0),
                "height": int(height or 0),
                "fps": float(fps or 0.0),
                "duration_sec": float(duration_sec or 0.0),
                "frame_count_total": int(frame_count_total or 0),
                "sampled_count": int(sampled_count or 0),
                "title": title,
                "notes": notes,
                "updated_at": now,
            }
            if existing:
                media_id = int(existing["id"])
                con.execute(
                    """
                    UPDATE media
                    SET source_type = COALESCE(NULLIF(:source_type, ''), source_type),
                        source = COALESCE(NULLIF(:source, ''), source),
                        stored_path = COALESCE(NULLIF(:stored_path, ''), stored_path),
                        width = :width,
                        height = :height,
                        fps = :fps,
                        duration_sec = :duration_sec,
                        frame_count_total = :frame_count_total,
                        sampled_count = :sampled_count,
                        title = COALESCE(NULLIF(:title, ''), title),
                        notes = COALESCE(NULLIF(:notes, ''), notes),
                        updated_at = :updated_at
                    WHERE id = :id
                    """,
                    {**vals, "id": media_id},
                )
                inserted = False
            else:
                cur = con.execute(
                    """
                    INSERT INTO media (
                        sha256, media_type, source_type, source, stored_path,
                        width, height, fps, duration_sec, frame_count_total, sampled_count,
                        title, notes, created_at, updated_at
                    ) VALUES (
                        :sha256, 'video', :source_type, :source, :stored_path,
                        :width, :height, :fps, :duration_sec, :frame_count_total, :sampled_count,
                        :title, :notes, :created_at, :updated_at
                    )
                    """,
                    {**vals, "created_at": now},
                )
                media_id = int(cur.lastrowid)
                inserted = True
            con.commit()

        return {
            "ok": True,
            "inserted": inserted,
            "id": media_id,
            "sha256": sha256,
            "stored_path": stored_path,
        }

    def add_path(
        self,
        image_path: str,
        title: str = "",
        notes: str = "",
        source: str = "",
        copy_store: bool = True,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
    ) -> Dict[str, Any]:
        if _looks_like_video_path_or_url(image_path):
            return self.add_video_path(
                video_path=image_path,
                title=title,
                notes=notes,
                source=source,
                copy_store=copy_store,
                max_dimension=max_dimension,
            )

        image, raw = _open_image_from_path(image_path, max_dimension=max_dimension)
        fp = _compute_fingerprint(image, original_raw=raw)
        suffix = Path(image_path).suffix or ".png"
        return self.upsert_image(
            fp,
            raw_bytes=raw,
            source_type="path",
            source=source or str(Path(image_path).expanduser()),
            title=title,
            notes=notes,
            copy_store=copy_store,
            original_suffix=suffix,
            media_kind="image",
        )

    def add_url(
        self,
        image_url: str,
        title: str = "",
        notes: str = "",
        copy_store: bool = True,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
    ) -> Dict[str, Any]:
        if _looks_like_video_path_or_url(image_url):
            return self.add_video_url(
                video_url=image_url,
                title=title,
                notes=notes,
                copy_store=copy_store,
                timeout_sec=timeout_sec,
                max_dimension=max_dimension,
            )

        raw = _download_image(image_url, timeout_sec=timeout_sec)
        image = _open_image_from_bytes(raw, max_dimension=max_dimension)
        fp = _compute_fingerprint(image, original_raw=raw)

        suffix = Path(urlparse(image_url).path).suffix or ".png"
        return self.upsert_image(
            fp,
            raw_bytes=raw,
            source_type="url",
            source=image_url,
            title=title,
            notes=notes,
            copy_store=copy_store,
            original_suffix=suffix,
            media_kind="image",
        )

    def add_video_path(
        self,
        video_path: str,
        title: str = "",
        notes: str = "",
        source: str = "",
        copy_store: bool = True,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
        frame_count: int = DEFAULT_VIDEO_FRAME_COUNT,
    ) -> Dict[str, Any]:
        missing = _ensure_video_deps() or _ensure_deps()
        if missing:
            return {"ok": False, "error": missing}

        p = Path(video_path).expanduser().resolve()
        if not p.exists() or not p.is_file():
            return {"ok": False, "error": f"Video path does not exist: {p}"}
        raw = p.read_bytes()
        if len(raw) > DEFAULT_MAX_VIDEO_BYTES:
            return {"ok": False, "error": f"Video is too large: {len(raw)} bytes > {DEFAULT_MAX_VIDEO_BYTES} bytes."}

        info = _extract_video_frame_fingerprints(
            str(p),
            frame_count=frame_count,
            max_dimension=max_dimension,
        )
        media_sha = _sha256_bytes(raw)
        media_result = self._upsert_media(
            sha256=media_sha,
            raw_bytes=raw,
            source_type="path",
            source=source or str(p),
            title=title,
            notes=notes,
            copy_store=copy_store,
            original_suffix=p.suffix or ".mp4",
            width=int(info.get("width", 0)),
            height=int(info.get("height", 0)),
            fps=float(info.get("fps", 0.0)),
            duration_sec=float(info.get("duration_sec", 0.0)),
            frame_count_total=int(info.get("frame_count_total", 0)),
            sampled_count=int(info.get("sampled_count", 0)),
        )
        media_id = int(media_result.get("id", 0))

        added = updated = failed = 0
        frame_results: List[Dict[str, Any]] = []
        for frame in info.get("frames", []) or []:
            try:
                fp = frame.fingerprint
                # Store normalized frame image bytes, not raw video.
                frame_img_bytes = b""
                # No original image object on the frame, so reconstruct a tiny PNG from hash is impossible.
                # Store a deterministic placeholder payload when copy_store=False; when copy_store=True, raw_bytes
                # still needs valid bytes. We use empty disabled write by setting copy_store=False for frames.
                result = self.upsert_image(
                    fp,
                    raw_bytes=frame_img_bytes,
                    source_type="video_frame",
                    source=source or str(p),
                    title=title,
                    notes=notes,
                    copy_store=False,
                    original_suffix=".png",
                    media_kind="video_frame",
                    source_media_id=media_id,
                    frame_index=frame.frame_index,
                    frame_time_sec=frame.time_sec,
                )
                frame_results.append(result)
                if result.get("inserted"):
                    added += 1
                else:
                    updated += 1
            except Exception as exc:
                failed += 1
                frame_results.append({"ok": False, "error": str(exc)})

        return {
            "ok": True,
            "action": "add_video_path",
            "media": media_result,
            "video_info": {k: v for k, v in info.items() if k != "frames"},
            "sampled_frames": int(info.get("sampled_count", 0)),
            "added_frames": added,
            "updated_frames": updated,
            "failed_frames": failed,
            "frame_results": frame_results[:50],
        }

    def add_video_url(
        self,
        video_url: str,
        title: str = "",
        notes: str = "",
        copy_store: bool = True,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
        frame_count: int = DEFAULT_VIDEO_FRAME_COUNT,
    ) -> Dict[str, Any]:
        suffix = _suffix_of_url_or_path(video_url) or ".mp4"
        tmp = ""
        try:
            tmp, raw = _temp_file_from_url(video_url, suffix=suffix, timeout_sec=timeout_sec, max_bytes=DEFAULT_MAX_VIDEO_BYTES)
            info = _extract_video_frame_fingerprints(
                tmp,
                frame_count=frame_count,
                max_dimension=max_dimension,
            )
            media_sha = _sha256_bytes(raw)
            media_result = self._upsert_media(
                sha256=media_sha,
                raw_bytes=raw,
                source_type="url",
                source=video_url,
                title=title,
                notes=notes,
                copy_store=copy_store,
                original_suffix=suffix,
                width=int(info.get("width", 0)),
                height=int(info.get("height", 0)),
                fps=float(info.get("fps", 0.0)),
                duration_sec=float(info.get("duration_sec", 0.0)),
                frame_count_total=int(info.get("frame_count_total", 0)),
                sampled_count=int(info.get("sampled_count", 0)),
            )
            media_id = int(media_result.get("id", 0))
            added = updated = failed = 0
            frame_results: List[Dict[str, Any]] = []
            for frame in info.get("frames", []) or []:
                try:
                    result = self.upsert_image(
                        frame.fingerprint,
                        raw_bytes=b"",
                        source_type="video_url_frame",
                        source=video_url,
                        title=title,
                        notes=notes,
                        copy_store=False,
                        original_suffix=".png",
                        media_kind="video_frame",
                        source_media_id=media_id,
                        frame_index=frame.frame_index,
                        frame_time_sec=frame.time_sec,
                    )
                    frame_results.append(result)
                    if result.get("inserted"):
                        added += 1
                    else:
                        updated += 1
                except Exception as exc:
                    failed += 1
                    frame_results.append({"ok": False, "error": str(exc)})
            return {
                "ok": True,
                "action": "add_video_url",
                "media": media_result,
                "video_info": {k: v for k, v in info.items() if k != "frames"},
                "sampled_frames": int(info.get("sampled_count", 0)),
                "added_frames": added,
                "updated_frames": updated,
                "failed_frames": failed,
                "frame_results": frame_results[:50],
            }
        finally:
            if tmp:
                try:
                    Path(tmp).unlink(missing_ok=True)
                except Exception:
                    pass

    def import_folder(
        self,
        folder: str,
        recursive: bool = True,
        copy_store: bool = True,
        limit: int = 10000,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
        include_videos: bool = False,
    ) -> Dict[str, Any]:
        root = Path(folder).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            return {"ok": False, "error": f"Folder does not exist: {root}"}

        self.init_db()
        pattern = "**/*" if recursive else "*"
        suffixes = set(SUPPORTED_IMAGE_SUFFIXES)
        if include_videos:
            suffixes |= set(SUPPORTED_VIDEO_SUFFIXES)
        paths = [p for p in root.glob(pattern) if p.is_file() and p.suffix.lower() in suffixes]

        if limit and limit > 0:
            paths = paths[: int(limit)]

        added = 0
        updated = 0
        added_video_frames = 0
        failed: List[Dict[str, str]] = []

        for p in paths:
            try:
                if p.suffix.lower() in SUPPORTED_VIDEO_SUFFIXES:
                    result = self.add_video_path(
                        str(p),
                        source=str(p),
                        copy_store=copy_store,
                        max_dimension=max_dimension,
                    )
                    added_video_frames += int(result.get("added_frames", 0) or 0)
                    if result.get("media", {}).get("inserted"):
                        added += 1
                    else:
                        updated += 1
                else:
                    result = self.add_path(
                        str(p),
                        source=str(p),
                        copy_store=copy_store,
                        max_dimension=max_dimension,
                    )
                    if result.get("inserted"):
                        added += 1
                    else:
                        updated += 1
            except Exception as exc:
                failed.append({"path": str(p), "error": str(exc)})

        return {
            "ok": True,
            "folder": str(root),
            "recursive": recursive,
            "include_videos": include_videos,
            "seen": len(paths),
            "added": added,
            "updated": updated,
            "added_video_frames": added_video_frames,
            "failed_count": len(failed),
            "failed": failed[:50],
        }

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        for key in ("id", "width", "height", "source_media_id", "frame_index"):
            if key in data:
                data[key] = _safe_int(data.get(key))
        for key in (
            "created_at",
            "updated_at",
            "score",
            "hash_distance",
            "frame_time_sec",
            "aspect_ratio",
            "entropy",
            "avg_luma",
            "std_luma",
            "color_distance",
            "aspect_penalty",
        ):
            if key in data:
                data[key] = _safe_float(data.get(key))
        return data

    def _all_candidate_rows(self) -> List[Dict[str, Any]]:
        self.init_db()
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT * FROM images
                WHERE phash != '' OR dhash != '' OR ahash != '' OR whash != '' OR edgehash != ''
                """
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def _score_candidate(self, fingerprint: ImageFingerprint, row: Dict[str, Any]) -> Dict[str, Any]:
        if row.get("sha256") == fingerprint.sha256:
            hash_distance = 0.0
            phash_d = dhash_d = ahash_d = whash_d = edge_d = crop_d = 0
        else:
            phash_d = min(
                _hash_distance_min(fingerprint.phash, row.get("phash", ""), row.get("mirror_phash", "")),
                _hash_distance_min(fingerprint.mirror_phash, row.get("phash", ""), row.get("mirror_phash", "")),
            )
            dhash_d = min(
                _hash_distance_min(fingerprint.dhash, row.get("dhash", ""), row.get("mirror_dhash", "")),
                _hash_distance_min(fingerprint.mirror_dhash, row.get("dhash", ""), row.get("mirror_dhash", "")),
            )
            ahash_d = hamming_hex(fingerprint.ahash, row.get("ahash", ""))
            whash_d = hamming_hex(fingerprint.whash, row.get("whash", ""))
            edge_d = hamming_hex(fingerprint.edgehash, row.get("edgehash", ""))
            crop_d = hamming_hex(fingerprint.crop_phash, row.get("crop_phash", ""))

            # Treat missing optional hashes as neutral-ish large but not totally fatal.
            def norm(v: int, fallback: int = 32) -> int:
                return fallback if v >= 9999 else v

            color_distance = _histogram_distance(fingerprint.hist_sig, str(row.get("hist_sig", "")))
            aspect_a = float(fingerprint.aspect_ratio or 0.0)
            aspect_b = _safe_float(row.get("aspect_ratio"), 0.0)
            if aspect_a > 0 and aspect_b > 0:
                aspect_penalty = min(25.0, abs(math.log(max(0.01, aspect_a / aspect_b))) * 18.0)
            else:
                aspect_penalty = 8.0

            luma_penalty = min(8.0, abs(float(fingerprint.avg_luma) - _safe_float(row.get("avg_luma"), 0.0)) / 32.0)

            hash_distance = (
                norm(phash_d) * 1.00
                + norm(dhash_d) * 0.80
                + norm(ahash_d) * 0.40
                + norm(whash_d) * 0.45
                + norm(edge_d) * 0.55
                + norm(crop_d) * 0.65
                + color_distance * 2.2
                + aspect_penalty
                + luma_penalty
            )

        color_distance = _histogram_distance(fingerprint.hist_sig, str(row.get("hist_sig", "")))
        aspect_a = float(fingerprint.aspect_ratio or 0.0)
        aspect_b = _safe_float(row.get("aspect_ratio"), 0.0)
        aspect_penalty = min(25.0, abs(math.log(max(0.01, aspect_a / aspect_b))) * 18.0) if aspect_a > 0 and aspect_b > 0 else 8.0

        score = 1.0 / (1.0 + float(hash_distance))
        if row.get("sha256") == fingerprint.sha256:
            match_strength = "exact"
            confidence = 1.0
        elif hash_distance <= 24:
            match_strength = "near"
            confidence = max(0.80, 1.0 - hash_distance / 100.0)
        elif hash_distance <= 55:
            match_strength = "likely"
            confidence = max(0.55, 1.0 - hash_distance / 130.0)
        elif hash_distance <= 95:
            match_strength = "possible"
            confidence = max(0.25, 1.0 - hash_distance / 160.0)
        else:
            match_strength = "weak"
            confidence = max(0.05, 1.0 - hash_distance / 240.0)

        scored = dict(row)
        scored.update(
            {
                "hash_distance": float(hash_distance),
                "score": float(score),
                "confidence": float(confidence),
                "match_strength": match_strength,
                "phash_distance": int(phash_d),
                "dhash_distance": int(dhash_d),
                "ahash_distance": int(ahash_d),
                "whash_distance": int(whash_d),
                "edgehash_distance": int(edge_d),
                "crop_phash_distance": int(crop_d),
                "color_distance": float(color_distance),
                "aspect_penalty": float(aspect_penalty),
            }
        )
        return scored

    def search_fingerprint(
        self,
        fingerprint: ImageFingerprint,
        max_results: int = 25,
        max_hash_distance: int = 80,
        include_exact: bool = True,
    ) -> Dict[str, Any]:
        self.init_db()

        max_results = max(1, min(int(max_results or 25), 200))
        max_hash_distance = max(0, int(max_hash_distance or 80))

        candidates = self._all_candidate_rows()
        scored: List[Dict[str, Any]] = []
        for row in candidates:
            item = self._score_candidate(fingerprint, row)
            if include_exact and item.get("sha256") == fingerprint.sha256:
                scored.append(item)
            elif _safe_float(item.get("hash_distance"), 999999.0) <= max_hash_distance:
                scored.append(item)

        by_id: Dict[int, Dict[str, Any]] = {}
        for item in scored:
            image_id = int(item.get("id", 0))
            existing = by_id.get(image_id)
            if existing is None or _safe_float(item.get("hash_distance"), 999999.0) < _safe_float(existing.get("hash_distance"), 999999.0):
                by_id[image_id] = item

        matches = sorted(
            by_id.values(),
            key=lambda x: (_safe_float(x.get("hash_distance"), 999999.0), -_safe_float(x.get("confidence"), 0.0)),
        )[:max_results]

        for rank, item in enumerate(matches, start=1):
            item["rank"] = rank
            evidence = [
                f"weighted distance {item.get('hash_distance', 999999):.2f}",
                f"match strength {item.get('match_strength', 'unknown')}",
                f"pHash {item.get('phash_distance', 9999)}, dHash {item.get('dhash_distance', 9999)}, edgeHash {item.get('edgehash_distance', 9999)}, cropHash {item.get('crop_phash_distance', 9999)}",
                f"query size {fingerprint.width}x{fingerprint.height}; indexed size {item.get('width')}x{item.get('height')}",
            ]
            if item.get("sha256") == fingerprint.sha256:
                evidence.insert(0, "exact sha256 match")
            if int(item.get("source_media_id", 0) or 0) > 0:
                evidence.append(f"matched indexed video frame at {item.get('frame_time_sec', 0):.2f}s")
            item["evidence"] = evidence

        return {
            "ok": True,
            "query_fingerprint": asdict(fingerprint),
            "count": len(matches),
            "matches": matches,
            "max_hash_distance": max_hash_distance,
            "matcher_version": 2,
            "matching_features": [
                "sha256",
                "phash",
                "dhash",
                "ahash",
                "whash",
                "edgehash",
                "crop_phash",
                "mirror_hashes",
                "color_histogram",
                "aspect_ratio",
                "luma_stats",
            ],
        }

    def search_path(
        self,
        image_path: str,
        max_results: int = 25,
        max_hash_distance: int = 80,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
    ) -> Dict[str, Any]:
        if _looks_like_video_path_or_url(image_path):
            return self.search_video_path(
                image_path,
                max_results=max_results,
                max_hash_distance=max_hash_distance,
                max_dimension=max_dimension,
            )
        image, raw = _open_image_from_path(image_path, max_dimension=max_dimension)
        fp = _compute_fingerprint(image, original_raw=raw)
        result = self.search_fingerprint(
            fp,
            max_results=max_results,
            max_hash_distance=max_hash_distance,
        )
        result["query_source"] = str(Path(image_path).expanduser())
        result["query_source_type"] = "path"
        result["query_media_kind"] = "image"
        return result

    def search_url(
        self,
        image_url: str,
        max_results: int = 25,
        max_hash_distance: int = 80,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
    ) -> Dict[str, Any]:
        if _looks_like_video_path_or_url(image_url):
            return self.search_video_url(
                image_url,
                max_results=max_results,
                max_hash_distance=max_hash_distance,
                timeout_sec=timeout_sec,
                max_dimension=max_dimension,
            )
        raw = _download_image(image_url, timeout_sec=timeout_sec)
        image = _open_image_from_bytes(raw, max_dimension=max_dimension)
        fp = _compute_fingerprint(image, original_raw=raw)
        result = self.search_fingerprint(
            fp,
            max_results=max_results,
            max_hash_distance=max_hash_distance,
        )
        result["query_source"] = image_url
        result["query_source_type"] = "url"
        result["query_media_kind"] = "image"
        return result

    def _search_video_frames(
        self,
        frames: List[VideoFrameFingerprint],
        *,
        max_results: int,
        max_hash_distance: int,
    ) -> Dict[str, Any]:
        frame_matches: List[Dict[str, Any]] = []
        aggregate: Dict[str, Dict[str, Any]] = {}

        for frame in frames:
            res = self.search_fingerprint(
                frame.fingerprint,
                max_results=max(max_results, 25),
                max_hash_distance=max_hash_distance,
            )
            for match in res.get("matches", []) or []:
                enriched = dict(match)
                enriched["query_frame_index"] = frame.frame_index
                enriched["query_frame_time_sec"] = frame.time_sec
                frame_matches.append(enriched)

                key = f"media:{match.get('source_media_id')}" if int(match.get("source_media_id", 0) or 0) > 0 else f"image:{match.get('id')}"
                agg = aggregate.get(key)
                if agg is None:
                    agg = {
                        "key": key,
                        "best_match": match,
                        "best_distance": _safe_float(match.get("hash_distance"), 999999.0),
                        "hits": 0,
                        "frame_hits": [],
                        "source": match.get("source", ""),
                        "source_type": match.get("source_type", ""),
                        "source_media_id": int(match.get("source_media_id", 0) or 0),
                        "media_kind": match.get("media_kind", ""),
                        "title": match.get("title", ""),
                        "notes": match.get("notes", ""),
                    }
                    aggregate[key] = agg
                agg["hits"] += 1
                dist = _safe_float(match.get("hash_distance"), 999999.0)
                if dist < _safe_float(agg.get("best_distance"), 999999.0):
                    agg["best_distance"] = dist
                    agg["best_match"] = match
                agg["frame_hits"].append(
                    {
                        "query_frame_index": frame.frame_index,
                        "query_frame_time_sec": frame.time_sec,
                        "matched_frame_index": match.get("frame_index", -1),
                        "matched_frame_time_sec": match.get("frame_time_sec", 0.0),
                        "distance": dist,
                        "match_strength": match.get("match_strength", ""),
                    }
                )

        aggregates = list(aggregate.values())
        for agg in aggregates:
            # Rank videos higher when multiple different query frames hit them.
            agg["aggregate_score"] = float((agg.get("hits", 0) * 8.0) - _safe_float(agg.get("best_distance"), 999999.0))
            agg["frame_hits"] = agg["frame_hits"][:20]

        aggregates.sort(key=lambda x: (-_safe_float(x.get("aggregate_score"), -999999.0), _safe_float(x.get("best_distance"), 999999.0)))
        frame_matches.sort(key=lambda x: (_safe_float(x.get("hash_distance"), 999999.0), -_safe_float(x.get("confidence"), 0.0)))

        return {
            "ok": True,
            "query_media_kind": "video",
            "sampled_query_frames": len(frames),
            "count": len(aggregates[:max_results]),
            "aggregate_matches": aggregates[:max_results],
            "frame_matches": frame_matches[: max_results * 5],
            "max_hash_distance": max_hash_distance,
            "matcher_version": 2,
        }

    def search_video_path(
        self,
        video_path: str,
        max_results: int = 25,
        max_hash_distance: int = 80,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
    ) -> Dict[str, Any]:
        info = _extract_video_frame_fingerprints(
            video_path,
            frame_count=DEFAULT_VIDEO_FRAME_COUNT,
            max_dimension=max_dimension,
        )
        frames: List[VideoFrameFingerprint] = info.get("frames", []) or []
        result = self._search_video_frames(frames, max_results=max_results, max_hash_distance=max_hash_distance)
        result["query_source"] = str(Path(video_path).expanduser())
        result["query_source_type"] = "path"
        result["video_info"] = {k: v for k, v in info.items() if k != "frames"}
        return result

    def search_video_url(
        self,
        video_url: str,
        max_results: int = 25,
        max_hash_distance: int = 80,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        max_dimension: int = DEFAULT_MAX_DIMENSION,
    ) -> Dict[str, Any]:
        suffix = _suffix_of_url_or_path(video_url) or ".mp4"
        tmp = ""
        try:
            tmp, _raw = _temp_file_from_url(video_url, suffix=suffix, timeout_sec=timeout_sec, max_bytes=DEFAULT_MAX_VIDEO_BYTES)
            info = _extract_video_frame_fingerprints(
                tmp,
                frame_count=DEFAULT_VIDEO_FRAME_COUNT,
                max_dimension=max_dimension,
            )
            frames: List[VideoFrameFingerprint] = info.get("frames", []) or []
            result = self._search_video_frames(frames, max_results=max_results, max_hash_distance=max_hash_distance)
            result["query_source"] = video_url
            result["query_source_type"] = "url"
            result["video_info"] = {k: v for k, v in info.items() if k != "frames"}
            return result
        finally:
            if tmp:
                try:
                    Path(tmp).unlink(missing_ok=True)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Public GPT/Ollama wrapper
# ---------------------------------------------------------------------------
def reverse_image_tool(
    action: str = "search",
    image_input: str = "",
    image_path: str = "",
    image_url: str = "",
    folder: str = "",
    db_path: str = DEFAULT_DB_PATH,
    store_dir: str = DEFAULT_STORE_DIR,
    title: str = "",
    notes: str = "",
    source: str = "",
    recursive: bool = True,
    copy_store: bool = True,
    max_results: int = 25,
    max_hash_distance: int = 80,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    limit: int = 10000,
    max_dimension: int = DEFAULT_MAX_DIMENSION,
) -> Dict[str, Any]:
    """
    GPT/Ollama-safe wrapper.

    Existing actions:
      - stats
      - init_db
      - add_path
      - add_url
      - import_folder
      - search

    Smarter media behavior:
      - search/add_path/add_url automatically route video suffixes to frame matching.
      - extra actions accepted without changing this signature: add_video, search_video,
        import_media_folder.
      - local paths are allowed even if the model puts them in image_url.
    """
    missing = _ensure_deps()
    if missing:
        return {"ok": False, "error": missing}

    db = ReverseImageDatabase(db_path=db_path, store_dir=store_dir)
    act = (action or "search").strip().lower()

    try:
        if act in {"init", "init_db", "create"}:
            return db.init_db()

        if act in {"stats", "status"}:
            return db.stats()

        if act in {"add", "add_path", "index_path", "add_video", "add_media", "index_media"}:
            input_kind, input_value, media_kind = _resolve_media_input(
                image_input=image_input,
                image_path=image_path,
                image_url=image_url,
            )

            if input_kind == "path":
                if media_kind == "video" or act in {"add_video", "add_media", "index_media"}:
                    return db.add_video_path(
                        video_path=input_value,
                        title=title,
                        notes=notes,
                        source=source,
                        copy_store=copy_store,
                        max_dimension=max_dimension,
                    )
                return db.add_path(
                    image_path=input_value,
                    title=title,
                    notes=notes,
                    source=source,
                    copy_store=copy_store,
                    max_dimension=max_dimension,
                )

            if input_kind == "url":
                if media_kind == "video" or act in {"add_video", "add_media", "index_media"}:
                    return db.add_video_url(
                        video_url=input_value,
                        title=title,
                        notes=notes,
                        copy_store=copy_store,
                        timeout_sec=timeout_sec,
                        max_dimension=max_dimension,
                    )
                return db.add_url(
                    image_url=input_value,
                    title=title,
                    notes=notes,
                    copy_store=copy_store,
                    timeout_sec=timeout_sec,
                    max_dimension=max_dimension,
                )

            return {"ok": False, "error": "Local image/video path or HTTP/HTTPS image/video URL is required for add_path."}

        if act in {"add_url", "index_url"}:
            input_kind, input_value, media_kind = _resolve_media_input(
                image_input=image_input,
                image_path=image_path,
                image_url=image_url,
            )

            if input_kind == "path":
                if media_kind == "video":
                    return db.add_video_path(
                        video_path=input_value,
                        title=title,
                        notes=notes,
                        source=source or input_value,
                        copy_store=copy_store,
                        max_dimension=max_dimension,
                    )
                return db.add_path(
                    image_path=input_value,
                    title=title,
                    notes=notes,
                    source=source or input_value,
                    copy_store=copy_store,
                    max_dimension=max_dimension,
                )

            if input_kind == "url":
                if media_kind == "video":
                    return db.add_video_url(
                        video_url=input_value,
                        title=title,
                        notes=notes,
                        copy_store=copy_store,
                        timeout_sec=timeout_sec,
                        max_dimension=max_dimension,
                    )
                return db.add_url(
                    image_url=input_value,
                    title=title,
                    notes=notes,
                    copy_store=copy_store,
                    timeout_sec=timeout_sec,
                    max_dimension=max_dimension,
                )

            return {"ok": False, "error": "Local image/video path or HTTP/HTTPS image/video URL is required for add_url."}

        if act in {"import", "import_folder", "index_folder", "import_media_folder", "import_videos"}:
            if not folder:
                return {"ok": False, "error": "folder is required for import_folder."}
            return db.import_folder(
                folder=folder,
                recursive=recursive,
                copy_store=copy_store,
                limit=limit,
                max_dimension=max_dimension,
                include_videos=act in {"import_media_folder", "import_videos"},
            )

        if act in {"search", "reverse_search", "find", "search_video", "reverse_video_search"}:
            input_kind, input_value, media_kind = _resolve_media_input(
                image_input=image_input,
                image_path=image_path,
                image_url=image_url,
            )

            if input_kind == "path":
                if media_kind == "video" or act in {"search_video", "reverse_video_search"}:
                    result = db.search_video_path(
                        video_path=input_value,
                        max_results=max_results,
                        max_hash_distance=max_hash_distance,
                        max_dimension=max_dimension,
                    )
                else:
                    result = db.search_path(
                        image_path=input_value,
                        max_results=max_results,
                        max_hash_distance=max_hash_distance,
                        max_dimension=max_dimension,
                    )
                result["resolved_input_kind"] = "path"
                result["resolved_input_value"] = input_value
                return result

            if input_kind == "url":
                if media_kind == "video" or act in {"search_video", "reverse_video_search"}:
                    result = db.search_video_url(
                        video_url=input_value,
                        max_results=max_results,
                        max_hash_distance=max_hash_distance,
                        timeout_sec=timeout_sec,
                        max_dimension=max_dimension,
                    )
                else:
                    result = db.search_url(
                        image_url=input_value,
                        max_results=max_results,
                        max_hash_distance=max_hash_distance,
                        timeout_sec=timeout_sec,
                        max_dimension=max_dimension,
                    )
                result["resolved_input_kind"] = "url"
                result["resolved_input_value"] = input_value
                return result

            return {
                "ok": False,
                "error": "image_path, image_input, or image_url is required for search. Local image/video paths are allowed.",
            }

        return {
            "ok": False,
            "error": f"Unknown reverse image action: {action}",
            "available_actions": [
                "init_db",
                "stats",
                "add_path",
                "add_url",
                "add_video",
                "import_folder",
                "import_media_folder",
                "search",
                "search_video",
            ],
        }
    except Exception as exc:
        return {
            "ok": False,
            "action": act,
            "error": str(exc),
        }


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Local reverse image/video search engine.")
    parser.add_argument(
        "action",
        choices=[
            "init_db",
            "stats",
            "add_path",
            "add_url",
            "add_video",
            "import_folder",
            "import_media_folder",
            "search",
            "search_video",
        ],
    )
    parser.add_argument("--image", default="", help="Image/video input alias. Accepts local path, file:// URL, or HTTP/HTTPS URL.")
    parser.add_argument("--image-path", default="")
    parser.add_argument("--image-url", default="")
    parser.add_argument("--folder", default="")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH)
    parser.add_argument("--store-dir", default=DEFAULT_STORE_DIR)
    parser.add_argument("--title", default="")
    parser.add_argument("--notes", default="")
    parser.add_argument("--source", default="")
    parser.add_argument("--max-results", type=int, default=25)
    parser.add_argument("--max-hash-distance", type=int, default=80)
    parser.add_argument("--limit", type=int, default=10000)
    parser.add_argument("--timeout-sec", type=int, default=DEFAULT_TIMEOUT_SEC)
    parser.add_argument("--max-dimension", type=int, default=DEFAULT_MAX_DIMENSION)
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--no-copy-store", action="store_true")
    args = parser.parse_args()

    result = reverse_image_tool(
        action=args.action,
        image_input=args.image,
        image_path=args.image_path,
        image_url=args.image_url,
        folder=args.folder,
        db_path=args.db_path,
        store_dir=args.store_dir,
        title=args.title,
        notes=args.notes,
        source=args.source,
        recursive=not args.no_recursive,
        copy_store=not args.no_copy_store,
        max_results=args.max_results,
        max_hash_distance=args.max_hash_distance,
        timeout_sec=args.timeout_sec,
        limit=args.limit,
        max_dimension=args.max_dimension,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _main()
