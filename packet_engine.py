from __future__ import annotations

"""
PromptChat network-capable packet_engine.py

A drop-in module that combines:
  1) a ctypes-backed libpcap/Npcap passive packet backend,
  2) protocol parsers for Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS,
  3) safe send helpers for DNS/UDP/TCP,
  4) explicitly gated raw L2 injection through libpcap,
  5) a small compatibility web-sniffer surface so older tools.py imports of
     SnifferConfig/SnifferEngine/sniff_url/sniff_text can still work if desired.

Safety model:
  - Default packet sending is normal OS socket sending only: UDP, TCP, DNS query.
  - Raw L2 frame injection is disabled unless allow_raw_send=True and the call
    also passes confirm_authorized=True.
  - No flood/loop sender is provided.
  - No auth bypass, spoofing workflow, stealth scanning, or exploit logic is
    included.

Requires:
  - Capture: libpcap on Linux/macOS, Npcap/WinPcap on Windows.
  - Admin/root privileges may be required for live capture or raw packet send.
"""

import asyncio
import base64
import ctypes
import ctypes.util
import hashlib
import html
import ipaddress
import json
import os
import random
import re
import socket
import struct
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import urljoin, urlparse

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


# =============================================================================
# Shared helpers
# =============================================================================

BytesLike = Union[bytes, bytearray, memoryview]

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
DLT_IPV4 = 228
DLT_IPV6 = 229

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_IPV6 = 0x86DD

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

SECRET_QUERY_KEYS = {
    "token", "access_token", "auth", "authorization", "key", "api_key",
    "apikey", "sig", "signature", "policy", "expires", "session", "jwt",
    "bearer", "password", "passwd", "secret", "credential", "credentials",
}


def _now() -> float:
    return float(time.time())


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _bytes_preview(raw: bytes, limit: int = 96) -> Dict[str, Any]:
    data = bytes(raw or b"")
    out = {
        "len": len(data),
        "hex": data[: max(0, limit)].hex(),
        "truncated": len(data) > max(0, limit),
    }
    try:
        text = data[: max(0, limit)].decode("utf-8", "replace")
        if any(ch.isprintable() for ch in text):
            out["text"] = text
    except Exception:
        pass
    return out


def _coerce_payload(payload: Union[str, bytes, bytearray, memoryview], *, hex_mode: bool = False) -> bytes:
    if isinstance(payload, (bytes, bytearray, memoryview)):
        return bytes(payload)
    text = str(payload or "")
    if hex_mode:
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", text)
        if len(cleaned) % 2:
            raise ValueError("Hex payload must contain an even number of hex digits.")
        return bytes.fromhex(cleaned)
    return text.encode("utf-8", "replace")


def _mac_to_str(raw: bytes) -> str:
    if len(raw) < 6:
        return ""
    return ":".join(f"{b:02x}" for b in raw[:6])


def _ipv4_to_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, raw[:4])
    except Exception:
        return ""


def _ipv6_to_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw[:16])
    except Exception:
        return ""


def _safe_domain_name(name: str) -> str:
    text = (name or "").strip().strip(".")
    if not text:
        raise ValueError("Domain name is required.")
    if len(text) > 253:
        raise ValueError("Domain name is too long.")
    labels = text.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"Invalid DNS label: {label!r}")
        if not re.match(r"^[A-Za-z0-9_-]+$", label):
            raise ValueError(f"Unsupported DNS label characters: {label!r}")
    return text


def _dns_qtype_number(qtype: Union[str, int]) -> int:
    if isinstance(qtype, int):
        return int(qtype)
    table = {
        "A": 1,
        "NS": 2,
        "CNAME": 5,
        "SOA": 6,
        "PTR": 12,
        "MX": 15,
        "TXT": 16,
        "AAAA": 28,
        "SRV": 33,
        "CAA": 257,
    }
    key = str(qtype or "A").upper().strip()
    return table.get(key, 1)


def _dns_qtype_name(qtype: int) -> str:
    table = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        257: "CAA",
    }
    return table.get(int(qtype), str(qtype))


def _build_dns_query(domain: str, qtype: Union[str, int] = "A", transaction_id: Optional[int] = None) -> bytes:
    name = _safe_domain_name(domain)
    qtype_num = _dns_qtype_number(qtype)
    tid = int(transaction_id if transaction_id is not None else random.randint(0, 0xFFFF)) & 0xFFFF
    flags = 0x0100  # standard recursive query
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode("ascii", "ignore") for label in name.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", qtype_num, 1)
    return header + question


def _redact_url_for_display(url: str) -> str:
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        pairs: List[str] = []
        for part in parsed.query.split("&"):
            if not part:
                continue
            key = part.split("=", 1)[0]
            if key.lower() in SECRET_QUERY_KEYS:
                pairs.append(f"{key}=<redacted>")
            else:
                pairs.append(part)
        query = "&".join(pairs)
        return parsed._replace(query=query).geturl()
    except Exception:
        return url


# =============================================================================
# libpcap backend, expanded from uploaded libpcap_backend.py
# =============================================================================


@dataclass
class LibpcapCtypesBackend:
    """
    ctypes-backed libpcap/Npcap wrapper.

    Supported modes:
      - live capture from interface via open_live(...)
      - offline capture from .pcap/.pcapng via open_offline(...)
      - optional BPF filters via set_filter(...)
      - optional raw L2 frame injection via send_packet(...)
    """

    timeout_ms: int = 250
    snaplen: int = 65535
    promisc: bool = True
    logger: Any = None

    def __post_init__(self) -> None:
        self.lib: Any = None
        self.handle: Optional[int] = None
        self._errbuf = ctypes.create_string_buffer(256)
        self.PcapPkthdr: Any = None
        self.BpfProgram: Any = None
        self.PcapIf: Any = None
        self._load_library()

    def _log(self, msg: str) -> None:
        try:
            if self.logger is not None:
                if hasattr(self.logger, "log_message"):
                    self.logger.log_message(f"[LibpcapBackend] {msg}")
                elif callable(self.logger):
                    self.logger(f"[LibpcapBackend] {msg}")
        except Exception:
            pass

    def _load_library(self) -> None:
        candidates: List[str] = []
        try:
            for name in ("pcap", "wpcap"):
                libname = ctypes.util.find_library(name)
                if libname:
                    candidates.append(libname)
        except Exception:
            pass

        candidates.extend([
            "wpcap.dll",
            "Packet.dll",
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll"),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll"),
            "libpcap.so",
            "libpcap.so.1",
            "/usr/lib/libpcap.so",
            "/usr/lib/x86_64-linux-gnu/libpcap.so",
            "/usr/local/lib/libpcap.so",
            "libpcap.dylib",
        ])

        seen: set[str] = set()
        ordered: List[str] = []
        for candidate in candidates:
            text = str(candidate or "").strip()
            if text and text not in seen:
                ordered.append(text)
                seen.add(text)

        last_err: Optional[Exception] = None
        for candidate in ordered:
            try:
                self.lib = ctypes.CDLL(candidate)
                self._bind()
                self._log(f"Loaded libpcap library: {candidate}")
                return
            except Exception as exc:
                last_err = exc

        raise RuntimeError(f"Unable to load libpcap/wpcap via ctypes: {last_err}")

    def _bind(self) -> None:
        class PcapPkthdr(ctypes.Structure):
            _fields_ = [
                ("ts_sec", ctypes.c_long),
                ("ts_usec", ctypes.c_long),
                ("caplen", ctypes.c_uint32),
                ("len", ctypes.c_uint32),
            ]

        class BpfProgram(ctypes.Structure):
            _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]

        class PcapIf(ctypes.Structure):
            pass

        PcapIf._fields_ = [
            ("next", ctypes.POINTER(PcapIf)),
            ("name", ctypes.c_char_p),
            ("description", ctypes.c_char_p),
            ("addresses", ctypes.c_void_p),
            ("flags", ctypes.c_uint),
        ]

        self.PcapPkthdr = PcapPkthdr
        self.BpfProgram = BpfProgram
        self.PcapIf = PcapIf

        self.lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        self.lib.pcap_open_live.restype = ctypes.c_void_p

        self.lib.pcap_open_offline.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.pcap_open_offline.restype = ctypes.c_void_p

        self.lib.pcap_close.argtypes = [ctypes.c_void_p]
        self.lib.pcap_close.restype = None

        self.lib.pcap_datalink.argtypes = [ctypes.c_void_p]
        self.lib.pcap_datalink.restype = ctypes.c_int

        self.lib.pcap_next_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(PcapPkthdr)),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ]
        self.lib.pcap_next_ex.restype = ctypes.c_int

        if hasattr(self.lib, "pcap_geterr"):
            self.lib.pcap_geterr.argtypes = [ctypes.c_void_p]
            self.lib.pcap_geterr.restype = ctypes.c_char_p

        if hasattr(self.lib, "pcap_compile"):
            self.lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
            self.lib.pcap_compile.restype = ctypes.c_int

        if hasattr(self.lib, "pcap_setfilter"):
            self.lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram)]
            self.lib.pcap_setfilter.restype = ctypes.c_int

        if hasattr(self.lib, "pcap_freecode"):
            self.lib.pcap_freecode.argtypes = [ctypes.POINTER(BpfProgram)]
            self.lib.pcap_freecode.restype = None

        if hasattr(self.lib, "pcap_sendpacket"):
            self.lib.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
            self.lib.pcap_sendpacket.restype = ctypes.c_int

        if hasattr(self.lib, "pcap_findalldevs"):
            self.lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(PcapIf)), ctypes.c_char_p]
            self.lib.pcap_findalldevs.restype = ctypes.c_int

        if hasattr(self.lib, "pcap_freealldevs"):
            self.lib.pcap_freealldevs.argtypes = [ctypes.POINTER(PcapIf)]
            self.lib.pcap_freealldevs.restype = None

    def list_interfaces(self) -> Dict[str, Any]:
        if not hasattr(self.lib, "pcap_findalldevs"):
            return {"ok": False, "error": "pcap_findalldevs is not available in this libpcap build."}

        alldevs = ctypes.POINTER(self.PcapIf)()
        rc = self.lib.pcap_findalldevs(ctypes.byref(alldevs), self._errbuf)
        if rc != 0:
            return {"ok": False, "error": self._errbuf.value.decode("utf-8", "ignore")}

        out: List[Dict[str, Any]] = []
        try:
            ptr = alldevs
            while ptr:
                item = ptr.contents
                name = item.name.decode("utf-8", "ignore") if item.name else ""
                desc = item.description.decode("utf-8", "ignore") if item.description else ""
                out.append({"name": name, "description": desc, "flags": int(item.flags or 0)})
                ptr = item.next
        finally:
            try:
                if alldevs and hasattr(self.lib, "pcap_freealldevs"):
                    self.lib.pcap_freealldevs(alldevs)
            except Exception:
                pass

        return {"ok": True, "count": len(out), "interfaces": out}

    def open_live(self, iface: str) -> None:
        self.close()
        handle = self.lib.pcap_open_live(
            str(iface).encode("utf-8", "ignore"),
            int(self.snaplen),
            1 if self.promisc else 0,
            int(self.timeout_ms),
            self._errbuf,
        )
        if not handle:
            raise RuntimeError(self._errbuf.value.decode("utf-8", "ignore") or "pcap_open_live failed")
        self.handle = handle
        self._log(f"Opened live capture on iface={iface!r}")

    def open_offline(self, path: str) -> None:
        self.close()
        handle = self.lib.pcap_open_offline(str(path).encode("utf-8", "ignore"), self._errbuf)
        if not handle:
            raise RuntimeError(self._errbuf.value.decode("utf-8", "ignore") or "pcap_open_offline failed")
        self.handle = handle
        self._log(f"Opened offline capture path={path!r}")

    def set_filter(self, bpf_filter: str, netmask: int = 0xFFFFFF00) -> Dict[str, Any]:
        if not self.handle:
            return {"ok": False, "error": "No pcap handle is open."}
        text = (bpf_filter or "").strip()
        if not text:
            return {"ok": True, "filter": ""}
        if not hasattr(self.lib, "pcap_compile") or not hasattr(self.lib, "pcap_setfilter"):
            return {"ok": False, "error": "pcap_compile/pcap_setfilter is not available."}

        program = self.BpfProgram()
        rc = self.lib.pcap_compile(self.handle, ctypes.byref(program), text.encode("utf-8", "ignore"), 1, ctypes.c_uint32(netmask))
        if rc != 0:
            return {"ok": False, "filter": text, "error": self.get_error() or "pcap_compile failed"}
        try:
            rc = self.lib.pcap_setfilter(self.handle, ctypes.byref(program))
            if rc != 0:
                return {"ok": False, "filter": text, "error": self.get_error() or "pcap_setfilter failed"}
        finally:
            try:
                if hasattr(self.lib, "pcap_freecode"):
                    self.lib.pcap_freecode(ctypes.byref(program))
            except Exception:
                pass
        return {"ok": True, "filter": text}

    def datalink(self) -> Optional[int]:
        if not self.handle:
            return None
        try:
            return int(self.lib.pcap_datalink(self.handle))
        except Exception:
            return None

    def get_error(self) -> str:
        if not self.handle or not hasattr(self.lib, "pcap_geterr"):
            return ""
        try:
            p = self.lib.pcap_geterr(self.handle)
            return p.decode("utf-8", "ignore") if p else ""
        except Exception:
            return ""

    def next_packet(self) -> Optional[Dict[str, Any]]:
        if not self.handle:
            return None

        hdr_ptr = ctypes.POINTER(self.PcapPkthdr)()
        data_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        rc = self.lib.pcap_next_ex(self.handle, ctypes.byref(hdr_ptr), ctypes.byref(data_ptr))

        if rc == 1 and hdr_ptr and data_ptr:
            hdr = hdr_ptr.contents
            raw = ctypes.string_at(data_ptr, int(hdr.caplen))
            ts = float(hdr.ts_sec) + (float(hdr.ts_usec) / 1_000_000.0)
            return {
                "timestamp": ts,
                "caplen": int(hdr.caplen),
                "wirelen": int(hdr.len),
                "raw_bytes": raw,
                "datalink": self.datalink(),
            }
        if rc in (0, -2):
            return None
        if rc == -1:
            raise RuntimeError(self.get_error() or "pcap_next_ex failed")
        return None

    def collect(self, *, max_packets: int = 128, budget_s: float = 2.0) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        deadline = time.time() + max(0.05, float(budget_s))
        while len(out) < int(max_packets) and time.time() < deadline:
            pkt = self.next_packet()
            if pkt is None:
                continue
            out.append(pkt)
        self._log(f"Collected {len(out)} packets from libpcap backend")
        return out

    def send_packet(self, raw_bytes: bytes) -> Dict[str, Any]:
        if not self.handle:
            return {"ok": False, "error": "No pcap handle is open."}
        if not hasattr(self.lib, "pcap_sendpacket"):
            return {"ok": False, "error": "pcap_sendpacket is not available in this libpcap build."}
        raw = bytes(raw_bytes or b"")
        if not raw:
            return {"ok": False, "error": "raw_bytes is empty."}
        rc = self.lib.pcap_sendpacket(self.handle, raw, int(len(raw)))
        if rc != 0:
            return {"ok": False, "error": self.get_error() or "pcap_sendpacket failed", "bytes": len(raw)}
        return {"ok": True, "bytes": len(raw)}

    def close(self) -> None:
        if self.handle:
            try:
                self.lib.pcap_close(self.handle)
            except Exception:
                pass
            self.handle = None


# =============================================================================
# Packet parsing
# =============================================================================


class PacketParser:
    def __init__(self, *, payload_preview_bytes: int = 128) -> None:
        self.payload_preview_bytes = max(0, int(payload_preview_bytes or 0))

    def parse_capture_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        raw = bytes(record.get("raw_bytes") or b"")
        datalink = record.get("datalink")
        parsed = self.parse(raw, datalink=datalink)
        parsed.update({
            "timestamp": record.get("timestamp", 0.0),
            "caplen": int(record.get("caplen", len(raw)) or len(raw)),
            "wirelen": int(record.get("wirelen", len(raw)) or len(raw)),
            "datalink": datalink,
            "sha256": hashlib.sha256(raw).hexdigest() if raw else "",
        })
        return parsed

    def parse(self, raw: bytes, *, datalink: Optional[int] = DLT_EN10MB) -> Dict[str, Any]:
        raw = bytes(raw or b"")
        out: Dict[str, Any] = {
            "ok": True,
            "length": len(raw),
            "layers": [],
            "summary": "unknown",
            "payload_preview": _bytes_preview(raw, self.payload_preview_bytes),
        }
        try:
            offset, ethertype = self._parse_link(raw, datalink, out)
            if ethertype == ETHERTYPE_IPV4:
                self._parse_ipv4(raw, offset, out)
            elif ethertype == ETHERTYPE_IPV6:
                self._parse_ipv6(raw, offset, out)
            elif ethertype == ETHERTYPE_ARP:
                self._parse_arp(raw, offset, out)
            else:
                out["summary"] = f"link ethertype=0x{int(ethertype or 0):04x} len={len(raw)}"
        except Exception as exc:
            out["ok"] = False
            out["error"] = str(exc)
            out["summary"] = f"parse_error len={len(raw)} error={exc}"
        return out

    def _parse_link(self, raw: bytes, datalink: Optional[int], out: Dict[str, Any]) -> Tuple[int, Optional[int]]:
        dl = int(datalink if datalink is not None else DLT_EN10MB)
        if dl == DLT_EN10MB:
            if len(raw) < 14:
                raise ValueError("Ethernet frame too short.")
            dst = _mac_to_str(raw[0:6])
            src = _mac_to_str(raw[6:12])
            ethertype = struct.unpack("!H", raw[12:14])[0]
            offset = 14
            vlans: List[Dict[str, int]] = []
            while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and len(raw) >= offset + 4:
                tci = struct.unpack("!H", raw[offset:offset + 2])[0]
                vlans.append({"tpid": ethertype, "pcp": (tci >> 13) & 0x7, "dei": (tci >> 12) & 0x1, "vlan_id": tci & 0x0FFF})
                ethertype = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
                offset += 4
            out["layers"].append("ethernet")
            out["ethernet"] = {"src": src, "dst": dst, "ethertype": ethertype, "vlans": vlans}
            return offset, ethertype

        if dl in (DLT_RAW, DLT_IPV4, DLT_IPV6):
            if not raw:
                raise ValueError("Raw packet is empty.")
            version = raw[0] >> 4
            if version == 4:
                return 0, ETHERTYPE_IPV4
            if version == 6:
                return 0, ETHERTYPE_IPV6
            return 0, None

        if dl == DLT_NULL:
            if len(raw) < 4:
                raise ValueError("Null/loopback record too short.")
            family = struct.unpack("=I", raw[:4])[0]
            if family in (2, socket.AF_INET):
                return 4, ETHERTYPE_IPV4
            if family in (10, socket.AF_INET6):
                return 4, ETHERTYPE_IPV6
            return 4, None

        if dl == DLT_LINUX_SLL:
            if len(raw) < 16:
                raise ValueError("Linux cooked v1 record too short.")
            proto = struct.unpack("!H", raw[14:16])[0]
            out["layers"].append("linux_sll")
            out["linux_sll"] = {"packet_type": struct.unpack("!H", raw[0:2])[0], "protocol": proto}
            return 16, proto

        # Best-effort fallback: try Ethernet first, then raw IP.
        if len(raw) >= 14:
            try:
                return self._parse_link(raw, DLT_EN10MB, out)
            except Exception:
                pass
        if raw and raw[0] >> 4 == 4:
            return 0, ETHERTYPE_IPV4
        if raw and raw[0] >> 4 == 6:
            return 0, ETHERTYPE_IPV6
        return 0, None

    def _parse_arp(self, raw: bytes, offset: int, out: Dict[str, Any]) -> None:
        if len(raw) < offset + 28:
            raise ValueError("ARP packet too short.")
        htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", raw[offset:offset + 8])
        pos = offset + 8
        sha = raw[pos:pos + hlen]; pos += hlen
        spa = raw[pos:pos + plen]; pos += plen
        tha = raw[pos:pos + hlen]; pos += hlen
        tpa = raw[pos:pos + plen]
        out["layers"].append("arp")
        out["arp"] = {
            "hardware_type": htype,
            "protocol_type": ptype,
            "operation": oper,
            "sender_mac": _mac_to_str(sha),
            "sender_ip": _ipv4_to_str(spa) if plen == 4 else spa.hex(),
            "target_mac": _mac_to_str(tha),
            "target_ip": _ipv4_to_str(tpa) if plen == 4 else tpa.hex(),
        }
        op = "request" if oper == 1 else "reply" if oper == 2 else str(oper)
        out["summary"] = f"ARP {op} {out['arp']['sender_ip']} -> {out['arp']['target_ip']}"

    def _parse_ipv4(self, raw: bytes, offset: int, out: Dict[str, Any]) -> None:
        if len(raw) < offset + 20:
            raise ValueError("IPv4 packet too short.")
        first = raw[offset]
        version = first >> 4
        ihl = (first & 0x0F) * 4
        if version != 4 or ihl < 20:
            raise ValueError("Invalid IPv4 header.")
        if len(raw) < offset + ihl:
            raise ValueError("Truncated IPv4 options.")
        total_length = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
        ident = struct.unpack("!H", raw[offset + 4:offset + 6])[0]
        flags_frag = struct.unpack("!H", raw[offset + 6:offset + 8])[0]
        ttl = raw[offset + 8]
        proto = raw[offset + 9]
        checksum = struct.unpack("!H", raw[offset + 10:offset + 12])[0]
        src = _ipv4_to_str(raw[offset + 12:offset + 16])
        dst = _ipv4_to_str(raw[offset + 16:offset + 20])
        payload_start = offset + ihl
        payload_end = min(len(raw), offset + total_length) if total_length else len(raw)
        payload = raw[payload_start:payload_end]
        out["layers"].append("ipv4")
        out["ip"] = {
            "version": 4,
            "src": src,
            "dst": dst,
            "protocol": proto,
            "ttl": ttl,
            "id": ident,
            "header_length": ihl,
            "total_length": total_length,
            "checksum": checksum,
            "flags": {"df": bool(flags_frag & 0x4000), "mf": bool(flags_frag & 0x2000)},
            "fragment_offset": flags_frag & 0x1FFF,
        }
        self._parse_transport(proto, payload, src, dst, out)

    def _parse_ipv6(self, raw: bytes, offset: int, out: Dict[str, Any]) -> None:
        if len(raw) < offset + 40:
            raise ValueError("IPv6 packet too short.")
        first4 = struct.unpack("!I", raw[offset:offset + 4])[0]
        version = (first4 >> 28) & 0xF
        if version != 6:
            raise ValueError("Invalid IPv6 header.")
        traffic_class = (first4 >> 20) & 0xFF
        flow_label = first4 & 0xFFFFF
        payload_length = struct.unpack("!H", raw[offset + 4:offset + 6])[0]
        next_header = raw[offset + 6]
        hop_limit = raw[offset + 7]
        src = _ipv6_to_str(raw[offset + 8:offset + 24])
        dst = _ipv6_to_str(raw[offset + 24:offset + 40])
        payload = raw[offset + 40:offset + 40 + payload_length] if payload_length else raw[offset + 40:]
        out["layers"].append("ipv6")
        out["ip"] = {
            "version": 6,
            "src": src,
            "dst": dst,
            "protocol": next_header,
            "next_header": next_header,
            "traffic_class": traffic_class,
            "flow_label": flow_label,
            "payload_length": payload_length,
            "hop_limit": hop_limit,
        }
        self._parse_transport(next_header, payload, src, dst, out)

    def _parse_transport(self, proto: int, payload: bytes, src_ip: str, dst_ip: str, out: Dict[str, Any]) -> None:
        if proto == IPPROTO_TCP:
            self._parse_tcp(payload, src_ip, dst_ip, out)
        elif proto == IPPROTO_UDP:
            self._parse_udp(payload, src_ip, dst_ip, out)
        elif proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            self._parse_icmp(payload, proto, src_ip, dst_ip, out)
        else:
            out["payload_preview"] = _bytes_preview(payload, self.payload_preview_bytes)
            out["summary"] = f"IP proto={proto} {src_ip} -> {dst_ip} len={len(payload)}"

    def _parse_tcp(self, payload: bytes, src_ip: str, dst_ip: str, out: Dict[str, Any]) -> None:
        if len(payload) < 20:
            raise ValueError("TCP segment too short.")
        src_port, dst_port, seq, ack, off_flags, window, checksum, urgent = struct.unpack("!HHIIHHHH", payload[:20])
        data_offset = ((off_flags >> 12) & 0xF) * 4
        flags_value = off_flags & 0x01FF
        flag_names = []
        for bit, name in [(0x100, "NS"), (0x080, "CWR"), (0x040, "ECE"), (0x020, "URG"), (0x010, "ACK"), (0x008, "PSH"), (0x004, "RST"), (0x002, "SYN"), (0x001, "FIN")]:
            if flags_value & bit:
                flag_names.append(name)
        data = payload[data_offset:] if data_offset <= len(payload) else b""
        out["layers"].append("tcp")
        out["tcp"] = {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "data_offset": data_offset,
            "flags": flag_names,
            "flags_value": flags_value,
            "window": window,
            "checksum": checksum,
            "urgent_pointer": urgent,
            "payload_len": len(data),
        }
        out["payload_preview"] = _bytes_preview(data, self.payload_preview_bytes)
        out["summary"] = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {'/'.join(flag_names) or '-'} payload={len(data)}"

    def _parse_udp(self, payload: bytes, src_ip: str, dst_ip: str, out: Dict[str, Any]) -> None:
        if len(payload) < 8:
            raise ValueError("UDP datagram too short.")
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", payload[:8])
        data = payload[8:]
        out["layers"].append("udp")
        out["udp"] = {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "checksum": checksum,
            "payload_len": len(data),
        }
        out["payload_preview"] = _bytes_preview(data, self.payload_preview_bytes)
        if src_port == 53 or dst_port == 53:
            dns = parse_dns_message(data)
            if dns.get("ok"):
                out["layers"].append("dns")
                out["dns"] = dns
                qnames = [q.get("name", "") for q in dns.get("questions", [])]
                out["summary"] = f"DNS {'response' if dns.get('qr') else 'query'} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {','.join(qnames)}"
                return
        out["summary"] = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} payload={len(data)}"

    def _parse_icmp(self, payload: bytes, proto: int, src_ip: str, dst_ip: str, out: Dict[str, Any]) -> None:
        if len(payload) < 4:
            raise ValueError("ICMP packet too short.")
        typ, code, checksum = struct.unpack("!BBH", payload[:4])
        layer = "icmpv6" if proto == IPPROTO_ICMPV6 else "icmp"
        out["layers"].append(layer)
        out[layer] = {"type": typ, "code": code, "checksum": checksum, "payload_len": max(0, len(payload) - 4)}
        out["payload_preview"] = _bytes_preview(payload[4:], self.payload_preview_bytes)
        out["summary"] = f"{layer.upper()} type={typ} code={code} {src_ip} -> {dst_ip}"


# =============================================================================
# DNS parser
# =============================================================================


def _read_dns_name(data: bytes, offset: int, *, max_jumps: int = 20) -> Tuple[str, int]:
    labels: List[str] = []
    pos = int(offset)
    jumped = False
    original_next = pos
    jumps = 0
    while True:
        if pos >= len(data):
            raise ValueError("DNS name exceeds packet length.")
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                original_next = pos
            return ".".join(labels), original_next
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("DNS compression pointer truncated.")
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                original_next = pos + 2
            pos = ptr
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                raise ValueError("DNS compression pointer loop suspected.")
            continue
        if length & 0xC0:
            raise ValueError("Unsupported DNS label type.")
        pos += 1
        label = data[pos:pos + length]
        pos += length
        labels.append(label.decode("utf-8", "replace"))


def parse_dns_message(data: bytes) -> Dict[str, Any]:
    raw = bytes(data or b"")
    if len(raw) < 12:
        return {"ok": False, "error": "DNS message too short."}
    try:
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", raw[:12])
        pos = 12
        questions: List[Dict[str, Any]] = []
        answers: List[Dict[str, Any]] = []

        for _ in range(min(qd, 64)):
            name, pos = _read_dns_name(raw, pos)
            if pos + 4 > len(raw):
                raise ValueError("DNS question truncated.")
            qtype, qclass = struct.unpack("!HH", raw[pos:pos + 4])
            pos += 4
            questions.append({"name": name, "type": _dns_qtype_name(qtype), "type_num": qtype, "class": qclass})

        total_rr = min(an + ns + ar, 256)
        for index in range(total_rr):
            section = "answer" if index < an else "authority" if index < an + ns else "additional"
            name, pos = _read_dns_name(raw, pos)
            if pos + 10 > len(raw):
                raise ValueError("DNS resource record truncated.")
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", raw[pos:pos + 10])
            pos += 10
            rdata = raw[pos:pos + rdlen]
            pos += rdlen
            value: Any = rdata.hex()
            try:
                if rtype == 1 and len(rdata) == 4:
                    value = _ipv4_to_str(rdata)
                elif rtype == 28 and len(rdata) == 16:
                    value = _ipv6_to_str(rdata)
                elif rtype in (2, 5, 12):
                    value, _ = _read_dns_name(raw, pos - rdlen)
                elif rtype == 15 and len(rdata) >= 2:
                    pref = struct.unpack("!H", rdata[:2])[0]
                    mx, _ = _read_dns_name(raw, pos - rdlen + 2)
                    value = {"preference": pref, "exchange": mx}
                elif rtype == 16:
                    txts = []
                    p = 0
                    while p < len(rdata):
                        ln = rdata[p]
                        p += 1
                        txts.append(rdata[p:p + ln].decode("utf-8", "replace"))
                        p += ln
                    value = txts
            except Exception:
                value = rdata.hex()
            answers.append({
                "section": section,
                "name": name,
                "type": _dns_qtype_name(rtype),
                "type_num": rtype,
                "class": rclass,
                "ttl": ttl,
                "value": value,
                "raw_len": rdlen,
            })

        return {
            "ok": True,
            "transaction_id": tid,
            "flags": flags,
            "qr": bool(flags & 0x8000),
            "opcode": (flags >> 11) & 0xF,
            "rcode": flags & 0xF,
            "question_count": qd,
            "answer_count": an,
            "authority_count": ns,
            "additional_count": ar,
            "questions": questions,
            "records": answers,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "raw_preview": _bytes_preview(raw, 64)}


# =============================================================================
# Packet receive/send engine
# =============================================================================


@dataclass
class PacketEngineConfig:
    timeout_ms: int = 250
    snaplen: int = 65535
    promisc: bool = True
    payload_preview_bytes: int = 128
    default_bpf_filter: str = ""
    allow_raw_send: bool = False
    max_send_bytes: int = 4096
    max_capture_packets: int = 1000
    capture_budget_s: float = 5.0
    logger: Any = None


class PacketEngine:
    def __init__(self, config: Optional[PacketEngineConfig] = None) -> None:
        self.config = config or PacketEngineConfig()
        self.backend: Optional[LibpcapCtypesBackend] = None
        self.parser = PacketParser(payload_preview_bytes=self.config.payload_preview_bytes)
        self.open_mode = ""
        self.open_target = ""
        self.current_filter = ""

    def _make_backend(self) -> LibpcapCtypesBackend:
        return LibpcapCtypesBackend(
            timeout_ms=self.config.timeout_ms,
            snaplen=self.config.snaplen,
            promisc=self.config.promisc,
            logger=self.config.logger,
        )

    def list_interfaces(self) -> Dict[str, Any]:
        backend = self._make_backend()
        try:
            return backend.list_interfaces()
        finally:
            backend.close()

    def open_live(self, interface: str, bpf_filter: str = "") -> Dict[str, Any]:
        self.close()
        self.backend = self._make_backend()
        self.backend.open_live(interface)
        filt = bpf_filter or self.config.default_bpf_filter or ""
        filter_result = self.backend.set_filter(filt) if filt else {"ok": True, "filter": ""}
        self.open_mode = "live"
        self.open_target = interface
        self.current_filter = filt
        return {"ok": True, "mode": "live", "interface": interface, "datalink": self.backend.datalink(), "filter": filter_result}

    def open_offline(self, path: str, bpf_filter: str = "") -> Dict[str, Any]:
        self.close()
        self.backend = self._make_backend()
        self.backend.open_offline(path)
        filt = bpf_filter or self.config.default_bpf_filter or ""
        filter_result = self.backend.set_filter(filt) if filt else {"ok": True, "filter": ""}
        self.open_mode = "offline"
        self.open_target = path
        self.current_filter = filt
        return {"ok": True, "mode": "offline", "path": path, "datalink": self.backend.datalink(), "filter": filter_result}

    def set_filter(self, bpf_filter: str) -> Dict[str, Any]:
        if not self.backend:
            return {"ok": False, "error": "No capture handle is open."}
        result = self.backend.set_filter(bpf_filter)
        if result.get("ok"):
            self.current_filter = bpf_filter
        return result

    def next_packet(self, *, decode: bool = True) -> Optional[Dict[str, Any]]:
        if not self.backend:
            return None
        pkt = self.backend.next_packet()
        if pkt is None:
            return None
        if decode:
            parsed = self.parser.parse_capture_record(pkt)
            parsed["raw_b64"] = base64.b64encode(pkt.get("raw_bytes", b"")).decode("ascii")
            return parsed
        safe = dict(pkt)
        raw = safe.pop("raw_bytes", b"")
        safe["raw_b64"] = base64.b64encode(raw).decode("ascii")
        safe["sha256"] = hashlib.sha256(raw).hexdigest() if raw else ""
        return safe

    def collect(self, *, max_packets: int = 128, budget_s: float = 2.0, decode: bool = True) -> Dict[str, Any]:
        if not self.backend:
            return {"ok": False, "error": "No capture handle is open."}
        max_packets = max(1, min(int(max_packets or 1), int(self.config.max_capture_packets or 1000)))
        budget_s = max(0.05, min(float(budget_s or 0.05), float(self.config.capture_budget_s or 5.0)))
        records = self.backend.collect(max_packets=max_packets, budget_s=budget_s)
        packets = []
        for record in records:
            if decode:
                parsed = self.parser.parse_capture_record(record)
                parsed["raw_b64"] = base64.b64encode(record.get("raw_bytes", b"")).decode("ascii")
                packets.append(parsed)
            else:
                safe = dict(record)
                raw = safe.pop("raw_bytes", b"")
                safe["raw_b64"] = base64.b64encode(raw).decode("ascii")
                safe["sha256"] = hashlib.sha256(raw).hexdigest() if raw else ""
                packets.append(safe)
        return {
            "ok": True,
            "mode": self.open_mode,
            "target": self.open_target,
            "filter": self.current_filter,
            "count": len(packets),
            "packets": packets,
        }

    def capture_live(self, interface: str, *, bpf_filter: str = "", max_packets: int = 128, budget_s: float = 2.0, decode: bool = True) -> Dict[str, Any]:
        try:
            open_result = self.open_live(interface, bpf_filter=bpf_filter)
            result = self.collect(max_packets=max_packets, budget_s=budget_s, decode=decode)
            result["open"] = open_result
            return result
        finally:
            self.close()

    def capture_offline(self, path: str, *, bpf_filter: str = "", max_packets: int = 1000, budget_s: float = 10.0, decode: bool = True) -> Dict[str, Any]:
        try:
            open_result = self.open_offline(path, bpf_filter=bpf_filter)
            result = self.collect(max_packets=max_packets, budget_s=budget_s, decode=decode)
            result["open"] = open_result
            return result
        finally:
            self.close()

    def send_udp(self, host: str, port: int, payload: Union[str, BytesLike] = b"", *, payload_hex: bool = False, bind_host: str = "", bind_port: int = 0, timeout_sec: float = 3.0, read_response: bool = True) -> Dict[str, Any]:
        data = _coerce_payload(payload, hex_mode=payload_hex)
        if len(data) > self.config.max_send_bytes:
            raise ValueError(f"UDP payload exceeds max_send_bytes={self.config.max_send_bytes}.")
        port_i = int(port)
        with socket.socket(socket.AF_INET if ":" not in host else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.settimeout(float(timeout_sec or 3.0))
            if bind_host or bind_port:
                sock.bind((bind_host or "", int(bind_port or 0)))
            sent = sock.sendto(data, (host, port_i))
            response: Dict[str, Any] = {}
            if read_response:
                try:
                    raw, addr = sock.recvfrom(65535)
                    response = {"from": str(addr), "bytes": len(raw), "preview": _bytes_preview(raw, 256)}
                except socket.timeout:
                    response = {"timeout": True}
        return {"ok": True, "protocol": "udp", "host": host, "port": port_i, "bytes_sent": sent, "response": response}

    def send_tcp(self, host: str, port: int, payload: Union[str, BytesLike] = b"", *, payload_hex: bool = False, timeout_sec: float = 5.0, read_response: bool = True) -> Dict[str, Any]:
        data = _coerce_payload(payload, hex_mode=payload_hex)
        if len(data) > self.config.max_send_bytes:
            raise ValueError(f"TCP payload exceeds max_send_bytes={self.config.max_send_bytes}.")
        port_i = int(port)
        response: Dict[str, Any] = {}
        with socket.create_connection((host, port_i), timeout=float(timeout_sec or 5.0)) as sock:
            sock.settimeout(float(timeout_sec or 5.0))
            sent = 0
            if data:
                sock.sendall(data)
                sent = len(data)
            if read_response:
                try:
                    raw = sock.recv(65535)
                    response = {"bytes": len(raw), "preview": _bytes_preview(raw, 512)}
                except socket.timeout:
                    response = {"timeout": True}
        return {"ok": True, "protocol": "tcp", "host": host, "port": port_i, "bytes_sent": sent, "response": response}

    def send_dns_query(self, domain: str, *, server: str = "1.1.1.1", qtype: Union[str, int] = "A", timeout_sec: float = 4.0) -> Dict[str, Any]:
        query = _build_dns_query(domain, qtype=qtype)
        with socket.socket(socket.AF_INET if ":" not in server else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.settimeout(float(timeout_sec or 4.0))
            sent = sock.sendto(query, (server, 53))
            raw, addr = sock.recvfrom(65535)
        parsed = parse_dns_message(raw)
        return {"ok": True, "protocol": "dns", "domain": domain, "server": server, "qtype": _dns_qtype_name(_dns_qtype_number(qtype)), "bytes_sent": sent, "response_from": str(addr), "response_bytes": len(raw), "dns": parsed}

    def send_l2_frame(self, interface: str, raw_bytes: bytes, *, confirm_authorized: bool = False) -> Dict[str, Any]:
        if not self.config.allow_raw_send or not confirm_authorized:
            return {
                "ok": False,
                "error": "Raw L2 send is disabled. Set PacketEngineConfig.allow_raw_send=True and pass confirm_authorized=True for authorized lab use.",
            }
        raw = bytes(raw_bytes or b"")
        if not raw:
            return {"ok": False, "error": "raw_bytes is empty."}
        if len(raw) > self.config.max_send_bytes:
            return {"ok": False, "error": f"Raw frame exceeds max_send_bytes={self.config.max_send_bytes}."}
        self.close()
        self.backend = self._make_backend()
        try:
            self.backend.open_live(interface)
            result = self.backend.send_packet(raw)
            result.update({"interface": interface, "protocol": "l2_raw"})
            return result
        finally:
            self.close()

    def close(self) -> None:
        if self.backend:
            try:
                self.backend.close()
            except Exception:
                pass
            self.backend = None
            self.open_mode = ""
            self.open_target = ""
            self.current_filter = ""


# Public alias for clearer naming.
NetworkPacketEngine = PacketEngine
PacketSnifferEngine = PacketEngine
NetworkPacketSnifferEngine = PacketEngine
NetworkSnifferConfig = PacketEngineConfig


# =============================================================================
# GPT/tool-friendly network functions
# =============================================================================


def packet_list_interfaces() -> Dict[str, Any]:
    engine = PacketEngine()
    try:
        return engine.list_interfaces()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def packet_capture_live(
    interface: str,
    bpf_filter: str = "",
    max_packets: int = 64,
    budget_s: float = 2.0,
    decode: bool = True,
) -> Dict[str, Any]:
    engine = PacketEngine()
    try:
        return engine.capture_live(interface, bpf_filter=bpf_filter, max_packets=max_packets, budget_s=budget_s, decode=decode)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "interface": interface, "filter": bpf_filter}


def packet_capture_offline(
    path: str,
    bpf_filter: str = "",
    max_packets: int = 1000,
    budget_s: float = 10.0,
    decode: bool = True,
) -> Dict[str, Any]:
    engine = PacketEngine()
    try:
        return engine.capture_offline(path, bpf_filter=bpf_filter, max_packets=max_packets, budget_s=budget_s, decode=decode)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "path": path, "filter": bpf_filter}


def packet_parse_hex(raw_hex: str, datalink: int = DLT_EN10MB) -> Dict[str, Any]:
    try:
        raw = _coerce_payload(raw_hex, hex_mode=True)
        return PacketParser().parse(raw, datalink=datalink)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def packet_send_udp(
    host: str,
    port: int,
    payload_text: str = "",
    payload_hex: str = "",
    timeout_sec: float = 3.0,
    read_response: bool = True,
) -> Dict[str, Any]:
    engine = PacketEngine()
    try:
        if payload_hex:
            return engine.send_udp(host, port, payload_hex, payload_hex=True, timeout_sec=timeout_sec, read_response=read_response)
        return engine.send_udp(host, port, payload_text, payload_hex=False, timeout_sec=timeout_sec, read_response=read_response)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "protocol": "udp", "host": host, "port": int(port)}


def packet_send_tcp(
    host: str,
    port: int,
    payload_text: str = "",
    payload_hex: str = "",
    timeout_sec: float = 5.0,
    read_response: bool = True,
) -> Dict[str, Any]:
    engine = PacketEngine()
    try:
        if payload_hex:
            return engine.send_tcp(host, port, payload_hex, payload_hex=True, timeout_sec=timeout_sec, read_response=read_response)
        return engine.send_tcp(host, port, payload_text, payload_hex=False, timeout_sec=timeout_sec, read_response=read_response)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "protocol": "tcp", "host": host, "port": int(port)}


def packet_dns_query(
    domain: str,
    server: str = "1.1.1.1",
    qtype: str = "A",
    timeout_sec: float = 4.0,
) -> Dict[str, Any]:
    engine = PacketEngine()
    try:
        return engine.send_dns_query(domain, server=server, qtype=qtype, timeout_sec=timeout_sec)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "protocol": "dns", "domain": domain, "server": server, "qtype": qtype}


def packet_send_l2_frame(
    interface: str,
    raw_hex: str,
    confirm_authorized: bool = False,
    max_send_bytes: int = 4096,
) -> Dict[str, Any]:
    try:
        raw = _coerce_payload(raw_hex, hex_mode=True)
        cfg = PacketEngineConfig(allow_raw_send=True, max_send_bytes=max(64, int(max_send_bytes or 4096)))
        engine = PacketEngine(cfg)
        return engine.send_l2_frame(interface, raw, confirm_authorized=confirm_authorized)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "interface": interface}


# =============================================================================
# Compatibility web-sniffer surface for older tools.py
# =============================================================================


@dataclass
class SniffItem:
    url: str
    kind: str = "link"
    tag: str = ""
    source: str = ""
    text: str = ""
    content_type: str = ""
    status: int = 0
    evidence: str = ""
    score: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SniffResult:
    ok: bool = True
    url: str = ""
    final_url: str = ""
    mode: str = "text"
    title: str = ""
    description: str = ""
    text: str = ""
    html: str = ""
    items: List[SniffItem] = field(default_factory=list)
    json_hits: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed_ms: int = 0

    def as_dict(self, include_html: bool = False) -> Dict[str, Any]:
        items = [i.as_dict() if hasattr(i, "as_dict") else dict(i) for i in self.items]
        links = [i for i in items if i.get("kind") == "link"]
        images = [i for i in items if i.get("kind") == "image"]
        videos = [i for i in items if i.get("kind") == "video"]
        audio = [i for i in items if i.get("kind") == "audio"]
        documents = [i for i in items if i.get("kind") == "document"]
        out: Dict[str, Any] = {
            "ok": self.ok,
            "url": self.url,
            "final_url": self.final_url,
            "mode": self.mode,
            "title": self.title,
            "description": self.description,
            "text": self.text,
            "count": len(items),
            "items": items,
            "links": links,
            "images": images,
            "videos": videos,
            "audio": audio,
            "documents": documents,
            "links_count": len(links),
            "images_count": len(images),
            "videos_count": len(videos),
            "audio_count": len(audio),
            "documents_count": len(documents),
            "json_hits": self.json_hits,
            "errors": self.errors,
            "elapsed_ms": self.elapsed_ms,
        }
        if include_html:
            out["html"] = self.html
        return out


@dataclass
class SnifferConfig:
    timeout_sec: float = 20.0
    max_page_chars: int = 12000
    max_text_chars: int = 12000
    max_items: int = 250
    verify_assets: bool = False
    use_playwright: bool = False
    include_junk: bool = False
    keep_signed_query_values: bool = False


class SnifferEngine:
    """
    Backward-compatible simple URL/text asset sniffer.

    This intentionally preserves the public surface older tools.py expects.
    The packet functionality lives in PacketEngine/NetworkPacketEngine.
    """

    def __init__(self, config: Optional[SnifferConfig] = None) -> None:
        self.config = config or SnifferConfig()

    def sniff_text(self, text: str, *, base_url: str = "", include_html: bool = False) -> SniffResult:
        start = _now()
        html_text = text or ""
        result = SniffResult(ok=True, url=base_url or "", final_url=base_url or "", mode="text", html=html_text if include_html else "")
        result.title = self._extract_title(html_text)
        result.description = self._extract_meta_description(html_text)
        result.text = self._clean_text(html_text)[: max(0, int(self.config.max_text_chars or 12000))]
        result.items = self._extract_items(html_text, base_url=base_url or "")[: max(1, int(self.config.max_items or 250))]
        result.json_hits = self._extract_json_url_hits(html_text, base_url=base_url or "")[:100]
        result.elapsed_ms = int((_now() - start) * 1000)
        return result

    def sniff_url(
        self,
        url: str,
        timeout_sec: Optional[float] = None,
        max_items: Optional[int] = None,
        include_html: bool = False,
        tor_socks_url: Optional[str] = None,
        use_playwright: Optional[bool] = None,
    ) -> SniffResult:
        start = _now()
        if requests is None:
            return SniffResult(ok=False, url=url, mode="url", errors=["requests is not installed."], elapsed_ms=int((_now() - start) * 1000))
        try:
            proxies = {"http": tor_socks_url, "https": tor_socks_url} if tor_socks_url else None
            resp = requests.get(
                url,
                timeout=float(timeout_sec if timeout_sec is not None else self.config.timeout_sec),
                headers={"User-Agent": "PromptChat-PacketEngine/web-compatible"},
                allow_redirects=True,
                proxies=proxies,
            )
            body = resp.text or ""
            cfg_items = self.config.max_items
            if max_items is not None:
                self.config.max_items = max_items
            try:
                result = self.sniff_text(body, base_url=resp.url, include_html=include_html)
            finally:
                self.config.max_items = cfg_items
            result.mode = "url"
            result.url = url
            result.final_url = resp.url
            result.ok = 200 <= int(resp.status_code) < 400
            if not result.ok:
                result.errors.append(f"HTTP status {resp.status_code}")
            result.elapsed_ms = int((_now() - start) * 1000)
            return result
        except Exception as exc:
            return SniffResult(ok=False, url=url, mode="url", errors=[str(exc)], elapsed_ms=int((_now() - start) * 1000))

    async def sniff_url_async(self, *args: Any, **kwargs: Any) -> SniffResult:
        return await asyncio.to_thread(self.sniff_url, *args, **kwargs)

    def _extract_title(self, html_text: str) -> str:
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_text or "")
        return self._clean_text(m.group(1))[:300] if m else ""

    def _extract_meta_description(self, html_text: str) -> str:
        for pat in [
            r'(?is)<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
            r'(?is)<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']',
        ]:
            m = re.search(pat, html_text or "")
            if m:
                return html.unescape(m.group(1)).strip()[:500]
        return ""

    def _clean_text(self, html_text: str) -> str:
        text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html_text or "")
        text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
        text = re.sub(r"(?s)<.*?>", " ", text)
        text = html.unescape(text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _classify_url(self, url: str) -> str:
        path = urlparse(url).path.lower()
        if re.search(r"\.(png|jpe?g|gif|webp|bmp|svg|avif|ico)(?:$|[?#])", path):
            return "image"
        if re.search(r"\.(mp4|webm|mkv|mov|m4v|m3u8|mpd)(?:$|[?#])", path):
            return "video"
        if re.search(r"\.(mp3|wav|flac|m4a|aac|ogg)(?:$|[?#])", path):
            return "audio"
        if re.search(r"\.(pdf|docx?|xlsx?|pptx?|zip|rar|7z|tar|gz)(?:$|[?#])", path):
            return "document"
        return "link"

    def _extract_items(self, text: str, *, base_url: str = "") -> List[SniffItem]:
        items: List[SniffItem] = []
        seen: set[str] = set()

        def add(candidate: str, *, tag: str = "", source: str = "regex", evidence: str = "") -> None:
            href = html.unescape(candidate or "").strip().strip('"\'')
            if not href or href.startswith(("javascript:", "mailto:", "#")):
                return
            absolute = urljoin(base_url, href) if base_url else href
            parsed = urlparse(absolute)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return
            clean = absolute if self.config.keep_signed_query_values else _redact_url_for_display(absolute)
            if clean in seen:
                return
            seen.add(clean)
            items.append(SniffItem(url=clean, kind=self._classify_url(clean), tag=tag, source=source, evidence=evidence))

        attr_re = re.compile(r'''(?is)\b(?:href|src|poster|data-src|data-href|content)=(["\'])(.*?)\1''')
        for m in attr_re.finditer(text or ""):
            add(m.group(2), tag="attr", source="html_attr", evidence=m.group(0)[:120])

        srcset_re = re.compile(r'''(?is)\b(?:srcset|imagesrcset)=(["\'])(.*?)\1''')
        for m in srcset_re.finditer(text or ""):
            for part in m.group(2).split(","):
                add(part.strip().split(" ")[0], tag="srcset", source="html_srcset")

        css_re = re.compile(r'''(?is)url\(([^)]+)\)''')
        for m in css_re.finditer(text or ""):
            add(m.group(1).strip(), tag="css_url", source="css")

        url_re = re.compile(r'''https?://[^\s"'<>\\]+''')
        for m in url_re.finditer(text or ""):
            add(m.group(0).rstrip("),.;"), tag="raw_url", source="regex")

        return items

    def _extract_json_url_hits(self, text: str, *, base_url: str = "") -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for m in re.finditer(r'''["'](?P<key>[A-Za-z0-9_:-]*(?:url|src|href|image|video|audio|thumbnail)[A-Za-z0-9_:-]*)["']\s*:\s*["'](?P<val>[^"']+)["']''', text or "", re.I):
            val = m.group("val")
            absolute = urljoin(base_url, val) if base_url else val
            if urlparse(absolute).scheme in {"http", "https"}:
                hits.append({"key": m.group("key"), "url": _redact_url_for_display(absolute), "kind": self._classify_url(absolute)})
        return hits


def sniff_text(text: str, base_url: str = "", **kwargs: Any) -> Dict[str, Any]:
    cfg = SnifferConfig()
    for key, value in kwargs.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
    return SnifferEngine(cfg).sniff_text(text, base_url=base_url).as_dict(include_html=bool(kwargs.get("include_html", False)))


def sniff_url(url: str, **kwargs: Any) -> Dict[str, Any]:
    cfg = SnifferConfig()
    for key, value in kwargs.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
    result = SnifferEngine(cfg).sniff_url(
        url,
        timeout_sec=kwargs.get("timeout_sec"),
        max_items=kwargs.get("max_items"),
        include_html=bool(kwargs.get("include_html", False)),
        tor_socks_url=kwargs.get("tor_socks_url"),
        use_playwright=kwargs.get("use_playwright"),
    )
    return result.as_dict(include_html=bool(kwargs.get("include_html", False)))


__all__ = [
    "LibpcapCtypesBackend",
    "PacketParser",
    "PacketEngineConfig",
    "PacketEngine",
    "NetworkPacketEngine",
    "PacketSnifferEngine",
    "NetworkPacketSnifferEngine",
    "NetworkSnifferConfig",
    "parse_dns_message",
    "packet_list_interfaces",
    "packet_capture_live",
    "packet_capture_offline",
    "packet_parse_hex",
    "packet_send_udp",
    "packet_send_tcp",
    "packet_dns_query",
    "packet_send_l2_frame",
    "SnifferConfig",
    "SniffItem",
    "SniffResult",
    "SnifferEngine",
    "sniff_text",
    "sniff_url",
]


# =============================================================================
# CLI
# =============================================================================


def _main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Packet engine using libpcap/Npcap for capture plus safe UDP/TCP/DNS send helpers.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("interfaces")

    p_cap = sub.add_parser("capture")
    p_cap.add_argument("--iface", required=True)
    p_cap.add_argument("--filter", default="")
    p_cap.add_argument("--max-packets", type=int, default=32)
    p_cap.add_argument("--budget-s", type=float, default=2.0)

    p_off = sub.add_parser("offline")
    p_off.add_argument("path")
    p_off.add_argument("--filter", default="")
    p_off.add_argument("--max-packets", type=int, default=1000)

    p_dns = sub.add_parser("dns")
    p_dns.add_argument("domain")
    p_dns.add_argument("--server", default="1.1.1.1")
    p_dns.add_argument("--qtype", default="A")

    p_udp = sub.add_parser("udp")
    p_udp.add_argument("host")
    p_udp.add_argument("port", type=int)
    p_udp.add_argument("--text", default="")
    p_udp.add_argument("--hex", default="")
    p_udp.add_argument("--no-read", action="store_true")

    p_tcp = sub.add_parser("tcp")
    p_tcp.add_argument("host")
    p_tcp.add_argument("port", type=int)
    p_tcp.add_argument("--text", default="")
    p_tcp.add_argument("--hex", default="")
    p_tcp.add_argument("--no-read", action="store_true")

    args = parser.parse_args()
    if args.cmd == "interfaces":
        result = packet_list_interfaces()
    elif args.cmd == "capture":
        result = packet_capture_live(args.iface, bpf_filter=args.filter, max_packets=args.max_packets, budget_s=args.budget_s)
    elif args.cmd == "offline":
        result = packet_capture_offline(args.path, bpf_filter=args.filter, max_packets=args.max_packets)
    elif args.cmd == "dns":
        result = packet_dns_query(args.domain, server=args.server, qtype=args.qtype)
    elif args.cmd == "udp":
        result = packet_send_udp(args.host, args.port, payload_text=args.text, payload_hex=args.hex, read_response=not args.no_read)
    elif args.cmd == "tcp":
        result = packet_send_tcp(args.host, args.port, payload_text=args.text, payload_hex=args.hex, read_response=not args.no_read)
    else:
        result = {"ok": False, "error": "unknown command"}
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    _main()
