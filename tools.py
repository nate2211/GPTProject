from __future__ import annotations

"""PromptChat tools.py with exact old signatures preserved plus application_engine tool integration."""

import html
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote_plus, unquote, urljoin, urlparse

import requests

try:
    from retrieval import SimpleFileRetrieval
except Exception:
    SimpleFileRetrieval = None

try:
    from project_tools import LocalPythonProjectTools
except Exception:
    LocalPythonProjectTools = None

try:
    from reverse_image_engine import reverse_image_tool
except Exception:
    reverse_image_tool = None

try:
    from sniffer_engine import SnifferConfig, SnifferEngine
except Exception:
    SnifferConfig = None
    SnifferEngine = None

try:
    from forensic_engine import (
        ForensicConfig,
        ForensicEngine,
        classify_url as forensic_classify_url_value,
        extract_urls_from_text as forensic_extract_urls_from_text,
        generate_url_variants as forensic_generate_url_variants,
    )
except Exception:
    ForensicConfig = None
    ForensicEngine = None
    forensic_classify_url_value = None
    forensic_extract_urls_from_text = None
    forensic_generate_url_variants = None

try:
    from cdn_engine import (
        CDNConfig,
        CDNEngine,
        cdn_analyze_asset as cdn_engine_analyze_asset,
        cdn_domain_context as cdn_engine_domain_context,
        cdn_extract_from_text as cdn_engine_extract_from_text,
        cdn_investigate_url as cdn_engine_investigate_url,
        cdn_url_variants as cdn_engine_url_variants,
    )
except Exception:
    CDNConfig = None
    CDNEngine = None
    cdn_engine_analyze_asset = None
    cdn_engine_domain_context = None
    cdn_engine_extract_from_text = None
    cdn_engine_investigate_url = None
    cdn_engine_url_variants = None

try:
    from engines import (
        archive_search_url as engine_archive_search_url,
        archive_search_domain as engine_archive_search_domain,
        archive_fetch_wayback_snapshot as engine_archive_fetch_wayback_snapshot,
        archive_compare_snapshots as engine_archive_compare_snapshots,
        archive_extract_lost_links as engine_archive_extract_lost_links,
        archive_timeline_report as engine_archive_timeline_report,
        sourcemap_find as engine_sourcemap_find,
        sourcemap_fetch as engine_sourcemap_fetch,
        sourcemap_extract_sources as engine_sourcemap_extract_sources,
        sourcemap_extract_urls as engine_sourcemap_extract_urls,
        sourcemap_reconstruct_tree as engine_sourcemap_reconstruct_tree,
        sourcemap_secret_redacted_scan as engine_sourcemap_secret_redacted_scan,
        metadata_url as engine_metadata_url,
        metadata_file as engine_metadata_file,
        metadata_image as engine_metadata_image,
        metadata_video as engine_metadata_video,
        metadata_pdf as engine_metadata_pdf,
        metadata_compare as engine_metadata_compare,
        metadata_redacted_report as engine_metadata_redacted_report,
        osint_domain as engine_osint_domain,
        osint_ip as engine_osint_ip,
        osint_certificates as engine_osint_certificates,
        osint_dns_history as engine_osint_dns_history,
        osint_public_mentions as engine_osint_public_mentions,
        osint_related_domains as engine_osint_related_domains,
        manifest_find as engine_manifest_find,
        manifest_parse_webapp as engine_manifest_parse_webapp,
        manifest_parse_hls as engine_manifest_parse_hls,
        manifest_parse_dash as engine_manifest_parse_dash,
        manifest_parse_rss as engine_manifest_parse_rss,
        manifest_parse_atom as engine_manifest_parse_atom,
        manifest_extract_assets as engine_manifest_extract_assets,
        route_extract_from_html as engine_route_extract_from_html,
        route_extract_from_js as engine_route_extract_from_js,
        route_extract_nextjs as engine_route_extract_nextjs,
        route_extract_nuxt as engine_route_extract_nuxt,
        route_extract_vite as engine_route_extract_vite,
        route_extract_react_router as engine_route_extract_react_router,
        route_probe_public_routes as engine_route_probe_public_routes,
        media_find as engine_media_find,
        media_extract_hls as engine_media_extract_hls,
        media_extract_dash as engine_media_extract_dash,
        media_extract_subtitles as engine_media_extract_subtitles,
        media_extract_thumbnails as engine_media_extract_thumbnails,
        media_probe_dimensions as engine_media_probe_dimensions,
        media_rank_best_sources as engine_media_rank_best_sources,
        entity_extract as engine_entity_extract,
        entity_link_urls as engine_entity_link_urls,
        entity_timeline as engine_entity_timeline,
        entity_cluster as engine_entity_cluster,
        entity_report as engine_entity_report,
        engines_status as engine_engines_status,
    )
except Exception:
    engine_archive_search_url = None
    engine_archive_search_domain = None
    engine_archive_fetch_wayback_snapshot = None
    engine_archive_compare_snapshots = None
    engine_archive_extract_lost_links = None
    engine_archive_timeline_report = None
    engine_sourcemap_find = None
    engine_sourcemap_fetch = None
    engine_sourcemap_extract_sources = None
    engine_sourcemap_extract_urls = None
    engine_sourcemap_reconstruct_tree = None
    engine_sourcemap_secret_redacted_scan = None
    engine_metadata_url = None
    engine_metadata_file = None
    engine_metadata_image = None
    engine_metadata_video = None
    engine_metadata_pdf = None
    engine_metadata_compare = None
    engine_metadata_redacted_report = None
    engine_osint_domain = None
    engine_osint_ip = None
    engine_osint_certificates = None
    engine_osint_dns_history = None
    engine_osint_public_mentions = None
    engine_osint_related_domains = None
    engine_manifest_find = None
    engine_manifest_parse_webapp = None
    engine_manifest_parse_hls = None
    engine_manifest_parse_dash = None
    engine_manifest_parse_rss = None
    engine_manifest_parse_atom = None
    engine_manifest_extract_assets = None
    engine_route_extract_from_html = None
    engine_route_extract_from_js = None
    engine_route_extract_nextjs = None
    engine_route_extract_nuxt = None
    engine_route_extract_vite = None
    engine_route_extract_react_router = None
    engine_route_probe_public_routes = None
    engine_media_find = None
    engine_media_extract_hls = None
    engine_media_extract_dash = None
    engine_media_extract_subtitles = None
    engine_media_extract_thumbnails = None
    engine_media_probe_dimensions = None
    engine_media_rank_best_sources = None
    engine_entity_extract = None
    engine_entity_link_urls = None
    engine_entity_timeline = None
    engine_entity_cluster = None
    engine_entity_report = None
    engine_engines_status = None

try:
    from packet_engine import (
        PacketEngine,
        PacketEngineConfig,
        DLT_EN10MB,
        packet_capture_live as packet_engine_capture_live,
        packet_capture_offline as packet_engine_capture_offline,
        packet_dns_query as packet_engine_dns_query,
        packet_list_interfaces as packet_engine_list_interfaces,
        packet_parse_hex as packet_engine_parse_hex,
        packet_send_l2_frame as packet_engine_send_l2_frame,
        packet_send_tcp as packet_engine_send_tcp,
        packet_send_udp as packet_engine_send_udp,
    )
except Exception:
    PacketEngine = None
    PacketEngineConfig = None
    DLT_EN10MB = 1
    packet_engine_capture_live = None
    packet_engine_capture_offline = None
    packet_engine_dns_query = None
    packet_engine_list_interfaces = None
    packet_engine_parse_hex = None
    packet_engine_send_l2_frame = None
    packet_engine_send_tcp = None
    packet_engine_send_udp = None


# ======================= Monero Monitor Engine Import ======================
# Put this near your other optional engine imports at the top of tools.py.
try:
    from monero_monitor_engine import (
        monero_daemon_status as engine_monero_daemon_status,
        monero_monitor_transaction as engine_monero_monitor_transaction,
        monero_monitor_transactions as engine_monero_monitor_transactions,
        p2pool_observer_pool_info as engine_p2pool_observer_pool_info,
        p2pool_observer_miner_info as engine_p2pool_observer_miner_info,
        monero_combined_monitor as engine_monero_combined_monitor,
    )
except Exception:
    engine_monero_daemon_status = None
    engine_monero_monitor_transaction = None
    engine_monero_monitor_transactions = None
    engine_p2pool_observer_pool_info = None
    engine_p2pool_observer_miner_info = None
    engine_monero_combined_monitor = None

# ======================= Stock/Resale Monitor Engine Imports ===============
# Put this near your other optional engine imports at the top of tools.py.
try:
    from stock_engine_monitor import (
        stock_quote as engine_stock_quote,
        stock_monitor as engine_stock_monitor,
        stock_compare_watchlist as engine_stock_compare_watchlist,
        stock_engine_status as engine_stock_engine_status,
    )
except Exception:
    engine_stock_quote = None
    engine_stock_monitor = None
    engine_stock_compare_watchlist = None
    engine_stock_engine_status = None

try:
    from resale_engine_monitor import (
        resale_search as engine_resale_search,
        resale_monitor as engine_resale_monitor,
        resale_parse_html as engine_resale_parse_html,
        resale_build_search_urls as engine_resale_build_search_urls,
        resale_engine_status as engine_resale_engine_status,
    )
except Exception:
    engine_resale_search = None
    engine_resale_monitor = None
    engine_resale_parse_html = None
    engine_resale_build_search_urls = None
    engine_resale_engine_status = None


# ======================= Intelligence Engine Import =========================
# Put this near your other optional engine imports at the top of tools.py.
try:
    from intelligence_engine import (
        intelligence_engine as engine_intelligence_engine,
        intelligence_tool_schema as engine_intelligence_tool_schema,
        make_intelligence_tool_function as engine_make_intelligence_tool_function,
    )
except Exception:
    engine_intelligence_engine = None
    engine_intelligence_tool_schema = None
    engine_make_intelligence_tool_function = None

# ======================= News Engine Import ================================
# Put this near your other optional engine imports at the top of tools.py.
try:
    from news_engine import (
        news_fetch_source as engine_news_fetch_source,
        news_search as engine_news_search,
        news_monitor as engine_news_monitor,
        news_parse_feed as engine_news_parse_feed,
        news_build_source_urls as engine_news_build_source_urls,
        news_engine_status as engine_news_engine_status,
    )
except Exception:
    engine_news_fetch_source = None
    engine_news_search = None
    engine_news_monitor = None
    engine_news_parse_feed = None
    engine_news_build_source_urls = None
    engine_news_engine_status = None





# ======================= Language Engine Import =============================
# Put this near your other optional engine imports at the top of tools.py.
#
# Normal case:
#   language_engine.py sits beside tools.py.
#
# Fallback paths exist because PromptChat sometimes runs from a different CWD.
# The engine is local-first: it improves English, formatting, query generation,
# tool prompts, summaries, and final answers without changing old signatures.
try:
    from language_engine import (
        language_engine as engine_language_engine,
        language_engine_tool_schema as engine_language_engine_tool_schema,
        make_language_engine_tool_function as engine_make_language_engine_tool_function,
        register_language_engine_tool as engine_register_language_engine_tool,
    )
except Exception:
    engine_language_engine = None
    engine_language_engine_tool_schema = None
    engine_make_language_engine_tool_function = None
    engine_register_language_engine_tool = None

    try:
        import importlib.util as _language_engine_importlib_util
        import sys as _language_engine_sys

        _language_engine_candidates: List[Path] = []
        try:
            _language_engine_candidates.append(Path(__file__).resolve().parent / "language_engine.py")
        except Exception:
            pass

        _language_engine_candidates.append(Path.cwd() / "language_engine.py")
        _language_engine_candidates.append(Path.home() / ".promptchat" / "language_engine.py")
        _language_engine_candidates.append(Path.home() / ".promptchat" / "engines" / "language_engine.py")

        for _language_engine_path in _language_engine_candidates:
            try:
                if not _language_engine_path.exists():
                    continue

                _language_engine_spec = _language_engine_importlib_util.spec_from_file_location(
                    "language_engine",
                    str(_language_engine_path),
                )
                if _language_engine_spec is None or _language_engine_spec.loader is None:
                    continue

                _language_engine_module = _language_engine_importlib_util.module_from_spec(_language_engine_spec)
                _language_engine_sys.modules.setdefault("language_engine", _language_engine_module)
                _language_engine_spec.loader.exec_module(_language_engine_module)

                engine_language_engine = getattr(_language_engine_module, "language_engine", None)
                engine_language_engine_tool_schema = getattr(_language_engine_module, "language_engine_tool_schema", None)
                engine_make_language_engine_tool_function = getattr(_language_engine_module, "make_language_engine_tool_function", None)
                engine_register_language_engine_tool = getattr(_language_engine_module, "register_language_engine_tool", None)
                break
            except Exception:
                engine_language_engine = None
                engine_language_engine_tool_schema = None
                engine_make_language_engine_tool_function = None
                engine_register_language_engine_tool = None

    except Exception:
        engine_language_engine = None
        engine_language_engine_tool_schema = None
        engine_make_language_engine_tool_function = None
        engine_register_language_engine_tool = None


# ======================= Python Engine Import ==============================
# Put this near your other optional engine imports at the top of tools.py.
#
# The normal case is that python_engine.py sits beside tools.py. The fallback
# loader exists because PromptChat sometimes runs from a different CWD, so the
# engine needs a proper module path instead of relying only on sys.path.
try:
    from python_engine import (
        PythonEngineConfig as engine_PythonEngineConfig,
        python_engine as engine_python_engine,
        python_engine_tool_schema as engine_python_engine_tool_schema,
        make_python_engine_tool_function as engine_make_python_engine_tool_function,
        register_python_engine_tool as engine_register_python_engine_tool,
    )
except Exception:
    engine_PythonEngineConfig = None
    engine_python_engine = None
    engine_python_engine_tool_schema = None
    engine_make_python_engine_tool_function = None
    engine_register_python_engine_tool = None

    try:
        import importlib.util as _python_engine_importlib_util
        import sys as _python_engine_sys

        _python_engine_candidates: List[Path] = []
        try:
            _python_engine_candidates.append(Path(__file__).resolve().parent / "python_engine.py")
        except Exception:
            pass
        _python_engine_candidates.append(Path.cwd() / "python_engine.py")
        _python_engine_candidates.append(Path.home() / ".promptchat" / "python_engine.py")
        _python_engine_candidates.append(Path.home() / ".promptchat" / "engines" / "python_engine.py")

        for _python_engine_path in _python_engine_candidates:
            try:
                if not _python_engine_path.exists():
                    continue

                _python_engine_spec = _python_engine_importlib_util.spec_from_file_location(
                    "python_engine",
                    str(_python_engine_path),
                )
                if _python_engine_spec is None or _python_engine_spec.loader is None:
                    continue

                _python_engine_module = _python_engine_importlib_util.module_from_spec(_python_engine_spec)
                _python_engine_sys.modules.setdefault("python_engine", _python_engine_module)
                _python_engine_spec.loader.exec_module(_python_engine_module)

                engine_PythonEngineConfig = getattr(_python_engine_module, "PythonEngineConfig", None)
                engine_python_engine = getattr(_python_engine_module, "python_engine", None)
                engine_python_engine_tool_schema = getattr(_python_engine_module, "python_engine_tool_schema", None)
                engine_make_python_engine_tool_function = getattr(_python_engine_module, "make_python_engine_tool_function", None)
                engine_register_python_engine_tool = getattr(_python_engine_module, "register_python_engine_tool", None)
                break
            except Exception:
                engine_PythonEngineConfig = None
                engine_python_engine = None
                engine_python_engine_tool_schema = None
                engine_make_python_engine_tool_function = None
                engine_register_python_engine_tool = None

    except Exception:
        engine_PythonEngineConfig = None
        engine_python_engine = None
        engine_python_engine_tool_schema = None
        engine_make_python_engine_tool_function = None
        engine_register_python_engine_tool = None




# ======================= Coding Engine Import ===============================
# Put coding_engine.py beside tools.py. The engine is a local-first code
# generation support brain: it extracts code tokens, symbols, imports,
# signatures, snippets, syntax packs, and prompt packs without executing code.
try:
    from coding_engine import (
        coding_engine as engine_coding_engine,
        coding_engine_tool_schema as engine_coding_engine_tool_schema,
        make_coding_engine_tool_function as engine_make_coding_engine_tool_function,
        register_coding_engine_tool as engine_register_coding_engine_tool,
    )

    try:
        from coding_engine import CodingEngine as engine_CodingEngine
    except Exception:
        engine_CodingEngine = None

    try:
        from coding_engine import CodingEngineConfig as engine_CodingEngineConfig
    except Exception:
        engine_CodingEngineConfig = None

    try:
        from coding_engine import CODE_GENERATION_ACTIONS as engine_CODE_GENERATION_ACTIONS
    except Exception:
        engine_CODE_GENERATION_ACTIONS = None

except Exception:
    engine_coding_engine = None
    engine_coding_engine_tool_schema = None
    engine_make_coding_engine_tool_function = None
    engine_register_coding_engine_tool = None
    engine_CodingEngine = None
    engine_CodingEngineConfig = None
    engine_CODE_GENERATION_ACTIONS = None

    try:
        import importlib.util as _coding_engine_importlib_util
        import sys as _coding_engine_sys

        _coding_engine_candidates: List[Path] = []
        try:
            _coding_engine_candidates.append(Path(__file__).resolve().parent / "coding_engine.py")
        except Exception:
            pass
        _coding_engine_candidates.append(Path.cwd() / "coding_engine.py")
        _coding_engine_candidates.append(Path.home() / ".promptchat" / "coding_engine.py")
        _coding_engine_candidates.append(Path.home() / ".promptchat" / "engines" / "coding_engine.py")

        for _coding_engine_path in _coding_engine_candidates:
            try:
                if not _coding_engine_path.exists():
                    continue

                _coding_engine_spec = _coding_engine_importlib_util.spec_from_file_location(
                    "coding_engine",
                    str(_coding_engine_path),
                )
                if _coding_engine_spec is None or _coding_engine_spec.loader is None:
                    continue

                _coding_engine_module = _coding_engine_importlib_util.module_from_spec(_coding_engine_spec)
                _coding_engine_sys.modules.setdefault("coding_engine", _coding_engine_module)
                _coding_engine_spec.loader.exec_module(_coding_engine_module)

                engine_coding_engine = getattr(_coding_engine_module, "coding_engine", None)
                engine_coding_engine_tool_schema = getattr(_coding_engine_module, "coding_engine_tool_schema", None)
                engine_make_coding_engine_tool_function = getattr(_coding_engine_module, "make_coding_engine_tool_function", None)
                engine_register_coding_engine_tool = getattr(_coding_engine_module, "register_coding_engine_tool", None)
                engine_CodingEngine = getattr(_coding_engine_module, "CodingEngine", None)
                engine_CodingEngineConfig = getattr(_coding_engine_module, "CodingEngineConfig", None)
                engine_CODE_GENERATION_ACTIONS = getattr(_coding_engine_module, "CODE_GENERATION_ACTIONS", None)
                break
            except Exception:
                engine_coding_engine = None
                engine_coding_engine_tool_schema = None
                engine_make_coding_engine_tool_function = None
                engine_register_coding_engine_tool = None
                engine_CodingEngine = None
                engine_CodingEngineConfig = None
                engine_CODE_GENERATION_ACTIONS = None

    except Exception:
        engine_coding_engine = None
        engine_coding_engine_tool_schema = None
        engine_make_coding_engine_tool_function = None
        engine_register_coding_engine_tool = None
        engine_CodingEngine = None
        engine_CodingEngineConfig = None
        engine_CODE_GENERATION_ACTIONS = None

# ======================= Standalone APIDoc Engine Import ====================
# Put this near your other optional engine imports at the top of tools.py.
#
# Normal case:
#   standalone_apidoc_engine.py sits beside tools.py.
#
# Fallback paths exist because PromptChat sometimes runs from a different CWD.
try:
    from apidoc_engine import (
        apidoc_engine as engine_apidoc_engine,
        apidoc_engine_tool_schema as engine_apidoc_engine_tool_schema,
        make_apidoc_engine_tool_function as engine_make_apidoc_engine_tool_function,
        register_apidoc_engine_tool as engine_register_apidoc_engine_tool,
    )
except Exception:
    engine_apidoc_engine = None
    engine_apidoc_engine_tool_schema = None
    engine_make_apidoc_engine_tool_function = None
    engine_register_apidoc_engine_tool = None

    try:
        import importlib.util as _apidoc_engine_importlib_util
        import sys as _apidoc_engine_sys

        _apidoc_engine_candidates: List[Path] = []
        try:
            _apidoc_engine_candidates.append(Path(__file__).resolve().parent / "standalone_apidoc_engine.py")
        except Exception:
            pass

        _apidoc_engine_candidates.append(Path.cwd() / "standalone_apidoc_engine.py")
        _apidoc_engine_candidates.append(Path.home() / ".promptchat" / "standalone_apidoc_engine.py")
        _apidoc_engine_candidates.append(Path.home() / ".promptchat" / "engines" / "standalone_apidoc_engine.py")

        for _apidoc_engine_path in _apidoc_engine_candidates:
            try:
                if not _apidoc_engine_path.exists():
                    continue

                _apidoc_engine_spec = _apidoc_engine_importlib_util.spec_from_file_location(
                    "standalone_apidoc_engine",
                    str(_apidoc_engine_path),
                )
                if _apidoc_engine_spec is None or _apidoc_engine_spec.loader is None:
                    continue

                _apidoc_engine_module = _apidoc_engine_importlib_util.module_from_spec(_apidoc_engine_spec)
                _apidoc_engine_sys.modules.setdefault("standalone_apidoc_engine", _apidoc_engine_module)
                _apidoc_engine_spec.loader.exec_module(_apidoc_engine_module)

                engine_apidoc_engine = getattr(_apidoc_engine_module, "apidoc_engine", None)
                engine_apidoc_engine_tool_schema = getattr(_apidoc_engine_module, "apidoc_engine_tool_schema", None)
                engine_make_apidoc_engine_tool_function = getattr(_apidoc_engine_module, "make_apidoc_engine_tool_function", None)
                engine_register_apidoc_engine_tool = getattr(_apidoc_engine_module, "register_apidoc_engine_tool", None)
                break
            except Exception:
                engine_apidoc_engine = None
                engine_apidoc_engine_tool_schema = None
                engine_make_apidoc_engine_tool_function = None
                engine_register_apidoc_engine_tool = None

    except Exception:
        engine_apidoc_engine = None
        engine_apidoc_engine_tool_schema = None
        engine_make_apidoc_engine_tool_function = None
        engine_register_apidoc_engine_tool = None


# ======================= Tracker Engine Import ==============================
# GPTProject version:
# tracker_engine.py must be beside tools.py or otherwise importable on sys.path.
# No PromptChat fallback paths. No forced local loader. No renamed engine files.
try:
    from tracker_engine import (
        tracker_engine_tool as engine_tracker_engine_tool,
        tracker_engine_tool_schema as engine_tracker_engine_tool_schema,
        make_tracker_engine_tool_function as engine_make_tracker_engine_tool_function,
        register_tracker_engine_tool as engine_register_tracker_engine_tool,
    )

    try:
        from tracker_engine import TrackerEngine as engine_TrackerEngine
    except Exception:
        engine_TrackerEngine = None

    try:
        from tracker_engine import RealTrackerEngine as _engine_RealTrackerEngine
        if engine_TrackerEngine is None:
            engine_TrackerEngine = _engine_RealTrackerEngine
    except Exception:
        pass

    try:
        from tracker_engine import TrackerConfig as engine_TrackerConfig
    except Exception:
        engine_TrackerConfig = None

    try:
        from tracker_engine import TRACKER_ENGINE_TOOL_SPEC as engine_TRACKER_ENGINE_TOOL_SPEC
    except Exception:
        engine_TRACKER_ENGINE_TOOL_SPEC = None

except Exception:
    engine_tracker_engine_tool = None
    engine_tracker_engine_tool_schema = None
    engine_make_tracker_engine_tool_function = None
    engine_register_tracker_engine_tool = None
    engine_TrackerEngine = None
    engine_TrackerConfig = None
    engine_TRACKER_ENGINE_TOOL_SPEC = None


# ======================= Application Engine Import ==========================
# Put this near your other optional engine imports at the top of tools.py.
#
# Normal case:
#   application_engine.py sits beside tools.py.
#
# Fallback paths exist because PromptChat sometimes runs from a different CWD.
# The engine is consent-based: it lists windows/processes freely, but reading
# window/screen contents requires allow_all_local=true or an explicit allowed
# hwnd/pid/process name passed to the tool call.
try:
    import application_engine as _application_engine_module

    engine_ApplicationEngine = getattr(_application_engine_module, "ApplicationEngine", None)
    engine_ApplicationEngineBlock = getattr(_application_engine_module, "ApplicationEngineBlock", None)
    engine_APPLICATION_ENGINE_ACTIONS = getattr(_application_engine_module, "APPLICATION_ENGINE_ACTIONS", None)
except Exception:
    engine_ApplicationEngine = None
    engine_ApplicationEngineBlock = None
    engine_APPLICATION_ENGINE_ACTIONS = None

    try:
        import importlib.util as _application_engine_importlib_util
        import sys as _application_engine_sys

        _application_engine_candidates: List[Path] = []
        try:
            _application_engine_candidates.append(Path(__file__).resolve().parent / "application_engine.py")
        except Exception:
            pass

        _application_engine_candidates.append(Path.cwd() / "application_engine.py")
        _application_engine_candidates.append(Path.home() / ".promptchat" / "application_engine.py")
        _application_engine_candidates.append(Path.home() / ".promptchat" / "engines" / "application_engine.py")

        for _application_engine_path in _application_engine_candidates:
            try:
                if not _application_engine_path.exists():
                    continue

                _application_engine_spec = _application_engine_importlib_util.spec_from_file_location(
                    "application_engine",
                    str(_application_engine_path),
                )
                if _application_engine_spec is None or _application_engine_spec.loader is None:
                    continue

                _application_engine_module = _application_engine_importlib_util.module_from_spec(_application_engine_spec)
                _application_engine_sys.modules.setdefault("application_engine", _application_engine_module)
                _application_engine_spec.loader.exec_module(_application_engine_module)

                engine_ApplicationEngine = getattr(_application_engine_module, "ApplicationEngine", None)
                engine_ApplicationEngineBlock = getattr(_application_engine_module, "ApplicationEngineBlock", None)
                engine_APPLICATION_ENGINE_ACTIONS = getattr(_application_engine_module, "APPLICATION_ENGINE_ACTIONS", None)
                break
            except Exception:
                engine_ApplicationEngine = None
                engine_ApplicationEngineBlock = None
                engine_APPLICATION_ENGINE_ACTIONS = None

    except Exception:
        engine_ApplicationEngine = None
        engine_ApplicationEngineBlock = None
        engine_APPLICATION_ENGINE_ACTIONS = None


# ======================= Interactive Browser Engine Import ==================
# Put this near your other optional engine imports at the top of tools.py.
#
# Normal case:
#   interactive_browser_engine.py sits beside tools.py.
#
# This is a consent/handoff browser engine. It can open a visible Playwright
# browser for the user, optionally routed through Tor, then read the approved
# visible page after allow_read=true. It does not solve CAPTCHAs or return raw
# cookies/passwords/tokens.
try:
    import interactive_browser_engine as _interactive_browser_engine_module

    engine_interactive_tor = getattr(_interactive_browser_engine_module, "interactive_tor", None)
    engine_interactive_search = getattr(_interactive_browser_engine_module, "interactive_search", None)
    engine_interactive_browser_status = getattr(_interactive_browser_engine_module, "interactive_browser_status", None)
    engine_INTERACTIVE_BROWSER_ACTIONS = getattr(_interactive_browser_engine_module, "INTERACTIVE_BROWSER_ACTIONS", None)
except Exception:
    engine_interactive_tor = None
    engine_interactive_search = None
    engine_interactive_browser_status = None
    engine_INTERACTIVE_BROWSER_ACTIONS = None

    try:
        import importlib.util as _interactive_browser_importlib_util
        import sys as _interactive_browser_sys

        _interactive_browser_candidates: List[Path] = []
        try:
            _interactive_browser_candidates.append(Path(__file__).resolve().parent / "interactive_browser_engine.py")
        except Exception:
            pass

        _interactive_browser_candidates.append(Path.cwd() / "interactive_browser_engine.py")
        _interactive_browser_candidates.append(Path.home() / ".promptchat" / "interactive_browser_engine.py")
        _interactive_browser_candidates.append(Path.home() / ".promptchat" / "engines" / "interactive_browser_engine.py")

        for _interactive_browser_path in _interactive_browser_candidates:
            try:
                if not _interactive_browser_path.exists():
                    continue

                _interactive_browser_spec = _interactive_browser_importlib_util.spec_from_file_location(
                    "interactive_browser_engine",
                    str(_interactive_browser_path),
                )
                if _interactive_browser_spec is None or _interactive_browser_spec.loader is None:
                    continue

                _interactive_browser_module = _interactive_browser_importlib_util.module_from_spec(_interactive_browser_spec)
                _interactive_browser_sys.modules.setdefault("interactive_browser_engine", _interactive_browser_module)
                _interactive_browser_spec.loader.exec_module(_interactive_browser_module)

                engine_interactive_tor = getattr(_interactive_browser_module, "interactive_tor", None)
                engine_interactive_search = getattr(_interactive_browser_module, "interactive_search", None)
                engine_interactive_browser_status = getattr(_interactive_browser_module, "interactive_browser_status", None)
                engine_INTERACTIVE_BROWSER_ACTIONS = getattr(_interactive_browser_module, "INTERACTIVE_BROWSER_ACTIONS", None)
                break
            except Exception:
                engine_interactive_tor = None
                engine_interactive_search = None
                engine_interactive_browser_status = None
                engine_INTERACTIVE_BROWSER_ACTIONS = None

    except Exception:
        engine_interactive_tor = None
        engine_interactive_search = None
        engine_interactive_browser_status = None
        engine_INTERACTIVE_BROWSER_ACTIONS = None


DEFAULT_WEB_TIMEOUT_SEC = 20
DEFAULT_MAX_PAGE_CHARS = 12000
DEFAULT_TOR_SOCKS_URL = "socks5h://127.0.0.1:9150"


STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "but",
    "if",
    "to",
    "for",
    "of",
    "in",
    "on",
    "at",
    "by",
    "with",
    "from",
    "as",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "do",
    "does",
    "did",
    "how",
    "what",
    "when",
    "where",
    "why",
    "can",
    "could",
    "should",
    "would",
    "using",
    "use",
    "our",
    "us",
    "make",
    "try",
    "find",
    "look",
    "search",
    "browser",
    "tool",
    "tools",
    "latest",
    "new",
}


BAD_RESULT_DOMAINS = {
    "duckduckgo.com",
    "www.duckduckgo.com",
    "google.com",
    "www.google.com",
    "bing.com",
    "www.bing.com",
    "search.yahoo.com",
    "yahoo.com",
    "www.yahoo.com",
}


GOOD_BONUS_DOMAINS = {
    "docs.python-requests.org",
    "developer.mozilla.org",
    "docs.python.org",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "readthedocs.io",
    "pypi.org",
    "learn.microsoft.com",
    "ollama.com",
    "docs.ollama.com",
}


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: Dict[str, Any]
    fn: Callable[..., Any]

    def as_ollama_tool(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        self._tools[tool.name] = tool

    def names(self) -> List[str]:
        return sorted(self._tools.keys())

    def schemas(self) -> List[Dict[str, Any]]:
        return [tool.as_ollama_tool() for tool in self._tools.values()]

    def call(self, name: str, arguments: Any) -> str:
        if name not in self._tools:
            return json.dumps(
                {
                    "ok": False,
                    "error": f"Unknown tool: {name}",
                    "available_tools": self.names(),
                },
                ensure_ascii=False,
            )

        if isinstance(arguments, str):
            try:
                args = json.loads(arguments or "{}")
            except json.JSONDecodeError as exc:
                return json.dumps(
                    {"ok": False, "error": f"Invalid JSON tool arguments: {exc}"},
                    ensure_ascii=False,
                )
        elif isinstance(arguments, dict):
            args = arguments
        else:
            return json.dumps(
                {
                    "ok": False,
                    "error": "Tool arguments must be a JSON object or JSON string.",
                },
                ensure_ascii=False,
            )

        if not isinstance(args, dict):
            return json.dumps(
                {
                    "ok": False,
                    "error": "Tool arguments must decode to a JSON object.",
                },
                ensure_ascii=False,
            )

        try:
            result = self._tools[name].fn(**args)
            return json.dumps(result, ensure_ascii=False)
        except TypeError as exc:
            return json.dumps(
                {"ok": False, "error": f"Invalid tool arguments for {name}: {exc}"},
                ensure_ascii=False,
            )
        except Exception as exc:
            return json.dumps(
                {"ok": False, "error": f"Tool {name} failed: {exc}"},
                ensure_ascii=False,
            )


def get_time() -> Dict[str, str]:
    return {"ok": True, "unix_time": str(int(time.time()))}


def save_note(title: str, body: str) -> Dict[str, Any]:
    notes_dir = Path("data/notes")
    notes_dir.mkdir(parents=True, exist_ok=True)

    safe_title = "".join(c for c in title if c.isalnum() or c in (" ", "-", "_")).strip() or "note"
    note_path = notes_dir / f"{safe_title}.txt"
    note_path.write_text(body, encoding="utf-8")

    return {"ok": True, "saved_to": str(note_path)}


def list_notes() -> Dict[str, Any]:
    notes_dir = Path("data/notes")
    notes_dir.mkdir(parents=True, exist_ok=True)
    notes = sorted(p.name for p in notes_dir.glob("*.txt"))
    return {"ok": True, "notes": notes}


def read_note(title: str) -> Dict[str, Any]:
    notes_dir = Path("data/notes")
    note_path = notes_dir / f"{title}.txt"

    if not note_path.exists():
        return {"ok": False, "error": f"Note not found: {title}.txt"}

    return {
        "ok": True,
        "title": title,
        "content": note_path.read_text(encoding="utf-8"),
    }


def search_local_knowledge(
    query: str,
    limit: int = 5,
    per_file_limit: int = 2,
    excerpt_chars: int = 800,
) -> Dict[str, Any]:
    if SimpleFileRetrieval is None:
        return {
            "ok": False,
            "error": "SimpleFileRetrieval is not available. Check retrieval.py.",
        }

    retriever = SimpleFileRetrieval()
    results = retriever.search(
        query=query,
        limit=limit,
        per_file_limit=per_file_limit,
        excerpt_chars=excerpt_chars,
    )

    return {
        "ok": True,
        "query": query,
        "count": len(results),
        "results": results,
    }


def _normalize_url(url: str) -> str:
    raw = (url or "").strip()

    if not raw:
        raise ValueError("URL is required.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        first_part = raw.split("/", 1)[0].lower()
        if first_part.endswith(".onion"):
            raw = "http://" + raw
        else:
            raw = "https://" + raw

    parsed = urlparse(raw)

    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")

    return raw


def _make_session(
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: Optional[str] = None,
) -> tuple[requests.Session, int]:
    session = requests.Session()

    adapter = requests.adapters.HTTPAdapter(
        pool_connections=8,
        pool_maxsize=16,
        max_retries=0,
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36 GPTProject/1.0"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
    )

    if tor_socks_url:
        session.proxies = {
            "http": tor_socks_url,
            "https": tor_socks_url,
        }

    return session, int(timeout_sec)


def _clean_html_to_text(html_text: str) -> str:
    text = html_text or ""
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?is)<noscript.*?>.*?</noscript>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</div\s*>", "\n", text)
    text = re.sub(r"(?i)</li\s*>", "\n", text)
    text = re.sub(r"(?i)</tr\s*>", "\n", text)
    text = re.sub(r"(?i)</h[1-6]\s*>", "\n\n", text)
    text = re.sub(r"(?s)<.*?>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_title(html_text: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_text or "")
    if not match:
        return ""
    return _clean_html_to_text(match.group(1))[:300]


def _extract_meta_description(html_text: str) -> str:
    patterns = [
        r'(?is)<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
        r'(?is)<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']description["\']',
        r'(?is)<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']',
        r'(?is)<meta[^>]+content=["\'](.*?)["\'][^>]+property=["\']og:description["\']',
    ]

    for pattern in patterns:
        m = re.search(pattern, html_text or "")
        if m:
            return html.unescape(m.group(1)).strip()[:500]

    return ""


def _extract_links_from_html(
    base_url: str,
    html_text: str,
    max_links: int = 50,
) -> List[Dict[str, str]]:
    links: List[Dict[str, str]] = []
    seen: set[str] = set()

    for href, label in re.findall(
        r'(?is)<a\b[^>]*href=["\'](.*?)["\'][^>]*>(.*?)</a>',
        html_text or "",
    ):
        href = html.unescape(href).strip()

        if not href:
            continue

        lower_href = href.lower()

        if href.startswith("#") or lower_href.startswith("javascript:") or lower_href.startswith("mailto:"):
            continue

        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)

        if parsed.scheme not in {"http", "https"}:
            continue

        if absolute in seen:
            continue

        seen.add(absolute)

        links.append(
            {
                "url": absolute,
                "text": _clean_html_to_text(label)[:200],
                "domain": parsed.netloc,
            }
        )

        if len(links) >= max_links:
            break

    return links


def _request_failed_result(
    *,
    mode: str,
    url: str,
    error: Exception,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ok": False,
        "mode": mode,
        "url": url,
        "error": f"Request failed: {error}",
    }

    if tor_socks_url:
        result["tor_socks_url"] = tor_socks_url
        result["hint"] = (
            "Make sure Tor Browser or the Tor daemon is running, "
            "and that requests[socks] is installed."
        )

    return result



# ======================= Shared Sniffer Integration ========================
def _sniffer_available() -> bool:
    return SnifferConfig is not None and SnifferEngine is not None


def _sniffer_config(
    *,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    max_items: int = 250,
    verify_assets: bool = True,
    use_playwright: bool = False,
    include_junk: bool = False,
    keep_signed_query_values: bool = False,
) -> Any:
    if not _sniffer_available():
        return None

    cfg = SnifferConfig()
    cfg.timeout_sec = float(timeout_sec)
    cfg.max_page_chars = max(1000, int(max_chars or DEFAULT_MAX_PAGE_CHARS))
    cfg.max_text_chars = max(500, int(max_chars or DEFAULT_MAX_PAGE_CHARS))
    cfg.max_items = max(1, int(max_items or 250))
    cfg.verify_assets = bool(verify_assets)
    cfg.use_playwright = bool(use_playwright)
    cfg.include_junk = bool(include_junk)
    cfg.keep_signed_query_values = bool(keep_signed_query_values)
    return cfg


def _new_sniffer(
    *,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    max_items: int = 250,
    verify_assets: bool = True,
    use_playwright: bool = False,
    include_junk: bool = False,
    keep_signed_query_values: bool = False,
) -> Any:
    cfg = _sniffer_config(
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        max_items=max_items,
        verify_assets=verify_assets,
        use_playwright=use_playwright,
        include_junk=include_junk,
        keep_signed_query_values=keep_signed_query_values,
    )
    if cfg is None:
        return None
    return SnifferEngine(cfg)


def _run_sniffer_url(
    url: str,
    *,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    max_items: int = 250,
    include_html: bool = False,
    tor_socks_url: Optional[str] = None,
    use_playwright: bool = False,
    verify_assets: bool = True,
    include_junk: bool = False,
    keep_signed_query_values: bool = False,
) -> Dict[str, Any]:
    engine = _new_sniffer(
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        max_items=max_items,
        verify_assets=verify_assets,
        use_playwright=use_playwright,
        include_junk=include_junk,
        keep_signed_query_values=keep_signed_query_values,
    )
    if engine is None:
        return {
            "ok": False,
            "sniffer_available": False,
            "error": "sniffer_engine.py is not importable. Put sniffer_engine.py beside tools.py.",
        }

    try:
        result = engine.sniff_url(
            url,
            timeout_sec=timeout_sec,
            max_items=max_items,
            include_html=include_html,
            tor_socks_url=tor_socks_url,
            use_playwright=use_playwright,
        )
        return result.as_dict(include_html=include_html)
    except Exception as exc:
        return {
            "ok": False,
            "sniffer_available": True,
            "url": url,
            "error": str(exc),
        }


def _run_sniffer_text(
    text: str,
    *,
    base_url: str = "",
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    max_items: int = 250,
    include_html: bool = False,
    include_junk: bool = False,
) -> Dict[str, Any]:
    engine = _new_sniffer(
        timeout_sec=DEFAULT_WEB_TIMEOUT_SEC,
        max_chars=max_chars,
        max_items=max_items,
        verify_assets=False,
        use_playwright=False,
        include_junk=include_junk,
    )
    if engine is None:
        return {
            "ok": False,
            "sniffer_available": False,
            "error": "sniffer_engine.py is not importable. Put sniffer_engine.py beside tools.py.",
        }

    try:
        result = engine.sniff_text(text or "", base_url=base_url or "", include_html=include_html)
        return result.as_dict(include_html=include_html)
    except Exception as exc:
        return {
            "ok": False,
            "sniffer_available": True,
            "url": base_url or "",
            "error": str(exc),
        }


def _compact_sniffer_payload(data: Dict[str, Any], *, include_text: bool = False) -> Dict[str, Any]:
    if not data:
        return {
            "sniffer": {"ok": False, "sniffer_available": _sniffer_available()},
            "assets": {},
        }

    compact: Dict[str, Any] = {
        "sniffer": {
            "ok": bool(data.get("ok")),
            "sniffer_available": _sniffer_available(),
            "mode": data.get("mode", ""),
            "elapsed_ms": data.get("elapsed_ms", 0),
            "error": data.get("error", ""),
            "errors": data.get("errors", []),
        },
        "assets": {
            "count": int(data.get("count", 0) or 0),
            "links_count": int(data.get("links_count", 0) or 0),
            "images_count": int(data.get("images_count", 0) or 0),
            "videos_count": int(data.get("videos_count", 0) or 0),
            "audio_count": int(data.get("audio_count", 0) or 0),
            "documents_count": int(data.get("documents_count", 0) or 0),
            "links": data.get("links", []),
            "images": data.get("images", []),
            "videos": data.get("videos", []),
            "audio": data.get("audio", []),
            "documents": data.get("documents", []),
            "json_hits": data.get("json_hits", []),
        },
    }
    if include_text:
        compact["sniffed_text"] = data.get("text", "")
    return compact


def _merge_sniffed_links(
    existing_links: List[Dict[str, str]],
    sniffed: Dict[str, Any],
    *,
    max_links: int,
) -> List[Dict[str, str]]:
    merged: List[Dict[str, str]] = []
    seen: set[str] = set()

    def add(url: str, text: str = "", domain: str = "", kind: str = "link") -> None:
        clean = (url or "").strip()
        if not clean or clean in seen:
            return
        seen.add(clean)
        row: Dict[str, str] = {
            "url": clean,
            "text": (text or "")[:200],
            "domain": domain or urlparse(clean).netloc,
        }
        if kind and kind != "link":
            row["kind"] = kind
        merged.append(row)

    for row in existing_links or []:
        add(row.get("url", ""), row.get("text", ""), row.get("domain", ""), row.get("kind", "link"))

    for bucket in ("links", "images", "videos", "audio", "documents"):
        for item in (sniffed.get(bucket) or []):
            add(
                item.get("url", ""),
                item.get("text", "") or item.get("tag", "") or item.get("evidence", ""),
                urlparse(item.get("url", "")).netloc,
                item.get("kind", "link"),
            )
            if len(merged) >= max_links:
                return merged[:max_links]

    return merged[:max_links]


def sniff_url(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_items: int = 250,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    include_html: bool = False,
    tor_socks_url: Optional[str] = None,
    use_playwright: bool = False,
    verify_assets: bool = True,
) -> Dict[str, Any]:
    return _run_sniffer_url(
        url,
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        max_items=max_items,
        include_html=include_html,
        tor_socks_url=tor_socks_url,
        use_playwright=use_playwright,
        verify_assets=verify_assets,
    )


def sniff_text_assets(
    text: str,
    base_url: str = "",
    max_items: int = 250,
    include_html: bool = False,
) -> Dict[str, Any]:
    return _run_sniffer_text(
        text,
        base_url=base_url,
        max_items=max_items,
        include_html=include_html,
    )


def sniff_media(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_items: int = 250,
    tor_socks_url: Optional[str] = None,
    use_playwright: bool = False,
) -> Dict[str, Any]:
    data = _run_sniffer_url(
        url,
        timeout_sec=timeout_sec,
        max_items=max_items,
        tor_socks_url=tor_socks_url,
        use_playwright=use_playwright,
        verify_assets=True,
    )
    media = []
    media.extend(data.get("videos", []) or [])
    media.extend(data.get("audio", []) or [])
    return {
        "ok": bool(data.get("ok")),
        "url": data.get("url", url),
        "final_url": data.get("final_url", ""),
        "count": len(media),
        "media": media[:max_items],
        "videos": data.get("videos", []),
        "audio": data.get("audio", []),
        "json_hits": data.get("json_hits", []),
        "errors": data.get("errors", []),
        "sniffer_available": _sniffer_available(),
    }


def sniff_images(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_items: int = 250,
    tor_socks_url: Optional[str] = None,
    use_playwright: bool = False,
) -> Dict[str, Any]:
    data = _run_sniffer_url(
        url,
        timeout_sec=timeout_sec,
        max_items=max_items,
        tor_socks_url=tor_socks_url,
        use_playwright=use_playwright,
        verify_assets=True,
    )
    images = (data.get("images") or [])[:max_items]
    return {
        "ok": bool(data.get("ok")),
        "url": data.get("url", url),
        "final_url": data.get("final_url", ""),
        "count": len(images),
        "images": images,
        "json_hits": data.get("json_hits", []),
        "errors": data.get("errors", []),
        "sniffer_available": _sniffer_available(),
    }


def sniff_videos(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_items: int = 250,
    tor_socks_url: Optional[str] = None,
    use_playwright: bool = True,
) -> Dict[str, Any]:
    data = _run_sniffer_url(
        url,
        timeout_sec=timeout_sec,
        max_items=max_items,
        tor_socks_url=tor_socks_url,
        use_playwright=use_playwright,
        verify_assets=True,
    )
    videos = (data.get("videos") or [])[:max_items]
    return {
        "ok": bool(data.get("ok")),
        "url": data.get("url", url),
        "final_url": data.get("final_url", ""),
        "count": len(videos),
        "videos": videos,
        "audio": data.get("audio", []),
        "json_hits": data.get("json_hits", []),
        "errors": data.get("errors", []),
        "sniffer_available": _sniffer_available(),
    }


def search_and_sniff(
    query: str,
    max_results: int = 5,
    sniff_top_n: int = 3,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    search_result = search_web(
        query=query,
        max_results=max_results,
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url,
    )
    if not search_result.get("ok"):
        return search_result

    pages: List[Dict[str, Any]] = []
    for row in (search_result.get("results") or [])[: max(0, int(sniff_top_n or 0))]:
        page_url = row.get("url", "")
        if not page_url:
            continue
        sniffed = _run_sniffer_url(
            page_url,
            timeout_sec=timeout_sec,
            max_items=120,
            max_chars=DEFAULT_MAX_PAGE_CHARS,
            tor_socks_url=tor_socks_url,
            use_playwright=False,
            verify_assets=True,
        )
        pages.append({
            "search_result": row,
            "sniff": _compact_sniffer_payload(sniffed, include_text=False),
        })

    out = dict(search_result)
    out["sniffed_pages"] = pages
    out["sniffed_pages_count"] = len(pages)
    return out


# ======================= Shared Forensic Integration =======================
def _forensic_available() -> bool:
    return ForensicConfig is not None and ForensicEngine is not None


def _forensic_config(
    *,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_body_bytes: int = 2_000_000,
    max_text_chars: int = 200_000,
    max_evidence_items: int = 2_000,
    max_links_per_page: int = 500,
    max_archive_results: int = 50,
    max_sitemap_urls: int = 1_000,
    max_depth: int = 1,
    max_pages: int = 25,
    rate_limit_delay_sec: float = 0.2,
    respect_robots: bool = True,
    include_archive_search: bool = True,
    include_commoncrawl_search: bool = True,
    include_wayback_search: bool = True,
    include_dns: bool = True,
    include_tls: bool = True,
    include_sitemaps: bool = True,
    include_feeds: bool = True,
    include_oembed: bool = True,
    include_url_variants: bool = True,
    include_head_probe: bool = True,
    include_range_probe: bool = True,
    include_binary_magic: bool = True,
    allow_cross_host_crawl: bool = False,
    keep_original_url: bool = False,
    keep_secret_query_values: bool = False,
    sqlite_path: str = "",
    artifact_dir: str = "data/forensics/artifacts",
) -> Any:
    if not _forensic_available():
        return None

    cfg = ForensicConfig()
    cfg.timeout_sec = float(timeout_sec or DEFAULT_WEB_TIMEOUT_SEC)
    cfg.max_body_bytes = max(1024, int(max_body_bytes or 2_000_000))
    cfg.max_text_chars = max(500, int(max_text_chars or 200_000))
    cfg.max_evidence_items = max(1, int(max_evidence_items or 2_000))
    cfg.max_links_per_page = max(1, int(max_links_per_page or 500))
    cfg.max_archive_results = max(0, int(max_archive_results or 0))
    cfg.max_sitemap_urls = max(0, int(max_sitemap_urls or 0))
    cfg.max_depth = max(0, int(max_depth or 0))
    cfg.max_pages = max(1, int(max_pages or 1))
    cfg.rate_limit_delay_sec = max(0.0, float(rate_limit_delay_sec or 0.0))
    cfg.respect_robots = bool(respect_robots)
    cfg.include_archive_search = bool(include_archive_search)
    cfg.include_commoncrawl_search = bool(include_commoncrawl_search)
    cfg.include_wayback_search = bool(include_wayback_search)
    cfg.include_dns = bool(include_dns)
    cfg.include_tls = bool(include_tls)
    cfg.include_sitemaps = bool(include_sitemaps)
    cfg.include_feeds = bool(include_feeds)
    cfg.include_oembed = bool(include_oembed)
    cfg.include_url_variants = bool(include_url_variants)
    cfg.include_head_probe = bool(include_head_probe)
    cfg.include_range_probe = bool(include_range_probe)
    cfg.include_binary_magic = bool(include_binary_magic)
    cfg.allow_cross_host_crawl = bool(allow_cross_host_crawl)
    cfg.keep_original_url = bool(keep_original_url)
    cfg.keep_secret_query_values = bool(keep_secret_query_values)
    cfg.sqlite_path = sqlite_path or ""
    cfg.artifact_dir = artifact_dir or "data/forensics/artifacts"
    return cfg


def _new_forensic_engine(**kwargs: Any) -> Any:
    cfg = _forensic_config(**kwargs)
    if cfg is None:
        return None
    return ForensicEngine(cfg)


def _forensic_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "forensic_available": False,
        "error": "forensic_engine.py is not importable. Put forensic_engine.py beside tools.py.",
    }


def _compact_forensic_report(data: Dict[str, Any], *, max_evidence: int = 80) -> Dict[str, Any]:
    evidence = data.get("evidence", []) or []
    evidence_types: Dict[str, int] = {}
    collectors: Dict[str, int] = {}
    for item in evidence:
        et = str(item.get("evidence_type", "unknown"))
        co = str(item.get("collector", "unknown"))
        evidence_types[et] = evidence_types.get(et, 0) + 1
        collectors[co] = collectors.get(co, 0) + 1

    compact = dict(data)
    compact["forensic_available"] = _forensic_available()
    compact["evidence_type_counts"] = evidence_types
    compact["collector_counts"] = collectors
    if max_evidence >= 0 and len(evidence) > max_evidence:
        compact["evidence"] = evidence[:max_evidence]
        compact["evidence_truncated"] = True
        compact["evidence_returned"] = max_evidence
    else:
        compact["evidence_truncated"] = False
        compact["evidence_returned"] = len(evidence)
    return compact


def forensic_investigate_url(
    url: str,
    include_archives: bool = True,
    depth: int = 1,
    max_pages: int = 25,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_body_bytes: int = 2_000_000,
    max_evidence_items: int = 2_000,
    max_evidence_returned: int = 120,
    sqlite_path: str = "",
    artifact_dir: str = "data/forensics/artifacts",
    respect_robots: bool = True,
    allow_cross_host_crawl: bool = False,
    include_commoncrawl_search: bool = True,
    include_wayback_search: bool = True,
    include_dns: bool = True,
    include_tls: bool = True,
    include_sitemaps: bool = True,
    include_feeds: bool = True,
    include_url_variants: bool = True,
    include_head_probe: bool = True,
    include_range_probe: bool = True,
) -> Dict[str, Any]:
    """
    Run a public/authorized URL forensic investigation.

    This is intentionally passive/respectful by default: it honors robots.txt,
    redacts secret query values, rate-limits requests, and does not bypass logins,
    paywalls, or access controls.
    """
    engine = _new_forensic_engine(
        timeout_sec=timeout_sec,
        max_body_bytes=max_body_bytes,
        max_evidence_items=max_evidence_items,
        max_depth=depth,
        max_pages=max_pages,
        respect_robots=respect_robots,
        include_archive_search=include_archives,
        include_commoncrawl_search=include_commoncrawl_search,
        include_wayback_search=include_wayback_search,
        include_dns=include_dns,
        include_tls=include_tls,
        include_sitemaps=include_sitemaps,
        include_feeds=include_feeds,
        include_url_variants=include_url_variants,
        include_head_probe=include_head_probe,
        include_range_probe=include_range_probe,
        allow_cross_host_crawl=allow_cross_host_crawl,
        keep_original_url=False,
        keep_secret_query_values=False,
        sqlite_path=sqlite_path,
        artifact_dir=artifact_dir,
    )
    if engine is None:
        return _forensic_unavailable_result()

    try:
        report = engine.investigate_url(
            url,
            include_archives=include_archives,
            depth=depth,
            max_pages=max_pages,
        )
        return _compact_forensic_report(report.to_dict(), max_evidence=max_evidence_returned)
    except Exception as exc:
        return {
            "ok": False,
            "forensic_available": True,
            "target": url,
            "error": str(exc),
        }
    finally:
        try:
            engine.close()
        except Exception:
            pass


def forensic_analyze_file(
    path: str,
    max_body_bytes: int = 20_000_000,
    max_evidence_returned: int = 120,
    sqlite_path: str = "",
    artifact_dir: str = "data/forensics/artifacts",
) -> Dict[str, Any]:
    """Analyze a local file for hashes, type, metadata, and embedded URL evidence."""
    engine = _new_forensic_engine(
        max_body_bytes=max_body_bytes,
        sqlite_path=sqlite_path,
        artifact_dir=artifact_dir,
        keep_original_url=True,
    )
    if engine is None:
        return _forensic_unavailable_result()

    try:
        report = engine.analyze_file(path)
        return _compact_forensic_report(report.to_dict(), max_evidence=max_evidence_returned)
    except Exception as exc:
        return {
            "ok": False,
            "forensic_available": True,
            "target": path,
            "error": str(exc),
        }
    finally:
        try:
            engine.close()
        except Exception:
            pass


def forensic_extract_urls(
    text: str,
    base_url: str = "",
    max_urls: int = 500,
) -> Dict[str, Any]:
    """Extract and classify URLs from pasted text/HTML/JSON/code without fetching them."""
    if forensic_extract_urls_from_text is None:
        return _forensic_unavailable_result()

    try:
        urls = forensic_extract_urls_from_text(text or "", base_url=base_url or "")
        rows: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for u in urls:
            if not u or u in seen:
                continue
            seen.add(u)
            kind = forensic_classify_url_value(u) if forensic_classify_url_value else "unknown"
            rows.append({
                "url": u,
                "domain": urlparse(u).netloc,
                "kind": kind,
            })
            if len(rows) >= max(1, int(max_urls or 1)):
                break
        return {
            "ok": True,
            "forensic_available": _forensic_available(),
            "base_url": base_url or "",
            "count": len(rows),
            "urls": rows,
        }
    except Exception as exc:
        return {
            "ok": False,
            "forensic_available": _forensic_available(),
            "error": str(exc),
        }


def forensic_url_variants(
    url: str,
    max_variants: int = 100,
) -> Dict[str, Any]:
    """Generate safe URL variants useful for locating public cached/lost copies."""
    if forensic_generate_url_variants is None:
        return _forensic_unavailable_result()

    try:
        variants = forensic_generate_url_variants(url or "")[: max(1, int(max_variants or 1))]
        return {
            "ok": True,
            "forensic_available": _forensic_available(),
            "url": url,
            "count": len(variants),
            "variants": variants,
        }
    except Exception as exc:
        return {
            "ok": False,
            "forensic_available": _forensic_available(),
            "url": url,
            "error": str(exc),
        }


def forensic_domain_context(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    include_dns: bool = True,
    include_tls: bool = True,
    include_head_probe: bool = True,
    include_range_probe: bool = False,
    sqlite_path: str = "",
) -> Dict[str, Any]:
    """Collect compact DNS/TLS/header context for a URL without crawling linked pages."""
    engine = _new_forensic_engine(
        timeout_sec=timeout_sec,
        max_depth=0,
        max_pages=1,
        include_archive_search=False,
        include_commoncrawl_search=False,
        include_wayback_search=False,
        include_dns=include_dns,
        include_tls=include_tls,
        include_sitemaps=False,
        include_feeds=False,
        include_oembed=False,
        include_url_variants=False,
        include_head_probe=include_head_probe,
        include_range_probe=include_range_probe,
        sqlite_path=sqlite_path,
    )
    if engine is None:
        return _forensic_unavailable_result()

    try:
        report = engine.investigate_url(url, include_archives=False, depth=0, max_pages=1)
        return _compact_forensic_report(report.to_dict(), max_evidence=120)
    except Exception as exc:
        return {
            "ok": False,
            "forensic_available": True,
            "target": url,
            "error": str(exc),
        }
    finally:
        try:
            engine.close()
        except Exception:
            pass


def forensic_search_archives(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_archive_results: int = 50,
    include_commoncrawl_search: bool = True,
    include_wayback_search: bool = True,
    sqlite_path: str = "",
) -> Dict[str, Any]:
    """Search public archive indexes for historical/lost copies of a URL."""
    engine = _new_forensic_engine(
        timeout_sec=timeout_sec,
        max_depth=0,
        max_pages=1,
        max_archive_results=max_archive_results,
        include_archive_search=True,
        include_commoncrawl_search=include_commoncrawl_search,
        include_wayback_search=include_wayback_search,
        include_dns=False,
        include_tls=False,
        include_sitemaps=False,
        include_feeds=False,
        include_oembed=False,
        include_url_variants=True,
        include_head_probe=False,
        include_range_probe=False,
        sqlite_path=sqlite_path,
    )
    if engine is None:
        return _forensic_unavailable_result()

    try:
        report = engine.investigate_url(url, include_archives=True, depth=0, max_pages=1)
        data = report.to_dict()
        evidence = [
            item for item in (data.get("evidence") or [])
            if str(item.get("evidence_type", "")).startswith("archive")
            or item.get("collector") in {"wayback_cdx", "commoncrawl_index", "url_variants"}
        ]
        data["evidence"] = evidence
        data["evidence_count"] = len(evidence)
        return _compact_forensic_report(data, max_evidence=max_archive_results)
    except Exception as exc:
        return {
            "ok": False,
            "forensic_available": True,
            "target": url,
            "error": str(exc),
        }
    finally:
        try:
            engine.close()
        except Exception:
            pass


# ======================= Shared CDN Integration ============================
def _cdn_available() -> bool:
    return CDNConfig is not None and CDNEngine is not None


def _cdn_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "cdn_available": False,
        "error": "cdn_engine.py is not importable. Put cdn_engine.py beside tools.py.",
    }


def _compact_cdn_report(data: Dict[str, Any], *, max_items_returned: int = 160) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {"ok": False, "cdn_available": _cdn_available(), "error": "CDN engine returned a non-dict result."}

    items = data.get("items", []) or []
    candidates = data.get("candidates", []) or []
    domains = data.get("domains", []) or data.get("domain_contexts", []) or []

    kind_counts: Dict[str, int] = {}
    source_counts: Dict[str, int] = {}
    provider_counts: Dict[str, int] = {}

    for item in items:
        kind = str(item.get("kind", "unknown"))
        source = str(item.get("source", "unknown"))
        provider = str(item.get("cdn_provider", "") or item.get("provider", "") or "")
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        source_counts[source] = source_counts.get(source, 0) + 1
        if provider:
            provider_counts[provider] = provider_counts.get(provider, 0) + 1

    compact = dict(data)
    compact["cdn_available"] = _cdn_available()
    compact["kind_counts"] = kind_counts
    compact["source_counts"] = source_counts
    compact["provider_counts"] = provider_counts

    limit = max(1, int(max_items_returned or 1))
    if len(items) > limit:
        compact["items"] = items[:limit]
        compact["items_truncated"] = True
        compact["items_returned"] = limit
    else:
        compact["items_truncated"] = False
        compact["items_returned"] = len(items)

    if len(candidates) > limit:
        compact["candidates"] = candidates[:limit]
        compact["candidates_truncated"] = True
        compact["candidates_returned"] = limit
    else:
        compact["candidates_truncated"] = False
        compact["candidates_returned"] = len(candidates)

    if isinstance(domains, list) and len(domains) > 80:
        key = "domains" if "domains" in compact else "domain_contexts"
        compact[key] = domains[:80]
        compact["domain_contexts_truncated"] = True
    else:
        compact["domain_contexts_truncated"] = False

    return compact


def cdn_investigate_url(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_depth: int = 1,
    max_pages: int = 25,
    max_items: int = 800,
    max_items_returned: int = 160,
    include_archives: bool = False,
    probe_candidates: bool = True,
    sqlite_path: str = "",
) -> Dict[str, Any]:
    """
    Investigate a public/authorized page for CDN-hosted assets, hidden-ish
    linked assets, JS chunks, source maps, manifests, cache headers, and
    conservative URL variants. Does not bypass auth, signed URL protections,
    private buckets, ACLs, or rate limits.
    """
    if cdn_engine_investigate_url is None:
        return _cdn_unavailable_result()

    try:
        data = cdn_engine_investigate_url(
            url,
            timeout_sec=float(timeout_sec or DEFAULT_WEB_TIMEOUT_SEC),
            max_depth=max(0, int(max_depth or 0)),
            max_pages=max(1, int(max_pages or 1)),
            max_items=max(1, int(max_items or 1)),
            include_archives=bool(include_archives),
            probe_candidates=bool(probe_candidates),
            sqlite_path=sqlite_path or "",
        )
        return _compact_cdn_report(data, max_items_returned=max_items_returned)
    except Exception as exc:
        return {
            "ok": False,
            "cdn_available": _cdn_available(),
            "target": url,
            "error": str(exc),
        }


def cdn_analyze_asset(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    probe_candidates: bool = True,
    max_items_returned: int = 160,
) -> Dict[str, Any]:
    """Analyze a single public/authorized CDN asset URL and extract linked/chunk/map/manifest clues."""
    if cdn_engine_analyze_asset is None:
        return _cdn_unavailable_result()

    try:
        data = cdn_engine_analyze_asset(
            url,
            timeout_sec=float(timeout_sec or DEFAULT_WEB_TIMEOUT_SEC),
            probe_candidates=bool(probe_candidates),
        )
        return _compact_cdn_report(data, max_items_returned=max_items_returned)
    except Exception as exc:
        return {
            "ok": False,
            "cdn_available": _cdn_available(),
            "target": url,
            "error": str(exc),
        }


def cdn_extract_from_text(
    text: str,
    base_url: str = "",
    max_items: int = 800,
    max_items_returned: int = 160,
) -> Dict[str, Any]:
    """Extract CDN-style links, chunks, source maps, manifests, and asset URLs from pasted text/code/HTML."""
    if cdn_engine_extract_from_text is None:
        return _cdn_unavailable_result()

    try:
        data = cdn_engine_extract_from_text(
            text or "",
            base_url=base_url or "",
            max_items=max(1, int(max_items or 1)),
        )
        return _compact_cdn_report(data, max_items_returned=max_items_returned)
    except Exception as exc:
        return {
            "ok": False,
            "cdn_available": _cdn_available(),
            "error": str(exc),
        }


def cdn_url_variants(
    url: str,
    max_variants: int = 120,
) -> Dict[str, Any]:
    """Generate conservative URL variants for public CDN/cache/lost-asset discovery."""
    if cdn_engine_url_variants is None:
        return _cdn_unavailable_result()

    try:
        data = cdn_engine_url_variants(
            url,
            max_variants=max(1, int(max_variants or 1)),
        )
        if isinstance(data, dict):
            data["cdn_available"] = _cdn_available()
        return data
    except Exception as exc:
        return {
            "ok": False,
            "cdn_available": _cdn_available(),
            "url": url,
            "error": str(exc),
        }


def cdn_domain_context(
    host_or_url: str,
    timeout_sec: int = 10,
) -> Dict[str, Any]:
    """Collect CDN provider, DNS, TLS, and edge/cache context for a host or URL."""
    if cdn_engine_domain_context is None:
        return _cdn_unavailable_result()

    try:
        data = cdn_engine_domain_context(
            host_or_url,
            timeout_sec=float(timeout_sec or 10),
        )
        if isinstance(data, dict):
            data["cdn_available"] = _cdn_available()
        return data
    except Exception as exc:
        return {
            "ok": False,
            "cdn_available": _cdn_available(),
            "target": host_or_url,
            "error": str(exc),
        }


# ======================= Shared Engines.py Integration ======================
def _engines_available() -> bool:
    return engine_engines_status is not None

def _engines_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "engines_available": False,
        "error": "engines.py is not importable. Put engines.py beside tools.py.",
    }

def _call_engine_tool(fn: Any, tool_name: str, **kwargs: Any) -> Dict[str, Any]:
    if fn is None:
        result = _engines_unavailable_result()
        result["tool"] = tool_name
        return result
    try:
        data = fn(**kwargs)
        if isinstance(data, dict):
            data = dict(data)
            data.setdefault("ok", True)
            data["engines_available"] = _engines_available()
            data["tool"] = tool_name
            return data
        return {"ok": True, "engines_available": _engines_available(), "tool": tool_name, "result": data}
    except Exception as exc:
        return {"ok": False, "engines_available": _engines_available(), "tool": tool_name, "error": str(exc)}

def archive_search_url(url: 'str', max_results: 'int' = 80, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_archive_search_url, "archive_search_url", url=url, max_results=max_results, timeout_sec=timeout_sec)

def archive_search_domain(domain: 'str', max_results: 'int' = 80, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_archive_search_domain, "archive_search_domain", domain=domain, max_results=max_results, timeout_sec=timeout_sec)

def archive_fetch_wayback_snapshot(url: 'str', timestamp: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_archive_fetch_wayback_snapshot, "archive_fetch_wayback_snapshot", url=url, timestamp=timestamp, timeout_sec=timeout_sec)

def archive_compare_snapshots(left_url: 'str', right_url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_archive_compare_snapshots, "archive_compare_snapshots", left_url=left_url, right_url=right_url, timeout_sec=timeout_sec)

def archive_extract_lost_links(current_url: 'str', max_snapshots: 'int' = 5, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_archive_extract_lost_links, "archive_extract_lost_links", current_url=current_url, max_snapshots=max_snapshots, timeout_sec=timeout_sec)

def archive_timeline_report(url: 'str', max_results: 'int' = 80, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_archive_timeline_report, "archive_timeline_report", url=url, max_results=max_results, timeout_sec=timeout_sec)

def sourcemap_find(url: 'str', include_guesses: 'bool' = True, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_sourcemap_find, "sourcemap_find", url=url, include_guesses=include_guesses, timeout_sec=timeout_sec)

def sourcemap_fetch(url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_sourcemap_fetch, "sourcemap_fetch", url=url, timeout_sec=timeout_sec)

def sourcemap_extract_sources(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_sourcemap_extract_sources, "sourcemap_extract_sources", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def sourcemap_extract_urls(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_sourcemap_extract_urls, "sourcemap_extract_urls", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def sourcemap_reconstruct_tree(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_sourcemap_reconstruct_tree, "sourcemap_reconstruct_tree", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def sourcemap_secret_redacted_scan(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_sourcemap_secret_redacted_scan, "sourcemap_secret_redacted_scan", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def metadata_url(url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_metadata_url, "metadata_url", url=url, timeout_sec=timeout_sec)

def metadata_file(path: 'str') -> 'Dict[str, Any]':
    return _call_engine_tool(engine_metadata_file, "metadata_file", path=path)

def metadata_image(path_or_url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_metadata_image, "metadata_image", path_or_url=path_or_url, timeout_sec=timeout_sec)

def metadata_video(path_or_url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_metadata_video, "metadata_video", path_or_url=path_or_url, timeout_sec=timeout_sec)

def metadata_pdf(path_or_url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_metadata_pdf, "metadata_pdf", path_or_url=path_or_url, timeout_sec=timeout_sec)

def metadata_compare(left: 'str', right: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_metadata_compare, "metadata_compare", left=left, right=right, timeout_sec=timeout_sec)

def metadata_redacted_report(target: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_metadata_redacted_report, "metadata_redacted_report", target=target, timeout_sec=timeout_sec)

def osint_domain(domain: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_osint_domain, "osint_domain", domain=domain, timeout_sec=timeout_sec)

def osint_ip(ip: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_osint_ip, "osint_ip", ip=ip, timeout_sec=timeout_sec)

def osint_certificates(domain: 'str', max_results: 'int' = 100, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_osint_certificates, "osint_certificates", domain=domain, max_results=max_results, timeout_sec=timeout_sec)

def osint_dns_history(domain: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_osint_dns_history, "osint_dns_history", domain=domain, timeout_sec=timeout_sec)

def osint_public_mentions(query: 'str', max_results: 'int' = 20, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_osint_public_mentions, "osint_public_mentions", query=query, max_results=max_results, timeout_sec=timeout_sec)

def osint_related_domains(domain: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_osint_related_domains, "osint_related_domains", domain=domain, timeout_sec=timeout_sec)

def manifest_find(url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_manifest_find, "manifest_find", url=url, timeout_sec=timeout_sec)

def manifest_parse_webapp(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_manifest_parse_webapp, "manifest_parse_webapp", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def manifest_parse_hls(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_manifest_parse_hls, "manifest_parse_hls", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def manifest_parse_dash(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_manifest_parse_dash, "manifest_parse_dash", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def manifest_parse_rss(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_manifest_parse_rss, "manifest_parse_rss", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def manifest_parse_atom(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_manifest_parse_atom, "manifest_parse_atom", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def manifest_extract_assets(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_manifest_extract_assets, "manifest_extract_assets", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def route_extract_from_html(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_route_extract_from_html, "route_extract_from_html", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def route_extract_from_js(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_route_extract_from_js, "route_extract_from_js", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def route_extract_nextjs(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_route_extract_nextjs, "route_extract_nextjs", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def route_extract_nuxt(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_route_extract_nuxt, "route_extract_nuxt", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def route_extract_vite(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_route_extract_vite, "route_extract_vite", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def route_extract_react_router(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_route_extract_react_router, "route_extract_react_router", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def route_probe_public_routes(base_url: 'str', routes: 'Sequence[str]', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_route_probe_public_routes, "route_probe_public_routes", base_url=base_url, routes=routes, timeout_sec=timeout_sec)

def media_find(url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_media_find, "media_find", url=url, timeout_sec=timeout_sec)

def media_extract_hls(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_media_extract_hls, "media_extract_hls", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def media_extract_dash(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_media_extract_dash, "media_extract_dash", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def media_extract_subtitles(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_media_extract_subtitles, "media_extract_subtitles", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def media_extract_thumbnails(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_media_extract_thumbnails, "media_extract_thumbnails", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def media_probe_dimensions(url: 'str', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_media_probe_dimensions, "media_probe_dimensions", url=url, timeout_sec=timeout_sec)

def media_rank_best_sources(media_items: 'Sequence[Any]') -> 'Dict[str, Any]':
    return _call_engine_tool(engine_media_rank_best_sources, "media_rank_best_sources", media_items=media_items)

def entity_extract(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_entity_extract, "entity_extract", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def entity_link_urls(text_or_url: 'str', entities: 'Optional[Sequence[str]]' = None, base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_entity_link_urls, "entity_link_urls", text_or_url=text_or_url, entities=entities, base_url=base_url, timeout_sec=timeout_sec)

def entity_timeline(text_or_url: 'str', entity: 'str' = '', base_url: 'str' = '', include_archives: 'bool' = False, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_entity_timeline, "entity_timeline", text_or_url=text_or_url, entity=entity, base_url=base_url, include_archives=include_archives, timeout_sec=timeout_sec)

def entity_cluster(text_or_url: 'str', base_url: 'str' = '', timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_entity_cluster, "entity_cluster", text_or_url=text_or_url, base_url=base_url, timeout_sec=timeout_sec)

def entity_report(text_or_url: 'str', base_url: 'str' = '', include_archives: 'bool' = False, timeout_sec: 'int' = 20) -> 'Dict[str, Any]':
    return _call_engine_tool(engine_entity_report, "entity_report", text_or_url=text_or_url, base_url=base_url, include_archives=include_archives, timeout_sec=timeout_sec)

def engines_status() -> 'Dict[str, Any]':
    return _call_engine_tool(engine_engines_status, "engines_status")




# ======================= Shared Intelligence Engine Integration =============
def _intelligence_engine_available() -> bool:
    return (
        engine_make_intelligence_tool_function is not None
        and engine_intelligence_tool_schema is not None
    ) or engine_intelligence_engine is not None


def _intelligence_engine_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "intelligence_engine_available": False,
        "error": "intelligence_engine.py is not importable. Put intelligence_engine.py beside tools.py.",
    }


def _fallback_intelligence_tool_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The user's question or task to investigate.",
            },
            "context": {
                "type": "string",
                "description": "Optional extra context, pasted error, code summary, or user constraints.",
                "default": "",
            },
            "mode": {
                "type": "string",
                "enum": ["auto", "general", "code", "debug", "docs", "research", "math"],
                "default": "auto",
            },
            "max_evidence": {
                "type": "integer",
                "minimum": 1,
                "maximum": 40,
                "default": 16,
            },
            "allow_web": {"type": "boolean", "default": True},
            "allow_project": {"type": "boolean", "default": True},
            "allow_local": {"type": "boolean", "default": True},
            "allow_apidoc": {"type": "boolean", "default": True},
            "allow_math": {"type": "boolean", "default": True},
        },
        "required": ["query"],
        "additionalProperties": False,
    }


def _intelligence_engine_schema() -> Dict[str, Any]:
    if engine_intelligence_tool_schema is None:
        return _fallback_intelligence_tool_schema()
    try:
        schema = engine_intelligence_tool_schema()
        if isinstance(schema, dict):
            schema.setdefault("additionalProperties", False)
            return schema
    except Exception:
        pass
    return _fallback_intelligence_tool_schema()


def _make_intelligence_engine_fn(tools: ToolRegistry) -> Callable[..., Dict[str, Any]]:
    if engine_make_intelligence_tool_function is not None:
        try:
            fn = engine_make_intelligence_tool_function(tools)
            if callable(fn):
                return fn
        except Exception:
            pass

    if engine_intelligence_engine is not None:
        def _direct(
            query: str,
            context: str = "",
            mode: str = "auto",
            max_evidence: int = 16,
            allow_web: bool = True,
            allow_project: bool = True,
            allow_local: bool = True,
            allow_apidoc: bool = True,
            allow_math: bool = True,
        ) -> Dict[str, Any]:
            return engine_intelligence_engine(
                query=query,
                context=context,
                mode=mode,
                max_evidence=max_evidence,
                allow_web=allow_web,
                allow_project=allow_project,
                allow_local=allow_local,
                allow_apidoc=allow_apidoc,
                allow_math=allow_math,
                tools=tools,
            )
        return _direct

    def _unavailable(
        query: str,
        context: str = "",
        mode: str = "auto",
        max_evidence: int = 16,
        allow_web: bool = True,
        allow_project: bool = True,
        allow_local: bool = True,
        allow_apidoc: bool = True,
        allow_math: bool = True,
    ) -> Dict[str, Any]:
        result = _intelligence_engine_unavailable_result()
        result.update({
            "query": query,
            "context": context,
            "mode": mode,
            "max_evidence": max_evidence,
            "allow_web": allow_web,
            "allow_project": allow_project,
            "allow_local": allow_local,
            "allow_apidoc": allow_apidoc,
            "allow_math": allow_math,
        })
        return result

    return _unavailable


# ======================= Intelligence Engine Tool Registration =============
def _register_intelligence_engine_tools(tools: ToolRegistry) -> None:
    """Register intelligence_engine.py's meta-research tool against this ToolRegistry."""
    tools.register(
        ToolSpec(
            name="intelligence_engine",
            description=(
                "Meta-research and verification engine for the local GPT. Use before answering hard questions, "
                "code/debug questions, API-doc questions, math/ranking questions, or anything that needs "
                "evidence gathered from the available tools."
            ),
            parameters=_intelligence_engine_schema(),
            fn=_make_intelligence_engine_fn(tools),
        )
    )




# ======================= Shared Language Engine Integration =================
def _language_engine_available() -> bool:
    return (
        engine_language_engine is not None
        or engine_language_engine_tool_schema is not None
        or engine_make_language_engine_tool_function is not None
    )


def _language_engine_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "language_engine_available": False,
        "error": "language_engine.py is not importable. Put language_engine.py beside tools.py.",
    }


def _fallback_language_engine_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "status",
                    "normalize_text",
                    "fix_spacing",
                    "fix_typos",
                    "grammar_check",
                    "rewrite",
                    "rewrite_plain_english",
                    "rewrite_technical",
                    "rewrite_fast_answer",
                    "summarize",
                    "summarize_tool_output",
                    "extract_intent",
                    "extract_constraints",
                    "make_search_queries",
                    "make_apidoc_queries",
                    "make_tool_prompt",
                    "make_final_answer",
                    "score_clarity",
                    "score_readability",
                    "rank_rewrites",
                    "diff_rewrites",
                    "cache_get",
                    "cache_put",
                    "help",
                ],
                "default": "rewrite",
                "description": "Language engine operation.",
            },
            "text": {
                "type": "string",
                "default": "",
                "description": "Primary text, user request, draft answer, code-adjacent prose, or tool output.",
            },
            "context": {
                "type": "string",
                "default": "",
                "description": "Optional extra context, user goal, previous tool output, or constraints.",
            },
            "style": {
                "type": "string",
                "enum": [
                    "auto",
                    "concise",
                    "direct",
                    "friendly",
                    "technical",
                    "plain_english",
                    "debug",
                    "apidoc",
                    "tool_prompt",
                    "final_answer",
                    "code_review",
                    "step_by_step",
                ],
                "default": "auto",
                "description": "Rewrite or answer style.",
            },
            "mode": {
                "type": "string",
                "default": "auto",
                "description": "Optional task mode hint such as debug, apidoc, code, or final_answer.",
            },
            "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000, "default": 12000},
            "max_sentences": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 8},
            "max_queries": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 12},
            "preserve_markdown": {"type": "boolean", "default": True},
            "preserve_code": {"type": "boolean", "default": True},
            "fast": {"type": "boolean", "default": True},
            "use_optional": {
                "type": "boolean",
                "default": True,
                "description": "Use optional local dependencies such as LanguageTool/ftfy when installed.",
            },
            "params": {
                "type": "object",
                "additionalProperties": True,
                "default": {},
                "description": "Action-specific params: auto_correct, strip_html, tool_name, candidates, styles, revised, key, value, ttl_sec.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    }


def _language_engine_schema() -> Dict[str, Any]:
    if engine_language_engine_tool_schema is not None:
        try:
            schema = engine_language_engine_tool_schema()
            if isinstance(schema, dict):
                schema.setdefault("additionalProperties", False)
                return schema
        except Exception:
            pass
    return _fallback_language_engine_schema()


def _make_language_engine_fn() -> Callable[..., Dict[str, Any]]:
    if engine_make_language_engine_tool_function is not None:
        try:
            fn = engine_make_language_engine_tool_function()
            if callable(fn):
                return fn
        except Exception:
            pass

    if callable(engine_language_engine):
        return engine_language_engine

    def _unavailable(
        action: str = "rewrite",
        text: str = "",
        context: str = "",
        style: str = "auto",
        mode: str = "auto",
        max_chars: int = 12000,
        max_sentences: int = 8,
        max_queries: int = 12,
        preserve_markdown: bool = True,
        preserve_code: bool = True,
        fast: bool = True,
        use_optional: bool = True,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = _language_engine_unavailable_result()
        result.update(
            {
                "action": action,
                "text_len": len(text or ""),
                "context_len": len(context or ""),
                "style": style,
                "mode": mode,
                "max_chars": max_chars,
                "max_sentences": max_sentences,
                "max_queries": max_queries,
                "preserve_markdown": preserve_markdown,
                "preserve_code": preserve_code,
                "fast": fast,
                "use_optional": use_optional,
                "params": params or {},
            }
        )
        return result

    return _unavailable


def _call_language_engine_tool(
    action: str = "rewrite",
    text: str = "",
    context: str = "",
    style: str = "auto",
    mode: str = "auto",
    max_chars: int = 12000,
    max_sentences: int = 8,
    max_queries: int = 12,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
    fast: bool = True,
    use_optional: bool = True,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    fn = _make_language_engine_fn()

    try:
        data = fn(
            action=action,
            text=text,
            context=context,
            style=style,
            mode=mode,
            max_chars=max_chars,
            max_sentences=max_sentences,
            max_queries=max_queries,
            preserve_markdown=preserve_markdown,
            preserve_code=preserve_code,
            fast=fast,
            use_optional=use_optional,
            params=params or {},
        )
    except TypeError:
        try:
            data = fn(action, text, context, style, mode, max_chars, max_sentences, max_queries, preserve_markdown, preserve_code, fast, use_optional, params or {})
        except Exception as exc:
            return {
                "ok": False,
                "language_engine_available": _language_engine_available(),
                "tool": "language_engine",
                "action": action,
                "error": str(exc),
            }
    except Exception as exc:
        return {
            "ok": False,
            "language_engine_available": _language_engine_available(),
            "tool": "language_engine",
            "action": action,
            "error": str(exc),
        }

    if isinstance(data, dict):
        out = dict(data)
        out.setdefault("ok", True)
        out["language_engine_available"] = _language_engine_available()
        out["tool"] = "language_engine"
        out.setdefault("action", action)
        return out

    return {
        "ok": True,
        "language_engine_available": _language_engine_available(),
        "tool": "language_engine",
        "action": action,
        "result": data,
    }


def language_engine(
    action: str = "rewrite",
    text: str = "",
    context: str = "",
    style: str = "auto",
    mode: str = "auto",
    max_chars: int = 12000,
    max_sentences: int = 8,
    max_queries: int = 12,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
    fast: bool = True,
    use_optional: bool = True,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generic language_engine entrypoint. Keeps the new GPT-facing signature explicit."""
    return _call_language_engine_tool(
        action=action,
        text=text,
        context=context,
        style=style,
        mode=mode,
        max_chars=max_chars,
        max_sentences=max_sentences,
        max_queries=max_queries,
        preserve_markdown=preserve_markdown,
        preserve_code=preserve_code,
        fast=fast,
        use_optional=use_optional,
        params=params,
    )


def language_engine_status() -> Dict[str, Any]:
    """Return language_engine status, available actions, and optional dependency state."""
    return _call_language_engine_tool(action="status")


def language_normalize_text(
    text: str,
    max_chars: int = 12000,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
    strip_html: bool = False,
    use_optional: bool = True,
) -> Dict[str, Any]:
    """Normalize Unicode, HTML entities, whitespace, and optionally HTML while preserving code/markdown."""
    return _call_language_engine_tool(
        action="normalize_text",
        text=text,
        max_chars=max_chars,
        preserve_markdown=preserve_markdown,
        preserve_code=preserve_code,
        use_optional=use_optional,
        params={"strip_html": strip_html},
    )


def language_fix_spacing(
    text: str,
    max_chars: int = 12000,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
) -> Dict[str, Any]:
    """Fix missing spaces, punctuation spacing, run-together prose, and rough markdown spacing."""
    return _call_language_engine_tool(
        action="fix_spacing",
        text=text,
        max_chars=max_chars,
        preserve_markdown=preserve_markdown,
        preserve_code=preserve_code,
    )


def language_fix_typos(
    text: str,
    max_chars: int = 12000,
    preserve_code: bool = True,
) -> Dict[str, Any]:
    """Fix common project/user typos without changing code blocks or inline code."""
    return _call_language_engine_tool(
        action="fix_typos",
        text=text,
        max_chars=max_chars,
        preserve_code=preserve_code,
    )


def language_grammar_check(
    text: str,
    max_chars: int = 12000,
    auto_correct: bool = False,
    use_optional: bool = True,
) -> Dict[str, Any]:
    """Check grammar/style with LanguageTool when available, otherwise use local heuristics."""
    return _call_language_engine_tool(
        action="grammar_check",
        text=text,
        max_chars=max_chars,
        use_optional=use_optional,
        params={"auto_correct": auto_correct},
    )


def language_rewrite(
    text: str,
    context: str = "",
    style: str = "auto",
    mode: str = "auto",
    max_chars: int = 12000,
    max_sentences: int = 8,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
    fast: bool = True,
    use_optional: bool = True,
) -> Dict[str, Any]:
    """Rewrite text into clearer English while preserving markdown/code and meaning."""
    return _call_language_engine_tool(
        action="rewrite",
        text=text,
        context=context,
        style=style,
        mode=mode,
        max_chars=max_chars,
        max_sentences=max_sentences,
        preserve_markdown=preserve_markdown,
        preserve_code=preserve_code,
        fast=fast,
        use_optional=use_optional,
    )


def language_rewrite_plain_english(
    text: str,
    context: str = "",
    max_chars: int = 12000,
    max_sentences: int = 8,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
) -> Dict[str, Any]:
    """Rewrite text into simpler plain English."""
    return _call_language_engine_tool(
        action="rewrite_plain_english",
        text=text,
        context=context,
        style="plain_english",
        max_chars=max_chars,
        max_sentences=max_sentences,
        preserve_markdown=preserve_markdown,
        preserve_code=preserve_code,
    )


def language_rewrite_technical(
    text: str,
    context: str = "",
    max_chars: int = 12000,
    max_sentences: int = 8,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
) -> Dict[str, Any]:
    """Rewrite text into a precise technical answer style."""
    return _call_language_engine_tool(
        action="rewrite_technical",
        text=text,
        context=context,
        style="technical",
        max_chars=max_chars,
        max_sentences=max_sentences,
        preserve_markdown=preserve_markdown,
        preserve_code=preserve_code,
    )


def language_rewrite_fast_answer(
    text: str,
    context: str = "",
    max_chars: int = 12000,
    max_sentences: int = 6,
    preserve_markdown: bool = True,
    preserve_code: bool = True,
) -> Dict[str, Any]:
    """Rewrite text into a quick direct answer the GPT can send immediately."""
    return _call_language_engine_tool(
        action="rewrite_fast_answer",
        text=text,
        context=context,
        style="direct",
        max_chars=max_chars,
        max_sentences=max_sentences,
        preserve_markdown=preserve_markdown,
        preserve_code=preserve_code,
    )


def language_summarize(
    text: str,
    context: str = "",
    max_chars: int = 12000,
    max_sentences: int = 8,
    style: str = "direct",
) -> Dict[str, Any]:
    """Summarize text using fast local sentence scoring."""
    return _call_language_engine_tool(
        action="summarize",
        text=text,
        context=context,
        style=style,
        max_chars=max_chars,
        max_sentences=max_sentences,
    )


def language_summarize_tool_output(
    text: str,
    context: str = "",
    max_chars: int = 12000,
    max_sentences: int = 10,
) -> Dict[str, Any]:
    """Summarize JSON/tool output into a user-facing answer draft."""
    return _call_language_engine_tool(
        action="summarize_tool_output",
        text=text,
        context=context,
        max_chars=max_chars,
        max_sentences=max_sentences,
    )


def language_extract_intent(
    text: str,
    context: str = "",
) -> Dict[str, Any]:
    """Extract likely user intent, task type, flags, and keywords from a rough request."""
    return _call_language_engine_tool(action="extract_intent", text=text, context=context)


def language_extract_constraints(
    text: str,
    context: str = "",
) -> Dict[str, Any]:
    """Extract constraints such as full file, exact signature, no unrelated changes, APIDocs, and copy-paste readiness."""
    return _call_language_engine_tool(action="extract_constraints", text=text, context=context)


def language_make_search_queries(
    text: str,
    context: str = "",
    max_queries: int = 12,
    style: str = "web",
) -> Dict[str, Any]:
    """Generate concise web/search queries from a rough user request."""
    return _call_language_engine_tool(
        action="make_search_queries",
        text=text,
        context=context,
        style=style,
        max_queries=max_queries,
    )


def language_make_apidoc_queries(
    text: str,
    context: str = "",
    max_queries: int = 20,
) -> Dict[str, Any]:
    """Generate APIDoc query strings from a rough coding/API request."""
    return _call_language_engine_tool(
        action="make_apidoc_queries",
        text=text,
        context=context,
        max_queries=max_queries,
    )


def language_make_tool_prompt(
    text: str,
    context: str = "",
    tool_name: str = "",
    max_chars: int = 12000,
) -> Dict[str, Any]:
    """Convert a rough user request into a cleaner prompt for another tool."""
    return _call_language_engine_tool(
        action="make_tool_prompt",
        text=text,
        context=context,
        max_chars=max_chars,
        params={"tool_name": tool_name},
    )


def language_make_final_answer(
    text: str,
    context: str = "",
    max_chars: int = 12000,
    style: str = "direct",
) -> Dict[str, Any]:
    """Clean and shape a final answer before sending it to the user."""
    return _call_language_engine_tool(
        action="make_final_answer",
        text=text,
        context=context,
        style=style,
        max_chars=max_chars,
    )


def language_score_clarity(
    text: str,
    max_chars: int = 12000,
) -> Dict[str, Any]:
    """Score clarity and return notes about repetition, long sentences, spacing, and vague wording."""
    return _call_language_engine_tool(action="score_clarity", text=text, max_chars=max_chars)


def language_score_readability(
    text: str,
    max_chars: int = 12000,
) -> Dict[str, Any]:
    """Score readability on a 0-100 scale using optional textstat or local heuristics."""
    return _call_language_engine_tool(action="score_readability", text=text, max_chars=max_chars)


def language_rank_rewrites(
    text: str,
    context: str = "",
    candidates: Optional[List[str]] = None,
    styles: Optional[List[str]] = None,
    max_chars: int = 12000,
) -> Dict[str, Any]:
    """Generate or rank rewrite candidates by clarity/readability/length score."""
    return _call_language_engine_tool(
        action="rank_rewrites",
        text=text,
        context=context,
        max_chars=max_chars,
        params={
            "candidates": candidates or [],
            "styles": styles or [],
        },
    )


def language_diff_rewrites(
    original: str,
    revised: str = "",
    context: str = "",
    style: str = "direct",
    max_chars: int = 12000,
) -> Dict[str, Any]:
    """Show a unified diff between original text and a rewrite."""
    return _call_language_engine_tool(
        action="diff_rewrites",
        text=original,
        context=context,
        style=style,
        max_chars=max_chars,
        params={"revised": revised},
    )


# ======================= Language Engine Tool Registration =================
def _register_language_engine_tools(tools: ToolRegistry) -> None:
    """Register language_engine.py tools without changing any old tool signatures."""
    tools.register(
        ToolSpec(
            name="language_engine",
            description=(
                "Generic local English/response helper. Use for cleanup, typo/spacing fixes, grammar checks, "
                "rewrites, summaries, intent/constraint extraction, APIDoc/search query generation, tool prompts, "
                "and final-answer polishing."
            ),
            parameters=_language_engine_schema(),
            fn=language_engine,
        )
    )

    tools.register(
        ToolSpec(
            name="language_engine_status",
            description="Return language_engine availability, supported actions, styles, and optional dependency status.",
            parameters=_schema({}),
            fn=lambda: language_engine_status(),
        )
    )

    tools.register(
        ToolSpec(
            name="language_normalize_text",
            description="Normalize Unicode, HTML entities, whitespace, optional HTML, markdown, and code-safe text.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "preserve_markdown": {"type": "boolean"},
                    "preserve_code": {"type": "boolean"},
                    "strip_html": {"type": "boolean"},
                    "use_optional": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=language_normalize_text,
        )
    )

    tools.register(
        ToolSpec(
            name="language_fix_spacing",
            description="Fix missing spaces, punctuation spacing, run-together prose, and rough markdown spacing.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "preserve_markdown": {"type": "boolean"},
                    "preserve_code": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=language_fix_spacing,
        )
    )

    tools.register(
        ToolSpec(
            name="language_fix_typos",
            description="Fix common typo patterns while preserving code blocks and inline code.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "preserve_code": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=language_fix_typos,
        )
    )

    tools.register(
        ToolSpec(
            name="language_grammar_check",
            description="Check grammar/style with LanguageTool when available, otherwise use local heuristics.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "auto_correct": {"type": "boolean"},
                    "use_optional": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=language_grammar_check,
        )
    )

    tools.register(
        ToolSpec(
            name="language_rewrite",
            description="Rewrite text into clearer English while preserving markdown/code and meaning.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "style": {"type": "string"},
                    "mode": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "max_sentences": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "preserve_markdown": {"type": "boolean"},
                    "preserve_code": {"type": "boolean"},
                    "fast": {"type": "boolean"},
                    "use_optional": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=language_rewrite,
        )
    )

    tools.register(
        ToolSpec(
            name="language_rewrite_plain_english",
            description="Rewrite text into simpler plain English.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "max_sentences": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "preserve_markdown": {"type": "boolean"},
                    "preserve_code": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=language_rewrite_plain_english,
        )
    )

    tools.register(
        ToolSpec(
            name="language_rewrite_technical",
            description="Rewrite text into a precise technical answer style.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "max_sentences": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "preserve_markdown": {"type": "boolean"},
                    "preserve_code": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=language_rewrite_technical,
        )
    )

    tools.register(
        ToolSpec(
            name="language_rewrite_fast_answer",
            description="Rewrite text into a quick direct answer the GPT can send immediately.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "max_sentences": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "preserve_markdown": {"type": "boolean"},
                    "preserve_code": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=language_rewrite_fast_answer,
        )
    )

    tools.register(
        ToolSpec(
            name="language_summarize",
            description="Summarize text using fast local sentence scoring.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "max_sentences": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "style": {"type": "string"},
                },
                required=["text"],
            ),
            fn=language_summarize,
        )
    )

    tools.register(
        ToolSpec(
            name="language_summarize_tool_output",
            description="Summarize JSON/tool output into a user-facing answer draft.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "max_sentences": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
                required=["text"],
            ),
            fn=language_summarize_tool_output,
        )
    )

    tools.register(
        ToolSpec(
            name="language_extract_intent",
            description="Extract likely user intent, task type, flags, and keywords from a rough request.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                },
                required=["text"],
            ),
            fn=language_extract_intent,
        )
    )

    tools.register(
        ToolSpec(
            name="language_extract_constraints",
            description="Extract constraints like full file, exact signature, no unrelated changes, APIDocs, and copy-paste readiness.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                },
                required=["text"],
            ),
            fn=language_extract_constraints,
        )
    )

    tools.register(
        ToolSpec(
            name="language_make_search_queries",
            description="Generate concise web/search queries from a rough user request.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "max_queries": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "style": {"type": "string"},
                },
                required=["text"],
            ),
            fn=language_make_search_queries,
        )
    )

    tools.register(
        ToolSpec(
            name="language_make_apidoc_queries",
            description="Generate APIDoc query strings from a rough coding/API request.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "max_queries": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
                required=["text"],
            ),
            fn=language_make_apidoc_queries,
        )
    )

    tools.register(
        ToolSpec(
            name="language_make_tool_prompt",
            description="Convert a rough user request into a cleaner prompt for another tool.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "tool_name": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                },
                required=["text"],
            ),
            fn=language_make_tool_prompt,
        )
    )

    tools.register(
        ToolSpec(
            name="language_make_final_answer",
            description="Clean and shape a final answer before sending it to the user.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                    "style": {"type": "string"},
                },
                required=["text"],
            ),
            fn=language_make_final_answer,
        )
    )

    tools.register(
        ToolSpec(
            name="language_score_clarity",
            description="Score clarity and return notes about repetition, long sentences, spacing, and vague wording.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                },
                required=["text"],
            ),
            fn=language_score_clarity,
        )
    )

    tools.register(
        ToolSpec(
            name="language_score_readability",
            description="Score readability on a 0-100 scale using optional textstat or local heuristics.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                },
                required=["text"],
            ),
            fn=language_score_readability,
        )
    )

    tools.register(
        ToolSpec(
            name="language_rank_rewrites",
            description="Generate or rank rewrite candidates by clarity/readability/length score.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "context": {"type": "string"},
                    "candidates": {"type": "array", "items": {"type": "string"}},
                    "styles": {"type": "array", "items": {"type": "string"}},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                },
                required=["text"],
            ),
            fn=language_rank_rewrites,
        )
    )

    tools.register(
        ToolSpec(
            name="language_diff_rewrites",
            description="Show a unified diff between original text and a rewrite.",
            parameters=_schema(
                {
                    "original": {"type": "string"},
                    "revised": {"type": "string"},
                    "context": {"type": "string"},
                    "style": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 1, "maximum": 2000000},
                },
                required=["original"],
            ),
            fn=language_diff_rewrites,
        )
    )


# ======================= Shared Python Engine Integration ==================
def _python_engine_available() -> bool:
    return (
        engine_python_engine is not None
        and engine_python_engine_tool_schema is not None
        and engine_make_python_engine_tool_function is not None
    )


def _python_engine_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "python_engine_available": False,
        "error": "python_engine.py is not importable. Put python_engine.py beside tools.py.",
    }


def _python_engine_schema() -> Dict[str, Any]:
    if engine_python_engine_tool_schema is not None:
        try:
            schema = engine_python_engine_tool_schema()
            if isinstance(schema, dict):
                return schema
        except Exception:
            pass

    return {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "status",
                    "write_file",
                    "read_file",
                    "list_files",
                    "delete_file",
                    "validate_code",
                    "run_code",
                    "run_file",
                    "run_task",
                    "collect_artifacts",
                    "read_artifact",
                ],
            },
            "relative_path": {"type": "string"},
            "content": {"type": "string"},
            "code": {"type": "string"},
            "task": {"type": "string"},
            "filename": {"type": "string"},
            "args": {"type": "array", "items": {"type": "string"}},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600},
            "validate": {"type": "boolean"},
            "recursive": {"type": "boolean"},
            "pattern": {"type": "string"},
            "max_files": {"type": "integer", "minimum": 1, "maximum": 2000},
            "max_chars": {"type": "integer", "minimum": 1, "maximum": 200000},
            "as_base64": {"type": "boolean"},
            "overwrite": {"type": "boolean"},
            "extra_allowed_imports": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["action"],
        "additionalProperties": False,
    }


def _make_python_engine_fn() -> Callable[..., Dict[str, Any]]:
    if engine_make_python_engine_tool_function is not None:
        try:
            fn = engine_make_python_engine_tool_function()
            if callable(fn):
                return fn
        except Exception:
            pass

    def _unavailable(
        action: str,
        relative_path: str = "",
        content: str = "",
        code: str = "",
        task: str = "",
        filename: str = "",
        args: Optional[List[str]] = None,
        timeout_seconds: Optional[int] = None,
        validate: bool = True,
        recursive: bool = True,
        pattern: str = "*",
        max_files: int = 200,
        max_chars: int = 12000,
        as_base64: bool = False,
        overwrite: bool = True,
        extra_allowed_imports: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        result = _python_engine_unavailable_result()
        result.update(
            {
                "action": action,
                "relative_path": relative_path,
                "content_len": len(content or ""),
                "code_len": len(code or ""),
                "task": task,
                "filename": filename,
                "args": args or [],
                "timeout_seconds": timeout_seconds,
                "validate": validate,
                "recursive": recursive,
                "pattern": pattern,
                "max_files": max_files,
                "max_chars": max_chars,
                "as_base64": as_base64,
                "overwrite": overwrite,
                "extra_allowed_imports": extra_allowed_imports or [],
            }
        )
        return result

    return _unavailable


def python_engine_tool(
    action: str,
    relative_path: str = "",
    content: str = "",
    code: str = "",
    task: str = "",
    filename: str = "",
    args: Optional[List[str]] = None,
    timeout_seconds: Optional[int] = None,
    validate: bool = True,
    recursive: bool = True,
    pattern: str = "*",
    max_files: int = 200,
    max_chars: int = 12000,
    as_base64: bool = False,
    overwrite: bool = True,
    extra_allowed_imports: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if engine_python_engine is None:
        result = _python_engine_unavailable_result()
        result.update(
            {
                "action": action,
                "relative_path": relative_path,
                "content_len": len(content or ""),
                "code_len": len(code or ""),
                "task": task,
                "filename": filename,
                "args": args or [],
                "timeout_seconds": timeout_seconds,
                "validate": validate,
                "recursive": recursive,
                "pattern": pattern,
                "max_files": max_files,
                "max_chars": max_chars,
                "as_base64": as_base64,
                "overwrite": overwrite,
                "extra_allowed_imports": extra_allowed_imports or [],
            }
        )
        return result

    try:
        data = engine_python_engine(
            action=action,
            relative_path=relative_path,
            content=content,
            code=code,
            task=task,
            filename=filename,
            args=args,
            timeout_seconds=timeout_seconds,
            validate=validate,
            recursive=recursive,
            pattern=pattern,
            max_files=max_files,
            max_chars=max_chars,
            as_base64=as_base64,
            overwrite=overwrite,
            extra_allowed_imports=extra_allowed_imports,
        )
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("ok", True)
            out["python_engine_available"] = _python_engine_available()
            return out
        return {"ok": True, "python_engine_available": _python_engine_available(), "result": data}
    except Exception as exc:
        return {"ok": False, "python_engine_available": _python_engine_available(), "error": str(exc)}


# ======================= Python Engine Tool Registration ===================
def _register_python_engine_tools(tools: ToolRegistry) -> None:
    """Register python_engine.py's controlled Python coding/runtime tool."""
    tools.register(
        ToolSpec(
            name="python_engine",
            description=(
                "Controlled Python coding engine for the local GPT. Creates files, validates generated Python, "
                "runs scripts in a workspace subprocess, captures stdout/stderr/artifacts, and returns structured JSON. "
                "Use for calculations, data processing, file analysis, plots, simulations, and script-based reasoning."
            ),
            parameters=_python_engine_schema(),
            fn=python_engine_tool if engine_make_python_engine_tool_function is None else _make_python_engine_fn(),
        )
    )





# ======================= Shared Coding Engine Integration ==================
_FALLBACK_CODE_GENERATION_ACTIONS = [
    "status",
    "tokenize_code",
    "parse_code",
    "extract_symbols",
    "extract_imports",
    "extract_signatures",
    "extract_docstrings",
    "extract_dependencies",
    "extract_style",
    "extract_patterns",
    "search_snippets",
    "search_syntax",
    "search_api_usage",
    "rank_snippets",
    "dedupe_snippets",
    "build_token_pack",
    "build_syntax_pack",
    "build_context_pack",
    "make_generation_prompt",
    "generate_script",
    "generate_module",
    "generate_class",
    "generate_function",
    "generate_cli",
    "generate_gui",
    "generate_engine",
    "generate_tool_wrapper",
    "generate_tests",
    "generate_requirements",
    "complete_code",
    "repair_code",
    "rewrite_code",
    "convert_code",
    "explain_code_error",
    "explain_syntax",
    "validate_syntax",
    "format_generated_code",
    "score_generated_code",
]


def _coding_engine_actions() -> List[str]:
    actions = engine_CODE_GENERATION_ACTIONS or _FALLBACK_CODE_GENERATION_ACTIONS
    try:
        return [str(x) for x in actions]
    except Exception:
        return list(_FALLBACK_CODE_GENERATION_ACTIONS)


def _coding_engine_available() -> bool:
    return (
        engine_coding_engine is not None
        or engine_coding_engine_tool_schema is not None
        or engine_make_coding_engine_tool_function is not None
        or engine_CodingEngine is not None
    )


def _coding_engine_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "coding_engine_available": False,
        "error": "coding_engine.py is not importable. Put coding_engine.py beside tools.py.",
    }


def _fallback_coding_engine_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": _coding_engine_actions(),
                "default": "build_context_pack",
                "description": "Coding engine operation.",
            },
            "payload": {
                "description": "Primary code/text/task/snippet payload. Can be a string or JSON object.",
            },
            "params": {
                "type": "object",
                "additionalProperties": True,
                "default": {},
                "description": "Action params: task, query, code, language, project_root, max_snippets, max_tokens, name, instructions, etc.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    }


def _coding_engine_schema() -> Dict[str, Any]:
    if engine_coding_engine_tool_schema is not None:
        try:
            schema = engine_coding_engine_tool_schema()
            if isinstance(schema, dict):
                schema.setdefault("additionalProperties", False)
                return schema
        except Exception:
            pass
    return _fallback_coding_engine_schema()


def _make_coding_engine_fn() -> Callable[..., Dict[str, Any]]:
    if engine_make_coding_engine_tool_function is not None:
        try:
            fn = engine_make_coding_engine_tool_function()
            if callable(fn):
                return fn
        except Exception:
            pass

    if callable(engine_coding_engine):
        return engine_coding_engine

    def _unavailable(
        action: str = "build_context_pack",
        payload: Any = None,
        params: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        merged = dict(params or {})
        merged.update(kwargs)
        result = _coding_engine_unavailable_result()
        result.update(
            {
                "tool": "coding_engine",
                "action": action,
                "payload_type": type(payload).__name__,
                "params": merged,
            }
        )
        return result

    return _unavailable


def _coerce_coding_params(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if params is None:
        return {}
    if isinstance(params, dict):
        return dict(params)
    if isinstance(params, str):
        try:
            loaded = json.loads(params or "{}")
            if isinstance(loaded, dict):
                return loaded
            return {"value": loaded}
        except Exception:
            return {"raw_params": params}
    return {"value": params}


def _call_coding_engine_tool(
    action: str = "build_context_pack",
    payload: Any = None,
    params: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    merged = _coerce_coding_params(params)
    merged.update(kwargs)
    fn = _make_coding_engine_fn()

    try:
        data = fn(action=action or "build_context_pack", payload=payload, params=merged)
    except TypeError:
        try:
            data = fn(action or "build_context_pack", payload, merged)
        except Exception as exc:
            return {
                "ok": False,
                "coding_engine_available": _coding_engine_available(),
                "tool": "coding_engine",
                "action": action,
                "error": str(exc),
            }
    except Exception as exc:
        return {
            "ok": False,
            "coding_engine_available": _coding_engine_available(),
            "tool": "coding_engine",
            "action": action,
            "error": str(exc),
        }

    if isinstance(data, dict):
        out = dict(data)
        out.setdefault("ok", True)
        out["coding_engine_available"] = _coding_engine_available()
        out["tool"] = "coding_engine"
        out.setdefault("action", action)
        return out

    return {
        "ok": True,
        "coding_engine_available": _coding_engine_available(),
        "tool": "coding_engine",
        "action": action,
        "result": data,
    }


def coding_engine(
    action: str = "build_context_pack",
    payload: Any = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generic coding_engine entrypoint for code-generation support packs, snippets, tokens, and generated templates."""
    return _call_coding_engine_tool(action=action, payload=payload, params=params)


def coding_engine_status() -> Dict[str, Any]:
    """Return coding_engine availability, version, and supported code-generation actions."""
    return _call_coding_engine_tool(action="status")


def coding_tokenize_code(
    code: str,
    language: str = "python",
    source: str = "payload",
    max_tokens: int = 5000,
    max_chars: int = 120000,
) -> Dict[str, Any]:
    """Tokenize code for GPT context packing."""
    return _call_coding_engine_tool(
        action="tokenize_code",
        payload=code,
        params={"code": code, "language": language, "source": source, "max_tokens": max_tokens, "max_chars": max_chars},
    )


def coding_parse_code(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Parse code and return syntax/node summary."""
    return _call_coding_engine_tool(action="parse_code", payload=code, params={"code": code, "language": language})


def coding_extract_symbols(
    code: str,
    language: str = "python",
    source: str = "payload",
) -> Dict[str, Any]:
    """Extract classes, functions, methods, and signatures from code."""
    return _call_coding_engine_tool(action="extract_symbols", payload=code, params={"code": code, "language": language, "source": source})


def coding_extract_imports(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Extract imports/includes/usings from code."""
    return _call_coding_engine_tool(action="extract_imports", payload=code, params={"code": code, "language": language})


def coding_extract_signatures(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Extract reusable function/class signatures from code."""
    return _call_coding_engine_tool(action="extract_signatures", payload=code, params={"code": code, "language": language})


def coding_extract_docstrings(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Extract module/class/function docstrings or doc comments."""
    return _call_coding_engine_tool(action="extract_docstrings", payload=code, params={"code": code, "language": language})


def coding_extract_dependencies(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Extract likely external dependencies from code."""
    return _call_coding_engine_tool(action="extract_dependencies", payload=code, params={"code": code, "language": language})


def coding_extract_style(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Extract style signals: indentation, line length, quote preference, type hints, dataclasses, main guard."""
    return _call_coding_engine_tool(action="extract_style", payload=code, params={"code": code, "language": language})


def coding_extract_patterns(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Extract reusable syntax/design patterns from code."""
    return _call_coding_engine_tool(action="extract_patterns", payload=code, params={"code": code, "language": language})


def coding_search_snippets(
    query: str,
    code: str = "",
    language: str = "python",
    project_root: str = "",
    max_snippets: int = 24,
    max_tokens: int = 8000,
) -> Dict[str, Any]:
    """Search/rank snippets from supplied code or a local project for a generation task."""
    return _call_coding_engine_tool(
        action="search_snippets",
        payload={"code": code},
        params={"query": query, "task": query, "language": language, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens},
    )


def coding_build_token_pack(
    task: str,
    language: str = "python",
    code: str = "",
    project_root: str = "",
    max_snippets: int = 24,
    max_tokens: int = 8000,
) -> Dict[str, Any]:
    """Build a compact token-focused context pack for code generation."""
    return _call_coding_engine_tool(
        action="build_token_pack",
        payload={"code": code},
        params={"task": task, "language": language, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens},
    )


def coding_build_syntax_pack(
    task: str,
    language: str = "python",
    code: str = "",
    project_root: str = "",
    max_snippets: int = 24,
    max_tokens: int = 8000,
) -> Dict[str, Any]:
    """Build a syntax/snippet pack for code generation."""
    return _call_coding_engine_tool(
        action="build_syntax_pack",
        payload={"code": code},
        params={"task": task, "language": language, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens},
    )


def coding_build_context_pack(
    task: str,
    language: str = "python",
    code: str = "",
    project_root: str = "",
    max_snippets: int = 24,
    max_tokens: int = 8000,
) -> Dict[str, Any]:
    """Build the main GPT code-generation context pack: imports, symbols, signatures, tokens, snippets, patterns, and constraints."""
    return _call_coding_engine_tool(
        action="build_context_pack",
        payload={"code": code},
        params={"task": task, "language": language, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens},
    )


def coding_make_generation_prompt(
    task: str,
    language: str = "python",
    code: str = "",
    project_root: str = "",
    max_snippets: int = 24,
    max_tokens: int = 8000,
) -> Dict[str, Any]:
    """Create a ready-to-send GPT code-generation prompt from a context pack."""
    return _call_coding_engine_tool(
        action="make_generation_prompt",
        payload={"code": code},
        params={"task": task, "language": language, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens},
    )


def coding_generate_script(
    task: str,
    language: str = "python",
    name: str = "generated_script",
    code: str = "",
    project_root: str = "",
    max_snippets: int = 24,
    max_tokens: int = 8000,
) -> Dict[str, Any]:
    """Generate a starter script/module template with context pack metadata."""
    return _call_coding_engine_tool(
        action="generate_script",
        payload={"code": code},
        params={"task": task, "language": language, "name": name, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens},
    )


def coding_generate_module(
    task: str,
    language: str = "python",
    module_name: str = "generated_module",
    code: str = "",
    project_root: str = "",
    max_snippets: int = 24,
    max_tokens: int = 8000,
) -> Dict[str, Any]:
    """Generate a module template with imports, dataclasses/helpers, and context pack metadata."""
    return _call_coding_engine_tool(
        action="generate_module",
        payload={"code": code},
        params={"task": task, "language": language, "module_name": module_name, "project_root": project_root, "max_snippets": max_snippets, "max_tokens": max_tokens},
    )


def coding_generate_class(
    task: str,
    language: str = "python",
    class_name: str = "GeneratedClass",
    code: str = "",
    project_root: str = "",
) -> Dict[str, Any]:
    """Generate a class skeleton for a task."""
    return _call_coding_engine_tool(
        action="generate_class",
        payload={"code": code},
        params={"task": task, "language": language, "class_name": class_name, "project_root": project_root},
    )


def coding_generate_function(
    task: str,
    language: str = "python",
    function_name: str = "generated_function",
    code: str = "",
    project_root: str = "",
) -> Dict[str, Any]:
    """Generate a function skeleton for a task."""
    return _call_coding_engine_tool(
        action="generate_function",
        payload={"code": code},
        params={"task": task, "language": language, "function_name": function_name, "project_root": project_root},
    )


def coding_generate_cli(
    task: str,
    language: str = "python",
    name: str = "generated_cli",
    code: str = "",
    project_root: str = "",
) -> Dict[str, Any]:
    """Generate a CLI script scaffold."""
    return _call_coding_engine_tool(
        action="generate_cli",
        payload={"code": code},
        params={"task": task, "language": language, "name": name, "project_root": project_root},
    )


def coding_generate_gui(
    task: str,
    language: str = "python",
    name: str = "generated_gui",
    code: str = "",
    project_root: str = "",
) -> Dict[str, Any]:
    """Generate a GUI script scaffold."""
    return _call_coding_engine_tool(
        action="generate_gui",
        payload={"code": code},
        params={"task": task, "language": language, "name": name, "project_root": project_root},
    )


def coding_generate_engine(
    task: str,
    language: str = "python",
    name: str = "generated_engine",
    code: str = "",
    project_root: str = "",
) -> Dict[str, Any]:
    """Generate a local engine scaffold with tool-style entrypoint."""
    return _call_coding_engine_tool(
        action="generate_engine",
        payload={"code": code},
        params={"task": task, "language": language, "name": name, "project_root": project_root},
    )


def coding_generate_tool_wrapper(
    task: str = "Generate tools.py wrapper for this engine.",
    engine_name: str = "coding_engine",
    language: str = "python",
    code: str = "",
) -> Dict[str, Any]:
    """Generate a tools.py wrapper snippet for an engine."""
    return _call_coding_engine_tool(
        action="generate_tool_wrapper",
        payload={"code": code},
        params={"task": task, "engine_name": engine_name, "language": language},
    )


def coding_generate_tests(
    task: str,
    language: str = "python",
    code: str = "",
    project_root: str = "",
) -> Dict[str, Any]:
    """Generate test scaffold/prompt for code."""
    return _call_coding_engine_tool(action="generate_tests", payload={"code": code}, params={"task": task, "language": language, "project_root": project_root})


def coding_generate_requirements(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Generate likely requirements/dependencies from code imports."""
    return _call_coding_engine_tool(action="generate_requirements", payload=code, params={"code": code, "language": language})


def coding_complete_code(
    prefix: str,
    task: str = "complete this code",
    language: str = "python",
    project_root: str = "",
) -> Dict[str, Any]:
    """Complete a partial code prefix using context-pack hints."""
    return _call_coding_engine_tool(action="complete_code", payload=prefix, params={"prefix": prefix, "task": task, "language": language, "project_root": project_root})


def coding_repair_code(
    code: str,
    language: str = "python",
    error: str = "",
) -> Dict[str, Any]:
    """Repair simple generated-code syntax issues and return a diff."""
    return _call_coding_engine_tool(action="repair_code", payload=code, params={"code": code, "language": language, "error": error})


def coding_rewrite_code(
    code: str,
    instructions: str = "Rewrite for clarity without changing behavior.",
    language: str = "python",
    project_root: str = "",
) -> Dict[str, Any]:
    """Build a rewrite prompt/pack for existing code."""
    return _call_coding_engine_tool(action="rewrite_code", payload=code, params={"code": code, "instructions": instructions, "task": instructions, "language": language, "project_root": project_root})


def coding_convert_code(
    code: str,
    source_language: str = "",
    target_language: str = "python",
    project_root: str = "",
) -> Dict[str, Any]:
    """Build a conversion prompt/pack between programming languages."""
    return _call_coding_engine_tool(action="convert_code", payload=code, params={"code": code, "source_language": source_language, "target_language": target_language, "language": target_language, "project_root": project_root})


def coding_validate_syntax(
    code: str,
    language: str = "python",
    filename: str = "<coding_engine>",
) -> Dict[str, Any]:
    """Validate generated code syntax without executing it."""
    return _call_coding_engine_tool(action="validate_syntax", payload=code, params={"code": code, "language": language, "filename": filename})


def coding_format_generated_code(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Format generated code using Black if installed, otherwise dedent/clean."""
    return _call_coding_engine_tool(action="format_generated_code", payload=code, params={"code": code, "language": language})


def coding_score_generated_code(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Score generated code structure and syntax quality."""
    return _call_coding_engine_tool(action="score_generated_code", payload=code, params={"code": code, "language": language})


def coding_explain_code_error(
    error: str,
    code: str = "",
    language: str = "python",
) -> Dict[str, Any]:
    """Explain a code-generation or traceback error and suggest repair context."""
    return _call_coding_engine_tool(action="explain_code_error", payload=error, params={"error": error, "code": code, "language": language})


def coding_explain_syntax(
    code: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Explain syntax validation failures with pointer/suggestions."""
    return _call_coding_engine_tool(action="explain_syntax", payload=code, params={"code": code, "language": language})


def _coding_common_schema(required: Optional[List[str]] = None) -> Dict[str, Any]:
    return _schema(
        {
            "task": {"type": "string", "description": "Coding task or generation goal."},
            "query": {"type": "string", "description": "Search/query text for snippets or syntax."},
            "code": {"type": "string", "description": "Code, snippets, or partial code to analyze/use."},
            "payload": {"description": "Generic string/object payload."},
            "language": {"type": "string", "default": "python"},
            "project_root": {"type": "string", "description": "Optional local project folder to mine snippets from."},
            "max_snippets": {"type": "integer", "minimum": 1, "maximum": 200, "default": 24},
            "max_tokens": {"type": "integer", "minimum": 500, "maximum": 200000, "default": 8000},
            "max_chars": {"type": "integer", "minimum": 100, "maximum": 2000000, "default": 120000},
            "name": {"type": "string"},
            "module_name": {"type": "string"},
            "class_name": {"type": "string"},
            "function_name": {"type": "string"},
            "engine_name": {"type": "string"},
            "instructions": {"type": "string"},
            "prefix": {"type": "string"},
            "error": {"type": "string"},
            "filename": {"type": "string"},
            "source": {"type": "string"},
            "source_language": {"type": "string"},
            "target_language": {"type": "string"},
            "params": {"type": "object", "additionalProperties": True},
        },
        required=required or [],
    )


def _register_coding_engine_tools(tools: ToolRegistry) -> None:
    """Register coding_engine.py code-generation support tools without changing old tool signatures."""
    tools.register(
        ToolSpec(
            name="coding_engine",
            description=(
                "Generic local code-generation support brain. Use for tokenizing code, extracting symbols/imports/"
                "signatures/docstrings/patterns, ranking snippets, building token/syntax/context packs, making generation "
                "prompts, generating starter scripts/modules/classes/functions/engines/tool wrappers/tests/requirements, "
                "validating/repairing/formatting/scoring generated code. Does not execute code."
            ),
            parameters=_coding_engine_schema(),
            fn=coding_engine,
        )
    )

    tools.register(ToolSpec(name="coding_engine_status", description="Return coding_engine availability and supported actions.", parameters=_schema({}), fn=lambda: coding_engine_status()))
    tools.register(ToolSpec(name="coding_tokenize_code", description="Tokenize code for GPT context packing.", parameters=_coding_common_schema(["code"]), fn=coding_tokenize_code))
    tools.register(ToolSpec(name="coding_parse_code", description="Parse code and return syntax/node summary.", parameters=_coding_common_schema(["code"]), fn=coding_parse_code))
    tools.register(ToolSpec(name="coding_extract_symbols", description="Extract classes, functions, methods, signatures, and docstrings from code.", parameters=_coding_common_schema(["code"]), fn=coding_extract_symbols))
    tools.register(ToolSpec(name="coding_extract_imports", description="Extract imports/includes/usings from code.", parameters=_coding_common_schema(["code"]), fn=coding_extract_imports))
    tools.register(ToolSpec(name="coding_extract_signatures", description="Extract reusable function/class signatures from code.", parameters=_coding_common_schema(["code"]), fn=coding_extract_signatures))
    tools.register(ToolSpec(name="coding_extract_docstrings", description="Extract module/class/function docstrings or doc comments from code.", parameters=_coding_common_schema(["code"]), fn=coding_extract_docstrings))
    tools.register(ToolSpec(name="coding_extract_dependencies", description="Extract likely external dependencies from code imports.", parameters=_coding_common_schema(["code"]), fn=coding_extract_dependencies))
    tools.register(ToolSpec(name="coding_extract_style", description="Extract coding style signals such as indentation, line length, quotes, type hints, dataclasses, and main guard.", parameters=_coding_common_schema(["code"]), fn=coding_extract_style))
    tools.register(ToolSpec(name="coding_extract_patterns", description="Extract reusable syntax/design patterns from code.", parameters=_coding_common_schema(["code"]), fn=coding_extract_patterns))
    tools.register(ToolSpec(name="coding_search_snippets", description="Search/rank snippets from supplied code or a local project for a code-generation task.", parameters=_coding_common_schema(["query"]), fn=coding_search_snippets))
    tools.register(ToolSpec(name="coding_build_token_pack", description="Build a compact token-focused pack for code generation.", parameters=_coding_common_schema(["task"]), fn=coding_build_token_pack))
    tools.register(ToolSpec(name="coding_build_syntax_pack", description="Build a syntax/snippet pack for code generation.", parameters=_coding_common_schema(["task"]), fn=coding_build_syntax_pack))
    tools.register(ToolSpec(name="coding_build_context_pack", description="Build the main GPT code-generation context pack: imports, symbols, signatures, snippets, tokens, patterns, and constraints.", parameters=_coding_common_schema(["task"]), fn=coding_build_context_pack))
    tools.register(ToolSpec(name="coding_make_generation_prompt", description="Create a ready-to-send GPT code-generation prompt from a context pack.", parameters=_coding_common_schema(["task"]), fn=coding_make_generation_prompt))
    tools.register(ToolSpec(name="coding_generate_script", description="Generate a starter script/template with context pack metadata.", parameters=_coding_common_schema(["task"]), fn=coding_generate_script))
    tools.register(ToolSpec(name="coding_generate_module", description="Generate a module template with imports, helpers, and context pack metadata.", parameters=_coding_common_schema(["task"]), fn=coding_generate_module))
    tools.register(ToolSpec(name="coding_generate_class", description="Generate a class skeleton for a task.", parameters=_coding_common_schema(["task"]), fn=coding_generate_class))
    tools.register(ToolSpec(name="coding_generate_function", description="Generate a function skeleton for a task.", parameters=_coding_common_schema(["task"]), fn=coding_generate_function))
    tools.register(ToolSpec(name="coding_generate_cli", description="Generate a CLI script scaffold.", parameters=_coding_common_schema(["task"]), fn=coding_generate_cli))
    tools.register(ToolSpec(name="coding_generate_gui", description="Generate a GUI script scaffold.", parameters=_coding_common_schema(["task"]), fn=coding_generate_gui))
    tools.register(ToolSpec(name="coding_generate_engine", description="Generate a local engine scaffold with a tool-style entrypoint.", parameters=_coding_common_schema(["task"]), fn=coding_generate_engine))
    tools.register(ToolSpec(name="coding_generate_tool_wrapper", description="Generate a tools.py wrapper snippet for an engine.", parameters=_coding_common_schema([]), fn=coding_generate_tool_wrapper))
    tools.register(ToolSpec(name="coding_generate_tests", description="Generate test scaffold/prompt for code.", parameters=_coding_common_schema(["task"]), fn=coding_generate_tests))
    tools.register(ToolSpec(name="coding_generate_requirements", description="Generate likely requirements/dependencies from code imports.", parameters=_coding_common_schema(["code"]), fn=coding_generate_requirements))
    tools.register(ToolSpec(name="coding_complete_code", description="Complete a partial code prefix using context-pack hints.", parameters=_coding_common_schema(["prefix"]), fn=coding_complete_code))
    tools.register(ToolSpec(name="coding_repair_code", description="Repair simple generated-code syntax issues and return a diff.", parameters=_coding_common_schema(["code"]), fn=coding_repair_code))
    tools.register(ToolSpec(name="coding_rewrite_code", description="Build a rewrite prompt/pack for existing code.", parameters=_coding_common_schema(["code"]), fn=coding_rewrite_code))
    tools.register(ToolSpec(name="coding_convert_code", description="Build a conversion prompt/pack between programming languages.", parameters=_coding_common_schema(["code"]), fn=coding_convert_code))
    tools.register(ToolSpec(name="coding_validate_syntax", description="Validate generated code syntax without executing it.", parameters=_coding_common_schema(["code"]), fn=coding_validate_syntax))
    tools.register(ToolSpec(name="coding_format_generated_code", description="Format generated code using Black if installed, otherwise dedent/clean.", parameters=_coding_common_schema(["code"]), fn=coding_format_generated_code))
    tools.register(ToolSpec(name="coding_score_generated_code", description="Score generated code structure and syntax quality.", parameters=_coding_common_schema(["code"]), fn=coding_score_generated_code))
    tools.register(ToolSpec(name="coding_explain_code_error", description="Explain a code-generation or traceback error and suggest repair context.", parameters=_coding_common_schema(["error"]), fn=coding_explain_code_error))
    tools.register(ToolSpec(name="coding_explain_syntax", description="Explain syntax validation failures with pointer/suggestions.", parameters=_coding_common_schema(["code"]), fn=coding_explain_syntax))

# ======================= Shared Standalone APIDoc Engine Integration ========
def _apidoc_engine_available() -> bool:
    return (
        engine_apidoc_engine is not None
        and engine_apidoc_engine_tool_schema is not None
        and engine_make_apidoc_engine_tool_function is not None
    )


def _apidoc_engine_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "apidoc_engine_available": False,
        "error": "standalone_apidoc_engine.py is not importable. Put standalone_apidoc_engine.py beside tools.py.",
    }


def _apidoc_engine_schema() -> Dict[str, Any]:
    if engine_apidoc_engine_tool_schema is not None:
        try:
            schema = engine_apidoc_engine_tool_schema()
            if isinstance(schema, dict):
                return schema
        except Exception:
            pass

    return {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "status",
                    "profiles",
                    "catalog",
                    "parse",
                    "discover",
                    "fetch",
                    "report",
                    "markdown",
                ],
                "default": "report",
                "description": "APIDoc engine operation.",
            },
            "query": {
                "type": "string",
                "default": "",
                "description": "Single APIDoc query, e.g. python: subprocess.run.",
            },
            "queries": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
                "description": "Multiple APIDoc queries.",
            },
            "profile": {"type": "string", "default": "all"},
            "output_style": {"type": "string", "default": "advanced_report"},
            "include_bundle": {"type": "boolean", "default": True},
            "include_markdown": {"type": "boolean", "default": True},
            "max_markdown_chars": {"type": "integer", "default": 0},
            "search_fallback": {"type": "boolean", "default": False},
            "crawl_direct_pages": {"type": "boolean", "default": False},
            "max_pages_per_query": {"type": "integer", "minimum": 1, "maximum": 80, "default": 2},
            "max_direct_urls_per_query": {"type": "integer", "minimum": 1, "maximum": 100, "default": 8},
            "max_links_per_page": {"type": "integer", "minimum": 0, "maximum": 800, "default": 20},
            "max_chars_per_page": {"type": "integer", "minimum": 500, "maximum": 250000, "default": 8000},
            "timeout": {"type": "integer", "minimum": 2, "maximum": 120, "default": 20},
            "out_path": {"type": "string", "default": ""},
            "cache_dir": {"type": "string", "default": ".apidoc_cache"},
            "params": {"type": "object", "additionalProperties": True, "default": {}},
        },
        "required": ["action"],
        "additionalProperties": False,
    }


def _make_apidoc_engine_fn() -> Callable[..., Dict[str, Any]]:
    if engine_make_apidoc_engine_tool_function is not None:
        try:
            fn = engine_make_apidoc_engine_tool_function()
            if callable(fn):
                return fn
        except Exception:
            pass

    def _unavailable(
        action: str = "report",
        query: str = "",
        queries: Optional[List[str]] = None,
        profile: str = "all",
        output_style: str = "advanced_report",
        params: Optional[Dict[str, Any]] = None,
        include_bundle: bool = True,
        include_markdown: bool = True,
        max_markdown_chars: int = 0,
        search_fallback: bool = False,
        crawl_direct_pages: bool = False,
        max_pages_per_query: int = 2,
        max_direct_urls_per_query: int = 8,
        max_links_per_page: int = 20,
        max_chars_per_page: int = 8000,
        timeout: int = 20,
        out_path: str = "",
        cache_dir: str = ".apidoc_cache",
    ) -> Dict[str, Any]:
        result = _apidoc_engine_unavailable_result()
        result.update(
            {
                "action": action,
                "query": query,
                "queries": queries or [],
                "profile": profile,
                "output_style": output_style,
                "params": params or {},
                "include_bundle": include_bundle,
                "include_markdown": include_markdown,
                "max_markdown_chars": max_markdown_chars,
                "search_fallback": search_fallback,
                "crawl_direct_pages": crawl_direct_pages,
                "max_pages_per_query": max_pages_per_query,
                "max_direct_urls_per_query": max_direct_urls_per_query,
                "max_links_per_page": max_links_per_page,
                "max_chars_per_page": max_chars_per_page,
                "timeout": timeout,
                "out_path": out_path,
                "cache_dir": cache_dir,
            }
        )
        return result

    return _unavailable


def apidoc_engine_tool(
    action: str = "report",
    query: str = "",
    queries: Optional[List[str]] = None,
    profile: str = "all",
    output_style: str = "advanced_report",
    params: Optional[Dict[str, Any]] = None,
    include_bundle: bool = True,
    include_markdown: bool = True,
    max_markdown_chars: int = 0,
    search_fallback: bool = False,
    crawl_direct_pages: bool = False,
    max_pages_per_query: int = 2,
    max_direct_urls_per_query: int = 8,
    max_links_per_page: int = 20,
    max_chars_per_page: int = 8000,
    timeout: int = 20,
    out_path: str = "",
    cache_dir: str = ".apidoc_cache",
) -> Dict[str, Any]:
    if engine_apidoc_engine is None:
        result = _apidoc_engine_unavailable_result()
        result.update(
            {
                "action": action,
                "query": query,
                "queries": queries or [],
                "profile": profile,
                "output_style": output_style,
                "params": params or {},
                "include_bundle": include_bundle,
                "include_markdown": include_markdown,
                "max_markdown_chars": max_markdown_chars,
                "search_fallback": search_fallback,
                "crawl_direct_pages": crawl_direct_pages,
                "max_pages_per_query": max_pages_per_query,
                "max_direct_urls_per_query": max_direct_urls_per_query,
                "max_links_per_page": max_links_per_page,
                "max_chars_per_page": max_chars_per_page,
                "timeout": timeout,
                "out_path": out_path,
                "cache_dir": cache_dir,
            }
        )
        return result

    try:
        data = engine_apidoc_engine(
            action=action,
            query=query,
            queries=queries,
            profile=profile,
            output_style=output_style,
            params=params,
            include_bundle=include_bundle,
            include_markdown=include_markdown,
            max_markdown_chars=max_markdown_chars,
            search_fallback=search_fallback,
            crawl_direct_pages=crawl_direct_pages,
            max_pages_per_query=max_pages_per_query,
            max_direct_urls_per_query=max_direct_urls_per_query,
            max_links_per_page=max_links_per_page,
            max_chars_per_page=max_chars_per_page,
            timeout=timeout,
            out_path=out_path,
            cache_dir=cache_dir,
        )
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("ok", True)
            out["apidoc_engine_available"] = _apidoc_engine_available()
            return out
        return {"ok": True, "apidoc_engine_available": _apidoc_engine_available(), "result": data}
    except Exception as exc:
        return {"ok": False, "apidoc_engine_available": _apidoc_engine_available(), "error": str(exc)}


# ======================= Standalone APIDoc Engine Registration ==============
def _register_apidoc_engine_tools(tools: ToolRegistry) -> None:
    """Register standalone_apidoc_engine.py's direct-first APIDoc tool."""
    tools.register(
        ToolSpec(
            name="apidoc_engine",
            description=(
                "Standalone direct-first API documentation engine. Resolves and fetches official docs "
                "for Python stdlib, NumPy, SciPy, Python packages, .NET/C#, C++, web APIs, Bannerlord, "
                "Monero, and other configured sources so the GPT can learn from grounded APIDocs."
            ),
            parameters=_apidoc_engine_schema(),
            fn=apidoc_engine_tool if engine_make_apidoc_engine_tool_function is None else _make_apidoc_engine_fn(),
        )
    )





# ======================= Shared Tracker Engine Integration =================
def _tracker_engine_available() -> bool:
    return (
        engine_tracker_engine_tool is not None
        or engine_make_tracker_engine_tool_function is not None
        or engine_TrackerEngine is not None
    )


def _tracker_engine_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "tracker_engine_available": False,
        "error": (
            "tracker_engine.py is not importable from the tools.py directory. "
            "Put tracker_engine.py beside tools.py and check last_import_error."
        ),
        "last_import_error": globals().get("_TRACKER_ENGINE_LAST_IMPORT_ERROR", ""),
        "import_attempts": globals().get("_TRACKER_ENGINE_IMPORT_ATTEMPTS", []),
    }



# Real actions exposed by the standalone tracker_engine.py build.
# These are the actions the engine itself understands. GPT-facing wrappers below
# may accept friendlier aliases like "search" or "crawl", but those aliases are
# normalized before the engine is called.
TRACKER_ENGINE_REAL_ACTIONS = [
    "database_stats",
    "db_stats",
    "help",
    "js_sniff",
    "linktracker",
    "network_sniff",
    "oniontracker",
    "pagetracker",
    "parse_urls",
    "runtime_sniff",
    "tool_schema",
    "track_links",
    "track_onion",
    "track_pages",
    "track_video",
    "videotracker",
]

# GPT-friendly aliases. These fix the old wrapper/action mismatch where
# tracker_search sent action="search" and tracker_crawl sent action="crawl",
# even though the standalone tracker engine exposes track_links/track_pages.
TRACKER_ACTION_ALIASES = {
    "": "help",
    "status": "help",
    "schema": "tool_schema",
    "tool_schema": "tool_schema",
    "database": "db_stats",
    "database_stats": "db_stats",
    "db": "db_stats",
    "db_stats": "db_stats",
    "db_search": "db_stats",
    "search": "track_links",
    "tracker_search": "track_links",
    "links": "track_links",
    "link": "track_links",
    "linktracker": "track_links",
    "track_links": "track_links",
    "crawl": "track_pages",
    "crawler": "track_pages",
    "tracker_crawl": "track_pages",
    "pages": "track_pages",
    "page": "track_pages",
    "pagetracker": "track_pages",
    "track_pages": "track_pages",
    "video": "track_video",
    "videos": "track_video",
    "media": "track_video",
    "audio": "track_video",
    "videotracker": "track_video",
    "track_video": "track_video",
    "onion": "track_onion",
    "tor": "track_onion",
    "tor_block": "track_onion",
    "oniontracker": "track_onion",
    "track_onion": "track_onion",
    "parse": "parse_urls",
    "parse_url": "parse_urls",
    "parse_urls": "parse_urls",
    "extract_urls": "parse_urls",
    "scan_payload": "parse_urls",
    "classify_urls": "parse_urls",
    "classify": "parse_urls",
    "js": "js_sniff",
    "js_sniff": "js_sniff",
    "runtime": "runtime_sniff",
    "runtime_sniff": "runtime_sniff",
    "network": "network_sniff",
    "network_sniff": "network_sniff",
    "export": "track_pages",
    "export_json": "track_pages",
    "export_markdown": "track_pages",
}


def _coerce_tracker_params(params: Any = None) -> Dict[str, Any]:
    """Accept dict params, JSON-string params, or loose values from GPT tool calls."""
    if params is None:
        return {}
    if isinstance(params, dict):
        return dict(params)
    if isinstance(params, str):
        raw = params.strip()
        if not raw:
            return {}
        try:
            decoded = json.loads(raw)
            if isinstance(decoded, dict):
                return dict(decoded)
            return {"value": decoded}
        except Exception:
            return {"raw_params": params}
    return {"value": params}


def _normalize_tracker_action(action: Any) -> str:
    raw = str(action or "").strip()
    key = raw.lower().replace("-", "_").replace(" ", "_")
    return TRACKER_ACTION_ALIASES.get(key, raw or "help")


def _tracker_seed_from_kwargs(payload: Any = None, params: Optional[Dict[str, Any]] = None) -> Any:
    """Pick the best seed payload when GPT sends query/url/text instead of payload."""
    if payload not in (None, ""):
        return payload
    params = params or {}
    for key in ("payload", "url", "onion_link", "query", "text", "context"):
        value = params.get(key)
        if value not in (None, ""):
            return value
    return payload

def _fallback_tracker_engine_tool_schema() -> Dict[str, Any]:
    actions = sorted(set(TRACKER_ENGINE_REAL_ACTIONS) | set(TRACKER_ACTION_ALIASES.keys()))
    return {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": actions,
                "description": (
                    "Tracker action. GPT-friendly aliases like search/crawl/linktracker/track_links "
                    "are accepted and normalized to the standalone tracker engine actions."
                ),
            },
            "payload": {
                "description": "Input URL, pasted text/HTML/JSON/code, list of URLs, or seed payload.",
            },
            "query": {
                "type": "string",
                "description": "Optional query alias. If action/payload are omitted, this becomes the payload for track_links.",
            },
            "url": {
                "type": "string",
                "description": "Optional URL alias. If payload is omitted, this becomes the payload.",
            },
            "context": {
                "type": "string",
                "description": "Optional research context. Passed through params.",
            },
            "mode": {
                "type": "string",
                "description": "Optional mode hint. Passed through params.",
            },
            "params": {
                "type": "object",
                "description": "Optional tracker params such as max_depth, timeout_sec, use_js, use_database, allow_onion, tor_socks_url.",
                "additionalProperties": True,
            },
        },
        "required": [],
        "additionalProperties": True,
    }


def _augment_tracker_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Make imported tracker schemas tolerant of GPT aliases without changing engine code."""
    out = dict(schema or {})
    out.setdefault("type", "object")
    props = dict(out.get("properties") or {})
    action_prop = dict(props.get("action") or {"type": "string"})
    enum_values = set(action_prop.get("enum") or [])
    enum_values.update(TRACKER_ENGINE_REAL_ACTIONS)
    enum_values.update(TRACKER_ACTION_ALIASES.keys())
    action_prop["enum"] = sorted(str(x) for x in enum_values if str(x))
    action_prop.setdefault(
        "description",
        "Tracker action. Aliases like search/crawl/linktracker are normalized before engine execution.",
    )
    props["action"] = action_prop
    props.setdefault("payload", {"description": "URL, text, list, dict, or seed payload."})
    props.setdefault("query", {"type": "string", "description": "Query alias used as payload when payload is absent."})
    props.setdefault("url", {"type": "string", "description": "URL alias used as payload when payload is absent."})
    props.setdefault("context", {"type": "string", "description": "Optional context passed through params."})
    props.setdefault("mode", {"type": "string", "description": "Optional mode hint passed through params."})
    props.setdefault("params", {"type": "object", "additionalProperties": True})
    out["properties"] = props
    out["required"] = []
    out["additionalProperties"] = True
    return out


def _tracker_engine_schema() -> Dict[str, Any]:
    if engine_tracker_engine_tool_schema is not None:
        try:
            schema = engine_tracker_engine_tool_schema()
            if isinstance(schema, dict):
                return _augment_tracker_schema(schema)
        except Exception:
            pass

    if isinstance(engine_TRACKER_ENGINE_TOOL_SPEC, dict):
        try:
            params = engine_TRACKER_ENGINE_TOOL_SPEC.get("parameters")
            if isinstance(params, dict):
                return _augment_tracker_schema(params)
        except Exception:
            pass

    return _fallback_tracker_engine_tool_schema()


def _make_tracker_engine_fn() -> Callable[..., Dict[str, Any]]:
    if engine_make_tracker_engine_tool_function is not None:
        try:
            fn = engine_make_tracker_engine_tool_function()
            if callable(fn):
                return fn
        except Exception:
            pass

    if callable(engine_tracker_engine_tool):
        return engine_tracker_engine_tool

    if engine_TrackerEngine is not None:
        try:
            engine = engine_TrackerEngine()

            def _engine_direct(
                action: str,
                payload: Any = None,
                params: Optional[Dict[str, Any]] = None,
            ) -> Dict[str, Any]:
                if hasattr(engine, "run"):
                    return engine.run(action, payload, params or {})
                if hasattr(engine, "arun"):
                    import asyncio as _tracker_asyncio
                    return _tracker_asyncio.run(engine.arun(action, payload, params or {}))
                return {
                    "ok": False,
                    "tracker_engine_available": True,
                    "error": "TrackerEngine object has no run/arun method.",
                }

            return _engine_direct
        except Exception:
            pass

    def _unavailable(
        action: str,
        payload: Any = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = _tracker_engine_unavailable_result()
        result["action"] = action
        return result

    return _unavailable


def _call_tracker_engine_tool(
    action: str,
    payload: Any = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    fn = _make_tracker_engine_fn()
    merged_params = _coerce_tracker_params(params)

    # If a wrapper passed a generic action like "search" but GPT supplied the real
    # action inside params, honor it. Otherwise normalize the wrapper action.
    requested_action = action
    params_action = merged_params.get("action")
    if params_action not in (None, "") and str(requested_action or "").strip().lower() in {
        "", "search", "crawl", "scan_payload", "classify_urls", "export_json", "export_markdown"
    }:
        requested_action = params_action
    merged_params.pop("action", None)

    fixed_action = _normalize_tracker_action(requested_action)
    fixed_payload = _tracker_seed_from_kwargs(payload, merged_params)

    # Export aliases run through track_pages but preserve requested output intent.
    raw_key = str(requested_action or "").strip().lower().replace("-", "_").replace(" ", "_")
    if raw_key in {"export_json", "json"}:
        merged_params.setdefault("export_format", "json")
    elif raw_key in {"export_markdown", "markdown", "md"}:
        merged_params.setdefault("export_format", "markdown")

    try:
        data = fn(action=fixed_action, payload=fixed_payload, params=merged_params)
    except TypeError:
        try:
            data = fn(fixed_action, fixed_payload, merged_params)
        except Exception as exc:
            return {
                "ok": False,
                "tracker_engine_available": _tracker_engine_available(),
                "tool": "tracker_engine",
                "requested_action": action,
                "action": fixed_action,
                "payload": fixed_payload,
                "error": str(exc),
            }
    except Exception as exc:
        return {
            "ok": False,
            "tracker_engine_available": _tracker_engine_available(),
            "tool": "tracker_engine",
            "requested_action": action,
            "action": fixed_action,
            "payload": fixed_payload,
            "error": str(exc),
        }

    if isinstance(data, dict):
        out = dict(data)
        out.setdefault("ok", True)
        out["tracker_engine_available"] = _tracker_engine_available()
        out["tool"] = "tracker_engine"
        out.setdefault("requested_action", action)
        out.setdefault("action", fixed_action)
        return out

    return {
        "ok": True,
        "tracker_engine_available": _tracker_engine_available(),
        "tool": "tracker_engine",
        "requested_action": action,
        "action": fixed_action,
        "result": data,
    }


# ----------------------- GPT Tor / Onion Param Normalization ----------------
def _tool_bool(value: Any, default: bool = False) -> bool:
    """Parse loose GPT/tool booleans without rejecting old callers."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if not s:
        return default
    if s in {"1", "true", "yes", "y", "on", "enable", "enabled", "js", "javascript", "browser", "playwright"}:
        return True
    if s in {"0", "false", "no", "n", "off", "disable", "disabled", "none", "http", "requests", "static"}:
        return False
    return default


def _normalize_tor_proxy_value(value: str = "") -> str:
    """Return a DNS-safe Tor SOCKS URL. Tor Browser normally listens on 9150."""
    raw = str(value or "").strip() or DEFAULT_TOR_SOCKS_URL
    if raw.startswith(("socks5://", "socks5h://", "http://", "https://")):
        return raw
    if raw.startswith("127.0.0.1:") or raw.startswith("localhost:"):
        return "socks5h://" + raw
    if raw.isdigit():
        return f"socks5h://127.0.0.1:{raw}"
    return raw


def _is_onion_url(value: str) -> bool:
    try:
        normalized = _normalize_url(value)
        host = urlparse(normalized).netloc.lower().split(":", 1)[0]
        return host.endswith(".onion")
    except Exception:
        return str(value or "").strip().lower().split("/", 1)[0].endswith(".onion")


def _normalize_tor_tracker_params(
    params: Optional[Dict[str, Any]] = None,
    *,
    tor_socks_url: str = "",
    use_js: Any = None,
    js_mode: str = "",
) -> Dict[str, Any]:
    """
    Normalize all aliases the GPT might use for the Tor tracker path.

    use_js=false/"http"  -> requests/static Tor crawl through SOCKS.
    use_js=true/"browser" -> browser/Playwright crawl through the same Tor proxy.
    """
    merged: Dict[str, Any] = dict(params or {})

    # Pull JavaScript intent from direct args first, then common aliases in params.
    mode = str(js_mode or merged.get("js_mode") or merged.get("browser_mode") or "").strip().lower()
    js_requested = None
    if use_js is not None:
        js_requested = _tool_bool(use_js, False)
    elif mode in {"on", "true", "yes", "js", "javascript", "browser", "playwright", "render", "rendered"}:
        js_requested = True
    elif mode in {"off", "false", "no", "http", "requests", "static", "raw", "none"}:
        js_requested = False
    else:
        for key in ("use_js", "javascript", "javascript_enabled", "render_js", "use_playwright", "playwright"):
            if key in merged:
                js_requested = _tool_bool(merged.get(key), False)
                break
    if js_requested is None:
        js_requested = False

    proxy_value = (
        tor_socks_url
        or str(merged.get("tor_proxy") or "")
        or str(merged.get("tor_socks_url") or "")
        or DEFAULT_TOR_SOCKS_URL
    )
    tor_proxy = _normalize_tor_proxy_value(proxy_value)

    # Guard/transport flags expected by tracker/sniffer variants.
    merged["allow_onion"] = True
    merged["tor_proxy"] = tor_proxy
    merged["tor_socks_url"] = tor_proxy
    merged["use_tor"] = True
    merged["route_through_tor"] = True

    # JS flags for both tracker_engine and sniffer/playwright-style engines.
    merged["use_js"] = bool(js_requested)
    merged["javascript"] = bool(js_requested)
    merged["javascript_enabled"] = bool(js_requested)
    merged["render_js"] = bool(js_requested)
    merged["use_playwright"] = bool(js_requested)
    merged["browser_mode"] = "playwright" if js_requested else "requests"
    merged["js_mode"] = "browser" if js_requested else "http"
    return merged


def tor_block(
    onion_link: str,
    action: str = "track_onion",
    use_js: bool = False,
    params: Optional[Dict[str, Any]] = None,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
) -> Dict[str, Any]:
    """
    GPT-facing Tor block wrapper.

    It keeps Tor/onion defaults out of the prompt: allow_onion is always enabled,
    tor_proxy defaults to Tor Browser's 9150 SOCKS port, and the GPT can choose
    static HTTP mode or JavaScript/browser mode with use_js.
    """
    target = _normalize_url(onion_link)
    normalized_action = str(action or "track_onion").strip().lower()
    merged = _normalize_tor_tracker_params(params, tor_socks_url=tor_socks_url, use_js=use_js)
    merged.setdefault("onion_link", target)

    # Friendly aliases so the model can say browse/links/crawl without knowing
    # the exact engine action names.
    action_aliases = {
        "onion": "track_onion",
        "track": "track_onion",
        "track_onion": "track_onion",
        "crawl": "track_onion" if _is_onion_url(target) else "crawl",
        "links": "track_links",
        "track_links": "track_links",
        "pages": "track_pages",
        "track_pages": "track_pages",
        "video": "track_video",
        "media": "track_video",
        "track_video": "track_video",
        "json": "export_json",
        "export_json": "export_json",
        "markdown": "export_markdown",
        "export_markdown": "export_markdown",
    }
    engine_action = action_aliases.get(normalized_action, normalized_action or "track_onion")

    # Direct Tor browsing fallback/utility. This is useful when tracker_engine is
    # unavailable or when the GPT just wants one rendered/static page.
    if normalized_action in {"browse", "fetch", "sniff", "page"}:
        if merged["use_js"]:
            return sniff_url(
                url=target,
                timeout_sec=int(merged.get("timeout_sec") or merged.get("timeout") or DEFAULT_WEB_TIMEOUT_SEC),
                max_items=int(merged.get("max_items") or 250),
                max_chars=int(merged.get("max_chars") or DEFAULT_MAX_PAGE_CHARS),
                include_html=bool(merged.get("include_html") or False),
                tor_socks_url=merged["tor_proxy"],
                use_playwright=True,
                verify_assets=bool(merged.get("verify_assets", True)),
            )
        return browse_tor(
            url=target,
            max_chars=int(merged.get("max_chars") or DEFAULT_MAX_PAGE_CHARS),
            timeout_sec=int(merged.get("timeout_sec") or merged.get("timeout") or DEFAULT_WEB_TIMEOUT_SEC),
            tor_socks_url=merged["tor_proxy"],
        )

    result = _call_tracker_engine_tool(engine_action, target, merged)
    result.setdefault("tor", {})
    if isinstance(result.get("tor"), dict):
        result["tor"].update({
            "enabled": True,
            "proxy": merged["tor_proxy"],
            "use_js": bool(merged["use_js"]),
            "mode": merged["js_mode"],
        })
    else:
        result["tor"] = {
            "enabled": True,
            "proxy": merged["tor_proxy"],
            "use_js": bool(merged["use_js"]),
            "mode": merged["js_mode"],
        }
    return result


def tracker_engine(
    action: str = "",
    payload: Any = None,
    params: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Generic GPT-facing tracker engine entrypoint.

    Preferred call:
      tracker_engine(action="track_links", payload="https://...", params={...})

    Tolerant GPT call:
      tracker_engine(query="...", context="...", mode="research")

    The tolerant form is accepted because local models often guess query/context
    arguments from other tools. Those extra fields are merged into params and
    query/url becomes payload when payload is absent.
    """
    merged = _coerce_tracker_params(params)
    for key, value in (kwargs or {}).items():
        if value is not None:
            merged.setdefault(key, value)

    if not action:
        action = str(merged.pop("action", "") or "")
    if not action:
        if merged.get("url") or merged.get("onion_link"):
            action = "track_onion" if _is_onion_url(str(merged.get("url") or merged.get("onion_link") or "")) else "track_links"
        elif merged.get("query"):
            action = "track_links"
        else:
            action = "help"

    seed = _tracker_seed_from_kwargs(payload, merged)
    return _call_tracker_engine_tool(action=action, payload=seed, params=merged)


def tracker_parse_urls(
    text: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Extract and classify URLs from pasted text/HTML/JSON/code without crawling."""
    return _call_tracker_engine_tool("parse_urls", text, params)


def tracker_scan_payload(
    payload: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Scan a payload for URLs/assets. Maps to parse_urls for the standalone tracker engine."""
    return _call_tracker_engine_tool("parse_urls", payload, params)


def tracker_classify_urls(
    payload: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Classify/extract URLs without crawling. Maps to parse_urls for the standalone tracker engine."""
    merged = _coerce_tracker_params(params)
    merged.setdefault("classify", True)
    return _call_tracker_engine_tool("parse_urls", payload, merged)


def tracker_search(
    query: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run tracker-engine search-like tracking. Maps GPT search intent to track_links."""
    merged = _coerce_tracker_params(params)
    merged.setdefault("query", query)
    return _call_tracker_engine_tool("track_links", query, merged)


def tracker_crawl(
    payload: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Bounded crawl over URL seeds. Maps GPT crawl intent to track_pages."""
    return _call_tracker_engine_tool("track_pages", payload, params)


def tracker_links(
    payload: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Track links/assets/documents from URL or pasted payload seeds."""
    return _call_tracker_engine_tool("track_links", payload, params)


def tracker_pages(
    payload: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Track relevant page candidates from URL or search seeds."""
    return _call_tracker_engine_tool("track_pages", payload, params)


def tracker_video(
    payload: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Track video/audio/HLS/DASH/media candidates from URL or payload seeds."""
    return _call_tracker_engine_tool("track_video", payload, params)


def tracker_onion(
    onion_link: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Tor-aware onion tracker wrapper. Defaults are GPT-friendly:
    allow_onion=true, Tor SOCKS proxy defaults to 127.0.0.1:9150, and
    params.use_js / params.javascript / params.js_mode chooses static vs JS mode.
    """
    merged = _normalize_tor_tracker_params(params)
    target = _normalize_url(onion_link)
    merged.setdefault("onion_link", target)
    return _call_tracker_engine_tool("track_onion", target, merged)


def tracker_db_stats(
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return tracker engine database counts and item-kind stats."""
    return _call_tracker_engine_tool("db_stats", None, params)


def tracker_db_search(
    query: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Search tracker engine stored pages/items when supported; otherwise returns db stats with query preserved."""
    merged = _coerce_tracker_params(params)
    merged.setdefault("query", query)
    return _call_tracker_engine_tool("db_stats", query, merged)


def tracker_export_json(
    payload: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run tracker pages and request JSON-style export metadata."""
    merged = _coerce_tracker_params(params)
    merged.setdefault("export_format", "json")
    return _call_tracker_engine_tool("track_pages", payload, merged)


def tracker_export_markdown(
    payload: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run tracker pages and request Markdown-style export metadata."""
    merged = _coerce_tracker_params(params)
    merged.setdefault("export_format", "markdown")
    return _call_tracker_engine_tool("track_pages", payload, merged)


# Direct action-name aliases. These are registered as top-level GPT tools too,
# because local models sometimes call the engine action name as if it were a tool.
def track_links(payload: Any, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return tracker_links(payload, params)


def track_pages(payload: Any, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return tracker_pages(payload, params)


def track_video(payload: Any, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return tracker_video(payload, params)


def track_onion(payload: Any = "", onion_link: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return tracker_onion(onion_link or str(payload or ""), params)


def linktracker(payload: Any, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return tracker_links(payload, params)


def pagetracker(payload: Any, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return tracker_pages(payload, params)


def videotracker(payload: Any, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return tracker_video(payload, params)


def oniontracker(payload: Any = "", onion_link: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return tracker_onion(onion_link or str(payload or ""), params)


# ======================= Tracker Engine Tool Registration ==================
def _register_tracker_engine_tools(tools: ToolRegistry) -> None:
    """Register tracker_engine.py tools and action-name aliases for local GPT calls."""
    tracker_payload_schema = _schema(
        {
            "payload": {"description": "URL, pasted text, search query, list of URL seeds, or dict payload."},
            "params": {
                "type": "object",
                "description": "Optional params: max_depth, timeout_sec, use_js, use_database, query, same_host_only, tor_socks_url.",
                "additionalProperties": True,
            },
        },
        required=["payload"],
    )

    tracker_query_schema = _schema(
        {
            "query": {"type": "string"},
            "params": {"type": "object", "additionalProperties": True},
        },
        required=["query"],
    )

    tools.register(
        ToolSpec(
            name="tracker_engine",
            description=(
                "Generic GPT tracker engine. Preferred args: action, payload, params. "
                "Also accepts query/url/context/mode aliases and normalizes search/crawl to track_links/track_pages."
            ),
            parameters=_tracker_engine_schema(),
            fn=tracker_engine,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_parse_urls",
            description="Extract and classify URLs from pasted text/HTML/JSON/code without crawling.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "params": {
                        "type": "object",
                        "description": "Optional tracker params.",
                        "additionalProperties": True,
                    },
                },
                required=["text"],
            ),
            fn=tracker_parse_urls,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_scan_payload",
            description="Scan a pasted payload for tracker URLs/assets without a full crawl. Alias of parse_urls for standalone tracker.",
            parameters=_schema(
                {
                    "payload": {"description": "Text, HTML, JSON, code, list, or dict payload."},
                    "params": {"type": "object", "additionalProperties": True},
                },
                required=["payload"],
            ),
            fn=tracker_scan_payload,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_classify_urls",
            description="Classify one or more URLs into page/video/audio/image/document/code/stream. Alias of parse_urls for standalone tracker.",
            parameters=_schema(
                {
                    "payload": {"description": "One URL, pasted text, or list of URLs."},
                    "params": {"type": "object", "additionalProperties": True},
                },
                required=["payload"],
            ),
            fn=tracker_classify_urls,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_search",
            description="Search-like tracker call. Maps to standalone tracker action track_links.",
            parameters=tracker_query_schema,
            fn=tracker_search,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_crawl",
            description="Bounded crawl over URL seeds. Maps to standalone tracker action track_pages.",
            parameters=tracker_payload_schema,
            fn=tracker_crawl,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_links",
            description="Track links/assets/documents from URL or pasted payload seeds.",
            parameters=tracker_payload_schema,
            fn=tracker_links,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_pages",
            description="Track relevant page candidates from URL/search/payload seeds.",
            parameters=tracker_payload_schema,
            fn=tracker_pages,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_video",
            description="Track video/audio/HLS/DASH/media candidates from URL or payload seeds.",
            parameters=tracker_payload_schema,
            fn=tracker_video,
        )
    )

    # Register direct action-name aliases because GPT often tries to call the
    # engine action as a top-level tool. These all delegate through the safe
    # tracker_* wrappers above.
    alias_specs = [
        ("track_links", "Alias for tracker_links / action track_links.", track_links),
        ("track_pages", "Alias for tracker_pages / action track_pages.", track_pages),
        ("track_video", "Alias for tracker_video / action track_video.", track_video),
        ("linktracker", "Legacy alias for tracker_links.", linktracker),
        ("pagetracker", "Legacy alias for tracker_pages.", pagetracker),
        ("videotracker", "Legacy alias for tracker_video.", videotracker),
    ]
    for alias_name, alias_description, alias_fn in alias_specs:
        tools.register(
            ToolSpec(
                name=alias_name,
                description=alias_description,
                parameters=tracker_payload_schema,
                fn=alias_fn,
            )
        )

    onion_schema = _schema(
        {
            "payload": {"description": "Onion or normal HTTP/HTTPS URL."},
            "onion_link": {"type": "string", "description": "Explicit onion URL alias."},
            "params": {
                "type": "object",
                "description": "Optional: use_js/javascript/js_mode, tor_proxy/tor_socks_url, max_depth, timeout_sec, use_database.",
                "additionalProperties": True,
            },
        },
        required=[],
    )

    tools.register(
        ToolSpec(
            name="tor_block",
            description=(
                "GPT-friendly Tor/onion block. Runs the tracker through Tor with allow_onion=true automatically. "
                "Set use_js=false for static requests mode or use_js=true for JavaScript/browser/Playwright mode."
            ),
            parameters=_schema(
                {
                    "onion_link": {
                        "type": "string",
                        "description": "Onion or normal HTTP/HTTPS URL to route through Tor.",
                    },
                    "action": {
                        "type": "string",
                        "enum": [
                            "track_onion",
                            "crawl",
                            "links",
                            "pages",
                            "video",
                            "media",
                            "browse",
                            "fetch",
                            "sniff",
                            "json",
                            "markdown",
                        ],
                        "description": "What to run. Defaults to track_onion.",
                    },
                    "use_js": {
                        "type": "boolean",
                        "description": "false = static Tor requests; true = JavaScript/browser/Playwright mode through Tor.",
                    },
                    "tor_socks_url": {
                        "type": "string",
                        "description": "Tor SOCKS proxy. Defaults to socks5h://127.0.0.1:9150.",
                    },
                    "params": {
                        "type": "object",
                        "description": "Optional tracker params: max_depth, max_pages_total, max_items, use_database, timeout_sec, include_html, same_host_only, etc.",
                        "additionalProperties": True,
                    },
                },
                required=["onion_link"],
            ),
            fn=tor_block,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_onion",
            description=(
                "Tor-aware onion tracker wrapper. Automatically sets allow_onion=true and a Tor SOCKS proxy. "
                "Set params.use_js=true / params.javascript=true / params.js_mode='browser' for JavaScript mode; "
                "leave false for static Tor requests mode."
            ),
            parameters=_schema(
                {
                    "onion_link": {"type": "string"},
                    "params": {
                        "type": "object",
                        "description": "Optional: use_js/javascript/js_mode, tor_proxy/tor_socks_url, max_depth, max_pages_total, use_database.",
                        "additionalProperties": True,
                    },
                },
                required=["onion_link"],
            ),
            fn=tracker_onion,
        )
    )

    tools.register(ToolSpec(name="track_onion", description="Alias for tracker_onion / action track_onion.", parameters=onion_schema, fn=track_onion))
    tools.register(ToolSpec(name="oniontracker", description="Legacy alias for tracker_onion.", parameters=onion_schema, fn=oniontracker))

    tools.register(
        ToolSpec(
            name="tracker_db_stats",
            description="Return tracker_engine database counts and item-kind stats.",
            parameters=_schema({"params": {"type": "object", "additionalProperties": True}}),
            fn=tracker_db_stats,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_db_search",
            description="Search stored tracker_engine pages/items by query when supported; otherwise returns db stats with query preserved.",
            parameters=tracker_query_schema,
            fn=tracker_db_search,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_export_json",
            description="Run tracker pages and request JSON-style export metadata.",
            parameters=tracker_payload_schema,
            fn=tracker_export_json,
        )
    )

    tools.register(
        ToolSpec(
            name="tracker_export_markdown",
            description="Run tracker pages and request Markdown-style export metadata.",
            parameters=tracker_payload_schema,
            fn=tracker_export_markdown,
        )
    )


# ======================= Shared News Engine Integration ====================
def _news_engine_available() -> bool:
    return (
        engine_news_fetch_source is not None
        and engine_news_search is not None
        and engine_news_monitor is not None
        and engine_news_parse_feed is not None
        and engine_news_build_source_urls is not None
        and engine_news_engine_status is not None
    )


def _news_engine_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "news_engine_available": False,
        "error": "news_engine.py is not importable. Put news_engine.py beside tools.py and install requests.",
    }


def _call_news_engine_tool(fn: Any, tool_name: str, **kwargs: Any) -> Dict[str, Any]:
    if fn is None:
        result = _news_engine_unavailable_result()
        result["tool"] = tool_name
        return result
    try:
        data = fn(**kwargs)
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("ok", True)
            out["news_engine_available"] = _news_engine_available()
            out["tool"] = tool_name
            return out
        return {"ok": True, "news_engine_available": _news_engine_available(), "tool": tool_name, "result": data}
    except Exception as exc:
        return {"ok": False, "news_engine_available": _news_engine_available(), "tool": tool_name, "error": str(exc)}


def news_fetch_source(
    source: str,
    category: str = "top",
    query: str = "",
    limit: int = 80,
    timeout_sec: float = 20,
    verify_tls: bool = True,
    include_html: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """Fetch one public news source/category/search page or feed."""
    return _call_news_engine_tool(
        engine_news_fetch_source,
        "news_fetch_source",
        source=source,
        category=category,
        query=query,
        limit=limit,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        include_html=include_html,
        include_raw=include_raw,
    )


def news_search(
    query: str,
    sources: Optional[List[str]] = None,
    category: str = "top",
    limit_per_source: int = 20,
    timeout_sec: float = 20,
    verify_tls: bool = True,
    include_html: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """Search public news/fashion/business sources using their public search or section pages."""
    return _call_news_engine_tool(
        engine_news_search,
        "news_search",
        query=query,
        sources=sources,
        category=category,
        limit_per_source=limit_per_source,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        include_html=include_html,
        include_raw=include_raw,
    )


def news_monitor(
    watches: List[Dict[str, Any]],
    alert_rules: Optional[Dict[str, Any]] = None,
    new_only: bool = True,
    timeout_sec: float = 20,
    verify_tls: bool = True,
    write_state: bool = False,
    state_path: str = "data/news_monitor/state.json",
    include_html: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """Monitor public news watches and emit new-item/keyword/category alerts."""
    return _call_news_engine_tool(
        engine_news_monitor,
        "news_monitor",
        watches=watches,
        alert_rules=alert_rules,
        new_only=new_only,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        write_state=write_state,
        state_path=state_path,
        include_html=include_html,
        include_raw=include_raw,
    )


def news_parse_feed(
    xml_or_html_text: str,
    source: str = "custom",
    base_url: str = "",
    query: str = "",
    limit: int = 80,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """Parse user-provided RSS/Atom/XML or public HTML into normalized news items."""
    return _call_news_engine_tool(
        engine_news_parse_feed,
        "news_parse_feed",
        xml_or_html_text=xml_or_html_text,
        source=source,
        base_url=base_url,
        query=query,
        limit=limit,
        include_raw=include_raw,
    )


def news_build_source_urls(
    source: str = "",
    category: str = "top",
    query: str = "",
    custom_url: str = "",
) -> Dict[str, Any]:
    """Build public feed/page/search URLs for a supported news source."""
    return _call_news_engine_tool(
        engine_news_build_source_urls,
        "news_build_source_urls",
        source=source,
        category=category,
        query=query,
        custom_url=custom_url,
    )


def news_engine_status() -> Dict[str, Any]:
    """Return loaded news engine status and supported source/category map."""
    return _call_news_engine_tool(engine_news_engine_status, "news_engine_status")


# ======================= News Engine Tool Registration =====================
def _register_news_engine_tools(tools: ToolRegistry) -> None:
    """Register safe news_engine.py tools."""
    tools.register(
        ToolSpec(
            name="news_fetch_source",
            description="Fetch one public news source/category/search feed. Supports CNBC, Fox News, Hypebeast, Vogue, Reuters/AP/BBC-style sources, and custom URLs.",
            parameters=_schema(
                {
                    "source": {"type": "string", "description": "Source alias such as cnbc, fox, fox_business, hypebeast, vogue, vogue_business, reuters, ap, bbc, cnn, the_verge, nytimes."},
                    "category": {"type": "string", "description": "Category like top, latest, markets, business, fashion, culture, tech, politics, world."},
                    "query": {"type": "string", "description": "Optional source search query."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "include_html": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                },
                required=["source"],
            ),
            fn=news_fetch_source,
        )
    )

    tools.register(
        ToolSpec(
            name="news_search",
            description="Search across several public news/fashion/business sources using public search pages/feeds only.",
            parameters=_schema(
                {
                    "query": {"type": "string"},
                    "sources": {"type": "array", "items": {"type": "string"}},
                    "category": {"type": "string"},
                    "limit_per_source": {"type": "integer", "minimum": 1, "maximum": 500},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "include_html": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                },
                required=["query"],
            ),
            fn=news_search,
        )
    )

    tools.register(
        ToolSpec(
            name="news_monitor",
            description="Monitor public news watches and return new/keyword/category alerts with stateful dedupe when write_state=true.",
            parameters=_schema(
                {
                    "watches": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": True,
                            "properties": {
                                "source": {"type": "string"},
                                "category": {"type": "string"},
                                "query": {"type": "string"},
                                "url": {"type": "string"},
                                "required_words": {"type": "array", "items": {"type": "string"}},
                                "banned_words": {"type": "array", "items": {"type": "string"}},
                                "limit": {"type": "integer"},
                                "max_age_hours": {"type": "number"},
                            },
                        },
                    },
                    "alert_rules": {
                        "type": "object",
                        "additionalProperties": True,
                        "description": "Supports required_words, any_words, banned_words, sources, categories, new_only, min_score, note.",
                    },
                    "new_only": {"type": "boolean"},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "write_state": {"type": "boolean"},
                    "state_path": {"type": "string"},
                    "include_html": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                },
                required=["watches"],
            ),
            fn=news_monitor,
        )
    )

    tools.register(
        ToolSpec(
            name="news_parse_feed",
            description="Parse pasted RSS/Atom/XML or public HTML into normalized news items without fetching anything.",
            parameters=_schema(
                {
                    "xml_or_html_text": {"type": "string"},
                    "source": {"type": "string"},
                    "base_url": {"type": "string"},
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "include_raw": {"type": "boolean"},
                },
                required=["xml_or_html_text"],
            ),
            fn=news_parse_feed,
        )
    )

    tools.register(
        ToolSpec(
            name="news_build_source_urls",
            description="Build public feed/page/search URLs for a supported news source and category.",
            parameters=_schema(
                {
                    "source": {"type": "string"},
                    "category": {"type": "string"},
                    "query": {"type": "string"},
                    "custom_url": {"type": "string"},
                }
            ),
            fn=news_build_source_urls,
        )
    )

    tools.register(
        ToolSpec(
            name="news_engine_status",
            description="Return supported news sources, aliases, categories, and safety limits.",
            parameters=_schema({}),
            fn=lambda: news_engine_status(),
        )
    )


# ======================= Shared Monero Monitor Integration =================
def _monero_monitor_available() -> bool:
    return (
        engine_monero_daemon_status is not None
        and engine_monero_monitor_transaction is not None
        and engine_monero_monitor_transactions is not None
        and engine_p2pool_observer_pool_info is not None
        and engine_p2pool_observer_miner_info is not None
        and engine_monero_combined_monitor is not None
    )


def _monero_monitor_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "monero_monitor_available": False,
        "error": "monero_monitor_engine.py is not importable. Put monero_monitor_engine.py beside tools.py and install requests.",
    }


def _call_monero_monitor_tool(fn: Any, tool_name: str, **kwargs: Any) -> Dict[str, Any]:
    if fn is None:
        result = _monero_monitor_unavailable_result()
        result["tool"] = tool_name
        return result
    try:
        data = fn(**kwargs)
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("ok", True)
            out["monero_monitor_available"] = _monero_monitor_available()
            out["tool"] = tool_name
            return out
        return {
            "ok": True,
            "monero_monitor_available": _monero_monitor_available(),
            "tool": tool_name,
            "result": data,
        }
    except Exception as exc:
        return {
            "ok": False,
            "monero_monitor_available": _monero_monitor_available(),
            "tool": tool_name,
            "error": str(exc),
        }


def monero_daemon_status(
    daemon_rpc_url: str = "http://127.0.0.1:18081",
    timeout_sec: float = 20,
    verify_tls: bool = True,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """Check local/authorized monerod status through daemon RPC."""
    return _call_monero_monitor_tool(
        engine_monero_daemon_status,
        "monero_daemon_status",
        daemon_rpc_url=daemon_rpc_url,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        include_raw=include_raw,
    )


def monero_monitor_transaction(
    tx_hash: str,
    daemon_rpc_url: str = "http://127.0.0.1:18081",
    timeout_sec: float = 20,
    confirmations_target: int = 10,
    verify_tls: bool = True,
    include_tx_json: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """Monitor a known Monero tx hash for mempool/mined/confirmation status."""
    return _call_monero_monitor_tool(
        engine_monero_monitor_transaction,
        "monero_monitor_transaction",
        tx_hash=tx_hash,
        daemon_rpc_url=daemon_rpc_url,
        timeout_sec=timeout_sec,
        confirmations_target=confirmations_target,
        verify_tls=verify_tls,
        include_tx_json=include_tx_json,
        include_raw=include_raw,
    )


def monero_monitor_transactions(
    tx_hashes: List[str],
    daemon_rpc_url: str = "http://127.0.0.1:18081",
    timeout_sec: float = 20,
    confirmations_target: int = 10,
    verify_tls: bool = True,
    include_tx_json: bool = False,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """Monitor several known Monero tx hashes at once."""
    return _call_monero_monitor_tool(
        engine_monero_monitor_transactions,
        "monero_monitor_transactions",
        tx_hashes=tx_hashes,
        daemon_rpc_url=daemon_rpc_url,
        timeout_sec=timeout_sec,
        confirmations_target=confirmations_target,
        verify_tls=verify_tls,
        include_tx_json=include_tx_json,
        include_raw=include_raw,
    )


def p2pool_observer_pool_info(
    network: str = "mini",
    base_url: str = "",
    timeout_sec: float = 20,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    """Read public P2Pool Observer pool/network status."""
    return _call_monero_monitor_tool(
        engine_p2pool_observer_pool_info,
        "p2pool_observer_pool_info",
        network=network,
        base_url=base_url,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
    )


def p2pool_observer_miner_info(
    miner: str,
    network: str = "mini",
    base_url: str = "",
    timeout_sec: float = 20,
    verify_tls: bool = True,
    include_shares: bool = True,
    include_payments: bool = True,
    limit: int = 50,
) -> Dict[str, Any]:
    """Read public P2Pool Observer miner stats by payout address, internal id, or alias."""
    return _call_monero_monitor_tool(
        engine_p2pool_observer_miner_info,
        "p2pool_observer_miner_info",
        miner=miner,
        network=network,
        base_url=base_url,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        include_shares=include_shares,
        include_payments=include_payments,
        limit=limit,
    )


def monero_combined_monitor(
    tx_hash: str = "",
    tx_hashes: Optional[List[str]] = None,
    miner: str = "",
    daemon_rpc_url: str = "http://127.0.0.1:18081",
    network: str = "mini",
    base_url: str = "",
    timeout_sec: float = 20,
    confirmations_target: int = 10,
    verify_tls: bool = True,
    include_tx_json: bool = False,
    include_raw: bool = False,
    include_shares: bool = True,
    include_payments: bool = True,
) -> Dict[str, Any]:
    """Monitor Monero tx hashes and P2Pool Observer miner stats in one call."""
    return _call_monero_monitor_tool(
        engine_monero_combined_monitor,
        "monero_combined_monitor",
        tx_hash=tx_hash,
        tx_hashes=tx_hashes,
        miner=miner,
        daemon_rpc_url=daemon_rpc_url,
        network=network,
        base_url=base_url,
        timeout_sec=timeout_sec,
        confirmations_target=confirmations_target,
        verify_tls=verify_tls,
        include_tx_json=include_tx_json,
        include_raw=include_raw,
        include_shares=include_shares,
        include_payments=include_payments,
    )


# ======================= Monero Monitor Tool Registration ==================
# Put this near _register_engines_tools/_register_packet_tools.
def _register_monero_monitor_tools(tools: ToolRegistry) -> None:
    """Register safe monero_monitor_engine.py tools."""
    tools.register(
        ToolSpec(
            name="monero_daemon_status",
            description="Check local/authorized monerod RPC status, sync state, chain height, and txpool size.",
            parameters=_schema(
                {
                    "daemon_rpc_url": {"type": "string", "description": "Default: http://127.0.0.1:18081. May include basic auth in URL if needed."},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                }
            ),
            fn=monero_daemon_status,
        )
    )

    tools.register(
        ToolSpec(
            name="monero_monitor_transaction",
            description=(
                "Monitor a known Monero transaction hash using local/authorized monerod RPC. "
                "Reports not_found, mempool, mined, confirmations, and double_spend_seen. "
                "Does not deanonymize sender/receiver/amount."
            ),
            parameters=_schema(
                {
                    "tx_hash": {"type": "string"},
                    "daemon_rpc_url": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "confirmations_target": {"type": "integer", "minimum": 0, "maximum": 1000000},
                    "verify_tls": {"type": "boolean"},
                    "include_tx_json": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                },
                required=["tx_hash"],
            ),
            fn=monero_monitor_transaction,
        )
    )

    tools.register(
        ToolSpec(
            name="monero_monitor_transactions",
            description="Monitor multiple known Monero tx hashes using local/authorized monerod RPC.",
            parameters=_schema(
                {
                    "tx_hashes": {"type": "array", "items": {"type": "string"}},
                    "daemon_rpc_url": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "confirmations_target": {"type": "integer", "minimum": 0, "maximum": 1000000},
                    "verify_tls": {"type": "boolean"},
                    "include_tx_json": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                },
                required=["tx_hashes"],
            ),
            fn=monero_monitor_transactions,
        )
    )

    tools.register(
        ToolSpec(
            name="p2pool_observer_pool_info",
            description="Read public P2Pool Observer pool/network status for main, mini, nano, or a custom observer base URL.",
            parameters=_schema(
                {
                    "network": {"type": "string", "enum": ["main", "mini", "nano"]},
                    "base_url": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                }
            ),
            fn=p2pool_observer_pool_info,
        )
    )

    tools.register(
        ToolSpec(
            name="p2pool_observer_miner_info",
            description=(
                "Read public P2Pool Observer miner stats by payout address, internal id, or alias. "
                "Useful for checking shares/payments for your own miner."
            ),
            parameters=_schema(
                {
                    "miner": {"type": "string"},
                    "network": {"type": "string", "enum": ["main", "mini", "nano"]},
                    "base_url": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "include_shares": {"type": "boolean"},
                    "include_payments": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
                required=["miner"],
            ),
            fn=p2pool_observer_miner_info,
        )
    )

    tools.register(
        ToolSpec(
            name="monero_combined_monitor",
            description="Monitor known Monero tx hashes and P2Pool Observer miner stats in one combined safe report.",
            parameters=_schema(
                {
                    "tx_hash": {"type": "string"},
                    "tx_hashes": {"type": "array", "items": {"type": "string"}},
                    "miner": {"type": "string"},
                    "daemon_rpc_url": {"type": "string"},
                    "network": {"type": "string", "enum": ["main", "mini", "nano"]},
                    "base_url": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "confirmations_target": {"type": "integer", "minimum": 0, "maximum": 1000000},
                    "verify_tls": {"type": "boolean"},
                    "include_tx_json": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                    "include_shares": {"type": "boolean"},
                    "include_payments": {"type": "boolean"},
                }
            ),
            fn=monero_combined_monitor,
        )
    )


# ======================= build_default_tool_registry hook ==================
# Add this near the bottom of build_default_tool_registry(), right before
# _register_engines_tools(tools) or right after reverse_image registration:
#
#     _register_intelligence_engine_tools(tools)
    _register_news_engine_tools(tools)
#     _register_monero_monitor_tools(tools)
#     _register_engines_tools(tools)
#     _register_packet_tools(tools)
#     _register_project_tools(tools, app_config)
#     return tools
# ======================= Shared Stock Monitor Integration ==================
def _stock_monitor_available() -> bool:
    return (
        engine_stock_quote is not None
        and engine_stock_monitor is not None
        and engine_stock_compare_watchlist is not None
        and engine_stock_engine_status is not None
    )


def _stock_monitor_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "stock_monitor_available": False,
        "error": "stock_engine_monitor.py is not importable. Put stock_engine_monitor.py beside tools.py and install requests.",
    }


def _call_stock_monitor_tool(fn: Any, tool_name: str, **kwargs: Any) -> Dict[str, Any]:
    if fn is None:
        result = _stock_monitor_unavailable_result()
        result["tool"] = tool_name
        return result
    try:
        data = fn(**kwargs)
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("ok", True)
            out["stock_monitor_available"] = _stock_monitor_available()
            out["tool"] = tool_name
            return out
        return {"ok": True, "stock_monitor_available": _stock_monitor_available(), "tool": tool_name, "result": data}
    except Exception as exc:
        return {"ok": False, "stock_monitor_available": _stock_monitor_available(), "tool": tool_name, "error": str(exc)}


def stock_quote(
    symbol: str,
    range_: str = "1d",
    interval: str = "1m",
    timeout_sec: float = 15,
    verify_tls: bool = True,
    fallback: bool = True,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """Fetch one stock/ETF/crypto quote from public quote sources."""
    return _call_stock_monitor_tool(
        engine_stock_quote,
        "stock_quote",
        symbol=symbol,
        range_=range_,
        interval=interval,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        fallback=fallback,
        include_raw=include_raw,
    )


def stock_monitor(
    symbols: List[str],
    rules: Optional[List[Dict[str, Any]]] = None,
    range_: str = "1d",
    interval: str = "1m",
    timeout_sec: float = 15,
    verify_tls: bool = True,
    fallback: bool = True,
    include_raw: bool = False,
    write_state: bool = False,
    state_path: str = "data/stock_monitor/state.json",
) -> Dict[str, Any]:
    """Monitor several stock/ETF/crypto symbols and fire simple price/change/volume alerts."""
    return _call_stock_monitor_tool(
        engine_stock_monitor,
        "stock_monitor",
        symbols=symbols,
        rules=rules,
        range_=range_,
        interval=interval,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        fallback=fallback,
        include_raw=include_raw,
        write_state=write_state,
        state_path=state_path,
    )


def stock_compare_watchlist(
    watchlist: List[Dict[str, Any]],
    timeout_sec: float = 15,
    verify_tls: bool = True,
    write_state: bool = False,
    state_path: str = "data/stock_monitor/state.json",
) -> Dict[str, Any]:
    """Monitor a richer stock watchlist: [{symbol, price_below, price_above, ...}]."""
    return _call_stock_monitor_tool(
        engine_stock_compare_watchlist,
        "stock_compare_watchlist",
        watchlist=watchlist,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        write_state=write_state,
        state_path=state_path,
    )


def stock_engine_status() -> Dict[str, Any]:
    """Check whether stock_engine_monitor.py is loaded."""
    return _call_stock_monitor_tool(engine_stock_engine_status, "stock_engine_status")


# ======================= Shared Resale Monitor Integration =================
def _resale_monitor_available() -> bool:
    return (
        engine_resale_search is not None
        and engine_resale_monitor is not None
        and engine_resale_parse_html is not None
        and engine_resale_build_search_urls is not None
        and engine_resale_engine_status is not None
    )


def _resale_monitor_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "resale_monitor_available": False,
        "error": "resale_engine_monitor.py is not importable. Put resale_engine_monitor.py beside tools.py and install requests.",
    }


def _call_resale_monitor_tool(fn: Any, tool_name: str, **kwargs: Any) -> Dict[str, Any]:
    if fn is None:
        result = _resale_monitor_unavailable_result()
        result["tool"] = tool_name
        return result
    try:
        data = fn(**kwargs)
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("ok", True)
            out["resale_monitor_available"] = _resale_monitor_available()
            out["tool"] = tool_name
            return out
        return {"ok": True, "resale_monitor_available": _resale_monitor_available(), "tool": tool_name, "result": data}
    except Exception as exc:
        return {"ok": False, "resale_monitor_available": _resale_monitor_available(), "tool": tool_name, "error": str(exc)}


def resale_search(
    platform: str,
    query: str,
    brand: str = "",
    size: str = "",
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    currency: str = "",
    sort: str = "newest",
    limit: int = 60,
    timeout_sec: float = 20,
    verify_tls: bool = True,
    include_html: bool = False,
    include_raw_json: bool = False,
) -> Dict[str, Any]:
    """Search one resale marketplace public results page without login/CAPTCHA/proxy bypass."""
    return _call_resale_monitor_tool(
        engine_resale_search,
        "resale_search",
        platform=platform,
        query=query,
        brand=brand,
        size=size,
        min_price=min_price,
        max_price=max_price,
        currency=currency,
        sort=sort,
        limit=limit,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        include_html=include_html,
        include_raw_json=include_raw_json,
    )


def resale_monitor(
    searches: List[Dict[str, Any]],
    alert_rules: Optional[Dict[str, Any]] = None,
    new_only: bool = True,
    timeout_sec: float = 20,
    verify_tls: bool = True,
    write_state: bool = False,
    state_path: str = "data/resale_monitor/state.json",
    include_html: bool = False,
    include_raw_json: bool = False,
) -> Dict[str, Any]:
    """Run multiple resale searches, dedupe by state, and fire new-listing/price/keyword alerts."""
    return _call_resale_monitor_tool(
        engine_resale_monitor,
        "resale_monitor",
        searches=searches,
        alert_rules=alert_rules,
        new_only=new_only,
        timeout_sec=timeout_sec,
        verify_tls=verify_tls,
        write_state=write_state,
        state_path=state_path,
        include_html=include_html,
        include_raw_json=include_raw_json,
    )


def resale_parse_html(
    platform: str,
    html_text: str,
    base_url: str = "",
    query: str = "",
    brand: str = "",
    size: str = "",
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    currency: str = "",
    limit: int = 60,
    include_raw_json: bool = False,
) -> Dict[str, Any]:
    """Parse user-provided/exported marketplace HTML for listing candidates."""
    return _call_resale_monitor_tool(
        engine_resale_parse_html,
        "resale_parse_html",
        platform=platform,
        html_text=html_text,
        base_url=base_url,
        query=query,
        brand=brand,
        size=size,
        min_price=min_price,
        max_price=max_price,
        currency=currency,
        limit=limit,
        include_raw_json=include_raw_json,
    )


def resale_build_search_urls(
    platform: str,
    query: str,
    brand: str = "",
    size: str = "",
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    currency: str = "",
    sort: str = "newest",
    limit: int = 60,
) -> Dict[str, Any]:
    """Build safe public search URLs for supported resale marketplaces."""
    return _call_resale_monitor_tool(
        engine_resale_build_search_urls,
        "resale_build_search_urls",
        platform=platform,
        query=query,
        brand=brand,
        size=size,
        min_price=min_price,
        max_price=max_price,
        currency=currency,
        sort=sort,
        limit=limit,
    )


def resale_engine_status() -> Dict[str, Any]:
    """Check whether resale_engine_monitor.py is loaded."""
    return _call_resale_monitor_tool(engine_resale_engine_status, "resale_engine_status")


# ======================= Stock Monitor Tool Registration ===================
# Put this near _register_monero_monitor_tools/_register_engines_tools.
def _register_stock_monitor_tools(tools: ToolRegistry) -> None:
    """Register safe stock_engine_monitor.py tools."""
    tools.register(
        ToolSpec(
            name="stock_quote",
            description="Fetch one public quote for a stock/ETF/crypto symbol. Uses public quote endpoints only; no broker login/trading.",
            parameters=_schema(
                {
                    "symbol": {"type": "string"},
                    "range_": {"type": "string", "description": "Yahoo-style range, e.g. 1d, 5d, 1mo."},
                    "interval": {"type": "string", "description": "Yahoo-style interval, e.g. 1m, 5m, 1d."},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "fallback": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                },
                required=["symbol"],
            ),
            fn=stock_quote,
        )
    )

    tools.register(
        ToolSpec(
            name="stock_monitor",
            description="Monitor several public market symbols and return alerts for price/change/volume rules.",
            parameters=_schema(
                {
                    "symbols": {"type": "array", "items": {"type": "string"}},
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "symbol": {"type": "string"},
                                "price_above": {"type": "number"},
                                "price_below": {"type": "number"},
                                "percent_change_above": {"type": "number"},
                                "percent_change_below": {"type": "number"},
                                "volume_above": {"type": "number"},
                                "market_state": {"type": "string"},
                                "note": {"type": "string"},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "range_": {"type": "string"},
                    "interval": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "fallback": {"type": "boolean"},
                    "include_raw": {"type": "boolean"},
                    "write_state": {"type": "boolean"},
                    "state_path": {"type": "string"},
                },
                required=["symbols"],
            ),
            fn=stock_monitor,
        )
    )

    tools.register(
        ToolSpec(
            name="stock_compare_watchlist",
            description="Monitor a rich stock watchlist where every row can include symbol and alert thresholds.",
            parameters=_schema(
                {
                    "watchlist": {"type": "array", "items": {"type": "object"}},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "write_state": {"type": "boolean"},
                    "state_path": {"type": "string"},
                },
                required=["watchlist"],
            ),
            fn=stock_compare_watchlist,
        )
    )

    tools.register(
        ToolSpec(
            name="stock_engine_status",
            description="Return stock monitor engine status and source list.",
            parameters=_schema({}),
            fn=lambda: stock_engine_status(),
        )
    )


# ======================= Resale Monitor Tool Registration ==================
def _register_resale_monitor_tools(tools: ToolRegistry) -> None:
    """Register safe resale_engine_monitor.py tools."""
    tools.register(
        ToolSpec(
            name="resale_search",
            description="Search one resale marketplace public page for listing candidates. No login, CAPTCHA bypass, proxy evasion, or checkout automation.",
            parameters=_schema(
                {
                    "platform": {"type": "string", "enum": ["depop", "poshmark", "grailed", "mercari", "mercari_japan", "mercari_jp", "bunjang", "bunjung"]},
                    "query": {"type": "string"},
                    "brand": {"type": "string"},
                    "size": {"type": "string"},
                    "min_price": {"type": "number"},
                    "max_price": {"type": "number"},
                    "currency": {"type": "string"},
                    "sort": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "include_html": {"type": "boolean"},
                    "include_raw_json": {"type": "boolean"},
                },
                required=["platform", "query"],
            ),
            fn=resale_search,
        )
    )

    tools.register(
        ToolSpec(
            name="resale_monitor",
            description="Run multiple resale marketplace searches, dedupe seen listings, and fire new-listing/price/keyword alerts.",
            parameters=_schema(
                {
                    "searches": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "platform": {"type": "string"},
                                "query": {"type": "string"},
                                "brand": {"type": "string"},
                                "size": {"type": "string"},
                                "min_price": {"type": "number"},
                                "max_price": {"type": "number"},
                                "currency": {"type": "string"},
                                "sort": {"type": "string"},
                                "limit": {"type": "integer"},
                            },
                            "required": ["platform", "query"],
                            "additionalProperties": True,
                        },
                    },
                    "alert_rules": {
                        "type": "object",
                        "properties": {
                            "new_only": {"type": "boolean"},
                            "max_price": {"type": "number"},
                            "min_price": {"type": "number"},
                            "required_words": {"type": "array", "items": {"type": "string"}},
                            "banned_words": {"type": "array", "items": {"type": "string"}},
                        },
                        "additionalProperties": True,
                    },
                    "new_only": {"type": "boolean"},
                    "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
                    "verify_tls": {"type": "boolean"},
                    "write_state": {"type": "boolean"},
                    "state_path": {"type": "string"},
                    "include_html": {"type": "boolean"},
                    "include_raw_json": {"type": "boolean"},
                },
                required=["searches"],
            ),
            fn=resale_monitor,
        )
    )

    tools.register(
        ToolSpec(
            name="resale_parse_html",
            description="Parse user-provided/exported marketplace HTML for listing candidates without fetching the site.",
            parameters=_schema(
                {
                    "platform": {"type": "string"},
                    "html_text": {"type": "string"},
                    "base_url": {"type": "string"},
                    "query": {"type": "string"},
                    "brand": {"type": "string"},
                    "size": {"type": "string"},
                    "min_price": {"type": "number"},
                    "max_price": {"type": "number"},
                    "currency": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    "include_raw_json": {"type": "boolean"},
                },
                required=["platform", "html_text"],
            ),
            fn=resale_parse_html,
        )
    )

    tools.register(
        ToolSpec(
            name="resale_build_search_urls",
            description="Build public search URLs for depop, poshmark, grailed, mercari, mercari_japan, and bunjang.",
            parameters=_schema(
                {
                    "platform": {"type": "string"},
                    "query": {"type": "string"},
                    "brand": {"type": "string"},
                    "size": {"type": "string"},
                    "min_price": {"type": "number"},
                    "max_price": {"type": "number"},
                    "currency": {"type": "string"},
                    "sort": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                },
                required=["platform", "query"],
            ),
            fn=resale_build_search_urls,
        )
    )

    tools.register(
        ToolSpec(
            name="resale_engine_status",
            description="Return resale monitor engine status, supported platforms, aliases, and safety limits.",
            parameters=_schema({}),
            fn=lambda: resale_engine_status(),
        )
    )


# ======================= build_default_tool_registry hook ==================
# Add these near the bottom of build_default_tool_registry(), before return tools:
#
#     _register_monero_monitor_tools(tools)   # if you installed the Monero patch
#     _register_stock_monitor_tools(tools)
#     _register_resale_monitor_tools(tools)
#     _register_engines_tools(tools)
#     _register_packet_tools(tools)
#     _register_project_tools(tools, app_config)
#     return tools
# ======================= Shared Packet Engine Integration ==================
def _packet_available() -> bool:
    return PacketEngine is not None and PacketEngineConfig is not None


def _packet_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "packet_available": False,
        "error": "packet_engine.py is not importable. Put packet_engine.py beside tools.py.",
    }


def _call_packet_tool(fn: Any, tool_name: str, **kwargs: Any) -> Dict[str, Any]:
    if fn is None:
        result = _packet_unavailable_result()
        result["tool"] = tool_name
        return result
    try:
        data = fn(**kwargs)
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("ok", True)
            out["packet_available"] = _packet_available()
            out["tool"] = tool_name
            return out
        return {
            "ok": True,
            "packet_available": _packet_available(),
            "tool": tool_name,
            "result": data,
        }
    except Exception as exc:
        return {
            "ok": False,
            "packet_available": _packet_available(),
            "tool": tool_name,
            "error": str(exc),
        }


def packet_list_interfaces() -> Dict[str, Any]:
    """List libpcap/Npcap interfaces visible to packet_engine.py."""
    return _call_packet_tool(packet_engine_list_interfaces, "packet_list_interfaces")


def packet_capture_live(
    interface: str,
    bpf_filter: str = "",
    max_packets: int = 64,
    budget_s: float = 2.0,
    decode: bool = True,
) -> Dict[str, Any]:
    """Capture packets from a live interface with an optional BPF filter."""
    return _call_packet_tool(
        packet_engine_capture_live,
        "packet_capture_live",
        interface=interface,
        bpf_filter=bpf_filter,
        max_packets=max_packets,
        budget_s=budget_s,
        decode=decode,
    )


def packet_capture_offline(
    path: str,
    bpf_filter: str = "",
    max_packets: int = 1000,
    budget_s: float = 10.0,
    decode: bool = True,
) -> Dict[str, Any]:
    """Read packets from a pcap/pcapng file with optional BPF filtering."""
    return _call_packet_tool(
        packet_engine_capture_offline,
        "packet_capture_offline",
        path=path,
        bpf_filter=bpf_filter,
        max_packets=max_packets,
        budget_s=budget_s,
        decode=decode,
    )


def packet_parse_hex(raw_hex: str, datalink: int = DLT_EN10MB) -> Dict[str, Any]:
    """Parse a hex-encoded packet/frame into Ethernet/IP/TCP/UDP/DNS/ICMP/ARP layers."""
    return _call_packet_tool(
        packet_engine_parse_hex,
        "packet_parse_hex",
        raw_hex=raw_hex,
        datalink=datalink,
    )


def packet_send_udp(
    host: str,
    port: int,
    payload_text: str = "",
    payload_hex: str = "",
    timeout_sec: float = 3.0,
    read_response: bool = True,
) -> Dict[str, Any]:
    """Send one UDP payload through the OS socket stack and optionally read one response."""
    return _call_packet_tool(
        packet_engine_send_udp,
        "packet_send_udp",
        host=host,
        port=port,
        payload_text=payload_text,
        payload_hex=payload_hex,
        timeout_sec=timeout_sec,
        read_response=read_response,
    )


def packet_send_tcp(
    host: str,
    port: int,
    payload_text: str = "",
    payload_hex: str = "",
    timeout_sec: float = 5.0,
    read_response: bool = True,
) -> Dict[str, Any]:
    """Open one TCP connection through the OS socket stack, send one payload, and optionally read one response."""
    return _call_packet_tool(
        packet_engine_send_tcp,
        "packet_send_tcp",
        host=host,
        port=port,
        payload_text=payload_text,
        payload_hex=payload_hex,
        timeout_sec=timeout_sec,
        read_response=read_response,
    )


def packet_dns_query(
    domain: str,
    server: str = "1.1.1.1",
    qtype: str = "A",
    timeout_sec: float = 4.0,
) -> Dict[str, Any]:
    """Send one DNS query over UDP and parse the DNS response."""
    return _call_packet_tool(
        packet_engine_dns_query,
        "packet_dns_query",
        domain=domain,
        server=server,
        qtype=qtype,
        timeout_sec=timeout_sec,
    )


def packet_send_l2_frame(
    interface: str,
    raw_hex: str,
    confirm_authorized: bool = False,
    max_send_bytes: int = 4096,
) -> Dict[str, Any]:
    """Send one raw L2 frame only when explicitly authorized for a lab interface."""
    return _call_packet_tool(
        packet_engine_send_l2_frame,
        "packet_send_l2_frame",
        interface=interface,
        raw_hex=raw_hex,
        confirm_authorized=confirm_authorized,
        max_send_bytes=max_send_bytes,
    )

def _fetch_url(
    url: str,
    *,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_url = _normalize_url(url)
    session, timeout_value = _make_session(
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url,
    )

    mode = "tor" if tor_socks_url else "web"

    try:
        response = session.get(
            normalized_url,
            timeout=timeout_value,
            allow_redirects=True,
        )
        response.raise_for_status()
        body = response.text or ""
    except requests.RequestException as exc:
        return _request_failed_result(
            mode=mode,
            url=normalized_url,
            error=exc,
            tor_socks_url=tor_socks_url,
        )
    finally:
        session.close()

    content_type = response.headers.get("Content-Type", "")
    title = _extract_title(body)
    meta_description = _extract_meta_description(body)
    text = _clean_html_to_text(body)

    truncated = False
    if len(text) > max_chars:
        text = text[:max_chars]
        truncated = True

    result = {
        "ok": True,
        "mode": mode,
        "url": normalized_url,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": content_type,
        "title": title,
        "description": meta_description,
        "text": text,
        "truncated": truncated,
        "char_count": len(text),
        "tor_socks_url": tor_socks_url or "",
    }

    # New shared sniffer path. This keeps the public browse_web/browse_tor
    # signatures unchanged while enriching their output with page assets.
    sniffed = _run_sniffer_text(
        body,
        base_url=response.url,
        max_chars=max_chars,
        max_items=250,
        include_html=False,
    )
    result.update(_compact_sniffer_payload(sniffed, include_text=False))
    return result


def browse_web(
    url: str,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
) -> Dict[str, Any]:
    return _fetch_url(
        url,
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        tor_socks_url=None,
    )


def browse_tor(
    url: str,
    max_chars: int = DEFAULT_MAX_PAGE_CHARS,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
) -> Dict[str, Any]:
    return _fetch_url(
        url,
        timeout_sec=timeout_sec,
        max_chars=max_chars,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
    )


def extract_links(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_links: int = 25,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_url = _normalize_url(url)
    session, timeout_value = _make_session(
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url,
    )

    mode = "tor" if tor_socks_url else "web"

    try:
        response = session.get(
            normalized_url,
            timeout=timeout_value,
            allow_redirects=True,
        )
        response.raise_for_status()
        body = response.text or ""
    except requests.RequestException as exc:
        return _request_failed_result(
            mode=mode,
            url=normalized_url,
            error=exc,
            tor_socks_url=tor_socks_url,
        )
    finally:
        session.close()

    links = _extract_links_from_html(response.url, body, max_links=max_links)
    sniffed = _run_sniffer_text(
        body,
        base_url=response.url,
        max_chars=DEFAULT_MAX_PAGE_CHARS,
        max_items=max(50, max_links * 4),
        include_html=False,
    )
    links = _merge_sniffed_links(links, sniffed, max_links=max_links)

    result = {
        "ok": True,
        "mode": mode,
        "url": normalized_url,
        "final_url": response.url,
        "count": len(links),
        "links": links,
        "tor_socks_url": tor_socks_url or "",
    }
    result.update(_compact_sniffer_payload(sniffed, include_text=False))
    return result


def extract_links_tor(
    url: str,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    max_links: int = 25,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
) -> Dict[str, Any]:
    return extract_links(
        url=url,
        timeout_sec=timeout_sec,
        max_links=max_links,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
    )


def check_tor_proxy(
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    timeout_sec: int = 8,
) -> Dict[str, Any]:
    session, timeout_value = _make_session(
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
    )

    try:
        response = session.get(
            "https://check.torproject.org/api/ip",
            timeout=timeout_value,
        )
        response.raise_for_status()
        data = response.json()
        return {
            "ok": True,
            "tor_socks_url": tor_socks_url,
            "is_tor": bool(data.get("IsTor")),
            "ip": data.get("IP", ""),
            "raw": data,
        }
    except Exception as exc:
        return {
            "ok": False,
            "tor_socks_url": tor_socks_url,
            "error": str(exc),
            "hint": "Start Tor Browser or Tor daemon and install requests[socks] if needed.",
        }
    finally:
        session.close()


def _rewrite_query(query: str) -> List[str]:
    raw = (query or "").strip()

    if not raw:
        return []

    terms = []
    for token in re.findall(r"[A-Za-z0-9_'\-]+", raw):
        t = token.lower().strip("'")
        if len(t) >= 3 and t not in STOPWORDS:
            terms.append(token)

    compact = " ".join(terms[:12]).strip()
    rewrites = [raw]

    if compact and compact != raw:
        rewrites.append(compact)

    return list(dict.fromkeys(rewrites))


def _extract_duckduckgo_results(
    body: str,
    max_results: int = 20,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for match in re.finditer(
        r'(?is)<a[^>]+class=["\'][^"\']*result__a[^"\']*["\'][^>]+href=["\'](.*?)["\'][^>]*>(.*?)</a>',
        body or "",
    ):
        url = html.unescape(match.group(1))
        title = _clean_html_to_text(match.group(2))

        if "uddg=" in url:
            m = re.search(r"[?&]uddg=([^&]+)", url)
            if m:
                url = unquote(m.group(1))

        out.append({"title": title, "url": url, "snippet": ""})

        if len(out) >= max_results:
            break

    if out:
        return out

    for match in re.finditer(
        r'(?is)<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
        body or "",
    ):
        url = html.unescape(match.group(1))
        title = _clean_html_to_text(match.group(2))
        host = urlparse(url).netloc.lower()

        if title and host not in BAD_RESULT_DOMAINS:
            out.append({"title": title[:300], "url": url, "snippet": ""})

        if len(out) >= max_results:
            break

    return out


def _extract_generic_results(
    body: str,
    max_results: int = 20,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for match in re.finditer(r"https?://[^\s\"'<>]+", body or ""):
        url = html.unescape(match.group(0)).rstrip(").,;")
        host = urlparse(url).netloc.lower()

        if host in BAD_RESULT_DOMAINS or url in seen:
            continue

        seen.add(url)
        out.append({"title": url, "url": url, "snippet": ""})

        if len(out) >= max_results:
            break

    return out


def _score_result(item: Dict[str, Any], query: str) -> float:
    hay = f"{item.get('title', '')} {item.get('snippet', '')} {item.get('url', '')}".lower()

    terms = [
        t.lower()
        for t in re.findall(r"[A-Za-z0-9_'\-]+", query or "")
        if len(t) > 2 and t.lower() not in STOPWORDS
    ]

    score = sum(1.0 for t in terms if t in hay)

    host = urlparse(item.get("url", "")).netloc.lower()
    for good in GOOD_BONUS_DOMAINS:
        if host == good or host.endswith("." + good):
            score += 1.5
            break

    return score


def search_web(
    query: str,
    max_results: int = 5,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: Optional[str] = None,
) -> Dict[str, Any]:
    raw_query = (query or "").strip()
    rewrites = _rewrite_query(raw_query)

    if not rewrites:
        return {"ok": False, "error": "Could not generate search queries."}

    all_results: List[Dict[str, Any]] = []
    seen_urls: set[str] = set()

    session, timeout_value = _make_session(
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url,
    )

    mode = "tor" if tor_socks_url else "web"

    try:
        for rewritten in rewrites:
            candidate_urls = [
                f"https://html.duckduckgo.com/html/?q={quote_plus(rewritten)}",
                f"https://lite.duckduckgo.com/lite/?q={quote_plus(rewritten)}",
            ]

            parsed_any: List[Dict[str, Any]] = []

            for search_url in candidate_urls:
                try:
                    response = session.get(search_url, timeout=timeout_value, allow_redirects=True)
                    response.raise_for_status()
                    body = response.text or ""
                except requests.RequestException:
                    continue

                parsed = _extract_duckduckgo_results(body, max_results=max_results * 3)

                if not parsed:
                    parsed = _extract_generic_results(body, max_results=max_results * 3)

                if parsed:
                    parsed_any = parsed
                    break

            for item in parsed_any:
                url = item.get("url", "")

                if not url or url in seen_urls:
                    continue

                seen_urls.add(url)
                item["matched_query"] = rewritten
                item["score"] = _score_result(item, raw_query)
                all_results.append(item)

    finally:
        session.close()

    all_results.sort(key=lambda x: x.get("score", 0.0), reverse=True)
    final_results = all_results[:max_results]

    return {
        "ok": True,
        "mode": mode,
        "query": raw_query,
        "rewritten_queries": rewrites,
        "count": len(final_results),
        "results": final_results,
        "tor_socks_url": tor_socks_url or "",
    }


def search_tor(
    query: str,
    max_results: int = 5,
    timeout_sec: int = DEFAULT_WEB_TIMEOUT_SEC,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
) -> Dict[str, Any]:
    return search_web(
        query=query,
        max_results=max_results,
        timeout_sec=timeout_sec,
        tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
    )


def _project_call(
    project: Any,
    method_name: str,
    *args: Any,
    **kwargs: Any,
) -> Dict[str, Any]:
    method = getattr(project, method_name, None)

    if not callable(method):
        return {
            "ok": False,
            "error": (
                f"project_tools.py does not implement {method_name}. "
                "Update project_tools.py with the dynamic project runner version first."
            ),
            "method": method_name,
        }

    result = method(*args, **kwargs)

    if isinstance(result, dict):
        return result

    return {
        "ok": True,
        "result": result,
    }



# ======================= Shared Application Engine Integration ===============
def _application_engine_available() -> bool:
    return engine_ApplicationEngine is not None


def _application_engine_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "application_engine_available": False,
        "error": "application_engine.py is not importable. Put application_engine.py beside tools.py.",
    }


def _application_engine_params(
    *,
    allow_all_local: bool = False,
    allow_sensitive: bool = False,
    require_consent_for_contents: bool = True,
    allowed_hwnds: Any = "",
    allowed_pids: Any = "",
    allowed_process_names: Any = "",
    deny_process_names: Any = "",
    out_dir: str = "out/application_engine",
) -> Dict[str, Any]:
    return {
        "allow_all_local": bool(allow_all_local),
        "allow_sensitive": bool(allow_sensitive),
        "require_consent_for_contents": bool(require_consent_for_contents),
        "allowed_hwnds": allowed_hwnds,
        "allowed_pids": allowed_pids,
        "allowed_process_names": allowed_process_names,
        "deny_process_names": deny_process_names,
        "out_dir": out_dir or "out/application_engine",
    }


def _new_application_engine(**kwargs: Any) -> Any:
    if engine_ApplicationEngine is None:
        return None
    return engine_ApplicationEngine(params=kwargs)


def _call_application_engine(action: str, params: Optional[Dict[str, Any]] = None, **engine_params: Any) -> Dict[str, Any]:
    engine = _new_application_engine(**engine_params)
    if engine is None:
        result = _application_engine_unavailable_result()
        result["action"] = action
        return result

    try:
        data = engine.execute(action, params or {})
        if isinstance(data, dict):
            data = dict(data)
            data.setdefault("ok", True)
            data["application_engine_available"] = _application_engine_available()
            data["tool"] = action
            return data
        return {
            "ok": True,
            "application_engine_available": _application_engine_available(),
            "tool": action,
            "result": data,
        }
    except Exception as exc:
        return {
            "ok": False,
            "application_engine_available": _application_engine_available(),
            "tool": action,
            "error": str(exc),
            "error_type": type(exc).__name__,
        }


def application_engine(
    action: str = "capabilities",
    params: Optional[Dict[str, Any]] = None,
    allow_all_local: bool = False,
    allow_sensitive: bool = False,
    require_consent_for_contents: bool = True,
    allowed_hwnds: Any = "",
    allowed_pids: Any = "",
    allowed_process_names: Any = "",
    deny_process_names: Any = "",
    out_dir: str = "out/application_engine",
) -> Dict[str, Any]:
    """
    Generic application_engine call.

    Safe local app observation wrapper. Inventory tools can list windows/processes.
    Reading window/screen contents requires allow_all_local=true for local dev or
    an explicit allowed_hwnds / allowed_pids / allowed_process_names gate.
    """
    engine_params = _application_engine_params(
        allow_all_local=allow_all_local,
        allow_sensitive=allow_sensitive,
        require_consent_for_contents=require_consent_for_contents,
        allowed_hwnds=allowed_hwnds,
        allowed_pids=allowed_pids,
        allowed_process_names=allowed_process_names,
        deny_process_names=deny_process_names,
        out_dir=out_dir,
    )
    return _call_application_engine(action or "capabilities", params or {}, **engine_params)


def application_engine_capabilities() -> Dict[str, Any]:
    """Return application_engine availability, installed backends, and supported actions."""
    return _call_application_engine("capabilities", {})


def application_list_processes(
    include_cmdline: bool = False,
    limit: int = 5000,
) -> Dict[str, Any]:
    """List local running processes without reading application content."""
    return _call_application_engine(
        "list_processes",
        {
            "include_cmdline": bool(include_cmdline),
            "limit": max(1, int(limit or 1)),
        },
    )


def application_list_windows(
    visible_only: bool = True,
    include_empty_titles: bool = False,
    limit: int = 2000,
) -> Dict[str, Any]:
    """List top-level application windows without reading application content."""
    return _call_application_engine(
        "list_windows",
        {
            "visible_only": bool(visible_only),
            "include_empty_titles": bool(include_empty_titles),
            "limit": max(1, int(limit or 1)),
        },
    )


def application_find_windows(
    query: str = "",
    pid: int = 0,
    process_name: str = "",
    visible_only: bool = True,
    include_empty_titles: bool = False,
    limit: int = 50,
) -> Dict[str, Any]:
    """Find windows by title, process name, class name, PID, or HWND-like text."""
    params: Dict[str, Any] = {
        "query": query or "",
        "process_name": process_name or "",
        "visible_only": bool(visible_only),
        "include_empty_titles": bool(include_empty_titles),
        "limit": max(1, int(limit or 1)),
    }
    if int(pid or 0) > 0:
        params["pid"] = int(pid)
    return _call_application_engine("find_windows", params)


def application_observe_window(
    hwnd: int = 0,
    pid: int = 0,
    query: str = "",
    process_name: str = "",
    include_ui_tree: bool = True,
    include_screenshot: bool = True,
    include_screenshot_base64: bool = False,
    include_ocr: bool = False,
    focus: bool = False,
    out_dir: str = "out/application_engine",
    max_depth: int = 4,
    max_elements: int = 250,
    visible_only: bool = True,
    allow_all_local: bool = False,
    allow_sensitive: bool = False,
    require_consent_for_contents: bool = True,
    allowed_hwnds: Any = "",
    allowed_pids: Any = "",
    allowed_process_names: Any = "",
    deny_process_names: Any = "",
) -> Dict[str, Any]:
    """
    Observe one authorized local window.

    Uses UI Automation when available, saves a screenshot when requested, and can
    OCR visible text if pytesseract is installed. This does not read raw process
    memory, install hooks, keylog, or bypass OS/app permissions.
    """
    params: Dict[str, Any] = {
        "query": query or "",
        "process_name": process_name or "",
        "include_ui_tree": bool(include_ui_tree),
        "include_screenshot": bool(include_screenshot),
        "include_screenshot_base64": bool(include_screenshot_base64),
        "include_ocr": bool(include_ocr),
        "focus": bool(focus),
        "out_dir": out_dir or "out/application_engine",
        "max_depth": max(0, int(max_depth or 0)),
        "max_elements": max(1, int(max_elements or 1)),
        "visible_only": bool(visible_only),
    }
    if int(hwnd or 0) > 0:
        params["hwnd"] = int(hwnd)
    if int(pid or 0) > 0:
        params["pid"] = int(pid)

    engine_params = _application_engine_params(
        allow_all_local=allow_all_local,
        allow_sensitive=allow_sensitive,
        require_consent_for_contents=require_consent_for_contents,
        allowed_hwnds=allowed_hwnds,
        allowed_pids=allowed_pids,
        allowed_process_names=allowed_process_names,
        deny_process_names=deny_process_names,
        out_dir=out_dir,
    )
    return _call_application_engine("observe_window", params, **engine_params)


def application_read_screen(
    include_screenshot: bool = True,
    include_screenshot_base64: bool = False,
    include_ocr: bool = True,
    out_dir: str = "out/application_engine",
    monitor_index: int = 1,
    allow_all_local: bool = False,
    allow_sensitive: bool = False,
    require_consent_for_contents: bool = True,
    allowed_process_names: Any = "",
    deny_process_names: Any = "",
) -> Dict[str, Any]:
    """
    Read the visible screen through screenshot/OCR only.

    Requires allow_all_local=true for local development because full-screen OCR
    can include private data from multiple windows.
    """
    engine_params = _application_engine_params(
        allow_all_local=allow_all_local,
        allow_sensitive=allow_sensitive,
        require_consent_for_contents=require_consent_for_contents,
        allowed_hwnds="",
        allowed_pids="",
        allowed_process_names=allowed_process_names,
        deny_process_names=deny_process_names,
        out_dir=out_dir,
    )
    return _call_application_engine(
        "read_screen",
        {
            "include_screenshot": bool(include_screenshot),
            "include_screenshot_base64": bool(include_screenshot_base64),
            "include_ocr": bool(include_ocr),
            "out_dir": out_dir or "out/application_engine",
            "monitor_index": max(0, int(monitor_index or 0)),
        },
        **engine_params,
    )


# ======================= Interactive Browser Engine Calls ====================
def _interactive_browser_available() -> bool:
    return engine_interactive_tor is not None and engine_interactive_search is not None


def _interactive_browser_unavailable_result() -> Dict[str, Any]:
    return {
        "ok": False,
        "interactive_browser_available": False,
        "error": "interactive_browser_engine.py is not importable. Put interactive_browser_engine.py beside tools.py and install Playwright if needed.",
        "install_hint": "pip install playwright && python -m playwright install chromium",
    }


def interactive_browser_status() -> Dict[str, Any]:
    """Return live human-in-the-loop browser sessions."""
    if engine_interactive_browser_status is None:
        return _interactive_browser_unavailable_result()
    try:
        data = engine_interactive_browser_status()
        if isinstance(data, dict):
            data = dict(data)
            data["interactive_browser_available"] = _interactive_browser_available()
            return data
        return {"ok": True, "interactive_browser_available": _interactive_browser_available(), "result": data}
    except Exception as exc:
        return {"ok": False, "interactive_browser_available": _interactive_browser_available(), "error": str(exc)}


def interactive_tor(
    action: str,
    url: str = "",
    query: str = "",
    session_id: str = "default_tor",
    tor_exe_path: str = "",
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    timeout_sec: int = 300,
    max_chars: int = 20000,
    allow_read: bool = False,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Human-in-the-loop Tor browser session.

    Opens a visible Playwright browser routed through Tor so the user can browse,
    login, complete challenges, or select pages manually. Reading page contents
    requires allow_read=true after user handoff. This tool does not solve
    CAPTCHAs and does not return raw cookies, passwords, or hidden tokens.
    """
    if engine_interactive_tor is None:
        return _interactive_browser_unavailable_result()
    try:
        data = engine_interactive_tor(
            action=action,
            url=url,
            query=query,
            session_id=session_id,
            tor_exe_path=tor_exe_path,
            tor_socks_url=tor_socks_url or DEFAULT_TOR_SOCKS_URL,
            timeout_sec=timeout_sec,
            max_chars=max_chars,
            allow_read=allow_read,
            params=params or {},
        )
        if isinstance(data, dict):
            data = dict(data)
            data["interactive_browser_available"] = _interactive_browser_available()
            return data
        return {"ok": True, "interactive_browser_available": _interactive_browser_available(), "result": data}
    except Exception as exc:
        return {"ok": False, "interactive_browser_available": _interactive_browser_available(), "error": str(exc)}


def interactive_search(
    action: str,
    url: str = "",
    query: str = "",
    session_id: str = "default_search",
    timeout_sec: int = 300,
    max_chars: int = 20000,
    allow_read: bool = False,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Human-in-the-loop normal browser/search session.

    Opens a visible Playwright browser so the user can browse, login, complete
    challenges, or select pages manually. Reading page contents requires
    allow_read=true after user handoff. This tool does not solve CAPTCHAs and
    does not return raw cookies, passwords, or hidden tokens.
    """
    if engine_interactive_search is None:
        return _interactive_browser_unavailable_result()
    try:
        data = engine_interactive_search(
            action=action,
            url=url,
            query=query,
            session_id=session_id,
            timeout_sec=timeout_sec,
            max_chars=max_chars,
            allow_read=allow_read,
            params=params or {},
        )
        if isinstance(data, dict):
            data = dict(data)
            data["interactive_browser_available"] = _interactive_browser_available()
            return data
        return {"ok": True, "interactive_browser_available": _interactive_browser_available(), "result": data}
    except Exception as exc:
        return {"ok": False, "interactive_browser_available": _interactive_browser_available(), "error": str(exc)}


# Misspelled aliases kept because the project/user sometimes types these names.
def interative_tor(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    return interactive_tor(*args, **kwargs)


def itnerative_tor(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    return interactive_tor(*args, **kwargs)


def interative_search(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    return interactive_search(*args, **kwargs)


def _schema(
    properties: Dict[str, Any],
    required: Optional[List[str]] = None,
) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }

    if required:
        data["required"] = required

    return data



# ======================= Interactive Browser Tool Registration ===============
def _register_interactive_browser_tools(tools: ToolRegistry) -> None:
    """Register human-in-the-loop Playwright browser/Tor tools."""
    actions = engine_INTERACTIVE_BROWSER_ACTIONS or [
        "capabilities",
        "status",
        "open_user_session",
        "search",
        "wait_for_handoff",
        "read_session",
        "continue_session",
        "close_session",
        "clear_session",
    ]

    common_properties: Dict[str, Any] = {
        "action": {
            "type": "string",
            "enum": actions,
            "description": "Browser session action.",
        },
        "url": {
            "type": "string",
            "description": "Optional URL to open/navigate. .onion hosts default to http:// if no scheme is provided.",
        },
        "query": {
            "type": "string",
            "description": "Optional search query. The engine opens a visible search page.",
        },
        "session_id": {
            "type": "string",
            "description": "Persistent local profile/session name.",
        },
        "timeout_sec": {
            "type": "integer",
            "minimum": 1,
            "maximum": 3600,
            "description": "Navigation/handoff timeout.",
        },
        "max_chars": {
            "type": "integer",
            "minimum": 500,
            "maximum": 2000000,
            "description": "Maximum visible body text characters returned by read_session.",
        },
        "allow_read": {
            "type": "boolean",
            "description": "Must be true to read visible page contents after user handoff.",
        },
        "params": {
            "type": "object",
            "description": "Optional settings: include_links, include_screenshot, data_dir, headless_reopen, handoff_file, wait_for_close, stop_tor, browser_channel.",
            "additionalProperties": True,
        },
    }

    tor_properties = dict(common_properties)
    tor_properties.update(
        {
            "tor_exe_path": {
                "type": "string",
                "description": "Optional explicit path to tor.exe. If blank, the engine tries common Tor Browser paths or existing 127.0.0.1:9150.",
            },
            "tor_socks_url": {
                "type": "string",
                "description": "Tor SOCKS proxy URL. Default socks5h://127.0.0.1:9150.",
            },
        }
    )

    interactive_tor_params = _schema(tor_properties, required=["action"])
    interactive_search_params = _schema(common_properties, required=["action"])

    tools.register(
        ToolSpec(
            name="interactive_tor",
            description=(
                "Human-in-the-loop Tor browser session. Opens/continues a visible Playwright browser routed "
                "through Tor so the user can browse/login/solve challenges manually. GPT may read only the "
                "approved visible page after allow_read=true; raw cookies/passwords/tokens are not returned."
            ),
            parameters=interactive_tor_params,
            fn=interactive_tor,
        )
    )

    tools.register(
        ToolSpec(
            name="interactive_search",
            description=(
                "Human-in-the-loop normal browser/search session. Opens/continues a visible Playwright browser "
                "for user involvement, then reads the approved visible page only when allow_read=true."
            ),
            parameters=interactive_search_params,
            fn=interactive_search,
        )
    )

    tools.register(
        ToolSpec(
            name="interactive_browser_status",
            description="Return live interactive browser sessions and persistent profile locations.",
            parameters=_schema({}, required=[]),
            fn=lambda: interactive_browser_status(),
        )
    )

    tools.register(
        ToolSpec(
            name="interative_tor",
            description="Alias for interactive_tor, preserving the common misspelling.",
            parameters=interactive_tor_params,
            fn=interative_tor,
        )
    )

    tools.register(
        ToolSpec(
            name="itnerative_tor",
            description="Alias for interactive_tor, preserving the common transposed misspelling.",
            parameters=interactive_tor_params,
            fn=itnerative_tor,
        )
    )

    tools.register(
        ToolSpec(
            name="interative_search",
            description="Alias for interactive_search, preserving the common misspelling.",
            parameters=interactive_search_params,
            fn=interative_search,
        )
    )



# ======================= Application Engine Tool Registration ================
def _register_application_engine_tools(tools: ToolRegistry) -> None:
    """Register application_engine.py local app/screen observation tools."""
    tools.register(
        ToolSpec(
            name="application_engine",
            description=(
                "Generic consent-based local application engine. Supports capabilities, list_processes, "
                "list_windows, find_windows, observe_window, and read_screen actions. Reading contents "
                "requires allow_all_local=true or an explicit allowed target."
            ),
            parameters=_schema(
                {
                    "action": {
                        "type": "string",
                        "description": "Action name: capabilities, list_processes, list_windows, find_windows, observe_window, read_screen.",
                    },
                    "params": {
                        "type": "object",
                        "description": "Action-specific parameters.",
                        "additionalProperties": True,
                    },
                    "allow_all_local": {
                        "type": "boolean",
                        "description": "Allow content observation for this local dev call.",
                    },
                    "allow_sensitive": {
                        "type": "boolean",
                        "description": "Allow sensitive-looking windows you own/control.",
                    },
                    "require_consent_for_contents": {"type": "boolean"},
                    "allowed_hwnds": {"description": "Optional allowed hwnd or comma/list of hwnds."},
                    "allowed_pids": {"description": "Optional allowed pid or comma/list of pids."},
                    "allowed_process_names": {"description": "Optional allowed process name or comma/list of names."},
                    "deny_process_names": {"description": "Optional extra denied process names."},
                    "out_dir": {"type": "string"},
                },
            ),
            fn=application_engine,
        )
    )

    tools.register(
        ToolSpec(
            name="application_engine_capabilities",
            description="Return application_engine availability, optional dependency status, and supported actions.",
            parameters=_schema({}),
            fn=lambda: application_engine_capabilities(),
        )
    )

    tools.register(
        ToolSpec(
            name="application_list_processes",
            description="List local running processes. This does not read window or screen contents.",
            parameters=_schema(
                {
                    "include_cmdline": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20000},
                }
            ),
            fn=application_list_processes,
        )
    )

    tools.register(
        ToolSpec(
            name="application_list_windows",
            description="List visible top-level local application windows with hwnd, title, class, pid, process name, and rectangle.",
            parameters=_schema(
                {
                    "visible_only": {"type": "boolean"},
                    "include_empty_titles": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
                }
            ),
            fn=application_list_windows,
        )
    )

    tools.register(
        ToolSpec(
            name="application_find_windows",
            description="Find local application windows by title/process/class substring, PID, or HWND-like text.",
            parameters=_schema(
                {
                    "query": {"type": "string"},
                    "pid": {"type": "integer", "minimum": 0},
                    "process_name": {"type": "string"},
                    "visible_only": {"type": "boolean"},
                    "include_empty_titles": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                }
            ),
            fn=application_find_windows,
        )
    )

    tools.register(
        ToolSpec(
            name="application_observe_window",
            description=(
                "Observe an authorized local window using UI Automation, screenshot capture, and optional OCR. "
                "Requires allow_all_local=true for local dev or allowed_hwnds/allowed_pids/allowed_process_names. "
                "Does not use keylogging, raw process memory, stealth hooks, or credential extraction."
            ),
            parameters=_schema(
                {
                    "hwnd": {"type": "integer", "minimum": 0},
                    "pid": {"type": "integer", "minimum": 0},
                    "query": {"type": "string"},
                    "process_name": {"type": "string"},
                    "include_ui_tree": {"type": "boolean"},
                    "include_screenshot": {"type": "boolean"},
                    "include_screenshot_base64": {"type": "boolean"},
                    "include_ocr": {"type": "boolean"},
                    "focus": {"type": "boolean"},
                    "out_dir": {"type": "string"},
                    "max_depth": {"type": "integer", "minimum": 0, "maximum": 12},
                    "max_elements": {"type": "integer", "minimum": 1, "maximum": 5000},
                    "visible_only": {"type": "boolean"},
                    "allow_all_local": {"type": "boolean"},
                    "allow_sensitive": {"type": "boolean"},
                    "require_consent_for_contents": {"type": "boolean"},
                    "allowed_hwnds": {"description": "Optional allowed hwnd or comma/list of hwnds."},
                    "allowed_pids": {"description": "Optional allowed pid or comma/list of pids."},
                    "allowed_process_names": {"description": "Optional allowed process name or comma/list of names."},
                    "deny_process_names": {"description": "Optional extra denied process names."},
                }
            ),
            fn=application_observe_window,
        )
    )

    tools.register(
        ToolSpec(
            name="application_read_screen",
            description=(
                "Read the visible screen through screenshot capture and optional OCR. "
                "Requires allow_all_local=true because full-screen OCR may include private data."
            ),
            parameters=_schema(
                {
                    "include_screenshot": {"type": "boolean"},
                    "include_screenshot_base64": {"type": "boolean"},
                    "include_ocr": {"type": "boolean"},
                    "out_dir": {"type": "string"},
                    "monitor_index": {"type": "integer", "minimum": 0, "maximum": 32},
                    "allow_all_local": {"type": "boolean"},
                    "allow_sensitive": {"type": "boolean"},
                    "require_consent_for_contents": {"type": "boolean"},
                    "allowed_process_names": {"description": "Optional allowed process name or comma/list of names."},
                    "deny_process_names": {"description": "Optional extra denied process names."},
                }
            ),
            fn=application_read_screen,
        )
    )


# ======================= Packet Engine Tool Registration ===================
def _register_packet_tools(tools: ToolRegistry) -> None:
    """Register packet_engine.py receive/send tools."""
    tools.register(
        ToolSpec(
            name="packet_list_interfaces",
            description="List libpcap/Npcap capture interfaces visible to packet_engine.py.",
            parameters=_schema({}),
            fn=lambda: packet_list_interfaces(),
        )
    )

    tools.register(
        ToolSpec(
            name="packet_capture_live",
            description="Capture packets from a live interface with optional BPF filter and decoded protocol layers.",
            parameters=_schema(
                {
                    "interface": {"type": "string"},
                    "bpf_filter": {"type": "string"},
                    "max_packets": {"type": "integer", "minimum": 1, "maximum": 5000},
                    "budget_s": {"type": "number", "minimum": 0.05, "maximum": 120},
                    "decode": {"type": "boolean"},
                },
                required=["interface"],
            ),
            fn=packet_capture_live,
        )
    )

    tools.register(
        ToolSpec(
            name="packet_capture_offline",
            description="Read packets from a pcap/pcapng file with optional BPF filtering and decoded protocol layers.",
            parameters=_schema(
                {
                    "path": {"type": "string"},
                    "bpf_filter": {"type": "string"},
                    "max_packets": {"type": "integer", "minimum": 1, "maximum": 100000},
                    "budget_s": {"type": "number", "minimum": 0.05, "maximum": 600},
                    "decode": {"type": "boolean"},
                },
                required=["path"],
            ),
            fn=packet_capture_offline,
        )
    )

    tools.register(
        ToolSpec(
            name="packet_parse_hex",
            description="Parse one hex-encoded packet/frame into Ethernet/IP/TCP/UDP/DNS/ICMP/ARP layers.",
            parameters=_schema(
                {
                    "raw_hex": {"type": "string"},
                    "datalink": {"type": "integer"},
                },
                required=["raw_hex"],
            ),
            fn=packet_parse_hex,
        )
    )

    tools.register(
        ToolSpec(
            name="packet_send_udp",
            description="Send one UDP payload through the normal OS socket stack and optionally read one response.",
            parameters=_schema(
                {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "payload_text": {"type": "string"},
                    "payload_hex": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 0.05, "maximum": 120},
                    "read_response": {"type": "boolean"},
                },
                required=["host", "port"],
            ),
            fn=packet_send_udp,
        )
    )

    tools.register(
        ToolSpec(
            name="packet_send_tcp",
            description="Open one TCP connection through the normal OS socket stack, send one payload, and optionally read one response.",
            parameters=_schema(
                {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "payload_text": {"type": "string"},
                    "payload_hex": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 0.05, "maximum": 120},
                    "read_response": {"type": "boolean"},
                },
                required=["host", "port"],
            ),
            fn=packet_send_tcp,
        )
    )

    tools.register(
        ToolSpec(
            name="packet_dns_query",
            description="Send one DNS query over UDP and parse the DNS response.",
            parameters=_schema(
                {
                    "domain": {"type": "string"},
                    "server": {"type": "string"},
                    "qtype": {"type": "string"},
                    "timeout_sec": {"type": "number", "minimum": 0.05, "maximum": 120},
                },
                required=["domain"],
            ),
            fn=packet_dns_query,
        )
    )

    tools.register(
        ToolSpec(
            name="packet_send_l2_frame",
            description=(
                "Send one raw L2 frame with packet_engine.py. This is gated: use only on an authorized lab interface, "
                "requires confirm_authorized=true, and sends one bounded frame only."
            ),
            parameters=_schema(
                {
                    "interface": {"type": "string"},
                    "raw_hex": {"type": "string"},
                    "confirm_authorized": {"type": "boolean"},
                    "max_send_bytes": {"type": "integer", "minimum": 64, "maximum": 65535},
                },
                required=["interface", "raw_hex"],
            ),
            fn=packet_send_l2_frame,
        )
    )

# ======================= Engines.py Tool Registration =======================
def _register_engines_tools(tools: ToolRegistry) -> None:
    """Register archive, sourcemap, metadata, OSINT, manifest, route, media, and entity tools."""
    tools.register(
        ToolSpec(
            name='archive_search_url',
            description='Search public archives for snapshots and historical references for one URL.',
            parameters=_schema({'url': {'type': 'string'}, 'max_results': {'type': 'integer'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=archive_search_url,
        )
    )

    tools.register(
        ToolSpec(
            name='archive_search_domain',
            description='Search public archives for historical URLs and snapshots across a domain.',
            parameters=_schema({'domain': {'type': 'string'}, 'max_results': {'type': 'integer'}, 'timeout_sec': {'type': 'integer'}}, required=['domain']),
            fn=archive_search_domain,
        )
    )

    tools.register(
        ToolSpec(
            name='archive_fetch_wayback_snapshot',
            description='Fetch one public Wayback snapshot by URL and optional timestamp.',
            parameters=_schema({'url': {'type': 'string'}, 'timestamp': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=archive_fetch_wayback_snapshot,
        )
    )

    tools.register(
        ToolSpec(
            name='archive_compare_snapshots',
            description='Compare two public/archive URLs for text, link, and asset differences.',
            parameters=_schema({'left_url': {'type': 'string'}, 'right_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['left_url', 'right_url']),
            fn=archive_compare_snapshots,
        )
    )

    tools.register(
        ToolSpec(
            name='archive_extract_lost_links',
            description='Recover links/assets seen in archived snapshots but missing from the current page.',
            parameters=_schema({'current_url': {'type': 'string'}, 'max_snapshots': {'type': 'integer'}, 'timeout_sec': {'type': 'integer'}}, required=['current_url']),
            fn=archive_extract_lost_links,
        )
    )

    tools.register(
        ToolSpec(
            name='archive_timeline_report',
            description='Build a public archive timeline report for a URL.',
            parameters=_schema({'url': {'type': 'string'}, 'max_results': {'type': 'integer'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=archive_timeline_report,
        )
    )

    tools.register(
        ToolSpec(
            name='sourcemap_find',
            description='Find source maps, chunk URLs, and sourceMappingURL clues for a script or page.',
            parameters=_schema({'url': {'type': 'string'}, 'include_guesses': {'type': 'boolean'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=sourcemap_find,
        )
    )

    tools.register(
        ToolSpec(
            name='sourcemap_fetch',
            description='Fetch and parse a public source map URL.',
            parameters=_schema({'url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=sourcemap_fetch,
        )
    )

    tools.register(
        ToolSpec(
            name='sourcemap_extract_sources',
            description='Extract source file paths and source contents from source map text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=sourcemap_extract_sources,
        )
    )

    tools.register(
        ToolSpec(
            name='sourcemap_extract_urls',
            description='Extract public URLs, endpoints, routes, and assets from source map text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=sourcemap_extract_urls,
        )
    )

    tools.register(
        ToolSpec(
            name='sourcemap_reconstruct_tree',
            description='Reconstruct a source tree from a source map text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=sourcemap_reconstruct_tree,
        )
    )

    tools.register(
        ToolSpec(
            name='sourcemap_secret_redacted_scan',
            description='Scan source map content for secret-like values with redaction only.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=sourcemap_secret_redacted_scan,
        )
    )

    tools.register(
        ToolSpec(
            name='metadata_url',
            description='Extract HTTP, HTML, OpenGraph, JSON-LD, and structured metadata from a URL.',
            parameters=_schema({'url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=metadata_url,
        )
    )

    tools.register(
        ToolSpec(
            name='metadata_file',
            description='Extract hashes, type, timestamps, and embedded metadata from a local file.',
            parameters=_schema({'path': {'type': 'string'}}, required=['path']),
            fn=metadata_file,
        )
    )

    tools.register(
        ToolSpec(
            name='metadata_image',
            description='Extract image metadata, dimensions, hashes, EXIF/IPTC/XMP-style clues where available.',
            parameters=_schema({'path_or_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['path_or_url']),
            fn=metadata_image,
        )
    )

    tools.register(
        ToolSpec(
            name='metadata_video',
            description='Extract video/media metadata from a public URL or local path where supported.',
            parameters=_schema({'path_or_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['path_or_url']),
            fn=metadata_video,
        )
    )

    tools.register(
        ToolSpec(
            name='metadata_pdf',
            description='Extract PDF metadata, links, and text clues from a public URL or local path where supported.',
            parameters=_schema({'path_or_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['path_or_url']),
            fn=metadata_pdf,
        )
    )

    tools.register(
        ToolSpec(
            name='metadata_compare',
            description='Compare metadata between two URLs/files.',
            parameters=_schema({'left': {'type': 'string'}, 'right': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['left', 'right']),
            fn=metadata_compare,
        )
    )

    tools.register(
        ToolSpec(
            name='metadata_redacted_report',
            description='Generate a metadata report with secret-like values redacted.',
            parameters=_schema({'target': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['target']),
            fn=metadata_redacted_report,
        )
    )

    tools.register(
        ToolSpec(
            name='osint_domain',
            description='Collect public domain context: DNS, RDAP-like, CT-style, and public URL clues where available.',
            parameters=_schema({'domain': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['domain']),
            fn=osint_domain,
        )
    )

    tools.register(
        ToolSpec(
            name='osint_ip',
            description='Collect public IP context and reverse/DNS-style clues where available.',
            parameters=_schema({'ip': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['ip']),
            fn=osint_ip,
        )
    )

    tools.register(
        ToolSpec(
            name='osint_certificates',
            description='Search public certificate-transparency style references for a domain.',
            parameters=_schema({'domain': {'type': 'string'}, 'max_results': {'type': 'integer'}, 'timeout_sec': {'type': 'integer'}}, required=['domain']),
            fn=osint_certificates,
        )
    )

    tools.register(
        ToolSpec(
            name='osint_dns_history',
            description='Collect public DNS history-style hints for a domain when configured/available.',
            parameters=_schema({'domain': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['domain']),
            fn=osint_dns_history,
        )
    )

    tools.register(
        ToolSpec(
            name='osint_public_mentions',
            description='Search public web references for a query and return URL mentions.',
            parameters=_schema({'query': {'type': 'string'}, 'max_results': {'type': 'integer'}, 'timeout_sec': {'type': 'integer'}}, required=['query']),
            fn=osint_public_mentions,
        )
    )

    tools.register(
        ToolSpec(
            name='osint_related_domains',
            description='Find related domains from DNS, certificates, archives, and URL references.',
            parameters=_schema({'domain': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['domain']),
            fn=osint_related_domains,
        )
    )

    tools.register(
        ToolSpec(
            name='manifest_find',
            description='Find web app, HLS, DASH, RSS, Atom, sitemap, and OpenSearch manifests from a URL.',
            parameters=_schema({'url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=manifest_find,
        )
    )

    tools.register(
        ToolSpec(
            name='manifest_parse_webapp',
            description='Parse a web app manifest from text or URL and extract app assets.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=manifest_parse_webapp,
        )
    )

    tools.register(
        ToolSpec(
            name='manifest_parse_hls',
            description='Parse an HLS m3u8 manifest from text or URL and extract streams/segments.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=manifest_parse_hls,
        )
    )

    tools.register(
        ToolSpec(
            name='manifest_parse_dash',
            description='Parse a DASH MPD manifest from text or URL and extract representations/segments.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=manifest_parse_dash,
        )
    )

    tools.register(
        ToolSpec(
            name='manifest_parse_rss',
            description='Parse RSS feed text or URL and extract links/enclosures/media.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=manifest_parse_rss,
        )
    )

    tools.register(
        ToolSpec(
            name='manifest_parse_atom',
            description='Parse Atom feed text or URL and extract links/enclosures/media.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=manifest_parse_atom,
        )
    )

    tools.register(
        ToolSpec(
            name='manifest_extract_assets',
            description='Extract all assets from manifest-like text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=manifest_extract_assets,
        )
    )

    tools.register(
        ToolSpec(
            name='route_extract_from_html',
            description='Extract client-side/public routes from HTML text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=route_extract_from_html,
        )
    )

    tools.register(
        ToolSpec(
            name='route_extract_from_js',
            description='Extract client-side/public routes from JavaScript text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=route_extract_from_js,
        )
    )

    tools.register(
        ToolSpec(
            name='route_extract_nextjs',
            description='Extract Next.js routes, build IDs, data URLs, and static asset routes.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=route_extract_nextjs,
        )
    )

    tools.register(
        ToolSpec(
            name='route_extract_nuxt',
            description='Extract Nuxt routes and payload/static asset references.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=route_extract_nuxt,
        )
    )

    tools.register(
        ToolSpec(
            name='route_extract_vite',
            description='Extract Vite manifest routes/chunks/assets.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=route_extract_vite,
        )
    )

    tools.register(
        ToolSpec(
            name='route_extract_react_router',
            description='Extract React Router-style route strings from JS/HTML.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=route_extract_react_router,
        )
    )

    tools.register(
        ToolSpec(
            name='route_probe_public_routes',
            description='Probe a provided list of public routes under a base URL with safe HTTP requests.',
            parameters=_schema({'base_url': {'type': 'string'}, 'routes': {'type': 'array', 'items': {'type': 'string'}}, 'timeout_sec': {'type': 'integer'}}, required=['base_url', 'routes']),
            fn=route_probe_public_routes,
        )
    )

    tools.register(
        ToolSpec(
            name='media_find',
            description='Find public video/audio/image/subtitle/thumbnail assets from a URL.',
            parameters=_schema({'url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=media_find,
        )
    )

    tools.register(
        ToolSpec(
            name='media_extract_hls',
            description='Extract HLS stream/segment/subtitle clues from m3u8 text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=media_extract_hls,
        )
    )

    tools.register(
        ToolSpec(
            name='media_extract_dash',
            description='Extract DASH media representation/segment clues from MPD text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=media_extract_dash,
        )
    )

    tools.register(
        ToolSpec(
            name='media_extract_subtitles',
            description='Extract subtitle/caption URLs and tracks from text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=media_extract_subtitles,
        )
    )

    tools.register(
        ToolSpec(
            name='media_extract_thumbnails',
            description='Extract thumbnail/poster/image candidates from text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=media_extract_thumbnails,
        )
    )

    tools.register(
        ToolSpec(
            name='media_probe_dimensions',
            description='Probe public media URL for size/type/dimension-style metadata where available.',
            parameters=_schema({'url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['url']),
            fn=media_probe_dimensions,
        )
    )

    tools.register(
        ToolSpec(
            name='media_rank_best_sources',
            description='Rank discovered media candidates by quality/source confidence.',
            parameters=_schema({'media_items': {'type': 'array', 'items': {}}}, required=['media_items']),
            fn=media_rank_best_sources,
        )
    )

    tools.register(
        ToolSpec(
            name='entity_extract',
            description='Extract people, brands, products, places, and named entities from text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=entity_extract,
        )
    )

    tools.register(
        ToolSpec(
            name='entity_link_urls',
            description='Link extracted/provided entities to URLs found in text or page content.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'entities': {'type': 'array', 'items': {'type': 'string'}}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=entity_link_urls,
        )
    )

    tools.register(
        ToolSpec(
            name='entity_timeline',
            description='Build an entity timeline from page text and optional public archive context.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'entity': {'type': 'string'}, 'base_url': {'type': 'string'}, 'include_archives': {'type': 'boolean'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=entity_timeline,
        )
    )

    tools.register(
        ToolSpec(
            name='entity_cluster',
            description='Cluster entities and related URLs from text or URL.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=entity_cluster,
        )
    )

    tools.register(
        ToolSpec(
            name='entity_report',
            description='Build an entity report linking people/brands/products/places to URLs and media.',
            parameters=_schema({'text_or_url': {'type': 'string'}, 'base_url': {'type': 'string'}, 'include_archives': {'type': 'boolean'}, 'timeout_sec': {'type': 'integer'}}, required=['text_or_url']),
            fn=entity_report,
        )
    )

    tools.register(
        ToolSpec(
            name='engines_status',
            description='Return availability/status for optional engines.py dependencies.',
            parameters=_schema({}, required=[]),
            fn=engines_status,
        )
    )


def _register_project_tools(
    tools: ToolRegistry,
    app_config: Any = None,
) -> None:
    """
    Register LocalPythonProjectTools methods.

    This version matches the newer project_tools.py class:
    - no broken choose_run_candidate registration
    - no broken run_any_command registration
    - run_project_command schema matches command/cwd/timeout/stdin/use_project_python
    - run_inferred_project schema matches candidate_index/extra_args/timeout/max_files/prefer_long_running
    """
    if app_config is None:
        return

    if not bool(getattr(app_config, "project_tools_enabled", True)):
        return

    if LocalPythonProjectTools is None:
        return

    project = LocalPythonProjectTools.from_app_config(app_config)

    if project is None:
        return

    def reg(
        name: str,
        description: str,
        parameters: Dict[str, Any],
        method_name: str,
    ) -> None:
        # Capture method_name as a default argument so each tool keeps the
        # method it was registered with.
        tools.register(
            ToolSpec(
                name=name,
                description=description,
                parameters=parameters,
                fn=lambda _method_name=method_name, **kw: _project_call(project, _method_name, **kw),
            )
        )

    empty_schema = {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }

    reg(
        "project_status",
        "Return configured local project root, .venv info, markers, and enabled capabilities. Use this first.",
        empty_schema,
        "project_status",
    )

    reg(
        "project_tree",
        "List files in the configured local project.",
        _schema(
            {
                "max_files": {"type": "integer", "minimum": 1, "maximum": 10000},
                "suffix": {"type": "string"},
                "include_hidden": {"type": "boolean"},
            }
        ),
        "project_tree",
    )

    reg(
        "read_project_file",
        "Read a text/code file from the configured local project root.",
        _schema(
            {
                "path": {"type": "string"},
                "max_chars": {"type": "integer", "minimum": 100, "maximum": 500000},
            },
            required=["path"],
        ),
        "read_project_file",
    )

    reg(
        "search_project",
        "Search project code/text and return ranked excerpts.",
        _schema(
            {
                "query": {"type": "string"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 200},
                "context_chars": {"type": "integer", "minimum": 80, "maximum": 10000},
                "suffix": {"type": "string"},
            },
            required=["query"],
        ),
        "search_project",
    )

    reg(
        "summarize_project",
        "Build a structural summary of files, packages, classes, functions, imports, and entrypoints.",
        _schema(
            {
                "max_files": {"type": "integer", "minimum": 50, "maximum": 10000},
            }
        ),
        "summarize_project",
    )

    reg(
        "inspect_python_entrypoints",
        "Inspect Python files for main guards, argparse flags, frameworks, and likely entrypoints.",
        _schema(
            {
                "max_files": {"type": "integer", "minimum": 50, "maximum": 10000},
            }
        ),
        "inspect_python_entrypoints",
    )

    reg(
        "infer_project_run_commands",
        "Infer likely Python project run/test/diagnostic commands from project files.",
        _schema(
            {
                "max_files": {"type": "integer", "minimum": 50, "maximum": 10000},
            }
        ),
        "infer_project_run_commands",
    )

    reg(
        "learn_project_for_execution",
        "Scan project status, .venv, summary, entrypoints, documented commands, and inferred run commands before execution.",
        _schema(
            {
                "max_files": {"type": "integer", "minimum": 50, "maximum": 10000},
            }
        ),
        "learn_project_for_execution",
    )

    reg(
        "run_project_command",
        (
            "Run an allowlisted command in the configured project. "
            "python/pip are redirected into the detected project .venv when present. "
            "shell=False is always used."
        ),
        _schema(
            {
                "command": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
                "cwd": {"type": "string"},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 100000},
                "stdin_text": {"type": "string"},
                "use_project_python": {"type": "boolean"},
            },
            required=["command"],
        ),
        "run_project_command",
    )

    reg(
        "run_python_file",
        "Run a Python file inside the configured project root using the project's .venv python when found.",
        _schema(
            {
                "path": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 100000},
                "cwd": {"type": "string"},
            },
            required=["path"],
        ),
        "run_python_file",
    )

    reg(
        "run_python_module",
        "Run python -m <module> inside the configured local project using the project's .venv python when found.",
        _schema(
            {
                "module": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 100000},
                "cwd": {"type": "string"},
            },
            required=["module"],
        ),
        "run_python_module",
    )

    reg(
        "run_inferred_project",
        "Run one inferred project run candidate by candidate_index.",
        _schema(
            {
                "candidate_index": {"type": "integer", "minimum": 0, "maximum": 10000},
                "extra_args": {"type": "array", "items": {"type": "string"}},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 100000},
                "max_files": {"type": "integer", "minimum": 50, "maximum": 10000},
                "prefer_long_running": {"type": "boolean"},
            }
        ),
        "run_inferred_project",
    )

    reg(
        "scan_and_run_project",
        "Scan/learn the project, infer run commands, choose the best candidate for the request, then execute it.",
        _schema(
            {
                "user_request": {"type": "string"},
                "candidate_index": {"type": "integer", "minimum": 0, "maximum": 10000},
                "extra_args": {"type": "array", "items": {"type": "string"}},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 100000},
                "max_files": {"type": "integer", "minimum": 50, "maximum": 10000},
                "prefer_long_running": {"type": "boolean"},
            }
        ),
        "scan_and_run_project",
    )

    reg(
        "compile_python_file",
        "Run python -m py_compile on a Python file inside the configured project.",
        _schema(
            {
                "path": {"type": "string"},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 100000},
            },
            required=["path"],
        ),
        "compile_python_file",
    )

    reg(
        "run_pytest",
        "Run pytest -q against the configured local project.",
        _schema(
            {
                "target": {"type": "string"},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 100000},
                "extra_args": {"type": "array", "items": {"type": "string"}},
            }
        ),
        "run_pytest",
    )

    reg(
        "run_ruff",
        "Run ruff check against the configured project. fix=true requires project_write_enabled=true.",
        _schema(
            {
                "target": {"type": "string"},
                "fix": {"type": "boolean"},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 100000},
            }
        ),
        "run_ruff",
    )

    reg(
        "write_project_file",
        "Write a text/code file inside the configured project. Requires project_write_enabled=true.",
        _schema(
            {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "create_dirs": {"type": "boolean"},
            },
            required=["path", "content"],
        ),
        "write_project_file",
    )

    reg(
        "create_project_file",
        "Create a text/code file inside the configured project. Requires project_write_enabled=true.",
        _schema(
            {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "overwrite": {"type": "boolean"},
                "create_dirs": {"type": "boolean"},
            },
            required=["path"],
        ),
        "create_project_file",
    )

    reg(
        "append_project_file",
        "Append text to a project file. Requires project_write_enabled=true.",
        _schema(
            {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "create_dirs": {"type": "boolean"},
            },
            required=["path", "content"],
        ),
        "append_project_file",
    )

    reg(
        "replace_in_project_file",
        "Replace exact text in one project file. Requires project_write_enabled=true.",
        _schema(
            {
                "path": {"type": "string"},
                "old": {"type": "string"},
                "new": {"type": "string"},
                "count": {"type": "integer", "minimum": 1, "maximum": 1000},
            },
            required=["path", "old", "new"],
        ),
        "replace_in_project_file",
    )

    reg(
        "patch_project_file",
        "Apply multiple exact text replacements to a project file. Requires project_write_enabled=true.",
        _schema(
            {
                "path": {"type": "string"},
                "replacements": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "old": {"type": "string"},
                            "new": {"type": "string"},
                            "count": {"type": "integer"},
                        },
                        "required": ["old", "new"],
                        "additionalProperties": False,
                    },
                },
            },
            required=["path", "replacements"],
        ),
        "patch_project_file",
    )

    reg(
        "make_project_dir",
        "Create a directory inside the configured project. Requires project_write_enabled=true.",
        _schema(
            {
                "path": {"type": "string"},
            },
            required=["path"],
        ),
        "make_project_dir",
    )

    reg(
        "delete_project_path",
        "Delete a file or directory. Requires project_write_enabled=true and project_delete_enabled=True.",
        _schema(
            {
                "path": {"type": "string"},
                "recursive": {"type": "boolean"},
            },
            required=["path"],
        ),
        "delete_project_path",
    )


def build_default_tool_registry(
    *,
    tor_socks_url: str = DEFAULT_TOR_SOCKS_URL,
    prefer_tor_for_web: bool = False,
    app_config: Any = None,
) -> ToolRegistry:
    tools = ToolRegistry()
    tor_socks_url_config = tor_socks_url or DEFAULT_TOR_SOCKS_URL

    def effective_tor_url(user_value: str = "") -> str:
        return (user_value or tor_socks_url_config or DEFAULT_TOR_SOCKS_URL).strip()

    tools.register(
        ToolSpec(
            name="get_time",
            description="Get the current Unix time.",
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            fn=lambda: get_time(),
        )
    )

    tools.register(
        ToolSpec(
            name="save_note",
            description="Save a note to local disk.",
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["title", "body"],
                "additionalProperties": False,
            },
            fn=save_note,
        )
    )

    tools.register(
        ToolSpec(
            name="list_notes",
            description="List saved note filenames.",
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            fn=lambda: list_notes(),
        )
    )

    tools.register(
        ToolSpec(
            name="read_note",
            description="Read one saved note by title without .txt.",
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                },
                "required": ["title"],
                "additionalProperties": False,
            },
            fn=read_note,
        )
    )

    tools.register(
        ToolSpec(
            name="search_local_knowledge",
            description="Search local text/code files in data/knowledge.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    "per_file_limit": {"type": "integer", "minimum": 1, "maximum": 5},
                    "excerpt_chars": {"type": "integer", "minimum": 150, "maximum": 2000},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            fn=search_local_knowledge,
        )
    )


    tools.register(
        ToolSpec(
            name="sniff_url",
            description="Sniff a URL for readable text, links, images, videos, audio, documents, manifests, and JSON-derived asset URLs. Can route through Tor via tor_socks_url and can use JavaScript/browser mode via use_playwright=true.",
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_items": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "max_chars": {"type": "integer", "minimum": 500, "maximum": 2000000},
                    "include_html": {"type": "boolean"},
                    "tor_socks_url": {"type": "string"},
                    "use_playwright": {"type": "boolean"},
                    "verify_assets": {"type": "boolean"},
                },
                required=["url"],
            ),
            fn=sniff_url,
        )
    )

    tools.register(
        ToolSpec(
            name="sniff_text_assets",
            description="Sniff pasted HTML/text for absolute/relative links, images, video/audio URLs, documents, manifests, and JSON embedded URLs.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "base_url": {"type": "string"},
                    "max_items": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "include_html": {"type": "boolean"},
                },
                required=["text"],
            ),
            fn=sniff_text_assets,
        )
    )

    tools.register(
        ToolSpec(
            name="sniff_media",
            description="Sniff a page for media assets: video files, HLS/DASH manifests, segments, and audio URLs.",
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_items": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "tor_socks_url": {"type": "string"},
                    "use_playwright": {"type": "boolean"},
                },
                required=["url"],
            ),
            fn=sniff_media,
        )
    )

    tools.register(
        ToolSpec(
            name="sniff_images",
            description="Sniff a page for image URLs from HTML, srcset, CSS url(), JSON, OpenGraph, and optional browser/runtime assets.",
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_items": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "tor_socks_url": {"type": "string"},
                    "use_playwright": {"type": "boolean"},
                },
                required=["url"],
            ),
            fn=sniff_images,
        )
    )

    tools.register(
        ToolSpec(
            name="sniff_videos",
            description="Sniff a page for video URLs and manifests. Defaults to browser/runtime mode because many video links are JavaScript generated.",
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_items": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "tor_socks_url": {"type": "string"},
                    "use_playwright": {"type": "boolean"},
                },
                required=["url"],
            ),
            fn=sniff_videos,
        )
    )

    tools.register(
        ToolSpec(
            name="search_and_sniff",
            description="Search the web, then sniff the top result pages for links, images, video/audio, documents, and JSON-discovered assets.",
            parameters=_schema(
                {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 20},
                    "sniff_top_n": {"type": "integer", "minimum": 0, "maximum": 10},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 120},
                    "tor_socks_url": {"type": "string"},
                },
                required=["query"],
            ),
            fn=search_and_sniff,
        )
    )


    tools.register(
        ToolSpec(
            name="forensic_investigate_url",
            description=(
                "Run a public/authorized internet forensic investigation for a URL. "
                "Collects evidence records, redirects, headers, hashes, DNS/TLS context, "
                "sitemaps, feeds, URL variants, and optional public archive references. "
                "Does not bypass logins, paywalls, robots policy, or access controls."
            ),
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "include_archives": {"type": "boolean"},
                    "depth": {"type": "integer", "minimum": 0, "maximum": 3},
                    "max_pages": {"type": "integer", "minimum": 1, "maximum": 250},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_body_bytes": {"type": "integer", "minimum": 1024, "maximum": 100000000},
                    "max_evidence_items": {"type": "integer", "minimum": 1, "maximum": 20000},
                    "max_evidence_returned": {"type": "integer", "minimum": 1, "maximum": 20000},
                    "sqlite_path": {"type": "string"},
                    "artifact_dir": {"type": "string"},
                    "respect_robots": {"type": "boolean"},
                    "allow_cross_host_crawl": {"type": "boolean"},
                    "include_commoncrawl_search": {"type": "boolean"},
                    "include_wayback_search": {"type": "boolean"},
                    "include_dns": {"type": "boolean"},
                    "include_tls": {"type": "boolean"},
                    "include_sitemaps": {"type": "boolean"},
                    "include_feeds": {"type": "boolean"},
                    "include_url_variants": {"type": "boolean"},
                    "include_head_probe": {"type": "boolean"},
                    "include_range_probe": {"type": "boolean"},
                },
                required=["url"],
            ),
            fn=forensic_investigate_url,
        )
    )

    tools.register(
        ToolSpec(
            name="forensic_analyze_file",
            description="Analyze a local file for hashes, MIME/magic type, metadata, and embedded URL evidence.",
            parameters=_schema(
                {
                    "path": {"type": "string"},
                    "max_body_bytes": {"type": "integer", "minimum": 1024, "maximum": 500000000},
                    "max_evidence_returned": {"type": "integer", "minimum": 1, "maximum": 20000},
                    "sqlite_path": {"type": "string"},
                    "artifact_dir": {"type": "string"},
                },
                required=["path"],
            ),
            fn=forensic_analyze_file,
        )
    )

    tools.register(
        ToolSpec(
            name="forensic_extract_urls",
            description="Extract and classify URLs from pasted text/HTML/JSON/code without fetching them.",
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "base_url": {"type": "string"},
                    "max_urls": {"type": "integer", "minimum": 1, "maximum": 20000},
                },
                required=["text"],
            ),
            fn=forensic_extract_urls,
        )
    )

    tools.register(
        ToolSpec(
            name="forensic_url_variants",
            description="Generate safe URL variants useful for locating public cached, archived, or moved copies.",
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "max_variants": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
                required=["url"],
            ),
            fn=forensic_url_variants,
        )
    )

    tools.register(
        ToolSpec(
            name="forensic_domain_context",
            description="Collect compact DNS/TLS/header context for a URL without crawling linked pages.",
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "include_dns": {"type": "boolean"},
                    "include_tls": {"type": "boolean"},
                    "include_head_probe": {"type": "boolean"},
                    "include_range_probe": {"type": "boolean"},
                    "sqlite_path": {"type": "string"},
                },
                required=["url"],
            ),
            fn=forensic_domain_context,
        )
    )

    tools.register(
        ToolSpec(
            name="forensic_search_archives",
            description="Search public archive indexes for historical/lost copies of a URL using Wayback/Common Crawl-style collectors.",
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_archive_results": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "include_commoncrawl_search": {"type": "boolean"},
                    "include_wayback_search": {"type": "boolean"},
                    "sqlite_path": {"type": "string"},
                },
                required=["url"],
            ),
            fn=forensic_search_archives,
        )
    )


    tools.register(
        ToolSpec(
            name="cdn_investigate_url",
            description=(
                "Investigate a public/authorized URL for CDN-hosted assets, hard-to-notice links, "
                "JS chunks, source maps, manifests, cache/header clues, and conservative CDN URL variants. "
                "Does not bypass auth, private buckets, ACLs, signed URLs, or rate limits."
            ),
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_depth": {"type": "integer", "minimum": 0, "maximum": 3},
                    "max_pages": {"type": "integer", "minimum": 1, "maximum": 250},
                    "max_items": {"type": "integer", "minimum": 1, "maximum": 5000},
                    "max_items_returned": {"type": "integer", "minimum": 1, "maximum": 5000},
                    "include_archives": {"type": "boolean"},
                    "probe_candidates": {"type": "boolean"},
                    "sqlite_path": {"type": "string"},
                },
                required=["url"],
            ),
            fn=cdn_investigate_url,
        )
    )

    tools.register(
        ToolSpec(
            name="cdn_analyze_asset",
            description=(
                "Analyze one public/authorized CDN asset URL. Useful for JS/CSS bundles, source maps, "
                "manifests, media playlists, and CDN cache/header metadata."
            ),
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "probe_candidates": {"type": "boolean"},
                    "max_items_returned": {"type": "integer", "minimum": 1, "maximum": 5000},
                },
                required=["url"],
            ),
            fn=cdn_analyze_asset,
        )
    )

    tools.register(
        ToolSpec(
            name="cdn_extract_from_text",
            description=(
                "Extract CDN-style links, hard-to-notice asset URLs, source maps, chunk names, manifests, "
                "and cacheable public asset references from pasted HTML/CSS/JS/JSON/text without fetching."
            ),
            parameters=_schema(
                {
                    "text": {"type": "string"},
                    "base_url": {"type": "string"},
                    "max_items": {"type": "integer", "minimum": 1, "maximum": 5000},
                    "max_items_returned": {"type": "integer", "minimum": 1, "maximum": 5000},
                },
                required=["text"],
            ),
            fn=cdn_extract_from_text,
        )
    )

    tools.register(
        ToolSpec(
            name="cdn_url_variants",
            description="Generate conservative URL variants for public CDN/cache/lost-asset discovery.",
            parameters=_schema(
                {
                    "url": {"type": "string"},
                    "max_variants": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
                required=["url"],
            ),
            fn=cdn_url_variants,
        )
    )

    tools.register(
        ToolSpec(
            name="cdn_domain_context",
            description="Collect CDN provider, DNS, TLS, and edge/cache context for a host or URL.",
            parameters=_schema(
                {
                    "host_or_url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 120},
                },
                required=["host_or_url"],
            ),
            fn=cdn_domain_context,
        )
    )

    tools.register(
        ToolSpec(
            name="browse_web",
            description="Fetch a normal web page and return readable text.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 500, "maximum": 50000},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 120},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            fn=browse_web,
        )
    )

    tools.register(
        ToolSpec(
            name="browse_tor",
            description="Fetch a web page through Tor SOCKS proxy in static/no-JavaScript requests mode. Use tor_block with use_js=true for JavaScript/browser mode.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_chars": {"type": "integer", "minimum": 500, "maximum": 50000},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "tor_socks_url": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            fn=lambda url, max_chars=DEFAULT_MAX_PAGE_CHARS, timeout_sec=DEFAULT_WEB_TIMEOUT_SEC, tor_socks_url="": browse_tor(
                url=url,
                max_chars=max_chars,
                timeout_sec=timeout_sec,
                tor_socks_url=effective_tor_url(tor_socks_url),
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="extract_links",
            description="Fetch a page and return extracted HTTP/HTTPS links.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 120},
                    "max_links": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            fn=extract_links,
        )
    )

    tools.register(
        ToolSpec(
            name="extract_links_tor",
            description="Fetch a page through Tor in static/no-JavaScript requests mode and return extracted HTTP/HTTPS links. Use tor_block with use_js=true for JavaScript-rendered pages.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "max_links": {"type": "integer", "minimum": 1, "maximum": 200},
                    "tor_socks_url": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            fn=lambda url, timeout_sec=DEFAULT_WEB_TIMEOUT_SEC, max_links=25, tor_socks_url="": extract_links_tor(
                url=url,
                timeout_sec=timeout_sec,
                max_links=max_links,
                tor_socks_url=effective_tor_url(tor_socks_url),
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="check_tor_proxy",
            description="Check whether configured Tor SOCKS proxy works.",
            parameters={
                "type": "object",
                "properties": {
                    "tor_socks_url": {"type": "string"},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 60},
                },
                "additionalProperties": False,
            },
            fn=lambda tor_socks_url="", timeout_sec=8: check_tor_proxy(
                tor_socks_url=effective_tor_url(tor_socks_url),
                timeout_sec=timeout_sec,
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="search_web",
            description="Search the web using DuckDuckGo HTML and return ranked result links.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 20},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 120},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            fn=(
                lambda query, max_results=5, timeout_sec=DEFAULT_WEB_TIMEOUT_SEC: search_web(
                    query=query,
                    max_results=max_results,
                    timeout_sec=timeout_sec,
                    tor_socks_url=tor_socks_url_config if prefer_tor_for_web else None,
                )
            ),
        )
    )

    tools.register(
        ToolSpec(
            name="search_tor",
            description="Search the web through configured Tor SOCKS proxy.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 20},
                    "timeout_sec": {"type": "integer", "minimum": 3, "maximum": 180},
                    "tor_socks_url": {"type": "string"},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            fn=lambda query, max_results=5, timeout_sec=DEFAULT_WEB_TIMEOUT_SEC, tor_socks_url="": search_tor(
                query=query,
                max_results=max_results,
                timeout_sec=timeout_sec,
                tor_socks_url=effective_tor_url(tor_socks_url),
            ),
        )
    )


    if reverse_image_tool is not None:
        tools.register(
            ToolSpec(
                name="reverse_image_search",
                description=(
                    "Local from-scratch reverse image search. "
                    "Builds/searches a SQLite image index using Pillow + ImageHash perceptual hashes. "
                    "Use action='import_folder' to index a folder, action='add_path' or 'add_url' to add one image, "
                    "action='search' to find visually similar indexed images, and action='stats' to inspect the index."
                ),
                parameters=_schema(
                    {
                        "action": {
                            "type": "string",
                            "enum": [
                                "init_db",
                                "stats",
                                "add_path",
                                "add_url",
                                "import_folder",
                                "search",
                            ],
                            "description": "Operation to run. Default is search.",
                        },
                        "image_input": {
                            "type": "string",
                            "description": "Best general image input. Accepts a local path, file:// URL, or HTTP/HTTPS image URL.",
                        },
                        "image_path": {
                            "type": "string",
                            "description": "Local image path for add_path or search. Windows paths and relative paths are allowed.",
                        },
                        "image_url": {
                            "type": "string",
                            "description": "HTTP/HTTPS image URL for add_url/search. Local paths are also accepted and auto-routed to image_path handling.",
                        },
                        "folder": {
                            "type": "string",
                            "description": "Folder of images to import when action is import_folder.",
                        },
                        "db_path": {
                            "type": "string",
                            "description": "SQLite database path. Defaults to data/reverse_image/reverse_images.sqlite3.",
                        },
                        "store_dir": {
                            "type": "string",
                            "description": "Directory where indexed image copies are stored.",
                        },
                        "title": {
                            "type": "string",
                            "description": "Optional human title/label for an indexed image.",
                        },
                        "notes": {
                            "type": "string",
                            "description": "Optional notes for an indexed image.",
                        },
                        "source": {
                            "type": "string",
                            "description": "Optional source string/page URL for add_path.",
                        },
                        "recursive": {
                            "type": "boolean",
                            "description": "Import folder recursively.",
                        },
                        "copy_store": {
                            "type": "boolean",
                            "description": "Copy indexed images into the local content-addressed store.",
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 200,
                            "description": "Maximum matches to return for search.",
                        },
                        "max_hash_distance": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 500,
                            "description": "Maximum weighted perceptual-hash distance to keep.",
                        },
                        "timeout_sec": {
                            "type": "integer",
                            "minimum": 3,
                            "maximum": 180,
                            "description": "Timeout for URL downloads.",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100000,
                            "description": "Maximum images to import from a folder.",
                        },
                        "max_dimension": {
                            "type": "integer",
                            "minimum": 128,
                            "maximum": 4096,
                            "description": "Maximum dimension used for normalized hashing.",
                        },
                    }
                ),
                fn=reverse_image_tool,
            )
        )


    _register_intelligence_engine_tools(tools)
    _register_language_engine_tools(tools)
    _register_python_engine_tools(tools)
    _register_coding_engine_tools(tools)
    _register_apidoc_engine_tools(tools)
    _register_tracker_engine_tools(tools)
    _register_interactive_browser_tools(tools)
    _register_application_engine_tools(tools)
    _register_news_engine_tools(tools)
    _register_monero_monitor_tools(tools)
    _register_stock_monitor_tools(tools)
    _register_resale_monitor_tools(tools)
    _register_engines_tools(tools)
    _register_packet_tools(tools)
    _register_project_tools(tools, app_config)
    return tools