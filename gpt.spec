# gpt.spec
# PyInstaller spec for GPTProject Pro GUI as a single-file executable.

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# PyInstaller spec files do not reliably expose __file__.
# This assumes you run: pyinstaller gpt.spec
# from the project root.
project_root = Path.cwd().resolve()

datas = []

prompts_dir = project_root / "prompts"
if prompts_dir.exists():
    datas.append((str(prompts_dir), "prompts"))

assets_dir = project_root / "assets"
if assets_dir.exists():
    datas.append((str(assets_dir), "assets"))

hiddenimports = []
hiddenimports += collect_submodules("PyQt5")
hiddenimports += [
    "PyQt5.sip",
    "requests",
    "requests.adapters",
    "urllib3",
    "config",
    "memory",
    "provider_local",
    "runtime",
    "tools",
    "retrieval",
    'apidoc_engine',
    'application_engine',
    'cdn_engine',
    'coding_engine',
    'engines',
    'forensic_engine',
    'gui',
    'intelligence_engine',
    'interactive_browser_engine',
    'language_engine',
    'libpcap_backend',
    'loggers',
    'main',
    'monero_monitor_engine',
    'news_engine',
    'packet_engine',
    'project_tools',
    'python_engine',
    'resale_engine_monitor',
    'reverse_image_engine',
    'sniffer_engine',
    'stock_engine_monitor',
    'tracker_engine'
]

try:
    hiddenimports += collect_submodules("dotenv")
except Exception:
    pass

try:
    hiddenimports += collect_submodules("socks")
except Exception:
    pass

a = Analysis(
    ["gui.py"],   # change if your GUI entry file has a different name
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

# One-file build = EXE only, with binaries/datas included here and no COLLECT step.
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="GPTProjectPro",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,   # e.g. str(project_root / "assets" / "app.ico")
)