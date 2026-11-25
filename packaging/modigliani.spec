# PyInstaller spec for modigliani.exe (built by .github/workflows/release.yml on tags).
# Run from the repository root: uv run pyinstaller --noconfirm --distpath dist packaging/modigliani.spec
# ruff: noqa
import os

from PyInstaller.utils.hooks import collect_all, collect_data_files

datas, binaries, hiddenimports = [], [], []
# mitmproxy, scapy and aiocoap load modules and data files dynamically.
for package in ("mitmproxy", "mitmproxy_rs", "scapy", "aiocoap", "dnslib", "uvicorn"):
    d, b, h = collect_all(package)
    datas += d
    binaries += b
    hiddenimports += h
datas += collect_data_files("modigliani", includes=["web/static/*", "py.typed"])

a = Analysis(
    [os.path.join(SPECPATH, "entry.py")],
    pathex=[os.path.join(SPECPATH, "..", "studio", "src")],
    datas=datas,
    binaries=binaries,
    hiddenimports=hiddenimports + ["modigliani.cli"],
    excludes=["tkinter", "mitmproxy.tools.web", "tornado"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="modigliani",
    console=True,
    upx=False,
)
