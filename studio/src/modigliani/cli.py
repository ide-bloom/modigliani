"""Modigliani Studio command line."""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Annotated, Any, cast

import typer
from rich.console import Console
from rich.table import Table

from modigliani import __version__, ca
from modigliani.annotate.model import AnnotationSet
from modigliani.capture.enrollment import Enrollment, EnrollmentError, visible_devices
from modigliani.capture.model import Capture
from modigliani.workspace import Workspace

app = typer.Typer(
    name="modigliani",
    help="Record a device's cloud traffic, infer its protocol, and revive it with Modigliani Server.",
    no_args_is_help=True,
    add_completion=False,
)
ca_app = typer.Typer(help="Manage the local certificate authority.", no_args_is_help=True)
app.add_typer(ca_app, name="ca")
console = Console()
err = Console(stderr=True)

WorkspaceOpt = Annotated[
    Path | None,
    typer.Option("--workspace", "-w", help="Workspace directory (default: $MODIGLIANI_HOME or the current directory)"),
]


def _ws(path: Path | None) -> Workspace:
    return Workspace.from_env(path)


def _fail(message: str, code: int = 1) -> typer.Exit:
    err.print(f"[red]error:[/red] {message}")
    return typer.Exit(code)


def _version(value: bool) -> None:
    if value:
        console.print(f"modigliani {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version")
    ] = False,
) -> None:
    """Modigliani Studio."""


# ----------------------------------------------------------------------------- enroll


@app.command()
def enroll(
    name: Annotated[str | None, typer.Option(help="A name for the device, e.g. 'plug'")] = None,
    mac: Annotated[str | None, typer.Option(help="Device MAC address")] = None,
    ip: Annotated[str | None, typer.Option(help="Device IP address")] = None,
    i_own_this_device: Annotated[
        bool, typer.Option("--i-own-this-device", help="Confirm you own the device (non-interactive)")
    ] = False,
    remove: Annotated[str | None, typer.Option(help="Remove an enrolled device by name")] = None,
    list_only: Annotated[bool, typer.Option("--list", help="Show enrolled and visible devices")] = False,
    workspace: WorkspaceOpt = None,
) -> None:
    """Pick devices by MAC or IP. Only enrolled devices are ever resolved, proxied or recorded."""
    ws = _ws(workspace)
    enr = Enrollment.load(ws.enrollment_file)
    if remove:
        if not enr.remove(remove):
            raise _fail(f"no enrolled device named {remove!r}")
        enr.save(ws.enrollment_file)
        console.print(f"removed {remove}")
        return
    if list_only or (name is None and mac is None and ip is None):
        table = Table(title="Enrolled devices")
        for col in ("name", "mac", "ip"):
            table.add_column(col)
        for d in enr.devices:
            table.add_row(d.name, d.mac or "-", d.ip or "-")
        console.print(table)
        seen = visible_devices()
        vt = Table(title="Visible on this network (from the ARP table; nothing is scanned)")
        for col in ("ip", "mac", "interface"):
            vt.add_column(col)
        for n in seen:
            vt.add_row(n.ip, n.mac, n.interface)
        console.print(vt)
        if list_only or not sys.stdin.isatty():
            return
        choice = typer.prompt("Enroll which device? (IP or MAC, empty to stop)", default="", show_default=False)
        if not choice:
            return
        match = next((n for n in seen if choice in (n.ip, n.mac)), None)
        ip = match.ip if match else (choice if "." in choice else None)
        mac = match.mac if match else (choice if ":" in choice or "-" in choice else None)
        name = typer.prompt("Name for this device")
    if name is None:
        raise _fail("--name is required")
    owned = i_own_this_device or (
        sys.stdin.isatty()
        and typer.confirm(
            f"Do you own '{name}' ({mac or ip}) and are you allowed to record its traffic?", default=False
        )
    )
    try:
        dev = enr.add(name, mac=mac, ip=ip, owner_confirmed=owned)
    except EnrollmentError as exc:
        raise _fail(str(exc)) from exc
    enr.save(ws.enrollment_file)
    console.print(f"enrolled [bold]{dev.name}[/bold] (mac={dev.mac or '-'}, ip={dev.ip or '-'})")


# ----------------------------------------------------------------------------- record


@app.command()
def record(
    mode: Annotated[str, typer.Option(help="passive (sniff) or proxy (terminate TLS with the local CA)")] = "passive",
    minutes: Annotated[float, typer.Option(help="How long to record")] = 10.0,
    name: Annotated[str | None, typer.Option(help="Capture name (default: timestamp)")] = None,
    interface: Annotated[
        str | None, typer.Option(help="Capture interface for passive mode (default: the Windows hotspot)")
    ] = None,
    route: Annotated[
        list[str] | None, typer.Option(help="Proxy route SCHEME:PORT=HOSTNAME[@UPSTREAM:PORT]; repeatable")
    ] = None,
    dns: Annotated[bool, typer.Option(help="Run router-mode DNS for enrolled devices")] = False,
    dns_port: Annotated[int, typer.Option(help="Router-mode DNS port")] = 53,
    dns_answer: Annotated[
        str | None, typer.Option(help="Answer enrolled devices' queries with this IP (proxy mode)")
    ] = None,
    dns_upstream: Annotated[str, typer.Option(help="Upstream resolver for router-mode DNS")] = "1.1.1.1",
    upstream_ca: Annotated[Path | None, typer.Option(help="Extra CA bundle for verifying the vendor's servers")] = None,
    stop_file: Annotated[Path | None, typer.Option(hidden=True, help="Stop when this file appears")] = None,
    ready_file: Annotated[Path | None, typer.Option(hidden=True, help="Create this file once listening")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Capture the enrolled devices' traffic."""
    ws = _ws(workspace)
    enr = Enrollment.load(ws.enrollment_file)
    if not enr.devices:
        raise _fail("no enrolled devices; run `modigliani enroll` first")
    cap_name = name or time.strftime("capture-%Y%m%d-%H%M%S")
    out = ws.capture_path(cap_name)
    ws.captures.mkdir(parents=True, exist_ok=True)
    ws.recording_marker.write_text(cap_name, encoding="utf-8")
    stop = threading.Event()

    def watch_stop() -> None:
        while not stop.is_set():
            if stop_file is not None and stop_file.exists():
                stop.set()
            time.sleep(0.2)

    threading.Thread(target=watch_stop, daemon=True).start()
    router = None
    if dns:
        from modigliani.capture.dns_router import RouterDns, start_dns

        router = RouterDns(enr, upstream=dns_upstream, answer_ip=dns_answer)
        start_dns(router, port=dns_port)
        console.print(f"router-mode DNS listening on UDP {dns_port}")
    seconds = minutes * 60
    if mode == "proxy":
        from modigliani.capture.proxy import ProxyError, Recorder, Route, run_proxy

        if not ca.exists(ws.ca_dir):
            raise _fail("proxy mode needs the local CA; run `modigliani ca init`")
        try:
            routes = [Route.parse(r) for r in (route or [])]
        except ProxyError as exc:
            raise _fail(str(exc)) from exc
        if not routes:
            raise _fail("proxy mode needs at least one --route (see docs/capture-setups.md)")
        recorder = Recorder(
            enrollment=enr, routes=routes, name=cap_name, resolver=router.resolve_real if router else None
        )
        ready = threading.Event()

        def announce() -> None:
            ready.wait()
            if ready_file is not None:
                ready_file.write_text("ready", encoding="utf-8")
            console.print(f"recording (proxy) on {', '.join(str(r.listen_port) for r in routes)} for {minutes:g} min")

        threading.Thread(target=announce, daemon=True).start()
        try:
            capture = asyncio.run(
                run_proxy(recorder, ws.ca_dir, seconds=seconds, upstream_ca=upstream_ca, stop=stop, ready=ready)
            )
        except KeyboardInterrupt:
            capture = recorder.capture()
    elif mode == "passive":
        from modigliani.capture.hotspot import CaptureUnavailableError, live_capture
        from modigliani.capture.pcap_import import import_pcap

        pcap = out.with_suffix("").with_suffix(".pcap")
        try:
            if ready_file is not None:
                ready_file.write_text("ready", encoding="utf-8")
            console.print(f"recording (passive) for {minutes:g} min; press Ctrl+C to stop early")
            live_capture(interface, enr, seconds, pcap, stop=stop)
        except CaptureUnavailableError as exc:
            raise _fail(str(exc)) from exc
        capture = import_pcap(pcap, enr, cap_name)
        capture.mode = "passive"
    else:
        raise _fail("--mode must be passive or proxy")
    stop.set()
    ws.recording_marker.unlink(missing_ok=True)
    if router is not None:
        capture.dns += router.records
    capture.save(out)
    console.print(f"saved {out} ({len(capture.flows)} flows from {len(capture.devices)} devices)")


@app.command("import")
def import_cmd(
    pcap: Annotated[Path, typer.Argument(help="pcap or pcapng file (OpenWrt, tcpdump, Wireshark)")],
    name: Annotated[str | None, typer.Option(help="Capture name")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Import a pcap file, keeping only enrolled devices' traffic."""
    from modigliani.capture.pcap_import import import_pcap

    ws = _ws(workspace)
    enr = Enrollment.load(ws.enrollment_file)
    if not enr.devices:
        raise _fail("no enrolled devices; run `modigliani enroll` first")
    capture = import_pcap(pcap, enr, name or pcap.stem)
    out = ws.capture_path(capture.name)
    capture.save(out)
    console.print(f"saved {out} ({len(capture.flows)} flows from {len(capture.devices)} enrolled devices)")


# ----------------------------------------------------------------------------- annotate


def _serve(state: object, port: int, open_browser: bool) -> None:
    import uvicorn

    from modigliani.web.app import StudioState, create_app

    assert isinstance(state, StudioState)
    url = f"http://127.0.0.1:{port}/"
    console.print(f"Studio at {url} (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(create_app(state), host="127.0.0.1", port=port, log_level="warning")


@app.command()
def annotate(
    capture: Annotated[
        str | None, typer.Argument(help="Capture name or path (default: the one being recorded, else the latest)")
    ] = None,
    add: Annotated[str | None, typer.Option(help="Add one annotation without opening Studio")] = None,
    at: Annotated[float | None, typer.Option(help="Unix time for --add (default: now)")] = None,
    device: Annotated[str | None, typer.Option(help="Enrolled device the annotation is about")] = None,
    port: Annotated[int, typer.Option(help="Studio port")] = 8765,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Do not open a browser")] = False,
    workspace: WorkspaceOpt = None,
) -> None:
    """Open the Studio timeline to mark the actions you perform in the vendor's phone app."""
    from modigliani.web.app import StudioState

    ws = _ws(workspace)
    capture = capture or ws.current_capture()
    if capture is None:
        raise _fail("no capture yet: start `modigliani record` first, or name a capture")
    cap_path = ws.capture_path(capture)
    ann_path = ws.annotations_path(cap_path)
    if add is not None:
        a = AnnotationSet.append(ann_path, add, at, cap_path.name, device)
        console.print(f"annotated {a.label!r} at {a.ts:.3f}: variable={a.variable} value={a.value!r} unit={a.unit}")
        return
    _serve(StudioState(capture_path=cap_path, annotations_path=ann_path), port, not no_browser)


# ----------------------------------------------------------------------------- infer


@app.command()
def infer(
    captures: Annotated[list[str], typer.Argument(help="Capture names or paths")],
    device: Annotated[str | None, typer.Option(help="Enrolled device name (default: the only device)")] = None,
    out: Annotated[Path | None, typer.Option(help="Output profile path (.yaml or .json)")] = None,
    profile_id: Annotated[str | None, typer.Option("--id", help="Profile id")] = None,
    name: Annotated[str | None, typer.Option(help="Device display name")] = None,
    vendor: Annotated[str | None, typer.Option(help="Vendor name")] = None,
    model: Annotated[str | None, typer.Option(help="Model name")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Build a device profile, with evidence, from captures and annotations."""
    from modigliani.infer.engine import infer_profile
    from modigliani.profile.io import save_profile
    from modigliani.profile.validate import semantic_errors

    ws = _ws(workspace)
    loaded: list[Capture] = []
    anns: list[AnnotationSet] = []
    for c in captures:
        path = ws.capture_path(c)
        if not path.exists():
            raise _fail(f"capture not found: {path}")
        loaded.append(Capture.load(path))
        anns.append(AnnotationSet.load(ws.annotations_path(path)))
    devices = sorted({f.device for cap in loaded for f in cap.flows})
    if device is None:
        if len(devices) > 1:
            raise _fail(f"captures contain several devices ({', '.join(devices)}); pass --device")
        device = devices[0] if devices else None
    annotations = [a for s in anns for a in s.for_device(device)]
    result = infer_profile(loaded, annotations, device=device, profile_id=profile_id, name=name or device)
    if vendor:
        result.profile.device.vendor = vendor
    if model:
        result.profile.device.model = model
    target = out or ws.local_profiles / f"{result.profile.id}.yaml"
    save_profile(result.profile, target)
    for line in result.summary:
        console.print(line)
    problems = semantic_errors(result.profile)
    for p in problems:
        err.print(f"[yellow]warning:[/yellow] {p}")
    console.print(f"wrote {target}")
    if not result.revivable:
        console.print("[bold red]Result: not revivable without firmware access.[/bold red]")


# ----------------------------------------------------------------------------- review / test


@app.command()
def review(
    profile: Annotated[Path, typer.Argument(help="Profile to inspect and edit")],
    capture: Annotated[str | None, typer.Option(help="Capture to show on the timeline")] = None,
    port: Annotated[int, typer.Option(help="Studio port")] = 8765,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Do not open a browser")] = False,
    workspace: WorkspaceOpt = None,
) -> None:
    """Inspect and edit a profile in Studio."""
    from modigliani.web.app import StudioState

    ws = _ws(workspace)
    if not profile.exists():
        raise _fail(f"profile not found: {profile}")
    cap_path = ws.capture_path(capture) if capture else None
    state = StudioState(
        profile_path=profile,
        capture_path=cap_path,
        annotations_path=ws.annotations_path(cap_path) if cap_path else None,
    )
    _serve(state, port, not no_browser)


@app.command("test")
def run_test(
    profile: Annotated[Path, typer.Argument(help="Profile to test")],
    captures: Annotated[
        list[str] | None, typer.Argument(help="Captures to replay (default: those named in the profile's provenance)")
    ] = None,
    device: Annotated[str | None, typer.Option(help="Device name in the captures")] = None,
    server_bin: Annotated[Path | None, typer.Option(help="Path to modigliani-server")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Replay the device's side of recorded sessions against Modigliani Server and check its answers."""
    from modigliani.profile.io import load_profile
    from modigliani.tester import find_server_binary, replay, running_server

    ws = _ws(workspace)
    prof = load_profile(profile)
    if prof.revivability.status == "not_revivable_without_firmware_access":
        raise _fail("this profile is marked not revivable without firmware access; there is nothing to test", 3)
    names = captures or [c.name for c in prof.provenance.captures]
    paths = [ws.capture_path(n) for n in names]
    missing = [str(p) for p in paths if not p.exists()]
    if not names or missing:
        raise _fail("recorded sessions not found: " + (", ".join(missing) or "the profile names no captures"))
    loaded = [Capture.load(p) for p in paths]
    try:
        binary = find_server_binary(server_bin)
    except FileNotFoundError as exc:
        raise _fail(str(exc)) from exc
    with running_server(binary, profile, prof) as server:
        results = replay(prof, loaded, server, device)
    table = Table(title=f"Replay of {profile.name}")
    for col in ("protocol", "message", "result", "detail"):
        table.add_column(col)
    for r in results:
        table.add_row(r.protocol, r.what, "[green]pass[/green]" if r.ok else "[red]FAIL[/red]", r.detail)
    console.print(table)
    failed = [r for r in results if not r.ok]
    console.print(f"{len(results) - len(failed)}/{len(results)} passed")
    if failed or not results:
        raise typer.Exit(1)


# ----------------------------------------------------------------------------- export / install / keys


@app.command()
def export(
    profile: Annotated[Path, typer.Argument(help="Local profile to export")],
    share: Annotated[bool, typer.Option("--share", help="Scrub identifiers and sign for sharing")] = False,
    out: Annotated[Path | None, typer.Option(help="Output directory (default: ./profiles/library)")] = None,
    license_id: Annotated[str, typer.Option("--license", help="CC0-1.0 or CC-BY-4.0")] = "CC0-1.0",
    author: Annotated[str | None, typer.Option(help="Author credit (for CC-BY-4.0)")] = None,
    key: Annotated[Path | None, typer.Option(help="ed25519 signing key (default: your user key)")] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Accept the scrub diff without prompting")] = False,
) -> None:
    """Write a profile for sharing: scrubbed (with a full diff you confirm) and signed."""
    from modigliani.profile import sign
    from modigliani.profile.io import load_profile, save_profile
    from modigliani.profile.scrub import identifiers_in, scrub
    from modigliani.profile.validate import semantic_errors

    prof = load_profile(profile)
    target_dir = out or Path("profiles") / "library"
    if not share:
        dest = target_dir / profile.name
        save_profile(prof, dest)
        console.print(f"wrote {dest} (not scrubbed: keep it private, or use --share)")
        return
    if license_id not in ("CC0-1.0", "CC-BY-4.0"):
        raise _fail("--license must be CC0-1.0 or CC-BY-4.0")
    secrets_before = identifiers_in(prof)
    scrubbed, changes = scrub(prof)
    table = Table(title="Scrub diff: these values are removed before sharing")
    for col in ("where", "before", "after", "why"):
        table.add_column(col, overflow="fold")
    for c in changes:
        table.add_row(c.path, c.before, c.after, c.reason)
    console.print(table)
    if not yes and not typer.confirm("Export the scrubbed profile?", default=False):
        raise typer.Exit(1)
    scrubbed.provenance.license = cast(Any, license_id)
    scrubbed.provenance.author = author
    problems = semantic_errors(scrubbed)
    if problems:
        raise _fail("scrubbed profile is invalid:\n" + "\n".join(problems))
    dest = target_dir / f"{scrubbed.id}.yaml"
    save_profile(scrubbed, dest)
    text = dest.read_text(encoding="utf-8")
    leaked = [s for s in secrets_before if s and s in text]
    if leaked:
        dest.unlink()
        raise _fail("refusing to export: identifiers survived scrubbing; please report this as a bug")
    key_path = key or sign.default_key_path()
    if not key_path.exists():
        sign.generate_key(key_path)
        console.print(f"generated signing key {key_path}")
    sig = sign.sign_file(dest, sign.load_key(key_path))
    console.print(f"wrote {dest} and {sig}")


@app.command()
def install(
    profile: Annotated[Path, typer.Argument(help="Shared (scrubbed) profile")],
    captures: Annotated[list[str], typer.Argument(help="Your own capture(s) of the device")],
    set_value: Annotated[
        list[str] | None, typer.Option("--set", help="NAME=VALUE for a placeholder; repeatable")
    ] = None,
    device: Annotated[str | None, typer.Option(help="Device name in the captures")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Fill a shared profile's placeholders from your own capture and save it to profiles/local/."""
    from modigliani.profile.install import fill_placeholders
    from modigliani.profile.io import load_profile, save_profile
    from modigliani.profile.sign import verify_file

    ws = _ws(workspace)
    v = verify_file(profile)
    console.print(f"signature: {v.status}" + (f" (key {v.key_id})" if v.key_id else ""))
    if v.status == "invalid":
        raise _fail("the profile's signature is invalid; it was modified after signing")
    overrides = {}
    for item in set_value or []:
        if "=" not in item:
            raise _fail(f"--set expects NAME=VALUE, got {item!r}")
        k, val = item.split("=", 1)
        overrides[k] = val
    loaded = [Capture.load(ws.capture_path(c)) for c in captures]
    filled, report = fill_placeholders(load_profile(profile), loaded, overrides, device)
    dest = ws.local_profiles / f"{filled.id}.yaml"
    save_profile(filled, dest)
    for k, val in report.filled.items():
        console.print(f"  {k} = {val} (from your capture)")
    for k in report.generated:
        console.print(f"  {k} = (generated)")
    for k in report.missing:
        err.print(f"[yellow]  {k}: not found; pass --set {k}=VALUE[/yellow]")
    console.print(f"wrote {dest}")


@app.command()
def keygen(
    path: Annotated[Path | None, typer.Option(help="Key file (default: your user config directory)")] = None,
    force: Annotated[bool, typer.Option(help="Replace an existing key")] = False,
) -> None:
    """Generate the ed25519 key used to sign shared profiles."""
    from modigliani.profile import sign

    try:
        p = sign.generate_key(path, force=force)
    except FileExistsError as exc:
        raise _fail(str(exc)) from exc
    import base64

    pub = base64.b64encode(sign.public_raw(sign.load_key(p))).decode()
    console.print(f"wrote {p}\npublic key (add to the server's trusted_keys): {pub}")


@app.command()
def verify(profile: Annotated[Path, typer.Argument(help="Profile to check")]) -> None:
    """Validate a profile and check its signature."""
    from modigliani.profile.io import load_data
    from modigliani.profile.sign import verify_file
    from modigliani.profile.validate import validate

    _, errors = validate(load_data(profile))
    for e in errors:
        err.print(f"[red]{e}[/red]")
    v = verify_file(profile)
    console.print(f"schema: {'ok' if not errors else f'{len(errors)} errors'}; signature: {v.status}")
    if errors or v.status == "invalid":
        raise typer.Exit(1)


# ----------------------------------------------------------------------------- ca / doctor


@ca_app.command("init")
def ca_init(
    force: Annotated[bool, typer.Option(help="Replace an existing CA")] = False,
    workspace: WorkspaceOpt = None,
) -> None:
    """Create the local CA (key encrypted with DPAPI on Windows, owner-only elsewhere)."""
    ws = _ws(workspace)
    try:
        info = ca.init(ws.ca_dir, force=force)
    except ca.CaError as exc:
        raise _fail(str(exc)) from exc
    console.print(
        f"created {info.cert_path}\n  {info.subject}\n  SHA-256 {info.fingerprint_sha256}\n  key: {info.key_protection}"
    )
    console.print(
        "The CA is never installed into this PC's trust store. Only enrolled devices are offered its certificates."
    )


@ca_app.command("show")
def ca_show(workspace: WorkspaceOpt = None) -> None:
    """Show the local CA."""
    ws = _ws(workspace)
    try:
        info = ca.info(ws.ca_dir)
    except ca.CaError as exc:
        raise _fail(str(exc)) from exc
    console.print(
        json.dumps(
            {
                "subject": info.subject,
                "sha256": info.fingerprint_sha256,
                "not_before": info.not_before.isoformat(),
                "not_after": info.not_after.isoformat(),
                "key_protection": info.key_protection,
                "certificate": str(info.cert_path),
            },
            indent=2,
        )
    )


@app.command()
def doctor(
    server: Annotated[str, typer.Option(help="Modigliani Server local API URL")] = "http://127.0.0.1:8080",
    probe: Annotated[str, typer.Option(help="Hostname to resolve for the DNS check")] = "example.com",
    workspace: WorkspaceOpt = None,
) -> None:
    """Check Npcap, hotspot state, DNS reachability, the CA and server connectivity."""
    from modigliani.doctor import run_checks

    checks = run_checks(_ws(workspace), server, probe)
    colors = {"ok": "green", "warn": "yellow", "fail": "red", "skip": "dim"}
    for c in checks:
        console.print(f"[{colors[c.status]}]{c.status.upper():>4}[/{colors[c.status]}]  {c.name}: {c.detail}")
    if any(c.status == "fail" for c in checks):
        raise typer.Exit(1)


def main() -> None:
    app()
