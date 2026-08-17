"""Connect: hand an admin a ready-to-use RDP / SSH launch for a monitored host.

DESIGN DECISION — this app never sees a credential.

It does not proxy, tunnel, or authenticate anything. It generates an .rdp file (Windows)
or an ssh:// link plus a copy-ready command (Linux), and the admin's OWN client — mstsc,
PuTTY, Windows Terminal — prompts for the credential through the operating system. That
keeps saved credentials, smart cards, Windows Hello and NLA working, and it keeps this
webapp off the credential path entirely: if it is ever compromised there is nothing here
to steal. A web form that collected SSH/RDP passwords would both train admins to type
privileged credentials into a web page and make this app the highest-value target on the
network. Neither is worth the convenience.

REACHABILITY comes from Prometheus `up`, which is already scraped every ~15s — not from a
fresh ICMP ping. No new subprocess, no raw-socket permissions, no blocking the request
thread, and no pretending that ping success means port 22/3389 is open. Note also that the
server's view of the network is not the admin's view: Django and the admin's workstation sit
in different positions, so a server-side probe cannot answer "can *I* reach this host".

It is therefore rendered as a BADGE, never as a disabled button. The moment you most want
to reach a box is when it is showing red — a greyed-out button would block exactly the case
the feature exists for.

If a bastion / jump host is introduced later, the only thing that changes is `_ssh_command`
and the .rdp gateway lines; the inventory and the UI stay as they are.
"""
from __future__ import annotations

from typing import Dict, List, Optional

import generate_report as gr   # from send_report/ (on sys.path) — the topology loader


# Which exporter is scraped on a port tells us the OS, so the protocol needs no new config.
#   9182 = windows_exporter · 9100/9101 = node_exporter
_PORT_OS = {"9182": "windows", "9100": "linux", "9101": "linux"}

_PROTOCOL = {
    "windows": {"protocol": "rdp", "port": 3389, "label": "RDP", "client": "Remote Desktop"},
    "linux":   {"protocol": "ssh", "port": 22,   "label": "SSH", "client": "SSH terminal"},
}


def _split_instance(instance: str) -> tuple:
    """'10.0.212.3:9182' -> ('10.0.212.3', '9182'). Targets without a port yield ('host', '')."""
    inst = (instance or "").strip()
    if "://" in inst:                       # a blackbox URL target, not a shell-able host
        return "", ""
    if ":" in inst:
        addr, _, port = inst.rpartition(":")
        return addr, port
    return inst, ""


def host_os(instance: str) -> Optional[str]:
    """'windows' | 'linux' | None (unknown exporter port / not a host target)."""
    _addr, port = _split_instance(instance)
    return _PORT_OS.get(port)


def fetch_up(cfg=None) -> Optional[Dict[str, bool]]:
    """{instance: reachable} straight from Prometheus `up` — ONE cheap instant query, not a
       full capture. Returns None when Prometheus itself can't be reached, which the UI shows
       as 'unknown' rather than silently claiming everything is down."""
    cfg = cfg or gr.load_config()
    try:
        from .models import SystemConfig
        sc = SystemConfig.get()
        if sc.prometheus_url:
            cfg.prom = sc.prometheus_url
    except Exception:                       # noqa: BLE001 — DB/config optional here
        pass
    try:
        prom = gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
        return {r["labels"]["instance"]: r["value"] >= 1
                for r in prom.query("up") if r["labels"].get("instance")}
    except Exception:                       # noqa: BLE001 — Prometheus down: reachability unknown
        return None


def _ssh_command(address: str, user: str = "") -> str:
    """The command an admin pastes into a terminal. A bastion, if one is ever introduced,
       is a -J flag added right here."""
    return f"ssh {user}@{address}" if user else f"ssh {address}"


def build_host(system: str, label: str, instance: str, up: Optional[Dict[str, bool]],
               os_hint: str = "") -> dict:
    """`os_hint` is the platform the TOPOLOGY already established for this component (from its
    scrape job — see gr.platform_of_job). It wins over the port lookup below, which is only a
    convention: a site scraping windows_exporter on a non-default port used to fall through to
    no OS at all, and so was offered no protocol and no Connect button on a host that is
    perfectly reachable over RDP. The port stays as the fallback for callers that have an
    instance string and nothing else."""
    addr, port = _split_instance(instance)
    osname = os_hint or _PORT_OS.get(port)
    proto = _PROTOCOL.get(osname or "", {})
    reachable = None if up is None else bool(up.get(instance, False))
    return {
        "system": system,
        "label": label,
        "instance": instance,        # the scrape target — the key we validate against
        "address": addr,             # the host itself, no exporter port
        "os": osname,                # windows | linux | None
        "protocol": proto.get("protocol"),
        "protocol_label": proto.get("label", "—"),
        "client": proto.get("client", ""),
        "connectable": bool(proto),
        "reachable": reachable,      # True | False | None (unknown)
        "ssh_command": _ssh_command(addr) if proto.get("protocol") == "ssh" else "",
        # Scheme URL. Makes a click launch the native client DIRECTLY, once
        # tools/install-connect-handlers.ps1 has registered the scheme on the workstation.
        # Until then the browser ignores it — which is why the dialog always offers the
        # paste-ready command and the .rdp download as well.
        "ssh_uri": f"ssh://{addr}" if proto.get("protocol") == "ssh" else "",
        "rdp_uri": f"rdp://{addr}" if proto.get("protocol") == "rdp" else "",
        "uri": f"{proto['protocol']}://{addr}" if proto else "",
        # What the admin pastes if they'd rather not install anything. Run box for RDP,
        # terminal for SSH — the dialog labels which is which.
        "command": (f"mstsc /v:{addr}" if proto.get("protocol") == "rdp"
                    else (_ssh_command(addr) if proto.get("protocol") == "ssh" else "")),
        "paste_target": ("the Run box (Win+R)" if proto.get("protocol") == "rdp"
                         else "a terminal" if proto.get("protocol") == "ssh" else ""),
        "port": proto.get("port"),
    }


def inventory(only: Optional[set] = None, with_reachability: bool = True) -> List[dict]:
    """Every monitored host, grouped by system: [{name, hosts:[...]}, ...].
       Reads the topology file only — no capture — so the page is cheap to open."""
    cfg = gr.load_config()
    systems = gr.load_topology(cfg.prometheus_yml)
    if only:
        systems = [s for s in systems if s.name in only]
    up = fetch_up(cfg) if with_reachability else None
    out = []
    for s in systems:
        hosts = [build_host(s.name, c.label, c.instance, up, getattr(c, "os", ""))
                 for c in s.components]
        out.append({
            "name": s.name,
            "hosts": hosts,
            "up_count": sum(1 for h in hosts if h["reachable"] is True),
            "down_count": sum(1 for h in hosts if h["reachable"] is False),
        })
    return out


def hosts_from_snapshot(systems, store) -> Dict[str, List[dict]]:
    """{system_name: [host, ...]} built from a snapshot that was ALREADY captured.

    Used by the report screen so the per-system launch strip costs nothing: the topology and
    the `up` series are both already in the snapshot the admin is looking at, so there is no
    extra Prometheus round-trip and the reachability shown matches the numbers on the page
    exactly (rather than drifting a few seconds ahead of them).
    """
    up = {inst: val >= 1 for inst, val in (getattr(store, "up", {}) or {}).items()}
    return {s.name: [build_host(s.name, c.label, c.instance, up, getattr(c, "os", ""))
                     for c in s.components]
            for s in systems}


_BAND_RANK = {"red": 2, "amber": 1}


def attach_flag_severity(hosts_by_system: Dict[str, List[dict]], system_vms) -> None:
    """Colour each host chip by the WORST flag standing against it.

    Derived from the very flags the panel above renders — never recomputed from thresholds —
    so a chip can never contradict the rows beside it. The engine embeds the component label
    as the second segment of every host-scoped flag key (`disk:<label>:<mount>`, `ram:<label>`,
    `cpu:<label>`, `unreachable:<label>`, `backup:<label>`), which is what we match on.

    Flags that belong to the system rather than a host (e.g. `untracked:<system>`) match no
    label and correctly colour nothing. Sets `severity` ("red"|"amber"|None) and `issues`
    (the flag texts, for the chip's tooltip) on each host dict, in place.
    """
    for svm in system_vms:
        hosts = hosts_by_system.get(svm.name) or []
        by_label = {h["label"]: h for h in hosts}
        for h in hosts:
            h["severity"] = None
            h["issues"] = []
        for f in getattr(svm, "flags", []):
            parts = (f.key or "").split(":")
            if len(parts) < 2:
                continue
            h = by_label.get(parts[1])
            if h is None:
                continue
            h["issues"].append(f.text)
            if _BAND_RANK.get(f.band, 0) > _BAND_RANK.get(h["severity"], 0):
                h["severity"] = f.band


def find_host(instance: str) -> Optional[dict]:
    """Resolve a scrape target back to a host — and PROVE it is one we monitor.

    SECURITY: every launch route goes through this. Without it, a crafted link could hand a
    colleague an .rdp pointing at an attacker-controlled box wearing this app's trusted URL —
    a clean phishing primitive. Only addresses present in the topology are ever emitted.
    """
    if not instance:
        return None
    cfg = gr.load_config()
    for s in gr.load_topology(cfg.prometheus_yml):
        for c in s.components:
            if c.instance == instance:
                return build_host(s.name, c.label, c.instance, None)
    return None


def rdp_file_text(host: dict, *, username: str = "", full_screen: bool = True) -> str:
    """A minimal, sane .rdp for mstsc. Deliberately NO password field — mstsc prompts, so the
       credential is handled by Windows (saved creds / smart card / Hello / NLA all work).
       CRLF line endings: mstsc is picky about them."""
    lines = [
        f"full address:s:{host['address']}:{_PROTOCOL['windows']['port']}",
        "prompt for credentials:i:1",     # always ask — never embed
        "promptcredentialonce:i:0",
        "authentication level:i:2",       # require server auth (NLA); warn+stop on mismatch
        "negotiate security layer:i:1",
        f"screen mode id:i:{2 if full_screen else 1}",   # 2 = full screen, 1 = windowed
        "smart sizing:i:1",
        "dynamic resolution:i:1",
        "redirectclipboard:i:1",
        "redirectprinters:i:0",
        "redirectsmartcards:i:1",
        "drivestoredirect:s:",            # no drive redirection by default
        "audiomode:i:2",                  # do not play remote audio locally
        "compression:i:1",
        "bitmapcachepersistenable:i:1",
        f"alternate shell:s:",
        f"remoteapplicationmode:i:0",
    ]
    if username:
        lines.insert(1, f"username:s:{username}")
    return "\r\n".join(lines) + "\r\n"


def rdp_filename(host: dict) -> str:
    """A recognisable download name: 'RTGS - Database (10.100.249.244).rdp'."""
    safe = lambda s: "".join(ch for ch in s if ch.isalnum() or ch in " ._-").strip() or "host"
    return f"{safe(host['system'])} - {safe(host['label'])} ({safe(host['address'])}).rdp"
