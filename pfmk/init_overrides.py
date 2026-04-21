"""Scaffold a commented overrides YAML from a parsed pfSense config.

The output is hand-crafted text (not yaml.dump) so it retains explanatory
comments and TODO markers. It must also round-trip cleanly through
pfmk.overrides.load_overrides — the tests verify this.
"""

from datetime import datetime, timezone

from pfmk.model import PfSenseConfig

_DEFAULT_ETHER_COUNT = 10  # RB3011UiAS-RM has 10 ethernet ports


def scaffold_overrides(config: PfSenseConfig, xml_path: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    interfaces_block = _interfaces_block(config)
    bypass_via_wan, bypass_via_wan2 = _bypass_ips_from_rules(config)

    sections = [
        _header(xml_path, now, config),
        "target:",
        '  routeros_version: "7.13"',
        "",
        _interfaces_header(),
        interfaces_block,
        "",
        _domains_block(config),
        "",
        _nordvpn_block(),
        "",
        _routing_block(bypass_via_wan, bypass_via_wan2),
    ]
    return "\n".join(sections).rstrip() + "\n"


# ──────────────────────────────────────────────────────────────────────
# Section builders
# ──────────────────────────────────────────────────────────────────────

def _header(xml_path: str, now: str, config: PfSenseConfig) -> str:
    return "\n".join(
        [
            "# Overrides scaffolded by `pfmk init-overrides`.",
            f"# Source:    {xml_path}",
            f"# Generated: {now}",
            f"# pfSense:   hostname={config.system.hostname} "
            f"domain={config.system.domain}",
            "#",
            "# Fields marked TODO require your input. Review the rest —",
            "# auto-guesses may not match your physical wiring.",
            "",
        ]
    )


def _interfaces_header() -> str:
    return "\n".join(
        [
            "# Interface map: pfSense short name → MikroTik ether port.",
            "# Guesses below assume a 10-port router (RB3011UiAS-RM style):",
            "#   ether1..2  = WAN-mode interfaces in the order pfSense had them",
            "#   ether3..10 = LAN bridge members",
            "# Edit if your wiring differs.",
            "interfaces:",
        ]
    )


def _interfaces_block(config: PfSenseConfig) -> str:
    """Render the interfaces: block with every pfSense interface covered.

    Strategy: first pass assigns ether ports to WAN-mode interfaces, then we
    emit WANs inline, LAN with bridge members, then everything else (disabled
    or pseudo) as `skip: true` with a reason comment.
    """

    enabled_wans = [
        i for i in config.interfaces if i.enabled and i.mode == "dhcp"
    ]
    lan = next(
        (i for i in config.interfaces if i.enabled and i.name == "lan"), None
    )
    # Roles: first enabled WAN = egress, second = ingress, rest unroled.
    roles: dict[str, str | None] = {}
    ether_for: dict[str, str] = {}
    for idx, iface in enumerate(enabled_wans):
        ether_for[iface.name] = f"ether{idx + 1}"
        if idx == 0:
            roles[iface.name] = "egress"
        elif idx == 1:
            roles[iface.name] = "ingress"
        else:
            roles[iface.name] = None

    used_ethers = set(ether_for.values())
    bridge_members = [
        f"ether{i}"
        for i in range(1, _DEFAULT_ETHER_COUNT + 1)
        if f"ether{i}" not in used_ethers
    ]

    lines: list[str] = []

    # WAN-mode interfaces inline (one line each).
    for iface in enabled_wans:
        descr = iface.description or iface.name.upper()
        role = roles[iface.name]
        role_bit = f", role: {role}" if role else ""
        lines.append(
            f"  {iface.name}: {{ target: {ether_for[iface.name]}{role_bit} }}"
            f"  # {descr}"
        )

    # LAN as the expanded form so we can include bridge members + comments.
    if lan is not None:
        descr = lan.description or "LAN"
        members_str = ", ".join(bridge_members)
        lines.append(f"  lan:")
        lines.append(f"    target: bridge-lan")
        lines.append(f"    role: lan")
        lines.append(f"    members: [{members_str}]")
        lines.append(f"    # pfSense descr: {descr!r}")
        if lan.ipaddr and lan.subnet:
            lines.append(f"    # current IP: {lan.ipaddr}/{lan.subnet}")

    # Everything else: disabled, pseudo-interfaces (ovpnc*), opt* we didn't
    # assign a WAN slot to, etc. All skipped-by-default with a reason.
    handled = {i.name for i in enabled_wans}
    if lan is not None:
        handled.add(lan.name)
    for iface in config.interfaces:
        if iface.name in handled:
            continue
        descr = iface.description or iface.name.upper()
        if not iface.enabled:
            reason = "disabled in pfSense"
        elif iface.mode == "unknown":
            reason = "pseudo-interface (likely OpenVPN client) — retired"
        else:
            reason = "review"
        lines.append(f"  {iface.name}: {{ skip: true }}  # {descr} — {reason}")

    return "\n".join(lines)


def _domains_block(config: PfSenseConfig) -> str:
    parsed_domain = config.system.domain or "local"
    return "\n".join(
        [
            "# DNS domain filter.",
            "# `keep` is informational; `drop` is the active filter.",
            "# TODO: list any domains you've retired (no longer own, consolidated).",
            "domains:",
            f"  keep: [{parsed_domain}]",
            "  drop: []  # e.g. [old.example, retired-vpn-network]",
        ]
    )


def _nordvpn_block() -> str:
    return "\n".join(
        [
            "# NordVPN via WireGuard (NordLynx).",
            "# Fill in the three TODOs below from NordVPN's API before generate,",
            "# or disable NordVPN by setting `enabled: false`.",
            "# See docs/migration-guide.md for the credential-fetch flow.",
            "vpn:",
            "  nordvpn:",
            "    enabled: true",
            "    interface_name: wg-nordvpn",
            "    listen_port: 51820",
            '    address: ""         # TODO: tunnel-local /32 from NordVPN (e.g. 10.5.0.2/32)',
            '    peer_pubkey: ""     # TODO: NordVPN server public key',
            '    endpoint_host: ""   # TODO: e.g. us1234.nordvpn.com',
            "    endpoint_port: 51820",
            "    allowed_address: 0.0.0.0/0",
            "    persistent_keepalive: 25s",
        ]
    )


def _routing_block(
    via_wan: list[tuple[str, str]],
    via_wan2: list[tuple[str, str]],
) -> str:
    lines = [
        "# Policy routing: LAN defaults through NordVPN, named hosts bypass to WAN(s).",
        "# Bypass lists scaffolded from pfSense rules that had <gateway> set.",
        "# Disabled source rules were omitted.",
        "routing:",
        "  default_via: nordvpn",
        "  bypass:",
    ]
    lines.append("    via_wan:")
    if via_wan:
        for ip, descr in via_wan:
            comment = f"  # {descr}" if descr else ""
            lines.append(f"      - {ip}{comment}")
    else:
        lines.append("      []")
    lines.append("    via_wan2:")
    if via_wan2:
        for ip, descr in via_wan2:
            comment = f"  # {descr}" if descr else ""
            lines.append(f"      - {ip}{comment}")
    else:
        lines.append("      []")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
# Bypass extraction from pfSense filter rules
# ──────────────────────────────────────────────────────────────────────

def _bypass_ips_from_rules(
    config: PfSenseConfig,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Walk filter rules with <gateway>; group by gateway name prefix.

    Heuristic: gateway name starts with "WAN2" → via_wan2; starts with "WAN"
    (but not WAN2) → via_wan. Anything else (e.g. NORDVPN_VPNV4, which is the
    default tunnel gateway) is not a bypass — skip.
    """

    via_wan: list[tuple[str, str]] = []
    via_wan2: list[tuple[str, str]] = []
    seen_via_wan: set[str] = set()
    seen_via_wan2: set[str] = set()

    for rule in config.filter_rules:
        if rule.disabled or not rule.gateway:
            continue
        src_ip = rule.source.address
        if not src_ip:
            continue
        # Skip subnet sources like 172.16.1.0/24 — they're catch-alls, not hosts
        if "/" in src_ip:
            continue

        gw = rule.gateway.upper()
        descr = rule.description or ""

        if gw.startswith("WAN2"):
            if src_ip not in seen_via_wan2:
                via_wan2.append((src_ip, descr))
                seen_via_wan2.add(src_ip)
        elif gw.startswith("WAN"):
            if src_ip not in seen_via_wan:
                via_wan.append((src_ip, descr))
                seen_via_wan.add(src_ip)
        # else: VPN-default gateways and anything non-WAN → not a bypass

    return via_wan, via_wan2
