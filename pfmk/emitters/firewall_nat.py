"""Translate pfSense NAT into RouterOS /ip firewall nat.

Port forwards (pfSense <nat><rule>) translate cleanly to RouterOS dst-nat.
Outbound rules (pfSense <nat><outbound><rule>) are a poorer fit: pfSense's
hybrid mode stacks many user and auto-generated masquerade variants. Rather
than reproduce each one, this emitter writes baseline masquerade rules for
the expected egress paths (WAN + WireGuard tunnel) and lists the original
outbound entries as comments for review.
"""

import ipaddress
import logging

from pfmk.emitters._common import escape, expand_protocol
from pfmk.model import Interface, NatOutbound, NatPortForward
from pfmk.overrides import InterfaceMapping, WireGuardNordVPN

logger = logging.getLogger(__name__)


def emit(
    port_forwards: list[NatPortForward],
    outbound: list[NatOutbound],
    interfaces: list[Interface],
    mappings: dict[str, InterfaceMapping],
    nordvpn: WireGuardNordVPN,
) -> str:
    lines: list[str] = ["# ==== NAT ===="]

    lan_cidr = _lan_cidr(interfaces)
    egress_iface = _find_target(mappings, role="egress")

    if lan_cidr and egress_iface:
        lines.append("")
        lines.append("# --- Outbound masquerade (LAN → WAN / VPN) ---")
        lines.append(
            f"/ip firewall nat add chain=srcnat action=masquerade "
            f"out-interface={egress_iface} src-address={lan_cidr} "
            f'comment="LAN → WAN"'
        )
        if nordvpn.enabled:
            lines.append(
                f"/ip firewall nat add chain=srcnat action=masquerade "
                f"out-interface={nordvpn.interface_name} src-address={lan_cidr} "
                f'comment="LAN → NordVPN tunnel"'
            )

    translated = skipped = 0
    if port_forwards:
        lines.append("")
        lines.append("# --- Port forwards (dst-nat) ---")
        for pf in port_forwards:
            out = _emit_port_forward(pf, mappings)
            lines.extend(out)
            if any("# SKIPPED" in line for line in out):
                skipped += 1
            else:
                translated += 1
    logger.info(
        "firewall_nat: %d port forward(s) translated, %d skipped; %d outbound rule(s) referenced",
        translated,
        skipped,
        len(outbound),
    )

    if outbound:
        lines.append("")
        lines.append(
            "# --- pfSense outbound NAT rules (reference, not re-translated) ---"
        )
        for rule in outbound:
            src = _describe_endpoint(rule.source)
            dst = _describe_endpoint(rule.destination)
            port_bits = []
            if rule.source_port:
                port_bits.append(f"sport={rule.source_port}")
            if rule.dest_port:
                port_bits.append(f"dport={rule.dest_port}")
            port_str = f" ({' '.join(port_bits)})" if port_bits else ""
            desc = rule.description or "(no description)"
            lines.append(
                f"#   [{rule.interface}] {desc}: {src} → {dst}{port_str}"
            )

    return "\n".join(lines)


def _lan_cidr(interfaces: list[Interface]) -> str | None:
    for iface in interfaces:
        if iface.name == "lan" and iface.ipaddr and iface.subnet:
            net = ipaddress.ip_network(
                f"{iface.ipaddr}/{iface.subnet}", strict=False
            )
            return str(net)
    return None


def _find_target(
    mappings: dict[str, InterfaceMapping], role: str
) -> str | None:
    for mapping in mappings.values():
        if mapping.role == role and not mapping.skip and mapping.target:
            return mapping.target
    return None


def _emit_port_forward(
    pf: NatPortForward,
    mappings: dict[str, InterfaceMapping],
) -> list[str]:
    header = f'# pfSense port-forward: {pf.description or "(no descr)"}'

    mapping = mappings.get(pf.interface)
    if mapping is None:
        return [
            header,
            f"# SKIPPED (no mapping for pfSense interface '{pf.interface}')",
        ]
    if mapping.skip or not mapping.target:
        return [
            header,
            f"# SKIPPED (pfSense interface '{pf.interface}' is retired)",
        ]
    if not pf.target_ip:
        return [header, "# SKIPPED (port forward has no <target>)"]
    if not pf.destination.port:
        return [header, "# SKIPPED (port forward has no destination port)"]

    in_iface = mapping.target
    dst_port = pf.destination.port.replace(":", "-")
    to_port = (pf.target_port or pf.destination.port).replace(":", "-")

    out: list[str] = [header]
    for proto in expand_protocol(pf.protocol):
        if proto is None:
            proto = "tcp"
        parts = [
            "chain=dstnat",
            "action=dst-nat",
            f"in-interface={in_iface}",
            f"protocol={proto}",
            f"dst-port={dst_port}",
            f"to-addresses={pf.target_ip}",
            f"to-ports={to_port}",
        ]
        if pf.destination.address:
            parts.insert(4, f"dst-address={pf.destination.address}")
        if pf.source.address and not pf.source.any:
            parts.append(f"src-address={pf.source.address}")
        if pf.disabled:
            parts.append("disabled=yes")
        parts.append(f'comment="{escape(pf.description or "port forward")}"')
        out.append("/ip firewall nat add " + " ".join(parts))
    return out


def _describe_endpoint(ep) -> str:
    if ep.any:
        return "any"
    if ep.address:
        return ep.address
    if ep.network:
        return ep.network
    return "any"
