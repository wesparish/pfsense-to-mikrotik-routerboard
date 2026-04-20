import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class TargetOverrides:
    routeros_version: str = "7.13"
    hostname: str | None = None
    timezone: str | None = None


@dataclass
class InterfaceMapping:
    """How a pfSense interface maps onto the MikroTik side.

    Keyed in YAML by pfSense short name (wan, lan, opt1, opt2, opt3).
    """

    target: str | None = None            # e.g. "ether1" or "bridge-lan"
    members: list[str] = field(default_factory=list)  # bridge member ports
    role: str | None = None              # free-form tag: egress, ingress, lan
    skip: bool = False                   # retired interfaces


@dataclass
class BypassLists:
    """LAN IPs that skip NordVPN and egress a specific WAN directly.

    pfSense expresses this as per-rule gateway (WAN_DHCP vs WAN2_DHCP).
    On RouterOS we split into two address lists + two routing-marks.
    """

    via_wan: list[str] = field(default_factory=list)
    via_wan2: list[str] = field(default_factory=list)


@dataclass
class RoutingOverrides:
    """Policy routing choices. Pure-override: no pfSense input needed."""

    default_via: str = "wan"             # "wan" or "nordvpn"
    bypass: BypassLists = field(default_factory=BypassLists)


@dataclass
class WireGuardNordVPN:
    """Override-driven NordVPN WireGuard (NordLynx) config.

    Empty fields become placeholders in the emitted .rsc so the user can spot
    and fill them before import.
    """

    enabled: bool = False
    interface_name: str = "wg-nordvpn"
    listen_port: int = 51820
    address: str = ""                    # tunnel-local IP, e.g. "10.5.0.2/32"
    private_key_placeholder: str = "NORDVPN_PRIVATE_KEY"
    peer_pubkey: str = ""
    endpoint_host: str = ""
    endpoint_port: int = 51820
    allowed_address: str = "0.0.0.0/0"
    persistent_keepalive: str = "25s"


@dataclass
class DomainsOverrides:
    """`keep` is informational (public domains the user retains).
    `drop` is the active filter — entries whose domain matches or is a
    subdomain of anything in `drop` are omitted from generated output."""

    keep: list[str] = field(default_factory=list)
    drop: list[str] = field(default_factory=list)


@dataclass
class Overrides:
    target: TargetOverrides = field(default_factory=TargetOverrides)
    interfaces: dict[str, InterfaceMapping] = field(default_factory=dict)
    domains: DomainsOverrides = field(default_factory=DomainsOverrides)
    nordvpn: WireGuardNordVPN = field(default_factory=WireGuardNordVPN)
    routing: RoutingOverrides = field(default_factory=RoutingOverrides)
    raw: dict = field(default_factory=dict)


def load_overrides(path: str | Path | None) -> Overrides:
    if path is None:
        return Overrides()
    data = yaml.safe_load(Path(path).read_text()) or {}

    target_data = data.get("target", {}) or {}
    target = TargetOverrides(
        routeros_version=target_data.get("routeros_version", "7.13"),
        hostname=target_data.get("hostname"),
        timezone=target_data.get("timezone"),
    )

    interfaces: dict[str, InterfaceMapping] = {}
    for name, entry in (data.get("interfaces") or {}).items():
        entry = entry or {}
        interfaces[name] = InterfaceMapping(
            target=entry.get("target"),
            members=list(entry.get("members") or []),
            role=entry.get("role"),
            skip=bool(entry.get("skip", False)),
        )

    domains_data = data.get("domains", {}) or {}
    domains = DomainsOverrides(
        keep=list(domains_data.get("keep") or []),
        drop=list(domains_data.get("drop") or []),
    )

    vpn_data = (data.get("vpn") or {}).get("nordvpn") or {}
    nordvpn = WireGuardNordVPN(
        enabled=bool(vpn_data.get("enabled", vpn_data.get("mode") == "wireguard")),
        interface_name=vpn_data.get("interface_name", "wg-nordvpn"),
        listen_port=int(vpn_data.get("listen_port", 51820)),
        address=vpn_data.get("address", ""),
        private_key_placeholder=vpn_data.get(
            "private_key_env", "NORDVPN_PRIVATE_KEY"
        ),
        peer_pubkey=vpn_data.get("peer_pubkey", ""),
        endpoint_host=vpn_data.get("endpoint_host", ""),
        endpoint_port=int(vpn_data.get("endpoint_port", 51820)),
        allowed_address=vpn_data.get("allowed_address", "0.0.0.0/0"),
        persistent_keepalive=vpn_data.get("persistent_keepalive", "25s"),
    )

    routing_data = data.get("routing", {}) or {}
    bypass_data = routing_data.get("bypass", {}) or {}
    routing = RoutingOverrides(
        default_via=routing_data.get("default_via", "wan"),
        bypass=BypassLists(
            via_wan=list(bypass_data.get("via_wan") or []),
            via_wan2=list(bypass_data.get("via_wan2") or []),
        ),
    )

    overrides = Overrides(
        target=target,
        interfaces=interfaces,
        domains=domains,
        nordvpn=nordvpn,
        routing=routing,
        raw=data,
    )
    logger.info(
        "overrides: %d iface mapping(s), %d domain drop(s), nordvpn=%s, "
        "default_via=%s, bypass via_wan=%d via_wan2=%d",
        len(interfaces),
        len(domains.drop),
        "enabled" if nordvpn.enabled else "disabled",
        routing.default_via,
        len(routing.bypass.via_wan),
        len(routing.bypass.via_wan2),
    )
    return overrides
