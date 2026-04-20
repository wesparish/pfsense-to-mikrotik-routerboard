import base64
import ipaddress
from pathlib import Path
from xml.etree import ElementTree as ET

from pfmk.model import (
    DhcpScope,
    DnsHost,
    DomainOverride,
    DynDnsEntry,
    Endpoint,
    FilterRule,
    Interface,
    NatOutbound,
    NatPortForward,
    PfSenseConfig,
    StaticLease,
    System,
)


def parse_config(path: str | Path) -> PfSenseConfig:
    tree = ET.parse(Path(path))
    root = tree.getroot()

    system = _parse_system(root)
    interfaces = _parse_interfaces(root)
    scopes = _parse_dhcp_scopes(root)
    dns_hosts = _parse_dns_hosts(root)
    domain_overrides = _parse_domain_overrides(root)
    filter_rules = _parse_filter_rules(root)
    port_forwards, outbound_nat = _parse_nat(root)
    dyndns = _parse_dyndns(root)

    iface_by_name = {i.name: i for i in interfaces}
    for scope in scopes:
        iface = iface_by_name.get(scope.interface)
        if iface and iface.ipaddr and iface.subnet:
            net = ipaddress.ip_network(f"{iface.ipaddr}/{iface.subnet}", strict=False)
            scope.network = str(net)
        if not scope.domain and system.domain:
            scope.domain = system.domain

    return PfSenseConfig(
        system=system,
        interfaces=interfaces,
        dhcp_scopes=scopes,
        dns_hosts=dns_hosts,
        domain_overrides=domain_overrides,
        filter_rules=filter_rules,
        nat_port_forwards=port_forwards,
        nat_outbound=outbound_nat,
        dyndns=dyndns,
    )


def _parse_system(root: ET.Element) -> System:
    sys_el = _require(root, "system")
    return System(
        hostname=_text(sys_el, "hostname", default=""),
        domain=_text(sys_el, "domain", default=""),
        timezone=_text(sys_el, "timezone", default="UTC"),
    )


def _parse_interfaces(root: ET.Element) -> list[Interface]:
    ifaces_el = root.find("interfaces")
    if ifaces_el is None:
        return []
    result: list[Interface] = []
    for child in ifaces_el:
        ipaddr_raw = _text(child, "ipaddr", default="")
        if ipaddr_raw == "dhcp":
            mode, ipaddr, subnet = "dhcp", None, None
        elif ipaddr_raw:
            mode = "static"
            ipaddr = ipaddr_raw
            subnet_text = _text(child, "subnet", default="")
            subnet = int(subnet_text) if subnet_text.isdigit() else None
        else:
            mode, ipaddr, subnet = "unknown", None, None
        result.append(
            Interface(
                name=child.tag,
                physical=_text(child, "if", default=""),
                description=_text(child, "descr", default=""),
                # In pfSense XML, <enable/> (present, no text) means enabled.
                enabled=child.find("enable") is not None,
                mode=mode,
                ipaddr=ipaddr,
                subnet=subnet,
            )
        )
    return result


def _parse_dhcp_scopes(root: ET.Element) -> list[DhcpScope]:
    dhcpd = root.find("dhcpd")
    if dhcpd is None:
        return []
    scopes: list[DhcpScope] = []
    for child in dhcpd:
        range_el = child.find("range")
        if range_el is None:
            continue
        range_from = _text(range_el, "from", default="")
        range_to = _text(range_el, "to", default="")
        if not range_from or not range_to:
            continue

        dns_servers = [
            el.text.strip() for el in child.findall("dnsserver") if el.text
        ]

        leases: list[StaticLease] = []
        for sm in child.findall("staticmap"):
            mac = _text(sm, "mac", default="")
            ip = _text(sm, "ipaddr", default="")
            if not mac or not ip:
                # Skip MAC-only reservations; useless without a pinned IP.
                continue
            leases.append(
                StaticLease(
                    mac=mac,
                    ipaddr=ip,
                    hostname=_text(sm, "hostname", default=""),
                    description=_text(sm, "descr", default=""),
                )
            )

        scopes.append(
            DhcpScope(
                interface=child.tag,
                range_from=range_from,
                range_to=range_to,
                gateway=_text(child, "gateway", default=""),
                dns_servers=dns_servers,
                domain=_text(child, "domain", default=""),
                static_leases=leases,
            )
        )
    return scopes


def _parse_dns_hosts(root: ET.Element) -> list[DnsHost]:
    hosts: list[DnsHost] = []
    for section in ("dnsmasq", "unbound"):
        el = root.find(section)
        if el is None:
            continue
        for host_el in el.findall("hosts"):
            host = _text(host_el, "host", default="")
            domain = _text(host_el, "domain", default="")
            ipaddr = _text(host_el, "ip", default="")
            if not ipaddr or (not host and not domain):
                continue
            hosts.append(
                DnsHost(
                    host=host,
                    domain=domain,
                    ipaddr=ipaddr,
                    description=_text(host_el, "descr", default=""),
                    source=section,
                )
            )
    return hosts


def _parse_domain_overrides(root: ET.Element) -> list[DomainOverride]:
    overrides: list[DomainOverride] = []
    for section in ("dnsmasq", "unbound"):
        el = root.find(section)
        if el is None:
            continue
        for do in el.findall("domainoverrides"):
            domain = _text(do, "domain", default="")
            ipaddr = _text(do, "ip", default="")
            if not domain or not ipaddr:
                continue
            overrides.append(
                DomainOverride(domain=domain, forward_to=ipaddr, source=section)
            )
    return overrides


def _parse_filter_rules(root: ET.Element) -> list[FilterRule]:
    filt = root.find("filter")
    if filt is None:
        return []
    rules: list[FilterRule] = []
    for r in filt.findall("rule"):
        rules.append(
            FilterRule(
                action=_text(r, "type", default="pass"),
                interface=_text(r, "interface", default=""),
                direction=_text(r, "direction", default="in"),
                ipprotocol=_text(r, "ipprotocol", default="inet"),
                protocol=_text(r, "protocol", default="") or None,
                source=_parse_endpoint(r.find("source")),
                destination=_parse_endpoint(r.find("destination")),
                disabled=r.find("disabled") is not None,
                description=_text(r, "descr", default=""),
                tracker=_text(r, "tracker", default=""),
            )
        )
    return rules


def _parse_endpoint(el: ET.Element | None) -> Endpoint:
    if el is None:
        return Endpoint(any=True)
    address = _text(el, "address", default="") or None
    network = _text(el, "network", default="") or None
    port = _text(el, "port", default="") or None
    is_any = el.find("any") is not None
    invert = el.find("not") is not None
    return Endpoint(
        any=is_any and not address and not network,
        address=address,
        network=network,
        port=port,
        invert=invert,
    )


def _parse_nat(
    root: ET.Element,
) -> tuple[list[NatPortForward], list[NatOutbound]]:
    nat = root.find("nat")
    if nat is None:
        return [], []

    port_forwards: list[NatPortForward] = []
    for r in nat.findall("rule"):
        port_forwards.append(
            NatPortForward(
                interface=_text(r, "interface", default=""),
                protocol=_text(r, "protocol", default="tcp"),
                source=_parse_endpoint(r.find("source")),
                destination=_parse_endpoint(r.find("destination")),
                target_ip=_text(r, "target", default=""),
                target_port=_text(r, "local-port", default=""),
                disabled=r.find("disabled") is not None,
                description=_text(r, "descr", default=""),
            )
        )

    outbound: list[NatOutbound] = []
    ob = nat.find("outbound")
    if ob is not None:
        for r in ob.findall("rule"):
            outbound.append(
                NatOutbound(
                    interface=_text(r, "interface", default=""),
                    source=_parse_endpoint(r.find("source")),
                    destination=_parse_endpoint(r.find("destination")),
                    source_port=_text(r, "sourceport", default="") or None,
                    dest_port=_text(r, "dstport", default="") or None,
                    nat_port=_text(r, "natport", default="") or None,
                    disabled=r.find("disabled") is not None,
                    description=_text(r, "descr", default=""),
                )
            )

    return port_forwards, outbound


def _parse_dyndns(root: ET.Element) -> list[DynDnsEntry]:
    dd = root.find("dyndnses")
    if dd is None:
        return []
    entries: list[DynDnsEntry] = []
    for child in dd.findall("dyndns"):
        entries.append(
            DynDnsEntry(
                provider=_text(child, "type", default=""),
                interface=_text(child, "interface", default=""),
                hostname=_text(child, "host", default=""),
                domain=_text(child, "domainname", default=""),
                description=_text(child, "descr", default=""),
                enabled=child.find("enable") is not None,
                username=_text(child, "username", default=""),
                password=_decode_pfsense_password(
                    _text(child, "password", default="")
                ),
            )
        )
    return entries


def _decode_pfsense_password(encoded: str) -> str:
    """pfSense stores DDNS passwords as base64. Decode best-effort."""

    if not encoded:
        return ""
    try:
        return base64.b64decode(encoded, validate=True).decode(
            "utf-8", errors="replace"
        )
    except (ValueError, UnicodeDecodeError):
        return encoded


def _require(el: ET.Element, tag: str) -> ET.Element:
    child = el.find(tag)
    if child is None:
        raise ValueError(f"missing required element <{tag}> under <{el.tag}>")
    return child


def _text(el: ET.Element, tag: str, default: str) -> str:
    child = el.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()
