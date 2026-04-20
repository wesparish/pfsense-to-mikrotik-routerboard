from pathlib import Path

from pfmk.emitters import firewall_nat as nat_emitter
from pfmk.overrides import InterfaceMapping, WireGuardNordVPN
from pfmk.parser import parse_config

FIXTURE = Path(__file__).parent / "fixtures" / "minimal.xml"


def _mappings() -> dict[str, InterfaceMapping]:
    return {
        "wan": InterfaceMapping(target="ether1", role="egress"),
        "opt1": InterfaceMapping(target="ether2", role="ingress"),
        "lan": InterfaceMapping(
            target="bridge-lan",
            role="lan",
            members=[f"ether{i}" for i in range(3, 11)],
        ),
        "opt2": InterfaceMapping(skip=True),
    }


def test_parser_extracts_port_forwards_and_outbound():
    config = parse_config(FIXTURE)
    assert len(config.nat_port_forwards) == 3
    assert len(config.nat_outbound) == 1
    assert config.nat_port_forwards[0].target_ip == "172.16.1.200"
    assert config.nat_outbound[0].description == "LAN to WAN"


def test_emitter_baseline_masquerade_rules_present():
    config = parse_config(FIXTURE)
    rendered = nat_emitter.emit(
        config.nat_port_forwards,
        config.nat_outbound,
        config.interfaces,
        _mappings(),
        WireGuardNordVPN(enabled=True),
    )
    assert (
        "action=masquerade out-interface=ether1 src-address=172.16.1.0/24"
        in rendered
    )
    assert (
        "action=masquerade out-interface=wg-nordvpn src-address=172.16.1.0/24"
        in rendered
    )


def test_emitter_translates_port_forward_onto_wan2():
    config = parse_config(FIXTURE)
    rendered = nat_emitter.emit(
        config.nat_port_forwards,
        config.nat_outbound,
        config.interfaces,
        _mappings(),
        WireGuardNordVPN(enabled=True),
    )
    assert (
        "chain=dstnat action=dst-nat in-interface=ether2 protocol=tcp "
        "dst-port=443 to-addresses=172.16.1.200 to-ports=443" in rendered
    )


def test_tcp_udp_port_forward_expands_to_two_rules():
    config = parse_config(FIXTURE)
    rendered = nat_emitter.emit(
        config.nat_port_forwards,
        config.nat_outbound,
        config.interfaces,
        _mappings(),
        WireGuardNordVPN(enabled=True),
    )
    assert "protocol=tcp dst-port=29810-29817 to-addresses=172.16.1.240" in rendered
    assert "protocol=udp dst-port=29810-29817 to-addresses=172.16.1.240" in rendered


def test_port_forward_on_retired_interface_skipped():
    config = parse_config(FIXTURE)
    rendered = nat_emitter.emit(
        config.nat_port_forwards,
        config.nat_outbound,
        config.interfaces,
        _mappings(),
        WireGuardNordVPN(enabled=True),
    )
    assert "SKIPPED (pfSense interface 'opt2' is retired)" in rendered
    assert "ssh via retired WAN3" in rendered  # kept in header comment


def test_outbound_rules_listed_as_comments_only():
    config = parse_config(FIXTURE)
    rendered = nat_emitter.emit(
        config.nat_port_forwards,
        config.nat_outbound,
        config.interfaces,
        _mappings(),
        WireGuardNordVPN(enabled=True),
    )
    assert "pfSense outbound NAT rules (reference" in rendered
    assert "#   [wan] LAN to WAN: 172.16.1.0/24 → any" in rendered


def test_nordvpn_masquerade_omitted_when_disabled():
    config = parse_config(FIXTURE)
    rendered = nat_emitter.emit(
        config.nat_port_forwards,
        config.nat_outbound,
        config.interfaces,
        _mappings(),
        WireGuardNordVPN(enabled=False),
    )
    assert "wg-nordvpn" not in rendered
