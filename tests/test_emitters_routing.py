from pathlib import Path

from pfmk.emitters import routing as routing_emitter
from pfmk.overrides import (
    BypassLists,
    InterfaceMapping,
    RoutingOverrides,
    WireGuardNordVPN,
)
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


def test_dual_bypass_emits_two_address_lists_and_two_tables():
    config = parse_config(FIXTURE)
    rendered = routing_emitter.emit(
        RoutingOverrides(
            default_via="nordvpn",
            bypass=BypassLists(
                via_wan=["172.16.1.3"],
                via_wan2=["172.16.1.70", "172.16.1.71"],
            ),
        ),
        WireGuardNordVPN(enabled=True),
        config.interfaces,
        _mappings(),
    )

    assert "list=bypass-to-wan address=172.16.1.3" in rendered
    assert "list=bypass-to-wan2 address=172.16.1.70" in rendered
    assert "list=bypass-to-wan2 address=172.16.1.71" in rendered
    assert "/routing table add name=via-wan fib" in rendered
    assert "/routing table add name=via-wan2 fib" in rendered
    assert "/routing table add name=via-nordvpn fib" in rendered


def test_bypass_dhcp_client_sets_per_wan_routing_tables():
    config = parse_config(FIXTURE)
    rendered = routing_emitter.emit(
        RoutingOverrides(
            default_via="nordvpn",
            bypass=BypassLists(via_wan=["172.16.1.3"]),
        ),
        WireGuardNordVPN(enabled=True),
        config.interfaces,
        _mappings(),
    )
    assert (
        "/ip dhcp-client set [find interface=ether1] "
        "default-route-tables=main,via-wan" in rendered
    )
    # ether2 always gets via-wan2 because ingress role triggers WAN2 return
    assert (
        "/ip dhcp-client set [find interface=ether2] "
        "default-route-tables=main,via-wan2" in rendered
    )


def test_mangle_order_bypass_before_nordvpn():
    config = parse_config(FIXTURE)
    rendered = routing_emitter.emit(
        RoutingOverrides(
            default_via="nordvpn",
            bypass=BypassLists(
                via_wan=["172.16.1.3"], via_wan2=["172.16.1.70"]
            ),
        ),
        WireGuardNordVPN(enabled=True),
        config.interfaces,
        _mappings(),
    )
    via_wan_pos = rendered.find("new-routing-mark=via-wan ")
    via_wan2_pos = rendered.find("new-routing-mark=via-wan2 ")
    via_nord_pos = rendered.find("new-routing-mark=via-nordvpn")
    assert 0 < via_wan_pos < via_nord_pos
    assert 0 < via_wan2_pos < via_nord_pos


def test_no_bypass_emits_only_nordvpn_and_wan2_return():
    config = parse_config(FIXTURE)
    rendered = routing_emitter.emit(
        RoutingOverrides(default_via="nordvpn"),
        WireGuardNordVPN(enabled=True),
        config.interfaces,
        _mappings(),
    )
    assert "bypass-to-wan" not in rendered
    assert "via-nordvpn" in rendered
    assert "wan2-in" in rendered


def test_default_via_wan_skips_nordvpn_parts():
    config = parse_config(FIXTURE)
    rendered = routing_emitter.emit(
        RoutingOverrides(default_via="wan"),
        WireGuardNordVPN(enabled=True),
        config.interfaces,
        _mappings(),
    )
    assert "via-nordvpn" not in rendered
    assert "wan2-in" in rendered


def test_no_nordvpn_no_ingress_no_bypass_emits_nothing():
    config = parse_config(FIXTURE)
    rendered = routing_emitter.emit(
        RoutingOverrides(default_via="wan"),
        WireGuardNordVPN(enabled=False),
        config.interfaces,
        {
            "wan": InterfaceMapping(target="ether1", role="egress"),
            "lan": InterfaceMapping(target="bridge-lan", role="lan"),
        },
    )
    assert rendered == ""
