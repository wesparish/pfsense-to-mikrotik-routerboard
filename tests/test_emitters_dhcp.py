from pathlib import Path

from pfmk.emitters import dhcp as dhcp_emitter
from pfmk.overrides import InterfaceMapping
from pfmk.parser import parse_config

FIXTURE = Path(__file__).parent / "fixtures" / "minimal.xml"


def _mappings() -> dict[str, InterfaceMapping]:
    return {
        "lan": InterfaceMapping(
            target="bridge-lan",
            members=[f"ether{i}" for i in range(3, 11)],
        ),
    }


def test_dhcp_parser_extracts_scope_and_leases():
    config = parse_config(FIXTURE)
    assert len(config.dhcp_scopes) == 1
    scope = config.dhcp_scopes[0]
    assert scope.interface == "lan"
    assert scope.range_from == "172.16.1.110"
    assert scope.range_to == "172.16.1.196"
    assert scope.gateway == "172.16.1.1"
    assert scope.dns_servers == ["172.16.1.222", "172.16.1.1"]
    assert scope.network == "172.16.1.0/24"
    # Only 2 leases — the empty-ipaddr one is skipped
    assert len(scope.static_leases) == 2


def test_dhcp_emitter_pool_server_network_and_leases():
    config = parse_config(FIXTURE)
    rendered = dhcp_emitter.emit(config.dhcp_scopes, _mappings())

    assert "# ==== DHCP server ====" in rendered
    assert "/ip pool add name=lan-pool ranges=172.16.1.110-172.16.1.196" in rendered
    assert (
        "/ip dhcp-server add name=lan-dhcp interface=bridge-lan "
        "address-pool=lan-pool" in rendered
    )
    assert (
        "/ip dhcp-server network add address=172.16.1.0/24 gateway=172.16.1.1 "
        "dns-server=172.16.1.222,172.16.1.1" in rendered
    )
    assert "mac-address=aa:bb:cc:00:00:01 address=172.16.1.10" in rendered
    assert "mac-address=aa:bb:cc:00:00:02 address=172.16.1.10" in rendered
    # Duplicate-IP warning on the second entry
    assert "duplicate IP" in rendered


def test_dhcp_emits_nothing_when_lan_interface_skipped():
    config = parse_config(FIXTURE)
    rendered = dhcp_emitter.emit(
        config.dhcp_scopes,
        {"lan": InterfaceMapping(skip=True)},
    )
    assert rendered == ""
