from pathlib import Path

from pfmk.emitters import interfaces as interfaces_emitter
from pfmk.overrides import InterfaceMapping
from pfmk.parser import parse_config

FIXTURE = Path(__file__).parent / "fixtures" / "minimal.xml"


def _default_mappings() -> dict[str, InterfaceMapping]:
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


def test_interfaces_emitter_covers_all_groups():
    config = parse_config(FIXTURE)
    rendered = interfaces_emitter.emit(config.interfaces, _default_mappings())

    assert "# ==== Interfaces ====" in rendered
    # Ether comments for WAN-like interfaces
    assert '/interface ethernet set [find name=ether1] comment="WAN"' in rendered
    assert '/interface ethernet set [find name=ether2] comment="WAN2"' in rendered
    # Bridge with all 8 members
    assert "/interface bridge add name=bridge-lan" in rendered
    assert "/interface bridge port add bridge=bridge-lan interface=ether3" in rendered
    assert "/interface bridge port add bridge=bridge-lan interface=ether10" in rendered
    # LAN /ip address
    assert "/ip address add address=172.16.1.1/24 interface=bridge-lan" in rendered
    # DHCP clients on both WANs
    assert "/ip dhcp-client add interface=ether1 disabled=no" in rendered
    assert "/ip dhcp-client add interface=ether2 disabled=no" in rendered


def test_skipped_and_disabled_interfaces_omitted():
    config = parse_config(FIXTURE)
    rendered = interfaces_emitter.emit(config.interfaces, _default_mappings())
    # opt2 is in the XML but marked skip; also it's disabled.
    assert "ether" not in rendered.split("opt2")[0] or "vtnet3" not in rendered
    assert "WAN3" not in rendered


def test_unmapped_interface_is_silently_skipped():
    config = parse_config(FIXTURE)
    mappings = {"lan": InterfaceMapping(target="bridge-lan", members=["ether3"])}
    rendered = interfaces_emitter.emit(config.interfaces, mappings)
    # Only LAN emitted; WAN + opt1 have no mapping and are skipped
    assert "bridge-lan" in rendered
    assert "ether1" not in rendered
    assert "ether2" not in rendered
