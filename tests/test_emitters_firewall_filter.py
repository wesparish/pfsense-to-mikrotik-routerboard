from pathlib import Path

from pfmk.emitters import firewall_filter as ff_emitter
from pfmk.overrides import InterfaceMapping
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


def test_parser_extracts_all_rules():
    config = parse_config(FIXTURE)
    assert len(config.filter_rules) == 5
    first = config.filter_rules[0]
    assert first.action == "pass"
    assert first.interface == "wan"
    assert first.destination.address == "172.16.1.70"
    assert first.destination.port == "443"


def test_emitter_produces_baseline_input_chain():
    config = parse_config(FIXTURE)
    rendered = ff_emitter.emit(
        config.filter_rules, config.interfaces, _mappings()
    )
    assert "chain=input action=accept connection-state=established,related" in rendered
    assert "chain=input action=drop connection-state=invalid" in rendered
    assert "chain=input action=accept in-interface=bridge-lan" in rendered
    assert "chain=input action=drop" in rendered


def test_emitter_translates_pass_rule():
    config = parse_config(FIXTURE)
    rendered = ff_emitter.emit(
        config.filter_rules, config.interfaces, _mappings()
    )
    assert (
        "chain=forward action=accept in-interface=ether1 protocol=tcp "
        "dst-address=172.16.1.70 dst-port=443" in rendered
    )


def test_tcp_udp_expands_to_two_rules():
    config = parse_config(FIXTURE)
    rendered = ff_emitter.emit(
        config.filter_rules, config.interfaces, _mappings()
    )
    # LAN outbound rule: tcp/udp → 2 rules, src-address=172.16.1.0/24
    lan_tcp = "chain=forward action=accept in-interface=bridge-lan protocol=tcp src-address=172.16.1.0/24"
    lan_udp = "chain=forward action=accept in-interface=bridge-lan protocol=udp src-address=172.16.1.0/24"
    assert lan_tcp in rendered
    assert lan_udp in rendered


def test_retired_interface_rule_is_skipped_with_note():
    config = parse_config(FIXTURE)
    rendered = ff_emitter.emit(
        config.filter_rules, config.interfaces, _mappings()
    )
    assert "SKIPPED (pfSense interface 'opt2' is retired)" in rendered


def test_ipv6_rule_is_skipped_with_note():
    config = parse_config(FIXTURE)
    rendered = ff_emitter.emit(
        config.filter_rules, config.interfaces, _mappings()
    )
    assert "SKIPPED (IPv6 rule not translated)" in rendered


def test_disabled_rule_emits_with_disabled_flag():
    config = parse_config(FIXTURE)
    rendered = ff_emitter.emit(
        config.filter_rules, config.interfaces, _mappings()
    )
    assert 'disabled=yes comment="disabled rule"' in rendered
