import tempfile
from pathlib import Path

import yaml

from pfmk.init_overrides import scaffold_overrides
from pfmk.overrides import load_overrides
from pfmk.parser import parse_config

FIXTURE = Path(__file__).parent / "fixtures" / "minimal.xml"


def test_scaffold_produces_valid_yaml():
    config = parse_config(FIXTURE)
    rendered = scaffold_overrides(config, str(FIXTURE))
    # Must parse cleanly as YAML
    parsed = yaml.safe_load(rendered)
    assert isinstance(parsed, dict)
    assert "interfaces" in parsed
    assert "routing" in parsed
    assert "vpn" in parsed
    assert "domains" in parsed


def test_scaffold_roundtrips_through_load_overrides():
    config = parse_config(FIXTURE)
    rendered = scaffold_overrides(config, str(FIXTURE))
    # Must be consumable by the real overrides loader
    with tempfile.NamedTemporaryFile(
        suffix=".yaml", mode="w", delete=False
    ) as f:
        f.write(rendered)
        tmp = f.name
    try:
        overrides = load_overrides(tmp)
        assert "wan" in overrides.interfaces
        assert "lan" in overrides.interfaces
        assert overrides.interfaces["wan"].target == "ether1"
        assert overrides.interfaces["lan"].target == "bridge-lan"
        assert overrides.routing.default_via == "nordvpn"
        assert overrides.nordvpn.enabled is True
    finally:
        Path(tmp).unlink()


def test_scaffold_has_todo_markers():
    config = parse_config(FIXTURE)
    rendered = scaffold_overrides(config, str(FIXTURE))
    # User-action fields should be clearly marked
    assert "TODO" in rendered
    # NordVPN placeholders
    assert 'peer_pubkey: ""' in rendered
    assert 'endpoint_host: ""' in rendered


def test_scaffold_allocates_bridge_members_after_wan_ethers():
    config = parse_config(FIXTURE)
    rendered = scaffold_overrides(config, str(FIXTURE))
    parsed = yaml.safe_load(rendered)
    # Fixture: wan + opt1 are dhcp → ether1, ether2 used for WAN
    # bridge-lan should get ether3..ether10
    members = parsed["interfaces"]["lan"]["members"]
    assert members[0] == "ether3"
    assert members[-1] == "ether10"


def test_scaffold_skips_non_ip_and_inverted_bypass_sources():
    """Aliases/hostnames and inverted sources shouldn't land in bypass lists."""
    from pfmk.model import Endpoint, FilterRule, PfSenseConfig, System

    config = PfSenseConfig(
        system=System(hostname="test", domain="local", timezone="UTC"),
        filter_rules=[
            # Alias name in the address slot — not a valid IP
            FilterRule(
                action="pass",
                interface="lan",
                direction="in",
                ipprotocol="inet",
                protocol=None,
                source=Endpoint(any=False, address="my_alias_name"),
                destination=Endpoint(any=True),
                disabled=False,
                description="alias-sourced rule",
                tracker="1",
                gateway="WAN_DHCP",
            ),
            # Inverted source — "everything except this IP"; not a bypass target
            FilterRule(
                action="pass",
                interface="lan",
                direction="in",
                ipprotocol="inet",
                protocol=None,
                source=Endpoint(any=False, address="172.16.1.200", invert=True),
                destination=Endpoint(any=True),
                disabled=False,
                description="inverted source",
                tracker="2",
                gateway="WAN2_DHCP",
            ),
        ],
    )
    rendered = scaffold_overrides(config, "synthetic")
    assert "my_alias_name" not in rendered
    assert "172.16.1.200" not in rendered


def test_scaffold_extracts_bypass_ips_from_gateway_rules():
    # Build a synthetic fixture with gateway-pinned rules inline (minimal
    # fixture doesn't have any).
    from pfmk.model import Endpoint, FilterRule, PfSenseConfig, System

    config = PfSenseConfig(
        system=System(hostname="test", domain="local", timezone="UTC"),
        filter_rules=[
            FilterRule(
                action="pass",
                interface="lan",
                direction="in",
                ipprotocol="inet",
                protocol=None,
                source=Endpoint(any=False, address="172.16.1.50"),
                destination=Endpoint(any=True),
                disabled=False,
                description="Laptop via WAN",
                tracker="1",
                gateway="WAN_DHCP",
            ),
            FilterRule(
                action="pass",
                interface="lan",
                direction="in",
                ipprotocol="inet",
                protocol=None,
                source=Endpoint(any=False, address="172.16.1.60"),
                destination=Endpoint(any=True),
                disabled=False,
                description="Workstation via WAN2",
                tracker="2",
                gateway="WAN2_DHCP",
            ),
            FilterRule(
                # This disabled rule should be ignored
                action="pass",
                interface="lan",
                direction="in",
                ipprotocol="inet",
                protocol=None,
                source=Endpoint(any=False, address="172.16.1.99"),
                destination=Endpoint(any=True),
                disabled=True,
                description="Disabled",
                tracker="3",
                gateway="WAN_DHCP",
            ),
            FilterRule(
                # NordVPN gateway is the default, not a bypass — ignore
                action="pass",
                interface="lan",
                direction="in",
                ipprotocol="inet",
                protocol=None,
                source=Endpoint(any=True),
                destination=Endpoint(any=True),
                disabled=False,
                description="NordVPN catch-all",
                tracker="4",
                gateway="NORDVPN_VPNV4",
            ),
        ],
    )
    rendered = scaffold_overrides(config, "synthetic")
    assert "- 172.16.1.50" in rendered  # via_wan
    assert "- 172.16.1.60" in rendered  # via_wan2
    assert "172.16.1.99" not in rendered  # disabled → excluded
