from pathlib import Path

from pfmk.emitters import emit_all
from pfmk.overrides import BypassLists, InterfaceMapping, Overrides, RoutingOverrides
from pfmk.parser import parse_config
from pfmk.summary import render_summary

FIXTURE = Path(__file__).parent / "fixtures" / "minimal.xml"


def _overrides() -> Overrides:
    return Overrides(
        interfaces={
            "wan": InterfaceMapping(target="ether1", role="egress"),
            "opt1": InterfaceMapping(target="ether2", role="ingress"),
            "lan": InterfaceMapping(
                target="bridge-lan",
                role="lan",
                members=[f"ether{i}" for i in range(3, 11)],
            ),
            "opt2": InterfaceMapping(skip=True),
        },
        routing=RoutingOverrides(
            default_via="nordvpn",
            bypass=BypassLists(via_wan=["172.16.1.3"], via_wan2=["172.16.1.70"]),
        ),
    )


def test_summary_renders_all_major_sections():
    config = parse_config(FIXTURE)
    overrides = _overrides()
    rendered = emit_all(config, overrides, source_path=str(FIXTURE))

    summary = render_summary(config, overrides, rendered)

    for header in [
        "Physical → logical",
        "LAN services",
        "WAN egress policy",
        "Inbound (port forwards",
        "Firewall",
        "Action items before /import",
    ]:
        assert header in summary, f"missing section: {header}"


def test_summary_compacts_bridge_member_range():
    config = parse_config(FIXTURE)
    overrides = _overrides()
    rendered = emit_all(config, overrides, source_path=str(FIXTURE))
    summary = render_summary(config, overrides, rendered)
    # Contiguous ether3..ether10 should collapse into "ether3-10"
    assert "ether3-10" in summary


def test_summary_reports_retired_interfaces_as_skipped():
    config = parse_config(FIXTURE)
    overrides = _overrides()
    rendered = emit_all(config, overrides, source_path=str(FIXTURE))
    summary = render_summary(config, overrides, rendered)
    assert "skipped: opt2" in summary
