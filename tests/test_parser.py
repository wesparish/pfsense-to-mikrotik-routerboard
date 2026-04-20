from pathlib import Path

from pfmk.parser import parse_config

FIXTURE = Path(__file__).parent / "fixtures" / "minimal.xml"


def test_parses_system_section():
    config = parse_config(FIXTURE)
    assert config.system.hostname == "router"
    assert config.system.domain == "example.test"
    assert config.system.timezone == "America/Chicago"


def test_parses_interfaces():
    config = parse_config(FIXTURE)
    by_name = {i.name: i for i in config.interfaces}

    assert by_name["wan"].enabled
    assert by_name["wan"].mode == "dhcp"
    assert by_name["wan"].physical == "vtnet0"

    assert by_name["lan"].mode == "static"
    assert by_name["lan"].ipaddr == "172.16.1.1"
    assert by_name["lan"].subnet == 24

    assert by_name["opt1"].enabled
    assert by_name["opt1"].description == "WAN2"

    # opt2 has no <enable/> tag → treated as disabled
    assert not by_name["opt2"].enabled
