from dataclasses import dataclass, field


@dataclass
class System:
    hostname: str
    domain: str
    timezone: str


@dataclass
class Interface:
    """A pfSense interface definition (wan, lan, opt1, ...)."""

    name: str                 # pfSense short name, e.g. "wan", "lan", "opt1"
    physical: str             # pfSense physical assignment, e.g. "vtnet0", "ovpnc4"
    description: str          # user-supplied descr
    enabled: bool
    mode: str                 # "dhcp" | "static" | "unknown"
    ipaddr: str | None = None
    subnet: int | None = None


@dataclass
class StaticLease:
    mac: str
    ipaddr: str
    hostname: str
    description: str


@dataclass
class DhcpScope:
    """DHCP server scope, tied to a pfSense interface (lan, opt1, ...)."""

    interface: str                       # pfSense interface short name
    range_from: str
    range_to: str
    gateway: str
    dns_servers: list[str] = field(default_factory=list)
    domain: str = ""
    network: str = ""                    # derived CIDR, e.g. "172.16.1.0/24"
    static_leases: list[StaticLease] = field(default_factory=list)


@dataclass
class DnsHost:
    host: str
    domain: str
    ipaddr: str
    description: str
    source: str                          # "dnsmasq" or "unbound"


@dataclass
class DomainOverride:
    """pfSense's conditional-forwarder entry: queries for domain → forward_to."""

    domain: str
    forward_to: str
    source: str


@dataclass
class Endpoint:
    """Source or destination slot of a pfSense firewall rule."""

    any: bool = True
    address: str | None = None           # "1.2.3.4", "1.2.3.0/24", "!1.2.3.4"
    network: str | None = None           # pfSense interface reference: "lan", "lanip", "(self)"
    port: str | None = None              # "80", "1024-65535"
    invert: bool = False                 # <not/> present on the source/destination


@dataclass
class FilterRule:
    action: str                          # pass | block | reject | match
    interface: str                       # pfSense short name(s), comma-sep possible
    direction: str                       # in | out (default "in")
    ipprotocol: str                      # inet | inet6 | inet46
    protocol: str | None                 # tcp | udp | tcp/udp | icmp | None (any)
    source: Endpoint
    destination: Endpoint
    disabled: bool
    description: str
    tracker: str


@dataclass
class NatPortForward:
    """pfSense dst-nat / port forward rule (<nat><rule>)."""

    interface: str
    protocol: str                        # tcp, udp, tcp/udp, ...
    source: Endpoint
    destination: Endpoint
    target_ip: str                       # internal host
    target_port: str                     # internal port / range
    disabled: bool
    description: str


@dataclass
class NatOutbound:
    """pfSense srcnat / outbound NAT rule (<nat><outbound><rule>)."""

    interface: str
    source: Endpoint
    destination: Endpoint
    source_port: str | None
    dest_port: str | None
    nat_port: str | None
    disabled: bool
    description: str


@dataclass
class DynDnsEntry:
    """pfSense <dyndnses><dyndns> entry."""

    provider: str                        # godaddy, cloudflare, ...
    interface: str                       # pfSense interface short name
    hostname: str                        # "wan", "wan2", "@" (apex)
    domain: str
    description: str
    enabled: bool
    username: str = ""                   # API key / email / user (provider-specific)
    password: str = ""                   # base64-decoded credential from XML


@dataclass
class PfSenseConfig:
    """Root of the parsed pfSense XML. Sections grow as emitters are built."""

    system: System
    interfaces: list[Interface] = field(default_factory=list)
    dhcp_scopes: list[DhcpScope] = field(default_factory=list)
    dns_hosts: list[DnsHost] = field(default_factory=list)
    domain_overrides: list[DomainOverride] = field(default_factory=list)
    filter_rules: list[FilterRule] = field(default_factory=list)
    nat_port_forwards: list[NatPortForward] = field(default_factory=list)
    nat_outbound: list[NatOutbound] = field(default_factory=list)
    dyndns: list[DynDnsEntry] = field(default_factory=list)
