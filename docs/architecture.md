# Architecture

Single-pass code generator. No state machine, no iterative compilation, no
round-tripping. Read XML, merge overrides, emit text.

## Shape

```
 pfSense XML  ──▶  parser.py  ──▶  model.py (typed)
                                       │
       YAML   ──▶  overrides.py  ──────┤
                                       ▼
                             emitters/*.py  ──▶  mikrotik.rsc
```

## Layers

### `pfmk/parser.py`

Stdlib `xml.etree.ElementTree`. One `_parse_*` function per top-level pfSense
section (`system`, `interfaces`, `dhcpd`, `dnsmasq`+`unbound`, `filter`, `nat`,
`dyndnses`). Each returns dataclasses from `pfmk/model.py`. Cross-section
post-processing (LAN CIDR derivation from interface ipaddr+subnet, base64
password decoding) happens in `parse_config`.

### `pfmk/model.py`

Typed dataclasses for every section we emit. No behavior — pure data.

### `pfmk/overrides.py`

Loads YAML → `Overrides` dataclass. Every user-controlled knob lives here.
Overrides are read-only to emitters; they do not mutate the parsed model.

### `pfmk/emitters/`

One module per RouterOS concern. Each emitter is a pure function:

```
(parsed_model_slice, overrides_slice) → str
```

Modules:

- `system.py` — identity, clock
- `interfaces.py` — ethernet, bridge, `/ip address`, dhcp-client
- `dhcp.py` — `/ip pool`, `/ip dhcp-server` + network + lease
- `dns.py` — `/ip dns set`, `/ip dns static`
- `wireguard.py` — NordVPN via NordLynx (override-driven, placeholders for secrets)
- `firewall_filter.py` — translated rules + chain=input baseline + chain=input
  auto-detection for router-targeted rules
- `firewall_nat.py` — port forwards, baseline masquerade, outbound references
- `routing.py` — policy routing, bypass lists, WAN2 asymmetric return
- `ddns.py` — GoDaddy + Cloudflare `/system script` + `/system scheduler`
- `_common.py` — `escape()` for double-quoted RouterOS args, `expand_protocol()`
  for `tcp/udp` → two-rule expansion

The orchestrator in `emitters/__init__.py` composes outputs into a single
`.rsc` with section header comments.

### `pfmk/cli.py`

`argparse` entry point — `pfmk generate <xml> --overrides <yaml> --out <path>`.
Delegates to parser → overrides loader → `emit_all`.

## Testing

- **Parser**: assert known values on a synthetic fixture XML
  (`tests/fixtures/minimal.xml`, no PII) for every section.
- **Each emitter**: assert key substrings + structural expectations in the
  rendered text. Not byte-exact golden-file tests except for `system`.
- **Edge cases** are isolated tests: disabled interface, IPv6 rule, retired
  interface, duplicate-IP lease, dropped domain, dual bypass, chain=input
  detection, tcp/udp expansion, empty overrides, etc.
- No integration tests against a real RouterOS — generator output is
  reviewed by a human before apply.

## Design choices

**No templating engine for output.** Emitters build strings directly (Jinja2
is a listed dep but currently unused; keep it for future refactoring if
emitters grow). RouterOS commands are simple enough that plain f-strings
keep the code easier to grep and trace.

**Overrides are a strict, typed surface.** Unknown YAML keys are ignored (by
design — forward compat). Known keys become fields on dataclasses with sane
defaults. Emitters never read raw YAML; they take typed overrides.

**Per-emitter skipping is visible, not silent.** When an emitter can't handle
something (retired interface, IPv6 rule, missing override field), it writes a
`# SKIPPED` or `# NOTE` comment inline so the human reviewer sees it. No
out-of-band logs, no separate report file.

**Secrets in output .rsc, not in YAML.** pfSense DDNS passwords (base64-
decoded) are inlined into the generated scripts. `overrides/*.yaml` is
gitignored by default; `output/` is also gitignored. If you share either,
strip credentials first.
