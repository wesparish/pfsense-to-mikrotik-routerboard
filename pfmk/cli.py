import argparse
from pathlib import Path

from pfmk.emitters import emit_all
from pfmk.overrides import load_overrides
from pfmk.parser import parse_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pfmk",
        description="Generate MikroTik RouterOS .rsc from a pfSense XML backup.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a RouterOS .rsc script")
    gen.add_argument("xml", help="Path to pfSense config XML")
    gen.add_argument("--overrides", help="Path to overrides YAML", default=None)
    gen.add_argument(
        "--out",
        help="Output .rsc path (default: output/mikrotik.rsc)",
        default="output/mikrotik.rsc",
    )

    args = parser.parse_args(argv)

    if args.command == "generate":
        return _generate(args.xml, args.overrides, args.out)
    return 1


def _generate(xml_path: str, overrides_path: str | None, out_path: str) -> int:
    config = parse_config(xml_path)
    overrides = load_overrides(overrides_path)
    rendered = emit_all(config, overrides, source_path=xml_path)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered)
    print(f"wrote {out} ({len(rendered)} bytes)")
    return 0
