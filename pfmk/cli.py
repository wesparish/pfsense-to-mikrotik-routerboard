import argparse
import logging
from pathlib import Path

from pfmk.emitters import emit_all
from pfmk.overrides import load_overrides
from pfmk.parser import parse_config
from pfmk.summary import render_summary

logger = logging.getLogger("pfmk")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pfmk",
        description="Generate MikroTik RouterOS .rsc from a pfSense XML backup.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Log what the generator is doing (-v for info, -vv for debug).",
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
    _configure_logging(args.verbose)

    if args.command == "generate":
        return _generate(args.xml, args.overrides, args.out)
    return 1


def _configure_logging(verbosity: int) -> None:
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)-5s %(name)s: %(message)s",
    )


def _generate(xml_path: str, overrides_path: str | None, out_path: str) -> int:
    logger.info("reading pfSense XML: %s", xml_path)
    config = parse_config(xml_path)

    logger.info("loading overrides: %s", overrides_path or "(none — using defaults)")
    overrides = load_overrides(overrides_path)
    if overrides_path is None:
        logger.warning(
            "no --overrides file provided; interface mappings are empty — "
            "most firewall/NAT rules will be skipped"
        )

    logger.info("emitting RouterOS .rsc")
    rendered = emit_all(config, overrides, source_path=xml_path)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered)
    logger.info("wrote %s (%d bytes)", out, len(rendered))
    print(f"wrote {out} ({len(rendered)} bytes)")
    print(render_summary(config, overrides, rendered), end="")
    return 0
