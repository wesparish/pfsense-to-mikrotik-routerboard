import argparse
import logging
from pathlib import Path

from pfmk.emitters import emit_all
from pfmk.init_overrides import scaffold_overrides
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

    init = sub.add_parser(
        "init-overrides",
        help="Scaffold an overrides YAML from a pfSense XML (edit, then pass to `generate`).",
    )
    init.add_argument("xml", help="Path to pfSense config XML")
    init.add_argument(
        "--out",
        help="Output YAML path (default: overrides/<hostname>.yaml)",
        default=None,
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )

    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    if args.command == "generate":
        return _generate(args.xml, args.overrides, args.out)
    if args.command == "init-overrides":
        return _init_overrides(args.xml, args.out, args.force)
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


def _init_overrides(xml_path: str, out_path: str | None, force: bool) -> int:
    logger.info("reading pfSense XML: %s", xml_path)
    config = parse_config(xml_path)

    default_name = config.system.hostname.split(".")[0] or "scaffold"
    out = Path(out_path) if out_path else Path("overrides") / f"{default_name}.yaml"

    if out.exists() and not force:
        print(
            f"ERROR: {out} already exists. Pass --force to overwrite, "
            f"or use --out to write elsewhere."
        )
        return 1

    out.parent.mkdir(parents=True, exist_ok=True)
    rendered = scaffold_overrides(config, xml_path)
    out.write_text(rendered)
    logger.info("wrote %s (%d bytes)", out, len(rendered))
    print(f"wrote {out} ({len(rendered)} bytes)")
    print(
        "\nNext steps:\n"
        f"  1. Review and edit {out} — search for 'TODO' lines.\n"
        f"  2. Generate the .rsc:\n"
        f"       poetry run pfmk generate {xml_path} --overrides {out}"
    )
    return 0
