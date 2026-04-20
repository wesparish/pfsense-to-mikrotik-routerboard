"""Small helpers shared across emitters."""


def escape(value: str) -> str:
    """Escape a string for use inside a double-quoted RouterOS argument."""

    return value.replace("\\", "\\\\").replace('"', '\\"')


def expand_protocol(protocol: str | None) -> list[str | None]:
    """pfSense's `tcp/udp` becomes two RouterOS rules; other values are single."""

    if protocol is None or protocol == "":
        return [None]
    if protocol == "tcp/udp":
        return ["tcp", "udp"]
    return [protocol]
