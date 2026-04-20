from pfmk.model import System
from pfmk.overrides import TargetOverrides


def emit(system: System, target: TargetOverrides) -> str:
    hostname = target.hostname or system.hostname
    timezone = target.timezone or system.timezone
    return "\n".join(
        [
            "# ==== System ====",
            f'/system identity set name="{_escape(hostname)}"',
            f'/system clock set time-zone-name="{_escape(timezone)}"',
        ]
    )


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
