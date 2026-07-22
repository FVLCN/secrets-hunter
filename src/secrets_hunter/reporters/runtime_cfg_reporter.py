from itertools import batched

from secrets_hunter.config import RuntimeConfig
from secrets_hunter.reporters.console_base import BaseConsoleReporter


class RuntimeConfigReporter(BaseConsoleReporter):
    SECTIONS = {
        "ignore_files": ("compact_list", 4),
        "ignore_extensions": ("compact_list", 6),
        "ignore_dirs": ("compact_list", 4)
    }

    @staticmethod
    def should_show(k: str, sections: list[str] | None) -> bool:
        return not sections or k in sections

    @staticmethod
    def add_section(lines: list[str], title: str) -> None:
        lines.append(f"\n{title}")
        lines.append("-" * RuntimeConfigReporter.WIDTH)

    @staticmethod
    def pretty_runtime_cfg(runtime_cfg: RuntimeConfig, sections: list[str] | None = None) -> None:
        lines = ["Scanner Runtime Configuration", "─" * RuntimeConfigReporter.WIDTH]

        for key, (fmt_type, cols) in RuntimeConfigReporter.SECTIONS.items():
            if not RuntimeConfigReporter.should_show(key, sections):
                continue

            val = getattr(runtime_cfg, key, None)

            if val is None:
                continue

            if fmt_type == "compact_list" and isinstance(val, (set, frozenset, list, tuple)):
                items = sorted([str(x) for x in val], key=lambda x: x.lower())
                RuntimeConfigReporter.add_section(lines, f"{key} ({len(items)})")

                for chunk in batched(items, cols):
                    lines.append(f"  - {', '.join(chunk)}")

        print("\n".join(lines) + "\n")
