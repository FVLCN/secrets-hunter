from dataclasses import dataclass

from secrets_hunter._version import __version__


@dataclass(frozen=True, slots=True)
class ToolInfo:
    name: str
    version: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version}


DEFAULT_TOOL_INFO = ToolInfo("secrets-hunter", __version__)
