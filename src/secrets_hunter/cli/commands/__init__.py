from . import scan, showconfig, train_model
from ..protocols import CommandModule, SubparserRegistry


COMMANDS: tuple[CommandModule, ...] = (scan, showconfig, train_model)
COMMAND_NAMES = frozenset(command.NAME for command in COMMANDS)


def register_commands(subparsers: SubparserRegistry) -> None:
    for command in COMMANDS:
        command.register(subparsers)
