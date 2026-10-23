import argparse
from collections.abc import Callable
from dataclasses import dataclass


CommandHandler = Callable[[argparse.Namespace], None]


@dataclass
class Command:
    name: str
    help_text: str
    configure: Callable[[argparse.ArgumentParser], None]
    handler: CommandHandler


class CommandToolkit:
    def __init__(self, description: str) -> None:
        self.description = description
        self.commands: dict[str, Command] = {}

    def register(self, command: Command) -> None:
        if command.name in self.commands:
            raise ValueError(f"command already registered: {command.name}")
        self.commands[command.name] = command

    def run(self) -> None:
        parser = argparse.ArgumentParser(description=self.description)
        subparsers = parser.add_subparsers(dest="command", required=True)

        for command in self.commands.values():
            command_parser = subparsers.add_parser(command.name, help=command.help_text)
            command.configure(command_parser)
            command_parser.set_defaults(handler=command.handler)

        args = parser.parse_args()
        args.handler(args)


def configure_greet(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("name", help="Name to greet")
    parser.add_argument("--upper", action="store_true", help="Print greeting in uppercase")


def handle_greet(args: argparse.Namespace) -> None:
    message = f"Hello, {args.name}!"
    if args.upper:
        message = message.upper()
    print(message)


def configure_sum(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("numbers", nargs="+", type=float, help="Numbers to add")


def handle_sum(args: argparse.Namespace) -> None:
    print(sum(args.numbers))


def build_toolkit() -> CommandToolkit:
    toolkit = CommandToolkit("Composable command line toolkit demo")

    toolkit.register(
        Command(
            name="greet",
            help_text="Print a greeting",
            configure=configure_greet,
            handler=handle_greet,
        )
    )

    toolkit.register(
        Command(
            name="sum",
            help_text="Add numbers",
            configure=configure_sum,
            handler=handle_sum,
        )
    )

    return toolkit


if __name__ == "__main__":
    build_toolkit().run()
