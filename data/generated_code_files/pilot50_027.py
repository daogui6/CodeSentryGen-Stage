import os
import sys

from colored import attr, fg


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False

    if sys.platform.startswith("win"):
        return bool(os.environ.get("WT_SESSION") or os.environ.get("ANSICON"))

    return sys.stdout.isatty()


def colorize(text: str, color: str = "green", bold: bool = False) -> str:
    if not supports_color():
        return text

    prefix = fg(color)
    if bold:
        prefix += attr("bold")

    return f"{prefix}{text}{attr('reset')}"


def print_status(message: str, status: str) -> None:
    colors = {
        "ok": "green",
        "warning": "yellow",
        "error": "red",
        "info": "cyan",
    }
    color = colors.get(status, "white")
    print(colorize(f"[{status.upper()}] {message}", color=color, bold=True))


if __name__ == "__main__":
    print_status("Operation completed successfully.", "ok")
    print_status("Configuration file is missing, using defaults.", "warning")
    print_status("Unable to connect to the server.", "error")
    print_status("Running on platform: " + sys.platform, "info")
