from datetime import datetime
from zoneinfo import ZoneInfo


def convert_timestamp_to_timezone(timestamp: float, timezone_name: str) -> datetime:
    timezone = ZoneInfo(timezone_name)
    return datetime.fromtimestamp(timestamp, tz=timezone)


def format_timestamp(timestamp: float, timezone_name: str) -> str:
    local_time = convert_timestamp_to_timezone(timestamp, timezone_name)
    return local_time.strftime("%Y-%m-%d %H:%M:%S %Z%z")


def compare_timezones(timestamp: float, timezone_names: list[str]) -> dict[str, str]:
    return {
        timezone_name: format_timestamp(timestamp, timezone_name)
        for timezone_name in timezone_names
    }


if __name__ == "__main__":
    sample_timestamp = 1717228800

    zones = [
        "UTC",
        "America/New_York",
        "Europe/London",
        "Asia/Shanghai",
    ]

    converted = compare_timezones(sample_timestamp, zones)

    for zone, value in converted.items():
        print(f"{zone}: {value}")
