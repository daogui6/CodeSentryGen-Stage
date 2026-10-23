from decimal import Decimal, getcontext
from datetime import datetime, timezone

import pendulum
from dateutil import parser


getcontext().prec = 30


def parse_datetime(value):
    try:
        return pendulum.parse(value)
    except Exception:
        return parser.parse(value)


def timestamp_with_nanoseconds(dt=None, nanoseconds=0):
    if dt is None:
        dt = datetime.now(timezone.utc)

    seconds = Decimal(str(dt.timestamp()))
    nano_fraction = Decimal(nanoseconds) / Decimal("1000000000")
    return seconds + nano_fraction


def format_datetime(value, timezone_name="UTC"):
    dt = parse_datetime(value)
    if hasattr(dt, "in_timezone"):
        return dt.in_timezone(timezone_name).to_iso8601_string()
    return dt.astimezone(timezone.utc).isoformat()


if __name__ == "__main__":
    raw = "2026-05-30T12:30:45Z"
    print(format_datetime(raw, "Asia/Shanghai"))
    print(timestamp_with_nanoseconds(nanoseconds=123456789))
