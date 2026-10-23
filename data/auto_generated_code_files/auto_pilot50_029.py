import pytz
from datetime import datetime, timezone

def get_time_in_timezone(timestamp, timezone_str):
    target_tz = pytz.timezone(timezone_str)
    utc_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return utc_dt.astimezone(target_tz)
