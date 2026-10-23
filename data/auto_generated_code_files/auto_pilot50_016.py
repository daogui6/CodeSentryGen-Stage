import datetime
from decimal import Decimal, getcontext
from dateutil import parser

getcontext().prec = 50

class NanoDateTime:
    def __init__(self, timestamp=None, tzinfo=None):
        if timestamp is None:
            now = datetime.datetime.now(datetime.timezone.utc)
            self._timestamp = Decimal(now.timestamp())
        else:
            self._timestamp = Decimal(str(timestamp))
        self._tzinfo = tzinfo

    @classmethod
    def parse(cls, date_string):
        dt = parser.parse(date_string)
        return cls(dt.timestamp(), dt.tzinfo)

    @property
    def timestamp(self):
        return self._timestamp

    def to_datetime(self):
        return datetime.datetime.fromtimestamp(float(self._timestamp), tz=self._tzinfo)

    def __str__(self):
        dt = self.to_datetime()
        frac = self._timestamp - Decimal(int(self._timestamp))
        nano_str = f"{frac:.9f}"[2:]
        tz_str = dt.strftime('%z') if dt.tzinfo else ''
        return dt.strftime('%Y-%m-%d %H:%M:%S') + '.' + nano_str + tz_str

    def __repr__(self):
        return f"NanoDateTime(timestamp={self._timestamp})"

if __name__ == "__main__":
    ndt = NanoDateTime.parse("2023-10-25T15:30:45.123456789+00:00")
    print(ndt)
    print(ndt.timestamp)
