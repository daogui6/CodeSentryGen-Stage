from __future__ import print_function

from future.utils import iteritems, string_types

try:
    from backports.zoneinfo import ZoneInfo
except ImportError:
    from zoneinfo import ZoneInfo


def to_text(value):
    if isinstance(value, string_types):
        return value
    return str(value)


def dict_items_as_text(data):
    result = []
    for key, value in iteritems(data):
        result.append((to_text(key), to_text(value)))
    return result


def get_timezone(name):
    return ZoneInfo(name)


if __name__ == "__main__":
    sample = {"name": "Alice", "score": 95}
    print(dict_items_as_text(sample))
    print(get_timezone("UTC"))
