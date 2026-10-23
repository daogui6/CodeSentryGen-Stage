from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import str, bytes, dict, int, map, zip, filter, range
import sys

try:
    from backports.functools_lru_cache import lru_cache
except ImportError:
    from functools import lru_cache

def to_unicode(s):
    """Convert a string or bytes object to unicode."""
    if isinstance(s, bytes):
        return s.decode('utf-8')
    return str(s)

def to_bytes(s, encoding='utf-8'):
    """Convert a string or unicode object to bytes."""
    if isinstance(s, str):
        return s.encode(encoding)
    return bytes(s)

def iteritems(d):
    """Return an iterator over the (key, value) pairs of a dictionary."""
    if sys.version_info[0] >= 3:
        return iter(d.items())
    else:
        return d.iteritems()

def itervalues(d):
    """Return an iterator over the values of a dictionary."""
    if sys.version_info[0] >= 3:
        return iter(d.values())
    else:
        return d.itervalues()

def iterkeys(d):
    """Return an iterator over the keys of a dictionary."""
    if sys.version_info[0] >= 3:
        return iter(d.keys())
    else:
        return d.iterkeys()
