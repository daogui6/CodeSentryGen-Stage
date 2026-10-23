class _MissingSentinel:
    def __repr__(self):
        return '<MISSING>'

_MISSING = _MissingSentinel()

class TrackedData:
    def __init__(self, data, collection=None):
        self._data = data
        self._collection = collection
        self._id = id(self)
        self._version = 0

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value
        self._version += 1
        if self._collection:
            self._collection.invalidate_by_dep(self._id)

    @property
    def version(self):
        return self._version

class MemoizeCollection:
    def __init__(self):
        self._cache = {}
        self._reverse_deps = {}

    def _make_key(self, args, kwargs):
        deps = []
        def process(arg):
            if isinstance(arg, TrackedData):
                deps.append(id(arg))
                return ('__tracked__', id(arg), arg.version)
            elif isinstance(arg, (list, tuple)):
                return tuple(process(x) for x in arg)
            elif isinstance(arg, dict):
                return tuple(sorted((k, process(v)) for k, v in arg.items()))
            return arg

        key_args = tuple(process(a) for a in args)
        key_kwargs = tuple(sorted((k, process(v)) for k, v in kwargs.items()))
        return (key_args, key_kwargs), deps

    def get(self, args, kwargs):
        key, deps = self._make_key(args, kwargs)
        if key in self._cache:
            return self._cache[key]
        for dep_id in deps:
            if dep_id not in self._reverse_deps:
                self._reverse_deps[dep_id] = set()
            self._reverse_deps[dep_id].add(key)
        return _MISSING

    def set(self, args, kwargs, value):
        key, deps = self._make_key(args, kwargs)
        self._cache[key] = value
        for dep_id in deps:
            if dep_id not in self._reverse_deps:
                self._reverse_deps[dep_id] = set()
            self._reverse_deps[dep_id].add(key)

    def invalidate_by_dep(self, dep_id):
        if dep_id in self._reverse_deps:
            for key in self._reverse_deps[dep_id]:
                self._cache.pop(key, None)
            del self._reverse_deps[dep_id]

def memoize(collection=None):
    if collection is None:
        collection = MemoizeCollection()
    def decorator(func):
        def wrapper(*args, **kwargs):
            res = collection.get(args, kwargs)
            if res is not _MISSING:
                return res
            res = func(*args, **kwargs)
            collection.set(args, kwargs, res)
            return res
        wrapper.collection = collection
        return wrapper
    return decorator
