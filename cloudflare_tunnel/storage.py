"""Private atomic persistence and a shared, reentrant cross-process mutation lock."""
import contextlib
import fcntl
import functools
import json
import os
import tempfile
import threading
import uuid

_mutex = threading.RLock()
_local = threading.local()


def atomic_write(path, value, mode=0o600):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, staging = tempfile.mkstemp(prefix=".cft-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, path)
    finally:
        if os.path.exists(staging):
            os.unlink(staging)


def write_json(path, value):
    atomic_write(path, json.dumps(value, indent=2))


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as stream:
            value = json.load(stream)
        if not isinstance(value, type(default)):
            raise ValueError("Unexpected data type in " + path)
        return value
    except FileNotFoundError:
        return default


@contextlib.contextmanager
def mutation_lock(data_dir):
    with _mutex:
        if getattr(_local, "locked", False):
            yield
            return
        os.makedirs(data_dir, exist_ok=True)
        fd = os.open(os.path.join(data_dir, ".mutation.lock"), os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "w") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            _local.locked = True
            try:
                yield
            finally:
                _local.locked = False
                fcntl.flock(stream, fcntl.LOCK_UN)


def serialized(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        with mutation_lock(self.data_dir):
            return method(self, *args, **kwargs)
    return wrapped


def tunnel_uuid(value):
    try:
        parsed = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Tunnel ID must be a UUID")
    if parsed != str(value).lower():
        raise ValueError("Tunnel ID must be a UUID")
    return parsed
