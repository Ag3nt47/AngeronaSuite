"""Private real-byte fixtures with a modeled ordinary-user native boundary.

This adapter never grants product authority. It replaces only the independently
covered native custody/token seam for disposable pytest paths, so elevated
Windows CI can keep genuine byte/identity/lifecycle assertions without writing
personal folders or pretending a privileged token is an ordinary product token.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

from angerona.core import deception_io
from angerona.modules import deception


def private_canary_io(monkeypatch, root):
    root = root.resolve()
    original_temporary = deception.tempfile.TemporaryDirectory
    monkeypatch.setattr(deception_io, "_CLOSE_HOLDS", [])

    def admitted(path):
        path = Path(path).absolute()
        if not path.is_relative_to(root):
            raise AssertionError("Private canary fixture escaped its pytest root")
        for component in (path, *path.parents):
            if component == root.parent:
                break
            try:
                info = component.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise AssertionError("Private fixture contains an unmodeled redirection")
        return path

    class Session:
        def __init__(self, base, *, personal=False, create_parents=False):
            assert personal is False, "Disposable fixtures must never resolve personal folders"
            self.base = admitted(base)
            self.create_parents = create_parents
            self.resources = []

        def __enter__(self):
            deception_io._available()
            if self.create_parents:
                self.base.mkdir(parents=True, exist_ok=True)
            assert self.base.is_dir()
            return self

        def __exit__(self, *_args):
            deception_io._close_all(self.resources)

        @contextmanager
        def leaf(self, name, *, create=False):
            path = admitted(self.base / name)
            flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL) if create else os.O_RDONLY
            flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileExistsError as error:
                raise deception_io.CanaryCollision("Private fixture collision preserved") from error
            owned = deception_io._Owned(descriptor, os.close)
            self.resources.append(owned)
            try:
                yield owned
            finally:
                owned.close()

        def info(self, leaf):
            value = os.fstat(leaf.value)
            assert stat.S_ISREG(value.st_mode)
            return dict(attributes=int(getattr(value, "st_file_attributes", 0)),
                        device=value.st_dev, inode=value.st_ino, size=value.st_size,
                        mtime_ns=value.st_mtime_ns, links=value.st_nlink)

        def read(self, leaf, maximum):
            os.lseek(leaf.value, 0, os.SEEK_SET)
            return os.read(leaf.value, maximum)

        def validate_leaf(self, leaf, path):
            named, held = admitted(path).lstat(), os.fstat(leaf.value)
            assert (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)

        def write(self, leaf, raw):
            offset = 0
            while offset < len(raw):
                amount = os.write(leaf.value, raw[offset:])
                assert amount > 0
                offset += amount
            os.fsync(leaf.value)

        def hide(self, leaf):
            # Handle-only hidden/system flags are independently tested through
            # an inert native facade; no real attribute mutation in this fixture.
            assert not leaf.closed

    def temporary(**kwargs):
        assert "dir" not in kwargs
        return original_temporary(dir=root, **kwargs)

    monkeypatch.setattr(deception_io, "_session", lambda base, **kwargs: Session(base, **kwargs))
    monkeypatch.setattr(deception.tempfile, "TemporaryDirectory", temporary)
