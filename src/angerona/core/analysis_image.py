"""Build a deterministic Linux initramfs without extracting Linux paths on Windows."""
from __future__ import annotations

import gzip
import io
import stat
import tarfile
import zipfile
from pathlib import PurePosixPath

from angerona.core.analysis_guest import INIT, SOURCE

MAX_IMAGE_BYTES = 160 * 1024 * 1024


def guest_name(value: str) -> str:
    value = value.removeprefix('./').rstrip('/')
    if (not value or value.startswith('/') or '\\' in value or '\x00' in value
            or any(p in {'', '.', '..'} for p in value.split('/'))):
        raise ValueError('Invalid guest archive path.')
    return value


def cpio(entries: dict[str, tuple[int, bytes]]) -> bytes:
    """newc records; symlinks are guest-only bytes, never host filesystem links."""
    contents = dict(entries)
    for name in entries:
        guest_name(name)
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                contents.setdefault(str(parent), (stat.S_IFDIR | 0o755, b''))
    if len(contents) > 20000 or sum(len(data) for _, data in contents.values()) > MAX_IMAGE_BYTES:
        raise ValueError('Guest image exceeds its entry or byte limit.')
    output = io.BytesIO()
    records = sorted(contents.items()) + [('TRAILER!!!', (0, b''))]
    for index, (name, (mode, data)) in enumerate(records, 1):
        encoded = name.encode('utf-8') + b'\0'
        fields = [index, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        output.write(b'070701' + ''.join(f'{v:08x}' for v in fields).encode() + encoded)
        output.write(b'\0' * (-output.tell() % 4))
        output.write(data)
        output.write(b'\0' * (-output.tell() % 4))
    return output.getvalue()


class GuestImage:
    def __init__(self):
        self.entries: dict[str, tuple[int, bytes]] = {}
        self.expanded = 0

    def add(self, name, data=b'', mode=stat.S_IFREG | 0o644):
        name = guest_name(name)
        self.expanded += len(data)
        if self.expanded > MAX_IMAGE_BYTES or len(self.entries) >= 20000:
            raise ValueError('Guest packages exceed their expansion budget.')
        self.entries[name] = mode, data

    def tar(self, content: bytes, operation):
        # APK v2 concatenates signed metadata and data gzip streams. Neither
        # package hooks nor metadata are installed or evaluated.
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as stream, tarfile.open(
            fileobj=stream, mode='r|', ignore_zeros=True,
        ) as archive:
            for member in archive:
                operation.check()
                raw = member.name.removeprefix('./').rstrip('/')
                if not raw or raw.startswith('.'):
                    continue
                name = guest_name(raw)
                if member.isdir():
                    self.add(name, mode=stat.S_IFDIR | 0o755)
                elif member.isfile():
                    if member.size > 40 * 1024**2:
                        raise ValueError('Guest package member exceeds its byte limit.')
                    self.add(name, archive.extractfile(member).read(member.size + 1),
                             stat.S_IFREG | (member.mode & 0o755))
                elif member.issym():
                    if len(member.linkname) > 512 or '\x00' in member.linkname:
                        raise ValueError('Invalid guest link.')
                    self.add(name, member.linkname.encode(), stat.S_IFLNK | 0o777)
                elif member.islnk():
                    target = guest_name(member.linkname)
                    if target not in self.entries:
                        raise ValueError('Guest hard link target is missing.')
                    mode, data = self.entries[target]
                    self.add(name, data, mode)
                else:
                    raise ValueError('Unsupported guest archive entry.')

    def wheel(self, content: bytes, operation):
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            if len(archive.infolist()) > 1000:
                raise ValueError('Too many wheel entries.')
            for member in archive.infolist():
                operation.check()
                if member.is_dir():
                    continue
                name = guest_name(member.filename)
                if member.file_size > 1024**2:
                    raise ValueError('Wheel member exceeds its byte limit.')
                self.add('usr/lib/python3.14/site-packages/' + name, archive.read(member))

    def finish(self) -> bytes:
        self.add('init', INIT, stat.S_IFREG | 0o755)
        self.add('opt/runner.py', SOURCE.encode())
        self.add('opt/empty.ini', b'')
        self.add('opt/bandit.yaml', b'{}\n')
        self.add('opt/gitleaks.toml', b'[extend]\nuseDefault = true\n')
        self.add('input', mode=stat.S_IFDIR | 0o755)
        return compress(cpio(self.entries))


def compress(content: bytes) -> bytes:
    value = bytearray(gzip.compress(content, compresslevel=6, mtime=0))
    value[9] = 255  # Normalize gzip's OS byte across supported Python versions.
    return bytes(value)
