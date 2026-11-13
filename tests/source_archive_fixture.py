"""Private, inert Git metadata transports for source-update preservation fixtures.

ZIP bytes are test supplier inputs. Separate integrity tests freeze the metadata
before tampering with a ZIP, so they do not derive expected hashes from damage.
"""
from __future__ import annotations

import hashlib
import io
import zipfile


def git_id(kind, raw):
    return hashlib.sha1(kind + b" " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def git_tree_metadata(files):
    children = {"": {}}
    for path, raw in files.items():
        parent, _, leaf = path.rpartition("/")
        current = parent
        while current:
            children.setdefault(current, {})
            ancestor, _, name = current.rpartition("/")
            children.setdefault(ancestor, {})[name] = ("tree", "040000", current)
            current = ancestor
        children.setdefault(parent, {})[leaf] = ("blob", "100644", git_id(b"blob", raw))
    digests, entries = {}, []
    for directory in sorted(children, key=lambda value: value.count("/") + bool(value), reverse=True):
        raw = bytearray()
        for leaf, (kind, mode, value) in sorted(children[directory].items(),
                key=lambda pair: pair[0].encode("utf-8") + (b"/" if pair[1][0] == "tree" else b"")):
            object_id = digests[value] if kind == "tree" else value
            raw.extend(("40000" if kind == "tree" else mode).encode() + b" " + leaf.encode("utf-8")
                       + b"\0" + bytes.fromhex(object_id))
            name = directory + "/" + leaf if directory else leaf
            entry = dict(path=name, type=kind, mode=mode, sha=object_id)
            if kind == "blob":
                entry["size"] = len(files[name])
            entries.append(entry)
        digests[directory] = git_id(b"tree", bytes(raw))
    return dict(sha=digests[""], truncated=False, tree=entries)


class SourceArchiveFetch(dict):
    """Keep existing mutable comparison fixtures while providing immutable APIs."""
    def __init__(self, archives, comparison):
        super().__init__({} if callable(comparison) else comparison)
        self.archives, self.comparison, self.trees = archives, comparison, {}

    def __call__(self, path):
        if path.startswith("compare/"):
            return self.comparison(path) if callable(self.comparison) else self
        if path.startswith("git/commits/"):
            revision = path.removeprefix("git/commits/")
            prefix = "AngeronaSuite-" + revision + "/"
            with zipfile.ZipFile(io.BytesIO(self.archives[revision])) as archive:
                files = {info.filename.removeprefix(prefix): archive.read(info)
                         for info in archive.infolist() if not info.is_dir()}
            tree = git_tree_metadata(files)
            self.trees[tree["sha"]] = tree
            return dict(sha=revision, tree=dict(sha=tree["sha"]))
        if path.startswith("git/trees/") and path.endswith("?recursive=1"):
            return self.trees[path.removeprefix("git/trees/").removesuffix("?recursive=1")]
        raise AssertionError("Unexpected fake canonical endpoint: " + path)
