# Historical native bridge is unavailable

The legacy indirect syscall extension is unsupported and intentionally blocked
from building. Its C implementation is retained for review, rather than offered
as a working security component.

Every command through setup.py, including help and metadata commands, exits
before importing setuptools or invoking a compiler. The C translation unit also
has an unconditional preprocessor error before its native includes. There is
no environment or command-line option to bypass either hold.

Normal Angerona package builds do not build this extension. The existing
Indirect Syscall Bridge module does not admit ambient native imports and
reports its separate ctypes/psutil fallback as degraded. An offline descriptive
self-test or a fallback operation does not establish native hook-bypass coverage.

## Unresolved correctness issues

The retained implementation has not been repaired or certified. Review finding
PW29 identifies incompatible allocation protection for a file read, incorrect
x64 prologue and generated-stub assumptions, unchecked allocation failure, and
insufficient PE offset bounds. The old implementation must not be treated as a
reference for safe containment or CET compatibility.

The build holds prevent accidental use of the supplied build paths. They do
not defend against an attacker who can rewrite the source, replace the
interpreter or compiler, or compromise the administrator or kernel boundary.
Existing binaries are not made safe by this source change.

## Requirements before replacement

A replacement needs a fixed private package namespace, release-manifest and
publisher/digest admission, no-reparse object binding, and an authenticated
broker ABI. Its native parser, allocations, architecture-specific calling
conventions, target identity and handle retirement need compiled tests and
independent review before it can supply response authority.

Removing a hold or copying a compiled extension into the source tree is not an
enrollment procedure. Any future supported implementation must preserve the
suite's policy, exact process identity and verified postcondition requirements.
