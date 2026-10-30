"""Legacy local advisory context, with no import-time knowledge-base I/O.

The optional operator-owned file defaults beside this module and can be
selected with EDR_KB_PATH. Missing files are never created. Retrieved text is
untrusted advisory data, not an instruction or authority to change security
policy; a textual match or absence of matches is not a scan verdict.
"""

import os

_SCRIPT_DIR         = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_BASE_PATH = os.getenv(
    "EDR_KB_PATH",
    os.path.join(_SCRIPT_DIR, "knowledge_base.txt")
)

MAX_KB_BYTES = 1024 * 1024
MAX_CONTEXT_BYTES = 16 * 1024
_ADVISORY = "[Advisory local knowledge-base text; not a security verdict.]\n"
_TRUNCATED = "\n[Context truncated: input or output limit reached; coverage is incomplete.]"
_UNAVAILABLE = "Local knowledge base unavailable: content could not be read or decoded."


def query_local_context(process_name):
    """Read bounded existing context without creating or modifying a file.

    Preserve the platform text encoding used by the original text reader.
    Decode a truncated multibyte prefix incrementally, retaining a partial
    trailing character rather than misreporting truncation as file corruption.
    """
    if not isinstance(process_name, str) or len(process_name) > 1024:
        return _ADVISORY + "Local knowledge base unavailable: query text is invalid."
    try:
        with open(KNOWLEDGE_BASE_PATH, "rb") as source:
            raw = source.read(MAX_KB_BYTES + 1)
    except FileNotFoundError:
        return ""
    except (OSError, ValueError, TypeError):
        return _ADVISORY + _UNAVAILABLE
    input_truncated = len(raw) > MAX_KB_BYTES
    try:
        import codecs
        import locale

        decoder = codecs.getincrementaldecoder(locale.getpreferredencoding(False))(errors="strict")
        text = decoder.decode(raw[:MAX_KB_BYTES], final=not input_truncated)
    except (UnicodeError, LookupError):
        return _ADVISORY + _UNAVAILABLE
    # Reserve the notice before collecting matches, so it always fits and a
    # partial result can never masquerade as complete coverage.
    remaining = MAX_CONTEXT_BYTES - len(_ADVISORY.encode("utf-8")) - len(_TRUNCATED.encode("utf-8"))
    result = bytearray()
    output_truncated = False
    selector = process_name.lower()
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        lowered = line.lower()
        if selector in lowered or "rule" in lowered:
            encoded = (("\n" if result else "") + line.strip()).encode("utf-8")
            if len(encoded) > remaining:
                result.extend(encoded[:remaining])
                output_truncated = True
                break
            result.extend(encoded)
            remaining -= len(encoded)
    partial = input_truncated or output_truncated
    context = result.decode("utf-8", errors="ignore")
    if not context:
        context = ("No matching context in the inspected prefix." if partial
                   else "No local assets conflict found.")
    return _ADVISORY + context + (_TRUNCATED if partial else "")
