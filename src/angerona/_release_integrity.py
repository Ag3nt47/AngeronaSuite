"""Build-time integrity values for packaged release sidecars.

The release workflow replaces the empty digest before freezing Angerona. Source
checkouts intentionally keep it empty and launch the Python recorder instead.
"""

BLACKBOX_SHA256 = ""
