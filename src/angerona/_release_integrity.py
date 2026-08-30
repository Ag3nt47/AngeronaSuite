"""Build-time integrity values for packaged release sidecars.

The release workflow replaces the empty digest before freezing Angerona. Source
checkouts intentionally keep it empty and launch the Python recorder instead.
"""

BLACKBOX_SHA256 = ""

# The external freeze watchdog is denied execution unless a release builder
# injects both values before freezing the main application. Source checkouts
# intentionally keep them empty and report the watchdog boundary as inactive.
FRZ_WATCHDOG_SHA256 = ""
FRZ_WATCHDOG_PUBLISHER = ""
