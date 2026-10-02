"""Cold capture startup with real Scapy decoding and no aggregate imports."""
from pathlib import Path
import subprocess
import sys

import pytest

from angerona.core.privilege import sanitized_child_environment


_CHILD = r'''
import builtins
import sys
from angerona.modules.arp_watchdog import ARPWatchdogModule

original_import = builtins.__import__
def bounded_import(name, *args, **kwargs):
    if name in {'scapy.all', 'scapy.layers.all'}:
        raise AssertionError('ARP capture attempted an aggregate protocol import')
    return original_import(name, *args, **kwargs)
builtins.__import__ = bounded_import

from scapy import sendrecv
from scapy.layers.l2 import ARP, Ether
captures = []
class Capture:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.running = False
        captures.append(self)
    def start(self):
        self.running = True
    def stop(self, join=True):
        self.running = False
    def join(self, timeout=None):
        pass
sendrecv.AsyncSniffer = Capture  # Never open a capture socket in this probe.

module = ARPWatchdogModule()
events = []
module.emit = lambda *args, **kwargs: events.append(kwargs)
module._set_coverage_health = lambda: None
module._try_start_scapy()
assert module._scapy_ok and len(captures) == 1, events
assert captures[0].kwargs['filter'] == 'arp'
assert captures[0].kwargs['store'] is False
wire = bytes(Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=2, psrc='192.0.2.1', pdst='192.0.2.2',
                 hwsrc='00:11:22:33:44:55', hwdst='00:00:00:00:00:00'))
decoded = Ether(wire)
assert decoded.getlayer('ARP').op == 2
captures[0].kwargs['prn'](decoded)
assert module._candidate == {'192.0.2.1': '00-11-22-33-44-55'}
assert not module._baseline  # Received traffic is not implicit trust.
assert events[-1]['realtime'] is True
assert not any(name == 'scapy.all' or name.startswith('scapy.layers.tls')
               for name in sys.modules)
module.stop()
assert not captures[0].running
print('Cold ARP decoding, candidate provenance and capture shutdown passed')
'''


def test_cold_arp_capture_decodes_frames_without_aggregate_imports(tmp_path):
    pytest.importorskip("scapy")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    environment = sanitized_child_environment(source={})
    environment.update(ANGERONA_DATA=str(tmp_path / "runtime"),
                       TEMP=str(temporary), TMP=str(temporary), QT_QPA_PLATFORM="offscreen")
    result = subprocess.run(
        [sys.executable, "-c", _CHILD], cwd=Path(__file__).resolve().parents[1],
        env=environment, capture_output=True, text=True, timeout=90,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "candidate provenance and capture shutdown passed" in result.stdout
