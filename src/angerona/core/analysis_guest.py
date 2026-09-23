"""Trusted offline guest entry point. Input files are never imported or executed."""

INIT = b"""#!/bin/sh
export PATH=/usr/bin:/bin:/sbin:/usr/sbin
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
exec </dev/ttyS0 >/dev/ttyS0 2>&1
/bin/busybox chmod 1777 /tmp
/usr/bin/python3 -I /opt/runner.py
/bin/busybox poweroff -f
"""

SOURCE = r'''
import json
import os
import pathlib
import re
import resource
import select
import subprocess
import termios
import tty

def main():
    job = json.loads(pathlib.Path('/job.json').read_text())
    # These checks supplement the host's fixed device configuration.
    net = sorted(os.listdir('/sys/class/net'))
    blocks = sorted(os.listdir('/sys/block'))
    mounts = pathlib.Path('/proc/mounts').read_text().splitlines()
    if (net != ['lo'] or blocks not in ([], ['sr0'])
            or (blocks and pathlib.Path('/sys/block/sr0/ro').read_text().strip() != '1')
            or any(line.split()[2] not in {
        'rootfs', 'proc', 'sysfs', 'devtmpfs'
    } for line in mounts)):
        raise ValueError('Unexpected guest device or mount')
    # Configure input before READY, then accept only one host control byte.
    # QEMU's Windows stdio backend can discard a burst when the UART is full.
    # Job identity is bound by READY/report and the exclusive host-owned pipe.
    with open('/dev/ttyS0', 'rb', buffering=0) as serial:
        tty.setcbreak(serial.fileno(), termios.TCSAFLUSH)
        print('ANGERONA_READY:' + job['job'], flush=True)
        if not select.select([serial], [], [], 45)[0]:
            raise ValueError('Host supervision not established')
        if os.read(serial.fileno(), 1) != b'G':
            raise ValueError('Unexpected host acknowledgement')
    tool = job['tool']
    if tool == 'bandit':
        command = ['/usr/bin/python3', '-I', '-m', 'bandit', '-r', '/input',
                   '--ini', '/opt/empty.ini', '-c', '/opt/bandit.yaml',
                   '--ignore-nosec', '-f', 'json', '-q']
    elif tool == 'gitleaks':
        command = ['/opt/gitleaks', 'dir', '/input', '--config', '/opt/gitleaks.toml',
                   '--gitleaks-ignore-path', '/opt/empty.ini', '--ignore-gitleaks-allow',
                   '--redact=100', '--no-banner', '--log-level', 'fatal',
                   '--report-format', 'json', '--report-path', '/tmp/results.json',
                   '--max-archive-depth', '0', '--max-decode-depth', '0']
    else:
        raise ValueError('Unknown adapter')
    # Limit files and child memory inside the already bounded RAM-only guest.
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**2, 4 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'TMPDIR': '/tmp',
           'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'GOMAXPROCS': '1'}
    with open('/tmp/stdout', 'wb') as out, open('/tmp/stderr', 'wb') as err:
        result = subprocess.run(command, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                cwd='/tmp', env=env, user=65534, group=65534,
                                extra_groups=[], timeout=240)
    if result.returncode not in (0, 1):
        raise ValueError('Analyzer did not complete')
    raw = pathlib.Path('/tmp/stdout' if tool == 'bandit' else '/tmp/results.json').read_bytes()
    parsed = json.loads(raw or b'[]')
    findings, errors = [], 0
    if tool == 'bandit':
        rows = parsed['results']
        errors = len(parsed['errors'])
    else:
        rows = parsed
    if len(rows) > 2000:
        raise ValueError('Too many findings')
    allowed = set(job['files'])
    for row in rows:
        name = row['filename' if tool == 'bandit' else 'File']
        if not name.startswith('/input/') or name[len('/input/'):] not in allowed:
            raise ValueError('Unexpected result file')
        rule = row['test_id' if tool == 'bandit' else 'RuleID']
        if not isinstance(rule, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', rule):
            raise ValueError('Unexpected rule')
        line = row['line_number' if tool == 'bandit' else 'StartLine']
        severity = row['issue_severity'] if tool == 'bandit' else 'HIGH'
        if severity not in ('LOW', 'MEDIUM', 'HIGH') or type(line) is not int or not 1 <= line <= 1000000:
            raise ValueError('Unexpected finding metadata')
        # Deliberately omit code, matches, secret values, tool messages and fingerprints.
        findings.append({'file': name[len('/input/'):], 'rule': rule,
                         'line': line, 'severity': severity})
    report = {'schema': 1, 'job': job['job'], 'tool': tool, 'input_sha256': job['input_sha256'],
              'catalog_sha256': job['catalog_sha256'], 'findings': findings, 'errors': errors,
              'isolation': {'network': net, 'block_devices': blocks, 'host_shares': False}}
    print('ANGERONA_REPORT:' + json.dumps(report, separators=(',', ':')), flush=True)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Raw exceptions/output could include input secrets; never export them.
        print('ANGERONA_ANALYZER_FAILED', flush=True)
'''
