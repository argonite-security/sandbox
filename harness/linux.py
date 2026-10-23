"""Linux: the game runs in a container with no route out. Its only network is a virtual cable to the
host, where the fake internet answers. Everything is watched from the host (kernel audit, packet
capture, file hashes), so the code under test can't hide from or tamper with the watchers."""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from .bait import find_leaks, kind_of
from .common import log
from .session import Session
from .sinkhole import Sinkhole

IMAGE = 'argonite-sandbox'
NAME = 'argonite-sbx'
UID = 10001
HOST_IP, GUEST_IP = '10.213.0.1', '10.213.0.2'
VETH_HOST, VETH_GUEST = 'sbxh', 'sbxg'
GUEST_HOME = '/home/player'
AUDIT_LOG = Path('/var/log/audit/audit.log')
# Programs the game, the X server and system-info libraries run on their own.
EXPECTED_EXEC = {'java', 'xvfb', 'xkbcomp', 'sleep', 'jspawnhelper', 'xrandr', 'getconf', 'uname', 'lsb_release', 'lspci', 'lshw', 'dmidecode', 'udevadm', 'nproc', 'glxinfo'}
DELETE_SYSCALLS = {'87', '263', '82', '264', '316'}  # unlink, unlinkat, rename, renameat, renameat2 (x86_64)
FIELD = re.compile(r'(\w+)=("([^"]*)"|(\S+))')


def sh(*cmd: str, check: bool = True) -> str:
    out = subprocess.run(list(cmd), capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f'{" ".join(cmd[:4])}: {out.stderr.strip()[:300]}')
    return out.stdout


def _decode(v: str | None, quoted: str | None) -> str:
    if quoted is not None:
        return quoted
    v = v or ''
    if re.fullmatch(r'(?:[0-9A-F]{2})+', v):
        try:
            return bytes.fromhex(v).decode('utf-8', 'replace').replace('\x00', ' ')
        except ValueError:
            return v
    return v


def parse_audit(text: str, since: float) -> dict[str, list[dict]]:
    """Audit records grouped by event serial, keeping only events after `since`."""
    events: dict[str, list[dict]] = {}
    for line in text.splitlines():
        m = re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\):(.*)', line)
        if not m or float(m.group(2)) < since:
            continue
        rec = {'type': m.group(1)}
        for f in FIELD.finditer(m.group(4)):
            rec.setdefault(f.group(1), _decode(f.group(4), f.group(3)))
        events.setdefault(m.group(3), []).append(rec)
    return events


def bait_op(sc: dict, path_rec: dict) -> str:
    """read, write or delete, from the audited syscall and its open flags."""
    num = sc.get('syscall', '')
    if num in DELETE_SYSCALLS or path_rec.get('nametype') == 'DELETE':
        return 'delete'
    raw = sc.get('a2' if num == '257' else 'a1' if num == '2' else '', '')
    if num in ('257', '2') and re.fullmatch(r'[0-9a-f]+', raw):
        return 'write' if int(raw, 16) & 3 else 'read'
    return 'write'


class LinuxSession(Session):
    os_key = 'linux'

    def isolate(self) -> None:
        sh('chown', '-R', f'{UID}:{UID}', str(self.work), str(self.home))
        resolv = self.root / 'resolv.conf'
        resolv.write_text(f'nameserver {HOST_IP}\noptions timeout:2 attempts:1\n')
        sh('docker', 'rm', '-f', NAME, check=False)
        sh(
            'docker', 'run', '-d', '--name', NAME, '--hostname', 'desktop-7f3k2', '--network', 'none',
            '--user', f'{UID}:{UID}', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '2048',
            '--memory', '9g', '--cpus', '3.5', '--shm-size', '512m',
            '-v', f'{self.work}:{self.work}', '-v', f'{self.home}:{GUEST_HOME}', '-v', f'{resolv}:/etc/resolv.conf:ro',
            '-v', '/opt/hostedtoolcache:/opt/hostedtoolcache:ro',
            '-e', f'HOME={GUEST_HOME}', '-e', 'USER=player', '-e', 'DISPLAY=:99', '-e', 'XDG_CACHE_HOME=/tmp/cache',
            '-e', 'MESA_SHADER_CACHE_DISABLE=true', '-e', 'LIBGL_ALWAYS_SOFTWARE=1', '-e', 'GALLIUM_DRIVER=llvmpipe', '-e', 'TZ=UTC',
            IMAGE, 'sleep', 'infinity',
        )
        pid = sh('docker', 'inspect', '-f', '{{.State.Pid}}', NAME).strip()
        sh('ip', 'link', 'add', VETH_HOST, 'type', 'veth', 'peer', 'name', VETH_GUEST)
        sh('ip', 'link', 'set', VETH_GUEST, 'netns', pid)
        sh('ip', 'addr', 'add', f'{HOST_IP}/24', 'dev', VETH_HOST)
        sh('ip', 'link', 'set', VETH_HOST, 'up')
        sh('sysctl', '-qw', f'net.ipv6.conf.{VETH_HOST}.disable_ipv6=1')
        ns = ['nsenter', '-t', pid, '-n']
        sh(*ns, 'sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1')
        sh(*ns, 'ip', 'addr', 'add', f'{GUEST_IP}/24', 'dev', VETH_GUEST)
        sh(*ns, 'ip', 'link', 'set', VETH_GUEST, 'up')
        sh(*ns, 'ip', 'link', 'set', 'lo', 'up')
        sh(*ns, 'ip', 'route', 'add', 'default', 'via', HOST_IP)
        # Nothing from the cable is forwarded; DNS and TCP land on the fake internet, the rest is dropped (and captured).
        self.rules = [
            ['-t', 'nat', '-I', 'PREROUTING', '1', '-i', VETH_HOST, '-p', 'udp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', '5353'],
            ['-t', 'nat', '-I', 'PREROUTING', '1', '-i', VETH_HOST, '-p', 'tcp', '-j', 'REDIRECT', '--to-ports', '9999'],
            ['-I', 'FORWARD', '1', '-i', VETH_HOST, '-j', 'DROP'],
            ['-I', 'FORWARD', '1', '-o', VETH_HOST, '-j', 'DROP'],
            ['-I', 'INPUT', '1', '-i', VETH_HOST, '-j', 'DROP'],
            ['-I', 'INPUT', '1', '-i', VETH_HOST, '-p', 'tcp', '--dport', '9999', '-j', 'ACCEPT'],
            ['-I', 'INPUT', '1', '-i', VETH_HOST, '-p', 'udp', '--dport', '5353', '-j', 'ACCEPT'],
        ]
        for r in self.rules:
            sh('iptables', *r)
        self.sink = Sinkhole(HOST_IP)
        self.sink.start()
        self.pcap_log = open(self.root / 'packets.txt', 'w')
        self.tcpdump = subprocess.Popen(['tcpdump', '-i', VETH_HOST, '-n', '-l', '-tt', '-q', 'not tcp and not (udp and dst port 53) and not arp'], stdout=self.pcap_log, stderr=subprocess.DEVNULL)

        self.audit_since = time.time() - 1
        sh('auditctl', '-D', check=False)
        sh('auditctl', '-b', '16384')
        sh('auditctl', '-a', 'always,exit', '-F', 'arch=b64', '-S', 'execve,execveat', '-F', f'uid={UID}', '-k', 'sbx_exec')
        sh('auditctl', '-a', 'always,exit', '-F', 'arch=b32', '-S', 'execve', '-F', f'uid={UID}', '-k', 'sbx_exec')
        for b in self.baits:
            if b.path.exists():
                sh('auditctl', '-w', str(b.path), '-p', 'rwa', '-k', 'sbx_bait')
        sh('auditctl', '-e', '1')
        sh('docker', 'exec', '-d', '-u', str(UID), NAME, 'Xvfb', ':99', '-screen', '0', '1280x720x24', '-nolisten', 'tcp')
        time.sleep(2)
        log('container isolated, pid', pid)

    def start(self, name: str, cmd: list[str], cwd: Path, log_path: Path) -> object:
        out = open(log_path, 'wb')
        return subprocess.Popen(['docker', 'exec', '-i', '-u', str(UID), '-w', str(cwd), NAME, *cmd], stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT)

    def stop_all(self) -> None:
        self.diff = sh('docker', 'diff', NAME, check=False)
        sh('docker', 'kill', NAME, check=False)
        for p in self.procs.values():
            if isinstance(p, subprocess.Popen):
                try:
                    p.wait(20)
                except subprocess.TimeoutExpired:
                    p.kill()

    def restore(self) -> None:
        sh('auditctl', '-D', check=False)
        time.sleep(1)
        self.tcpdump.terminate()
        self.pcap_log.close()
        self.sink.stop()
        for r in self.rules:
            sh('iptables', *[('-D' if x == '-I' else x) for x in r if x != '1'], check=False)
        sh('ip', 'link', 'del', VETH_HOST, check=False)

    def collect(self) -> None:
        super().collect()
        r = self.report
        guest_home = GUEST_HOME + '/'
        events = parse_audit(AUDIT_LOG.read_text('utf-8', 'replace') if AUDIT_LOG.exists() else '', self.audit_since)
        seen_exec: set[str] = set()
        for recs in events.values():
            sc = next((x for x in recs if x['type'] == 'SYSCALL'), None)
            if not sc:
                continue
            key = sc.get('key', '')
            if key == 'sbx_exec':
                ex = next((x for x in recs if x['type'] == 'EXECVE'), {})
                argc = int(ex.get('argc', '0') or 0)
                args = ' '.join(ex.get(f'a{i}', '') for i in range(min(argc, 20)))
                exe = sc.get('exe', '') or args.split(' ')[0]
                base = exe.rsplit('/', 1)[-1].lower()
                if base in EXPECTED_EXEC or exe in seen_exec:
                    continue
                seen_exec.add(exe)
                r['processes'].append({'exe': exe + ('' if sc.get('success') == 'yes' else ' (failed to start)'), 'args': args[:300]})
            elif key == 'sbx_bait':
                for p in (x for x in recs if x['type'] == 'PATH' and x.get('nametype') in ('NORMAL', 'DELETE', 'CREATE')):
                    name = p.get('name', '')
                    host_path = str(self.home) + '/' + name[len(guest_home):] if name.startswith(guest_home) else name
                    kind = kind_of(host_path, self.baits)
                    if not kind:
                        continue
                    op = bait_op(sc, p)
                    r['bait'].append({'bait': kind, 'path': self.show(host_path), 'op': op, 'exe': sc.get('exe')})
        # Files the container changed outside its two mounted folders.
        for line in getattr(self, 'diff', '').splitlines():
            kind, _, path = line.partition(' ')
            if kind not in ('A', 'C') or re.match(r'^/(tmp|var/tmp|dev|run|proc|sys)(/|$)', path):
                continue
            if re.match(r'^/(etc/(cron|profile\.d|systemd|init\.d|xdg/autostart|ld\.so)|var/spool/cron|usr/lib/systemd|lib/systemd)', path):
                r['persistence'].append({'where': path, 'detail': 'system file'})
            elif not re.match(r'^/(etc|home|root)?$', path):
                r['writtenOutside'].append(path)
        # The fake internet's notes.
        r['dns'] = sorted({n for _, n in self.sink.queries})
        conns = {(c['ip'], c['port'], c['proto'], c['sni'], c['http'], c['host']): c for c in self.sink.connections}
        try:
            for line in (self.root / 'packets.txt').read_text().splitlines():
                m = re.search(r'IP (\S+)\.(\d+) > (\S+)\.(\d+): (UDP|udp)', line)
                if m and m.group(1) == GUEST_IP:
                    conns[(m.group(3), int(m.group(4)), 'udp', None, None, None)] = {'ip': m.group(3), 'port': int(m.group(4)), 'proto': 'udp', 'sni': None, 'http': None, 'host': None}
        except OSError:
            pass
        r['connections'] = list(conns.values())[:300]
        leaks: dict[str, str] = {}
        for where, data in self.sink.payloads:
            for kind in find_leaks(data, self.baits):
                leaks.setdefault(kind, where)
        r['leaks'] = [{'bait': k, 'where': w} for k, w in leaks.items()]
