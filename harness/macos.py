"""macOS: the server and the game client run as the machine's logged-in user, inside its desktop session
(the client needs one), but in a group of their own whose outbound traffic the packet filter blocks and
logs. The user's passwordless sudo is switched off for the test so the code under test can't lift the
block. As on Windows, the site only counts what this finds, never its absence."""
from __future__ import annotations

import os
import pwd
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from .bait import kind_of
from .common import log
from .games import mc_tuple
from .session import Session

GROUP = 'argonite-net'
ANCHOR = 'com.apple/250.ArgoniteSandbox'
SUDO_LOCK = Path('/etc/sudoers.d/zz-argonite-sandbox')
EXPECTED = {'java'}
DROP = Path(__file__).with_name('drop.py')


def sh(*cmd: str, check: bool = True) -> str:
    out = subprocess.run(list(cmd), capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f'{" ".join(cmd[:3])}: {(out.stderr or out.stdout).strip()[:300]}')
    return out.stdout


class MacSession(Session):
    os_key = 'macos'
    real_home = True

    def __init__(self, run_info: dict, root: Path):
        super().__init__(run_info, root)
        self.user = os.environ.get('SUDO_USER') or 'runner'
        pw = pwd.getpwnam(self.user)
        self.uid = pw.pw_uid
        self.home = Path(pw.pw_dir)
        if not sh('dscl', '.', '-read', f'/Groups/{GROUP}', 'PrimaryGroupID', check=False).strip():
            sh('dseditgroup', '-o', 'create', '-r', 'Argonite sandbox', GROUP)
        self.gid = int(sh('dscl', '.', '-read', f'/Groups/{GROUP}', 'PrimaryGroupID').split()[-1])
        self.seen: dict[str, str] = {}

    def client_unsupported(self, mc: str) -> str | None:
        # Before 1.19 the game only ships Intel libraries for macOS, and these machines are Apple Silicon.
        t = mc_tuple(mc)
        return 'older game versions have no Apple Silicon client' if t and t < (1, 19, 0) else None

    def home_roots(self) -> list[Path]:
        roots = {b.path.parent for b in self.baits if b.path.is_absolute()}
        roots |= {self.home / 'Library/Application Support/minecraft', self.home / 'Library/LaunchAgents'}
        return sorted(roots)

    def isolate(self) -> None:
        sh('chown', '-R', f'{self.user}:staff', str(self.root))
        for b in self.baits:
            p = b.path
            while p.is_absolute() and p != self.home and p.exists() and p.stat().st_uid == 0:
                os.chown(p, self.uid, 20)
                p = p.parent
        SUDO_LOCK.write_text(f'{self.user} ALL=(ALL) !ALL\n')
        os.chmod(SUDO_LOCK, 0o440)
        if subprocess.run(['visudo', '-cf', str(SUDO_LOCK)], capture_output=True).returncode != 0:
            SUDO_LOCK.unlink()
            raise RuntimeError('could not switch off sudo for the test')
        rules = self.root / 'pf.conf'
        rules.write_text(
            'pass out quick on lo0 all\n'
            f'block return out log quick inet proto {{ tcp udp }} group {GROUP}\n'
            f'block return out log quick inet6 proto {{ tcp udp }} group {GROUP}\n'
        )
        sh('pfctl', '-a', ANCHOR, '-f', str(rules))
        out = subprocess.run(['pfctl', '-E'], capture_output=True, text=True)
        m = re.search(r'Token : (\d+)', out.stdout + out.stderr)
        self.pf_token = m.group(1) if m else None
        sh('ifconfig', 'pflog0', 'create', check=False)
        self.pflog = open(self.root / 'pflog.txt', 'w')
        self.pfdump = subprocess.Popen(['tcpdump', '-n', '-l', '-tt', '-i', 'pflog0'], stdout=self.pflog, stderr=subprocess.DEVNULL)
        iface = re.search(r'interface: (\S+)', sh('route', '-n', 'get', 'default', check=False))
        self.dnslog = open(self.root / 'dns.txt', 'w')
        self.dnsdump = subprocess.Popen(['tcpdump', '-n', '-l', '-i', iface.group(1) if iface else 'en0', 'udp port 53'], stdout=self.dnslog, stderr=subprocess.DEVNULL)
        self.fslog = open(self.root / 'fs.txt', 'w')
        self.fsusage = subprocess.Popen(['fs_usage', '-w', '-f', 'pathname'], stdout=self.fslog, stderr=subprocess.DEVNULL)
        self.cron_before = sh('crontab', '-l', '-u', self.user, check=False)
        self.watching = True
        threading.Thread(target=self.watch_procs, daemon=True).start()
        time.sleep(1)
        log('packet filter closed for group', GROUP)

    def ours(self) -> list[tuple[str, str, str]]:
        """(pid, command, args) of every process in the test's group."""
        rows = []
        for line in sh('ps', '-axo', 'pid=,rgid=,gid=,comm=,args=', check=False).splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4 and (parts[1] == str(self.gid) or parts[2] == str(self.gid)):
                rows.append((parts[0], parts[3], parts[4] if len(parts) > 4 else ''))
        return rows

    def watch_procs(self) -> None:
        while self.watching:
            for pid, comm, args in self.ours():
                self.seen.setdefault(pid, f'{comm}\t{args}')
            time.sleep(0.25)

    def start(self, name: str, cmd: list[str], cwd: Path, log_path: Path) -> object:
        out = open(log_path, 'wb')
        env = {'HOME': str(self.home), 'USER': self.user, 'LOGNAME': self.user, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8', 'TMPDIR': f'/tmp/{self.user}-sbx/'}
        os.makedirs(env['TMPDIR'], exist_ok=True)
        os.chown(env['TMPDIR'], self.uid, self.gid)
        launcher = ['launchctl', 'asuser', str(self.uid), sys.executable, '-I', str(DROP), str(self.uid), str(self.gid), str(cwd), '--', *cmd]
        return subprocess.Popen(launcher, env=env, stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT)

    def stop_all(self) -> None:
        for _ in range(3):
            for pid, _, _ in self.ours():
                subprocess.run(['kill', '-KILL', pid], capture_output=True)
            time.sleep(0.5)
        self.watching = False
        for p in self.procs.values():
            if isinstance(p, subprocess.Popen):
                try:
                    p.wait(20)
                except subprocess.TimeoutExpired:
                    p.kill()

    def restore(self) -> None:
        SUDO_LOCK.unlink(missing_ok=True)
        for proc in (self.fsusage, self.pfdump, self.dnsdump):
            proc.terminate()
        for f in (self.fslog, self.pflog, self.dnslog):
            f.close()
        sh('pfctl', '-a', ANCHOR, '-F', 'all', check=False)
        if self.pf_token:
            sh('pfctl', '-X', self.pf_token, check=False)

    def collect(self) -> None:
        super().collect()
        r = self.report
        names = {info.split('\t')[0].rsplit('/', 1)[-1] for info in self.seen.values()}
        shown: set[str] = set()
        for info in self.seen.values():
            comm, _, args = info.partition('\t')
            base = comm.rsplit('/', 1)[-1]
            if base not in EXPECTED and base not in ('python3', 'python', 'launchctl') and comm not in shown:
                shown.add(comm)
                r['processes'].append({'exe': comm, 'args': args[:300]})
        cron = sh('crontab', '-l', '-u', self.user, check=False)
        if cron.strip() and cron != self.cron_before:
            r['persistence'].append({'where': 'crontab', 'detail': cron.strip()[:200]})
        # fs_usage: "time  open  F=5  (R_____)  /Users/runner/.ssh/id_ed25519  0.000012  java.123456"
        for line in (self.root / 'fs.txt').read_text('utf-8', 'replace').splitlines():
            if str(self.home) not in line:
                continue
            proc = line.rsplit(None, 1)[-1].rsplit('.', 1)[0] if line.split() else ''
            if proc not in names:
                continue
            m = re.search(r'(/Users/\S.*?)\s+\d+\.\d+', line)
            path = m.group(1) if m else ''
            kind = kind_of(path, self.baits)
            if not kind:
                continue
            call = line.split()[1] if len(line.split()) > 1 else ''
            op = 'delete' if call in ('unlink', 'rename', 'unlinkat', 'renameat') else 'write' if re.search(r'\(_W|\(RW', line) else 'read'
            r['bait'].append({'bait': kind, 'path': self.show(path), 'op': op, 'exe': proc})
        queries, ips = {}, {}
        for line in (self.root / 'dns.txt').read_text('utf-8', 'replace').splitlines():
            q = re.search(r': (\d+)\+? [A-Z]+\? (\S+?)\.? \(', line)
            if q:
                queries[q.group(1)] = q.group(2).lower()
                continue
            a = re.search(r': (\d+)[\*\-|$]* \d+/\d+/\d+ (.*)', line)
            if a and a.group(1) in queries:
                for ip in re.findall(r'\bA{1,4} ([0-9a-f.:]+)', a.group(2)):
                    ips[ip.rstrip(',')] = queries[a.group(1)]
        conns = {}
        for line in (self.root / 'pflog.txt').read_text('utf-8', 'replace').splitlines():
            m = re.search(r'IP6? \S+?\.(\d+) > (\S+)\.(\d+): (UDP|Flags|\w+)', line)
            if m:
                ip, port = m.group(2), int(m.group(3))
                proto = 'udp' if m.group(4) == 'UDP' else 'tcp'
                conns[(ip, port, proto)] = {'ip': ip, 'port': port, 'proto': proto, 'host': ips.get(ip), 'sni': None, 'http': None}
        r['connections'] = list(conns.values())[:300]
        r['dns'] = sorted({c['host'] for c in conns.values() if c['host']})
