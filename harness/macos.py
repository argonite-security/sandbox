"""macOS: the server runs as a separate user whose outbound traffic the packet filter blocks and logs.
The game client needs the logged-in desktop, which a separate user doesn't have, so it isn't run
here. As on Windows, the site only counts what this finds, never its absence."""
from __future__ import annotations

import re
import secrets
import shutil
import subprocess
import threading
import time
from pathlib import Path

from .bait import kind_of
from .common import log
from .session import Session

USER = 'argonite'
ANCHOR = 'com.apple/250.ArgoniteSandbox'
EXPECTED = {'java'}


def sh(*cmd: str, check: bool = True) -> str:
    out = subprocess.run(list(cmd), capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f'{" ".join(cmd[:3])}: {(out.stderr or out.stdout).strip()[:300]}')
    return out.stdout


class MacSession(Session):
    os_key = 'macos'
    client_supported = False

    def __init__(self, run_info: dict, root: Path):
        super().__init__(run_info, root)
        if not sh('id', '-u', USER, check=False).strip():
            sh('sysadminctl', '-addUser', USER, '-fullName', 'Player', '-password', secrets.token_urlsafe(24), '-home', f'/Users/{USER}')
            sh('createhomedir', '-c', '-u', USER, check=False)
        self.home = Path(f'/Users/{USER}')
        self.home.mkdir(exist_ok=True)
        self.uid = sh('id', '-u', USER).strip()
        self.users_procs: dict[str, str] = {}

    def isolate(self) -> None:
        # The tested user can't read the runner's home, so the server gets its own copy of Java.
        jdk = Path(self.java).parent.parent
        copy = self.root / 'jdk'
        if not copy.exists():
            shutil.copytree(jdk, copy, symlinks=True)
        self.server_cmd = [str(copy / 'bin' / 'java'), *self.server_cmd[1:]]
        sh('chown', '-R', f'{USER}:staff', str(self.root), str(self.home))
        sh('chmod', 'o+x', str(self.root.parent))
        rules = self.root / 'pf.conf'
        rules.write_text(
            'pass out quick on lo0 all\n'
            f'block return out log quick inet proto {{ tcp udp }} user {USER}\n'
            f'block return out log quick inet6 proto {{ tcp udp }} user {USER}\n'
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
        self.cron_before = sh('crontab', '-l', '-u', USER, check=False)
        self.watching = True
        threading.Thread(target=self.watch_procs, daemon=True).start()
        time.sleep(1)
        log('packet filter closed for', USER)

    def watch_procs(self) -> None:
        while self.watching:
            out = sh('ps', '-axo', 'pid=,user=,comm=,args=', check=False)
            for line in out.splitlines():
                parts = line.split(None, 3)
                if len(parts) >= 3 and parts[1] == USER and parts[0] not in self.users_procs:
                    self.users_procs[parts[0]] = parts[2] + '\t' + (parts[3] if len(parts) > 3 else '')
            time.sleep(0.25)

    def start(self, name: str, cmd: list[str], cwd: Path, log_path: Path) -> object:
        out = open(log_path, 'wb')
        env = ['env', '-i', f'HOME={self.home}', f'USER={USER}', 'PATH=/usr/bin:/bin:/usr/sbin:/sbin', 'LANG=en_US.UTF-8']
        return subprocess.Popen(['sudo', '-u', USER, '-H', *env, *cmd], cwd=cwd, stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT)

    def stop_all(self) -> None:
        sh('pkill', '-KILL', '-u', USER, check=False)
        self.watching = False
        for p in self.procs.values():
            if isinstance(p, subprocess.Popen):
                try:
                    p.wait(20)
                except subprocess.TimeoutExpired:
                    p.kill()

    def restore(self) -> None:
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
        names = {cmd.split('\t')[0].rsplit('/', 1)[-1] for cmd in self.users_procs.values()}
        for pid, info in self.users_procs.items():
            comm, _, args = info.partition('\t')
            if comm.rsplit('/', 1)[-1] not in EXPECTED and comm not in ('sudo', 'env'):
                r['processes'].append({'exe': comm, 'args': args[:300]})
        cron = sh('crontab', '-l', '-u', USER, check=False)
        if cron.strip() and cron != self.cron_before:
            r['persistence'].append({'where': 'crontab', 'detail': cron.strip()[:200]})
        # fs_usage: "time  open  F=5  (R_____)  /Users/argonite/.ssh/id_ed25519  0.000012  java.123456"
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
        # DNS answers, to put names on the blocked connections.
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
