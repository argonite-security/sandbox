"""Windows: the game runs on the machine itself, without admin rights, with outbound traffic blocked by
the firewall. Windows' own auditing records what it started, which bait it opened and where it tried
to connect. A mod could still try to hide from this, so the site only counts what it finds."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from .bait import kind_of
from .common import download, log
from .session import Session
from .winproc import WinProc, image_name

SYS32 = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
MESA_URL = 'https://github.com/pal1000/mesa-dist-win/releases/download/26.2.4/mesa3d-26.2.4-release-msvc.7z'
MESA_SHA256 = '351fc8c8b695878ffb3eaa044b3ead08672a48b1a045e3c3e3975811df0f6695'
AUDIT = {
    '{0CCE922B-69AE-11D9-BED3-505054503030}': ['/success:enable'],  # process creation
    '{0CCE921D-69AE-11D9-BED3-505054503030}': ['/success:enable', '/failure:enable'],  # file system
    '{0CCE9226-69AE-11D9-BED3-505054503030}': ['/failure:enable'],  # filtering platform connection (blocked)
}
LOLBINS = ['powershell.exe', 'pwsh.exe', 'cmd.exe', 'curl.exe', 'bitsadmin.exe', 'certutil.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
           'wscript.exe', 'cscript.exe', 'ftp.exe', 'tftp.exe', 'msiexec.exe', 'ssh.exe', 'scp.exe', 'nslookup.exe', 'finger.exe']
EXPECTED = {'java.exe', 'javaw.exe', 'conhost.exe', 'werfault.exe'}
NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'


def ps(script: str, check: bool = True) -> str:
    out = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f'powershell: {out.stderr.strip()[:300]}')
    return out.stdout


def run(*cmd: str, check: bool = True) -> str:
    out = subprocess.run(list(cmd), capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f'{cmd[0]}: {(out.stderr or out.stdout).strip()[:300]}')
    return out.stdout


def events(log_name: str, ids: list[int], since: str) -> list[dict]:
    q = f"*[System[({' or '.join(f'EventID={i}' for i in ids)}) and TimeCreated[@SystemTime>='{since}']]]"
    text = run(str(SYS32 / 'wevtutil.exe'), 'qe', log_name, f'/q:{q}', '/f:xml', '/c:50000', check=False)
    out = []
    try:
        root = ET.fromstring(f'<Events>{text}</Events>')
    except ET.ParseError:
        return out
    for ev in root:
        sysn = ev.find(f'{NS}System')
        d = {'id': int(sysn.findtext(f'{NS}EventID') or 0)}
        ex = sysn.find(f'{NS}Execution')
        if ex is not None:
            d['_pid'] = int(ex.get('ProcessID') or 0)
        for data in ev.iter(f'{NS}Data'):
            d[data.get('Name')] = data.text or ''
        out.append(d)
    return out


def pid_of(v: str) -> int:
    try:
        return int(v, 16) if v.lower().startswith('0x') else int(v)
    except (ValueError, AttributeError):
        return -1


class WindowsSession(Session):
    os_key = 'windows'

    def __init__(self, run_info: dict, root: Path):
        super().__init__(run_info, root)
        self.home = Path(os.environ['USERPROFILE'])
        self.seen: dict[int, str] = {}
        self.wps: list[WinProc] = []

    def home_roots(self) -> list[Path]:
        roots = {b.path.parent for b in self.baits if b.path.is_absolute()}
        roots |= {self.home / 'AppData/Roaming/.minecraft', self.home / 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'}
        return sorted(roots)

    def client_java(self) -> str:
        """A copy of the JDK with Mesa's software OpenGL next to java.exe; the machine has no GPU."""
        jdk = Path(self.java).parent.parent
        copy = self.root / 'jdk-client'
        if not copy.exists():
            shutil.copytree(jdk, copy)
            archive = download(MESA_URL, self.cache / 'mesa.7z', sha256=MESA_SHA256)
            out = self.cache / 'mesa'
            seven = shutil.which('7z') or r'C:\Program Files\7-Zip\7z.exe'
            run(seven, 'x', '-y', f'-o{out}', str(archive), 'x64\\opengl32.dll', 'x64\\libgallium_wgl.dll', 'x64\\libglapi.dll', 'x64\\dxil.dll')
            for dll in (out / 'x64').glob('*.dll'):
                shutil.copy2(dll, copy / 'bin' / dll.name)
        return str(copy / 'bin' / 'java.exe')

    def env(self) -> dict[str, str]:
        keep = ('SystemRoot', 'SystemDrive', 'windir', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH', 'USERNAME', 'USERDOMAIN',
                'COMPUTERNAME', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'PUBLIC', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS', 'PATHEXT', 'ComSpec')
        e = {k: os.environ[k] for k in keep if k in os.environ}
        e['PATH'] = f'{SYS32};{SYS32.parent}'
        e['GALLIUM_DRIVER'] = 'llvmpipe'
        return e

    def isolate(self) -> None:
        self.since = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        for guid, flags in AUDIT.items():
            run(str(SYS32 / 'auditpol.exe'), '/set', f'/subcategory:{guid}', *flags)
        run(str(SYS32 / 'reg.exe'), 'add', r'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit', '/v', 'ProcessCreationIncludeCmdLine_Enabled', '/t', 'REG_DWORD', '/d', '1', '/f')
        run(str(SYS32 / 'wevtutil.exe'), 'sl', 'Security', '/ms:268435456')
        run(str(SYS32 / 'wevtutil.exe'), 'sl', 'Microsoft-Windows-DNS-Client/Operational', '/e:true', check=False)
        paths = [str(b.path) for b in self.baits if b.path.is_absolute() and b.path.exists()]
        ps("$r = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','ReadData,WriteData,AppendData,Delete','None','None','Success');"
           f"foreach ($p in (ConvertFrom-Json '{json.dumps(paths)}')) {{ $a = Get-Acl -LiteralPath $p -Audit; $a.AddAuditRule($r); Set-Acl -LiteralPath $p -AclObject $a }}")
        self.persist_before = self.persistence_state()
        # Outbound blocked for everything except the runner's own connection to GitHub.
        self.fw_before = ps('Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultOutboundAction | ConvertTo-Json -Compress')
        runner = [p for p in ps("(Get-Process -Name Runner.Listener,Runner.Worker,Runner.Server -ErrorAction SilentlyContinue).Path").splitlines() if p.strip()]
        rules = [f"New-NetFirewallRule -Group ArgoniteSandbox -DisplayName 'sandbox allow {i}' -Direction Outbound -Action Allow -Program '{p}' | Out-Null" for i, p in enumerate(runner)]
        blocked = [str(SYS32 / b) for b in LOLBINS] + [self.java, str(self.root / 'jdk-client' / 'bin' / 'java.exe'), str(self.root / 'jdk-client' / 'bin' / 'javaw.exe')]
        rules += [f"New-NetFirewallRule -Group ArgoniteSandbox -DisplayName 'sandbox block {i}' -Direction Outbound -Action Block -Program '{p}' | Out-Null" for i, p in enumerate(blocked)]
        rules.append('Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block')
        ps('; '.join(rules))
        self.watching = True
        threading.Thread(target=self.watch_jobs, daemon=True).start()
        log('firewall closed; runner allowed:', runner)

    def watch_jobs(self) -> None:
        while self.watching:
            for wp in self.wps:
                for pid in wp.pids():
                    if pid not in self.seen:
                        self.seen[pid] = image_name(pid) or '?'
            time.sleep(0.25)

    def start(self, name: str, cmd: list[str], cwd: Path, log_path: Path) -> object:
        try:
            wp = WinProc(cmd, str(cwd), self.env(), str(log_path))
        except OSError as e:
            self.notes.append(f'could not drop admin rights ({e}); ran with them')
            wp = WinProc(cmd, str(cwd), self.env(), str(log_path), restricted=False)
        self.wps.append(wp)
        self.seen[wp.pid] = cmd[0]
        return wp

    def alive(self, name: str) -> bool:
        p = self.procs.get(name)
        return isinstance(p, WinProc) and p.poll() is None

    def send(self, name: str, text: str) -> None:
        p = self.procs.get(name)
        if isinstance(p, WinProc):
            try:
                p.stdin.write(text.encode())
            except OSError:
                pass

    def stop_all(self) -> None:
        time.sleep(0.5)
        self.watching = False
        for wp in self.wps:
            wp.kill()

    def restore(self) -> None:
        try:
            before = json.loads(self.fw_before or '[]')
            ps('Remove-NetFirewallRule -Group ArgoniteSandbox -ErrorAction SilentlyContinue; '
               + '; '.join(f"Set-NetFirewallProfile -Name {p['Name']} -DefaultOutboundAction {'Block' if p['DefaultOutboundAction'] in (4, 'Block') else 'Allow'}" for p in before), check=False)
        except ValueError:
            ps('Remove-NetFirewallRule -Group ArgoniteSandbox -ErrorAction SilentlyContinue; Set-NetFirewallProfile -All -DefaultOutboundAction Allow', check=False)

    def persistence_state(self) -> dict[str, set[str]]:
        s: dict[str, set[str]] = {}
        for hive in ('HKCU', 'HKLM'):
            for key in ('Run', 'RunOnce'):
                path = rf'{hive}\Software\Microsoft\Windows\CurrentVersion\{key}'
                out = run(str(SYS32 / 'reg.exe'), 'query', path, check=False)
                s[path] = {l.strip() for l in out.splitlines() if 'REG_' in l}
        tasks = run(str(SYS32 / 'schtasks.exe'), '/query', '/fo', 'csv', '/nh', check=False)
        s['Scheduled task'] = {row[0] for row in csv.reader(io.StringIO(tasks)) if row}
        s['Service'] = set(ps('(Get-Service).Name', check=False).split())
        s['WMI subscription'] = set(ps("(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue).Name", check=False).split())
        return s

    def collect(self) -> None:
        super().collect()
        r = self.report
        after = self.persistence_state()
        for where, items in after.items():
            for item in sorted(items - self.persist_before.get(where, set()))[:10]:
                r['persistence'].append({'where': where, 'detail': item[:200]})

        sec = events('Security', [4688, 4663, 5157], self.since)
        tree = set(self.seen)
        grew = True
        while grew:
            grew = False
            for e in sec:
                if e['id'] == 4688 and pid_of(e.get('ProcessId', '')) in tree and pid_of(e.get('NewProcessId', '')) not in tree:
                    tree.add(pid_of(e['NewProcessId']))
                    grew = True
        seen_exe: set[str] = set()
        for e in sec:
            if e['id'] == 4688 and pid_of(e.get('NewProcessId', '')) in tree:
                exe = e.get('NewProcessName', '')
                base = exe.rsplit('\\', 1)[-1].lower()
                if base not in EXPECTED and exe not in seen_exe:
                    seen_exe.add(exe)
                    r['processes'].append({'exe': exe, 'args': (e.get('CommandLine') or '')[:300]})
        for pid, exe in self.seen.items():
            base = exe.rsplit('\\', 1)[-1].lower()
            if base not in EXPECTED and exe not in seen_exe and exe != '?' and pid not in (wp.pid for wp in self.wps):
                seen_exe.add(exe)
                r['processes'].append({'exe': exe, 'args': ''})
        for e in sec:
            if e['id'] != 4663 or pid_of(e.get('ProcessId', '')) not in tree:
                continue
            kind = kind_of(e.get('ObjectName', ''), self.baits)
            if not kind:
                continue
            mask = pid_of(e.get('AccessMask', '0'))
            op = 'delete' if mask & 0x10000 else 'write' if mask & 0x6 else 'read'
            r['bait'].append({'bait': kind, 'path': self.show(e['ObjectName']), 'op': op, 'exe': e.get('ProcessName')})

        names: dict[str, str] = {}
        dns: set[str] = set()
        for e in events('Microsoft-Windows-DNS-Client/Operational', [3008], self.since):
            if e.get('_pid') in tree and e.get('QueryName'):
                name = e['QueryName'].lower().rstrip('.')
                dns.add(name)
                for ip in re.findall(r'[0-9a-f.:]{7,}', (e.get('QueryResults') or '').lower()):
                    names[ip.removeprefix('::ffff:')] = name
        r['dns'] = sorted(dns)
        conns = {}
        for e in sec:
            if e['id'] == 5157 and pid_of(e.get('ProcessID', '')) in tree and e.get('Direction', '') in ('%%14593', 'Outbound'):
                ip, port = e.get('DestAddress', ''), int(e.get('DestPort') or 0)
                if ip.startswith('127.') or ip == '::1':
                    continue
                proto = 'udp' if e.get('Protocol') == '17' else 'tcp'
                conns[(ip, port, proto)] = {'ip': ip, 'port': port, 'proto': proto, 'host': names.get(ip), 'sni': None, 'http': None}
        r['connections'] = list(conns.values())[:300]
