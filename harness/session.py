"""The test itself, shared by every OS: get the file, install the game around it, plant bait, run the
server and a client that joins it, wait, stop, and report. Each OS supplies the isolation and the
watchers by overriding the hooks at the bottom."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import api
from .bait import Bait, plant
from .common import Unsupported, added, changed, download, empty_report, file_hash, jar_hosts, jar_meta, log, snapshot, tail, wait_for
from .games import Plan, plan as make_plan
from .install import gather_dependencies, install_curseforge, install_pack, install_server
from .launcher import client_command, install_client

SERVER_START_S = 900
CLIENT_JOIN_S = 900
# How long to keep watching once the game is up: three times as long as this file took to boot into a
# world (slow-starting packs get longer), but at least 5 and at most 20 minutes.
DWELL_FACTOR = 3
DWELL_MIN_S = 300
DWELL_MAX_S = 1200
STOP_S = 60
DONE = re.compile(r'Done \(\d|Done!|Done in \d')
JOINED = re.compile(r'joined the game|logged in with entity id')
CRASHED = re.compile(r'#@!@# Game crashed|Exception in server tick loop|This crash report has been saved to|Incompatible mods? (found|set)|Failed to start the minecraft server|Encountered an unexpected exception|Mod loading has failed|Loading errors encountered')


def loaded(text: str, meta: dict) -> bool:
    """Whether the loader's own list of loaded mods or plugins names the file."""
    for mod_id in meta['ids']:
        e = re.escape(mod_id)
        # Fabric/Quilt list "- modid 1.2.3" under "Loading N mods:"; Forge/NeoForge name it in their mod-file and container lines.
        listed = rf'(?i)mods \[(?:[^\]\n]*, )?{e}(?:, [^\]\n]*)?\]'  # old FML: "missing mods [mcp, FML, Forge, examplemod]"
        if re.search(rf'(?m)^\s*[|\\ ]*-\s+{e}\s', text) or re.search(listed, text) or re.search(rf'(?i)(Found valid mod file .*with \{{{e}\}}|ModContainer[^\n]*\b{e}\b|\bmods?\b[^\n]{{0,40}}\b{e}\b[^\n]*(loaded|constructed))', text):
            return not CRASHED.search(text)
    for name in meta['names']:
        if re.search(rf'(?i)(Loading server plugin|Enabling) {re.escape(name)}\b|\[{re.escape(name)}\] (Loading|Enabling)', text):
            return True
    return False


def java_home(major: int) -> str:
    for key in (f'JAVA_HOME_{major}_X64', f'JAVA_HOME_{major}_ARM64', f'JAVA_HOME_{major}_AARCH64'):
        if os.environ.get(key):
            exe = Path(os.environ[key]) / 'bin' / ('java.exe' if sys.platform == 'win32' else 'java')
            if exe.exists():
                return str(exe)
    raise Unsupported(f'Java {major} is not installed on this machine')


class Session:
    os_key = 'linux'

    def __init__(self, run: dict, root: Path):
        self.run = run
        self.root = root
        self.work = root / 'work'
        self.home = root / 'home'
        self.cache = root / 'cache'
        self.server_dir = self.work / 'server'
        self.client_root = self.work / 'client'
        self.game_dir = self.client_root / 'game'
        self.report = empty_report()
        self.notes: list[str] = []
        self.baits: list[Bait] = []
        self.main_meta: dict = {'ids': [], 'names': []}
        self.plan: Plan | None = None
        self.server_cmd: list[str] = []
        self.client_cmd: list[str] = []
        self.procs: dict[str, object] = {}

    # ---- Preparing (network open, nothing untrusted running) --------------------------------

    def prepare(self) -> None:
        for d in (self.work, self.home, self.cache):
            d.mkdir(parents=True, exist_ok=True)
        f = self.run['file']
        main = download(f['url'], self.cache / 'tested' / Path(f['name']).name, sha256=f['sha256'], max_bytes=f['size'] + 1)
        if main.stat().st_size != f['size']:
            raise RuntimeError('downloaded file has the wrong size')
        self.main = main
        self.plan = p = make_plan(self.run['projectType'], self.run['loaders'], self.run['gameVersions'], main)
        self.notes += p.notes
        why = self.client_unsupported(p.mc) if p.client else None
        if why:
            p.client = False
            self.notes.append(f'the game client is not run here: {why}')
        r = self.report['env']
        r['gameVersion'], r['loader'], r['java'] = p.mc, p.loader, str(p.java)
        java = java_home(p.java)
        self.java = java
        log('plan', p.kind, p.loader, p.mc, p.loader_version, 'java', p.java, 'client', p.client)

        self.server_cmd = install_server(self.server_dir, p, java, self.cache)
        if p.client:
            client_loader = p.loader if p.kind == 'mods' else 'vanilla'
            self.client_vid = install_client(self.client_root, client_loader, p.mc, p.loader_version or p.mc, java)
            self.game_dir.mkdir(parents=True, exist_ok=True)
            (self.game_dir / 'options.txt').write_text('onboardAccessibility:false\nskipMultiplayerWarning:true\njoinedFirstServer:true\nnarrator:0\nsoundCategory_master:0.0\nrenderDistance:4\npauseOnLostFocus:false\n')

        target = 'plugins' if p.kind in ('plugins', 'proxy') else 'mods'
        if p.pack is not None:
            if p.pack_format == 'curseforge':
                lookup = lambda ids: api.curseforge_files(self.run['id'], self.run['claimToken'], ids)  # noqa: E731
                self.notes += install_curseforge(main, p.pack, self.server_dir, self.game_dir if p.client else None, lookup)
            else:
                self.notes += install_pack(main, p.pack, self.server_dir, self.game_dir if p.client else None)
            # The pack's own mods weren't part of the pack file's scan, so their websites count as known here.
            hosts: set[str] = set()
            for d in (self.server_dir / 'mods', self.game_dir / 'mods'):
                for j in d.glob('*.jar') if d.exists() else []:
                    hosts |= jar_hosts(j)
            self.report['depHosts'] = sorted(hosts)
        else:
            self.main_meta = jar_meta(main)
            deps, hosts, notes = gather_dependencies(self.run['versionId'], p, main, self.cache / 'deps', self.run['loaders'])
            self.notes += notes
            self.report['env']['deps'] = [{'name': d['name'], 'source': d['source'], 'sha256': d['sha256']} for d in deps]
            self.report['depHosts'] = sorted(hosts)
            dests = [self.server_dir / target] + ([self.game_dir / 'mods'] if p.client and p.kind == 'mods' else [])
            for dest in dests:
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy2(main, dest / main.name)
                for d in deps:
                    shutil.copy2(d['path'], dest / Path(d['path']).name)

        self.baits, token = plant(self.home, self.os_key, p.mc)
        if p.client:
            self.player = 'Steve' + str(int(time.time()) % 1000)
            self.client_cmd = client_command(
                self.client_root, self.client_vid, self.client_java(), self.game_dir,
                username=self.player, uuid=uuid.uuid4().hex, token=token, server='127.0.0.1:25565',
            )

    def client_java(self) -> str:
        return self.java

    # ---- Running (network cut off, watchers on) ----------------------------------------------

    def execute(self) -> None:
        p = self.plan
        assert p
        self.before = {**snapshot(self.work), **self.home_snapshot()}
        self.isolate()
        try:
            server_log = self.root / 'server.log'
            self.procs['server'] = self.start('server', self.server_cmd, self.server_dir, server_log)
            boot_start = time.monotonic()
            started = wait_for(server_log, DONE, SERVER_START_S, lambda: self.alive('server'))
            self.report['server']['started'] = started
            log('server started' if started else 'server did not start')
            if p.client:
                client_log = self.root / 'client.log'
                self.procs['client'] = self.start('client', self.client_cmd, self.game_dir, client_log)
                self.report['client']['started'] = True
                joined = started and wait_for(server_log, JOINED, CLIENT_JOIN_S, lambda: self.alive('client') and self.alive('server'))
                self.report['client']['joined'] = bool(joined)
                log('client joined' if joined else 'client did not join')
            dwell = min(DWELL_MAX_S, max(DWELL_MIN_S, DWELL_FACTOR * (time.monotonic() - boot_start)))
            log(f'booted in {time.monotonic() - boot_start:.0f}s; watching for {dwell:.0f}s')
            watch_start = time.monotonic()
            while time.monotonic() < watch_start + dwell and any(self.alive(n) for n in self.procs):
                time.sleep(2)
            self.report['watched'] = round(time.monotonic() - watch_start)
            if self.alive('server'):
                self.send('server', 'stop\n' if p.loader != 'velocity' else 'end\n')
                end = time.monotonic() + STOP_S
                while time.monotonic() < end and self.alive('server'):
                    time.sleep(1)
        finally:
            self.stop_all()
            self.restore()
        self.collect()

    def collect(self) -> None:
        after = {**snapshot(self.work), **self.home_snapshot()}
        self.report['modified'] = [self.show(x) for x in changed(self.before, after)]
        home = str(self.home)
        new_home = [x for x in added(self.before, after) if x.startswith(home)]
        self.report['persistence'] += [{'where': self.show(x), 'detail': 'new file'} for x in new_home if self.is_persistence(x)]
        self.report['writtenOutside'] += [self.show(x) for x in new_home if not self.is_persistence(x) and not self.ignorable(x)]
        logs = {n: (self.root / f'{n}.log') for n in ('server', 'client')}
        texts = {n: (p.read_text('utf-8', 'replace') if p.exists() else '') for n, p in logs.items()}
        for side in ('server', 'client'):
            text = texts[side]
            crash_dir = (self.server_dir if side == 'server' else self.game_dir) / 'crash-reports'
            if (crash_dir.exists() and any(crash_dir.iterdir())) or CRASHED.search(text):
                self.report[side]['crashed'] = True
            if text and (self.main_meta['ids'] or self.main_meta['names']):
                self.report[side]['loaded'] = loaded(text, self.main_meta)
        self.report['log'] = '\n'.join([*(f'note: {n}' for n in self.notes), '--- server', tail(logs['server'], 12_000), '--- client', tail(logs['client'], 8_000)])[-30_000:]
        self.report['outcome'] = 'tested'

    PERSIST = re.compile(r'(/|\\)(\.bashrc|\.profile|\.bash_profile|\.zshrc|\.zprofile|\.xprofile|\.xinitrc|\.config[/\\]autostart|\.config[/\\]systemd|\.local[/\\]share[/\\]applications|Library[/\\]LaunchAgents|Start Menu[/\\]Programs[/\\]Startup)', re.I)

    def is_persistence(self, path: str) -> bool:
        return bool(self.PERSIST.search(path))

    def ignorable(self, path: str) -> bool:
        return bool(re.search(r'[/\\](\.java|\.cache|\.oracle_jre_usage|\.lwjgl|AppData[/\\]Local[/\\]Temp)[/\\]', path))

    def show(self, path: str) -> str:
        """A path as the report shows it: relative to the fake home or the game folders."""
        for base, label in ((self.home, '~'), (self.server_dir, 'server'), (self.game_dir, 'client'), (self.client_root, 'launcher')):
            b = str(base)
            if path.startswith(b):
                return label + path[len(b):].replace('\\', '/')
        return path

    # ---- Hooks ------------------------------------------------------------------------------

    def client_unsupported(self, mc: str) -> str | None:
        return None

    def home_roots(self) -> list[Path]:
        return [self.home]

    # True when home is the machine's real user folder (Windows, macOS), which holds gigabytes of
    # preinstalled tools; its top level is then checked file by file instead of as a whole tree.
    real_home = False

    def home_snapshot(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for r in self.home_roots():
            if self.real_home and r == self.home:
                for p in r.iterdir():
                    try:
                        if p.is_file() and not p.is_symlink() and p.stat().st_size < 10_000_000:
                            out[str(p)] = file_hash(p)
                    except OSError:
                        continue
                continue
            out.update(snapshot(r, everything=True))
        return out

    def isolate(self) -> None:
        raise NotImplementedError

    def restore(self) -> None:
        pass

    def start(self, name: str, cmd: list[str], cwd: Path, log_path: Path) -> object:
        raise NotImplementedError

    def alive(self, name: str) -> bool:
        p = self.procs.get(name)
        return isinstance(p, subprocess.Popen) and p.poll() is None

    def send(self, name: str, text: str) -> None:
        p = self.procs.get(name)
        if isinstance(p, subprocess.Popen) and p.stdin:
            try:
                p.stdin.write(text.encode())
                p.stdin.flush()
            except OSError:
                pass

    def stop_all(self) -> None:
        raise NotImplementedError


def run_session(cls: type[Session], run: dict, root: Path) -> dict:
    s = cls(run, root)
    try:
        s.prepare()
    except Unsupported as e:
        s.report['outcome'] = 'unsupported'
        s.report['error'] = str(e)[:500]
        return s.report
    except Exception as e:  # noqa: BLE001
        s.report['outcome'] = 'error'
        s.report['error'] = f'setup failed: {e}'[:500]
        return s.report
    try:
        s.execute()
    except Exception as e:  # noqa: BLE001
        log('run failed', repr(e))
        s.report['outcome'] = 'error'
        s.report['error'] = f'run failed: {e}'[:500]
    return s.report


def main(os_key: str, run_id: str, cls: type[Session], root: Path) -> int:
    run = api.claim(run_id)
    if not run:
        log('nothing to do: run already claimed or finished')
        return 0
    log('claimed', run['id'], run['projectType'], run['loaders'], run['gameVersions'])
    report = run_session(cls, run, root)
    log('outcome', report['outcome'], report.get('error') or '')
    res = api.submit(run['id'], run['claimToken'], report)
    log('submitted', res)
    return 0
