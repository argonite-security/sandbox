"""Installs the server, places the tested file and its dependencies, and unpacks modpacks."""
from __future__ import annotations

import json
import shutil
import subprocess
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath

from . import api
from .common import Unsupported, download, file_hash, get_json, is_windows, jar_hosts, jar_meta, log
from .games import Plan, mc_tuple

PACK_HOSTS = {'cdn.modrinth.com', 'github.com', 'raw.githubusercontent.com', 'gitlab.com'}
MAX_PACK_FILES = 600
MAX_DEPS = 25


def _run(cmd: list[str], cwd: Path, what: str, timeout: int = 1200) -> None:
    log('run', what)
    out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError(f'{what} failed: {out.stdout[-600:]} {out.stderr[-600:]}')


def install_server(srv: Path, plan: Plan, java: str, cache: Path) -> list[str]:
    """Installs the server into srv (with network, before anything untrusted is there) and returns its command."""
    srv.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    mem = ['-Xmx2G', '-Xms512M']
    mc, v = plan.mc, plan.loader_version or ''
    if plan.loader == 'fabric':
        inst = get_json('https://meta.fabricmc.net/v2/versions/installer')
        pick = next((i for i in inst if i.get('stable')), inst[0])  # type: ignore[union-attr]
        jar = download(pick['url'], cache / f'fabric-installer-{pick["version"]}.jar')
        _run([java, '-jar', str(jar), 'server', '-dir', str(srv), '-mcversion', mc, '-loader', v, '-downloadMinecraft'], srv, 'fabric installer')
        cmd = [java, *mem, '-jar', 'fabric-server-launch.jar', 'nogui']
    elif plan.loader == 'quilt':
        inst = get_json('https://meta.quiltmc.org/v3/versions/installer')
        jar = download(inst[0]['url'], cache / f'quilt-installer-{inst[0]["version"]}.jar')  # type: ignore[index]
        _run([java, '-jar', str(jar), 'install', 'server', mc, v, '--download-server', f'--install-dir={srv}'], srv, 'quilt installer')
        cmd = [java, *mem, '-jar', 'quilt-server-launch.jar', 'nogui']
    elif plan.loader in ('neoforge', 'forge'):
        neo = plan.loader == 'neoforge'
        full = v if neo else f'{mc}-{v}'
        base = 'https://maven.neoforged.net/releases/net/neoforged/neoforge' if neo else 'https://maven.minecraftforge.net/net/minecraftforge/forge'
        name = 'neoforge' if neo else 'forge'
        jar = download(f'{base}/{full}/{name}-{full}-installer.jar', cache / f'{name}-{full}-installer.jar')
        _run([java, '-jar', str(jar), '--installServer', str(srv)], srv, f'{name} installer')
        args = sorted(srv.glob(f'libraries/net/*/*/*/{"win" if is_windows() else "unix"}_args.txt'))
        shims = sorted(srv.glob('forge-*-shim.jar'))
        plain = [p for p in sorted(srv.glob('forge-*.jar')) if 'installer' not in p.name and 'shim' not in p.name]
        if args:
            jvm = ['@user_jvm_args.txt'] if (srv / 'user_jvm_args.txt').exists() else []
            cmd = [java, *mem, *jvm, f'@{args[-1].relative_to(srv).as_posix()}', 'nogui']
        elif shims:
            cmd = [java, *mem, '-jar', shims[-1].name, 'nogui']
        elif plain:
            cmd = [java, *mem, '-jar', plain[-1].name, 'nogui']
        else:
            raise RuntimeError(f'{name} installer left no way to start the server')
    elif plan.loader == 'paper':
        build = get_json(f'https://fill.papermc.io/v3/projects/paper/versions/{mc}/builds/latest')
        d = build['downloads']['server:default']  # type: ignore[index]
        download(d['url'], srv / 'paper.jar', sha256=d['checksums']['sha256'])
        # Paper fetches and patches the game on first start; do that now while the network is open.
        _run([java, '-Dpaperclip.patchonly=true', '-jar', 'paper.jar'], srv, 'paper patch')
        cmd = [java, *mem, '-jar', 'paper.jar', '--nogui']
    elif plan.loader == 'velocity':
        build = get_json(f'https://fill.papermc.io/v3/projects/velocity/versions/{v}/builds/latest')
        d = build['downloads']['server:default']  # type: ignore[index]
        download(d['url'], srv / 'velocity.jar', sha256=d['checksums']['sha256'])
        cmd = [java, '-Xmx1G', '-jar', 'velocity.jar']
    elif plan.loader == 'vanilla':
        manifest = get_json('https://piston-meta.mojang.com/mc/game/version_manifest_v2.json')
        entry = next(x for x in manifest['versions'] if x['id'] == mc)  # type: ignore[index]
        meta = get_json(entry['url'])
        s = meta['downloads']['server']  # type: ignore[index]
        download(s['url'], srv / 'server.jar', sha1=s['sha1'])
        cmd = [java, *mem, '-jar', 'server.jar', 'nogui']
    else:
        raise Unsupported(f'unknown loader {plan.loader}')
    if plan.loader != 'velocity':
        (srv / 'eula.txt').write_text('eula=true\n')
        flat = 'minecraft\\:flat' if (mc_tuple(mc) or (99, 0, 0)) >= (1, 19, 0) else 'FLAT'
        (srv / 'server.properties').write_text(
            '\n'.join([
                'online-mode=false', 'server-port=25565', 'server-ip=', f'level-type={flat}', 'spawn-protection=0', 'max-tick-time=-1',
                'view-distance=4', 'simulation-distance=4', 'enforce-secure-profile=false', 'sync-chunk-writes=false', 'motd=A Minecraft Server',
                'difficulty=easy', 'white-list=false', 'enforce-whitelist=false', 'enable-query=false', 'enable-rcon=false', 'generate-structures=false', '',
            ])
        )
    return cmd


def _safe_rel(path: str) -> PurePosixPath | None:
    p = PurePosixPath(path.replace('\\', '/'))
    if p.is_absolute() or not p.parts or any(part in ('..', '') or ':' in part for part in p.parts):
        return None
    return p


def install_pack(pack_file: Path, index: dict, server_dir: Path | None, client_dir: Path | None) -> list[str]:
    """Downloads a .mrpack's files (checking their hashes) into the server and client folders."""
    notes = []
    files = index.get('files') or []
    if len(files) > MAX_PACK_FILES:
        raise Unsupported('the modpack has too many files to run')
    for f in files:
        rel = _safe_rel(f.get('path', ''))
        env = f.get('env') or {}
        urls = [u for u in f.get('downloads') or [] if urllib.parse.urlsplit(u).hostname in PACK_HOSTS and u.startswith('https://')]
        sha512 = (f.get('hashes') or {}).get('sha512')
        if not rel or not urls or not sha512:
            notes.append(f'skipped pack file {f.get("path")}')
            continue
        targets = [d for d, side in ((server_dir, 'server'), (client_dir, 'client')) if d and env.get(side) != 'unsupported']
        if not targets:
            continue
        first = download(urls[0], targets[0] / rel, sha512=sha512)
        for t in targets[1:]:
            (t / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(first, t / rel)
    with zipfile.ZipFile(pack_file) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            top, _, rest = info.filename.partition('/')
            rel = _safe_rel(rest)
            if not rel:
                continue
            dirs = {'overrides': [server_dir, client_dir], 'server-overrides': [server_dir], 'client-overrides': [client_dir]}.get(top, [])
            for d in dirs:
                if d:
                    (d / rel).parent.mkdir(parents=True, exist_ok=True)
                    (d / rel).write_bytes(z.read(info))
    return notes


def _modrinth_loaders(plan: Plan) -> list[str]:
    return {'quilt': ['quilt', 'fabric'], 'paper': ['paper', 'spigot', 'bukkit', 'purpur']}.get(plan.loader, [plan.loader])


def _modrinth_pick(project: str, plan: Plan) -> dict | None:
    q = urllib.parse.urlencode({'loaders': json.dumps(_modrinth_loaders(plan)), 'game_versions': json.dumps([plan.mc])})
    try:
        versions = get_json(f'https://api.modrinth.com/v2/project/{urllib.parse.quote(project, safe="")}/version?{q}')
    except Exception:  # noqa: BLE001 - missing projects are expected
        return None
    if not versions:
        return None
    return next((v for v in versions if v.get('version_type') == 'release'), versions[0])  # type: ignore[union-attr]


def gather_dependencies(version_id: str, plan: Plan, main_file: Path, dest: Path, declared_loaders: list[str]) -> tuple[list[dict], set[str], list[str]]:
    """Downloads required dependencies into dest: from Argonite first, then Modrinth for the rest.
    Returns (dependency list for the report, websites written in them, notes)."""
    deps: list[dict] = []
    notes: list[str] = []
    dest.mkdir(parents=True, exist_ok=True)
    have_ids = set(jar_meta(main_file)['ids'])
    queue = list(jar_meta(main_file)['requires'])
    resolve_loader = plan.loader if plan.kind == 'mods' else next((l for l in declared_loaders if l), '')
    try:
        res = api.resolve(version_id, resolve_loader, plan.mc)
        for d in res.get('dependencies', [])[:MAX_DEPS]:
            f = (d.get('version') or {}).get('file') or {}
            if not f.get('id') or not f.get('sha256'):
                continue
            name = Path(f.get('filename') or f['id']).name
            path = download(api.file_url(f['id']), dest / name, sha256=f['sha256'])
            meta = jar_meta(path)
            have_ids |= set(meta['ids'])
            queue += meta['requires']
            deps.append({'name': (d.get('project') or {}).get('name') or name, 'source': 'argonite', 'sha256': f['sha256'], 'path': path})
    except Exception as e:  # noqa: BLE001
        notes.append(f'Argonite dependencies: {e}')
    # If the file is also on Modrinth, its dependency list there is the most reliable one.
    try:
        known = get_json(f'https://api.modrinth.com/v2/version_file/{file_hash(main_file, "sha1")}?algorithm=sha1')
        queue = [d['project_id'] for d in known.get('dependencies') or [] if d.get('dependency_type') == 'required' and d.get('project_id')] + queue  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001 - most files aren't on Modrinth
        pass
    seen: set[str] = set()
    while queue and len(deps) < MAX_DEPS:
        project = queue.pop(0)
        if project in have_ids or project in seen:
            continue
        seen.add(project)
        v = _modrinth_pick(project, plan)
        if not v:
            notes.append(f'dependency {project} not found')
            continue
        files = v.get('files') or []
        f = next((x for x in files if x.get('primary')), files[0] if files else None)
        if not f or urllib.parse.urlsplit(f['url']).hostname != 'cdn.modrinth.com':
            continue
        path = download(f['url'], dest / Path(f['filename']).name, sha512=f['hashes']['sha512'])
        meta = jar_meta(path)
        have_ids |= set(meta['ids'])
        queue += meta['requires']
        queue += [d['project_id'] for d in v.get('dependencies') or [] if d.get('dependency_type') == 'required' and d.get('project_id')]
        deps.append({'name': v.get('name') or project, 'source': 'modrinth', 'sha256': file_hash(path), 'path': path})
    hosts: set[str] = set()
    for d in deps:
        hosts |= jar_hosts(d['path'])
    return deps, hosts, notes
