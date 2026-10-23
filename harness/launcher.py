"""A small game launcher: installs the client for a loader and builds the command that starts it,
so the session token, player and server it joins are ours to choose."""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import zipfile
from pathlib import Path

from .common import download, download_many, get_json, log

MANIFEST = 'https://piston-meta.mojang.com/mc/game/version_manifest_v2.json'
LIBRARIES = 'https://libraries.minecraft.net/'
RESOURCES = 'https://resources.download.minecraft.net/'


def os_name() -> str:
    return {'win32': 'windows', 'darwin': 'osx'}.get(sys.platform, 'linux')


def _arch() -> str:
    m = platform.machine().lower()
    return 'arm64' if m in ('arm64', 'aarch64') else 'x86' if m in ('i386', 'i686', 'x86') else 'x86_64'


def rules_allow(rules: list | None, features: dict) -> bool:
    if not rules:
        return True
    allowed = False
    for rule in rules:
        ok = True
        o = rule.get('os') or {}
        if 'name' in o and o['name'] != os_name():
            ok = False
        if 'arch' in o and o['arch'] != _arch():
            ok = False
        for k, v in (rule.get('features') or {}).items():
            if bool(features.get(k)) != bool(v):
                ok = False
        if ok:
            allowed = rule.get('action') == 'allow'
    return allowed


def maven_path(name: str) -> str:
    coords, _, ext = name.partition('@')
    parts = coords.split(':')
    group, artifact, version = parts[0], parts[1], parts[2]
    classifier = f'-{parts[3]}' if len(parts) > 3 else ''
    return f'{group.replace(".", "/")}/{artifact}/{version}/{artifact}-{version}{classifier}.{ext or "jar"}'


def _lib_key(name: str) -> str:
    parts = name.split('@')[0].split(':')
    return ':'.join(parts[:2] + parts[3:])


def load_version(root: Path, vid: str) -> dict:
    """The version json with its parents merged in, child first."""
    data = json.loads((root / 'versions' / vid / f'{vid}.json').read_text('utf-8'))
    parent_id = data.get('inheritsFrom')
    if not parent_id:
        data['_jar'] = vid
        return data
    parent = load_version(root, parent_id)
    merged = {**parent, **{k: v for k, v in data.items() if k not in ('libraries', 'arguments')}}
    seen: set[str] = set()
    libs = []
    for lib in data.get('libraries', []) + parent.get('libraries', []):
        key = _lib_key(lib['name'])
        if key in seen:
            continue
        seen.add(key)
        libs.append(lib)
    merged['libraries'] = libs
    pa, ca = parent.get('arguments') or {}, data.get('arguments') or {}
    if pa or ca:
        merged['arguments'] = {'game': pa.get('game', []) + ca.get('game', []), 'jvm': pa.get('jvm', []) + ca.get('jvm', [])}
    merged['_jar'] = vid if (root / 'versions' / vid / f'{vid}.jar').exists() else parent['_jar']
    merged['id'] = vid
    return merged


def install_vanilla(root: Path, mc: str) -> None:
    manifest = get_json(MANIFEST)
    entry = next((v for v in manifest['versions'] if v['id'] == mc), None)  # type: ignore[index]
    if not entry:
        raise RuntimeError(f'unknown game version {mc}')
    vdir = root / 'versions' / mc
    download(entry['url'], vdir / f'{mc}.json', sha1=entry.get('sha1'))
    data = json.loads((vdir / f'{mc}.json').read_text('utf-8'))
    client = data['downloads']['client']
    download(client['url'], vdir / f'{mc}.jar', sha1=client['sha1'])


def install_client(root: Path, loader: str, mc: str, loader_version: str, java: str) -> str:
    """Installs the client into root and returns the version id to launch."""
    root.mkdir(parents=True, exist_ok=True)
    install_vanilla(root, mc)
    if loader == 'vanilla':
        vid = mc
    elif loader in ('fabric', 'quilt'):
        base = 'https://meta.fabricmc.net/v2' if loader == 'fabric' else 'https://meta.quiltmc.org/v3'
        profile = get_json(f'{base}/versions/loader/{mc}/{loader_version}/profile/json')
        vid = profile['id']  # type: ignore[index]
        (root / 'versions' / vid).mkdir(parents=True, exist_ok=True)
        (root / 'versions' / vid / f'{vid}.json').write_text(json.dumps(profile), 'utf-8')
    else:
        from . import forge

        name = loader
        installer = forge.installer(loader, mc, loader_version, root.parent / 'cache')
        legacy = forge.legacy_profile(installer)
        if legacy:
            vid = forge.legacy_client(root, installer, legacy)
            data = load_version(root, vid)
            _fetch_libraries(root, data)
            _fetch_assets(root, data)
            return vid
        profiles = root / 'launcher_profiles.json'
        if not profiles.exists():
            profiles.write_text('{"profiles":{}}', 'utf-8')
        before = {p.name for p in (root / 'versions').iterdir()}
        out = subprocess.run([java, '-jar', str(installer), '--installClient', str(root)], cwd=root.parent, capture_output=True, text=True, timeout=1200)
        if out.returncode != 0:
            raise RuntimeError(f'{name} client installer failed: {out.stdout[-800:]} {out.stderr[-800:]}')
        new = [p.name for p in (root / 'versions').iterdir() if p.name not in before and (p / f'{p.name}.json').exists()]
        if not new:
            raise RuntimeError(f'{name} client installer produced no version')
        vid = new[0]
    data = load_version(root, vid)
    _fetch_libraries(root, data)
    _fetch_assets(root, data)
    return vid


def _fetch_libraries(root: Path, data: dict) -> None:
    items: list[tuple[str, Path, str | None]] = []
    natives: list[tuple[str, Path, str | None]] = []
    for lib in data.get('libraries', []):
        if not rules_allow(lib.get('rules'), {}):
            continue
        art = (lib.get('downloads') or {}).get('artifact')
        if art and art.get('url'):
            items.append((art['url'], root / 'libraries' / art['path'], art.get('sha1')))
        elif not art and 'downloads' not in lib:
            path = maven_path(lib['name'])
            items.append(((lib.get('url') or LIBRARIES).rstrip('/') + '/' + path, root / 'libraries' / path, lib.get('sha1')))
        cls = (lib.get('natives') or {}).get(os_name())
        if cls:
            cls = cls.replace('${arch}', '64')
            n = ((lib.get('downloads') or {}).get('classifiers') or {}).get(cls)
            if n:
                natives.append((n['url'], root / 'libraries' / n['path'], n.get('sha1')))
    # Installer-produced libraries (no url) are already on disk.
    download_many([i for i in items if not (i[1].exists() and not i[2])])
    download_many(natives)
    ndir = root / 'natives' / data['id']
    ndir.mkdir(parents=True, exist_ok=True)
    for _, path, _ in natives:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir() or info.filename.startswith('META-INF') or '..' in info.filename:
                    continue
                (ndir / Path(info.filename).name).write_bytes(z.read(info))


def _fetch_assets(root: Path, data: dict) -> None:
    idx = data.get('assetIndex')
    if not idx:
        return
    index_path = download(idx['url'], root / 'assets' / 'indexes' / f'{idx["id"]}.json', sha1=idx.get('sha1'))
    objects = json.loads(index_path.read_text('utf-8')).get('objects', {})
    # Sounds are most of the size and nothing a mod does depends on them.
    items = [
        (f'{RESOURCES}{o["hash"][:2]}/{o["hash"]}', root / 'assets' / 'objects' / o['hash'][:2] / o['hash'], o['hash'])
        for name, o in objects.items()
        if not name.startswith(('minecraft/sounds/', 'minecraft/music/', 'minecraft/resourcepacks/'))
    ]
    log('assets', len(items))
    download_many(items, workers=24)


def _subst(s: str, values: dict) -> str:
    return re.sub(r'\$\{([a-zA-Z_]+)\}', lambda m: str(values.get(m.group(1), m.group(0))), s)


def _flatten(args: list, features: dict, values: dict) -> list[str]:
    out: list[str] = []
    for a in args:
        if isinstance(a, str):
            out.append(_subst(a, values))
        elif rules_allow(a.get('rules'), features):
            v = a.get('value')
            out += [_subst(x, values) for x in (v if isinstance(v, list) else [v])]
    return out


def client_command(root: Path, vid: str, java: str, game_dir: Path, *, username: str, uuid: str, token: str, server: str, memory: str = '3G') -> list[str]:
    data = load_version(root, vid)
    sep = os.pathsep
    cp = []
    for lib in data.get('libraries', []):
        if not rules_allow(lib.get('rules'), {}):
            continue
        art = (lib.get('downloads') or {}).get('artifact')
        path = root / 'libraries' / (art['path'] if art else maven_path(lib['name']))
        if path.exists() and str(path) not in cp:
            cp.append(str(path))
    cp.append(str(root / 'versions' / data['_jar'] / f'{data["_jar"]}.jar'))
    game_args = (data.get('arguments') or {}).get('game')
    quick_play = bool(game_args) and any(isinstance(a, dict) and '--quickPlayMultiplayer' in json.dumps(a) for a in game_args)
    values = {
        'auth_player_name': username,
        'version_name': vid,
        'game_directory': str(game_dir),
        'assets_root': str(root / 'assets'),
        'game_assets': str(root / 'assets'),
        'assets_index_name': (data.get('assetIndex') or {}).get('id', 'legacy'),
        'auth_uuid': uuid,
        'auth_access_token': token,
        'auth_session': f'token:{token}:{uuid}',
        'clientid': '',
        'auth_xuid': '0',
        'user_type': 'msa',
        'user_properties': '{}',
        'version_type': 'release',
        'natives_directory': str(root / 'natives' / data['id']),
        'launcher_name': 'minecraft-launcher',
        'launcher_version': '3.0.0',
        'classpath': sep.join(cp),
        'classpath_separator': sep,
        'library_directory': str(root / 'libraries'),
        'resolution_width': '1280',
        'resolution_height': '720',
        'quickPlayMultiplayer': server,
    }
    features = {'has_custom_resolution': True, 'is_quick_play_multiplayer': quick_play}
    if data.get('arguments'):
        jvm = _flatten(data['arguments'].get('jvm', []), features, values)
        game = _flatten(data['arguments'].get('game', []), features, values)
    else:
        jvm = [f'-Djava.library.path={values["natives_directory"]}', '-cp', values['classpath']]
        game = [_subst(a, values) for a in data.get('minecraftArguments', '').split()]
    if not quick_play:
        host, _, port = server.partition(':')
        game += ['--server', host, '--port', port or '25565']
    return [java, f'-Xmx{memory}', '-Xms512M', *jvm, data['mainClass'], *game]
