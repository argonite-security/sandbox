"""Forge and NeoForge installers. Current installers set up the server and client themselves; the old
ones (Forge 1.7.10 up to early 1.12.2 builds) only carry a launcher profile, so those are assembled by
hand the way third-party launchers do it."""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

from .common import download, get_json, log, request

MAVEN = {
    'forge': 'https://maven.minecraftforge.net/net/minecraftforge/forge',
    'neoforge': 'https://maven.neoforged.net/releases/net/neoforged/neoforge',
}
LIBRARIES = 'https://libraries.minecraft.net/'
OLD_FORGE_MAVEN = re.compile(r'^https?://files\.minecraftforge\.net/maven/?')


def installer(loader: str, mc: str, version: str, cache: Path) -> Path:
    """Downloads the installer. Old Forge builds carry a branch suffix (1.7.10-10.13.4.1614-1.7.10)."""
    if loader == 'neoforge':
        full = version
    else:
        xml = request(f'{MAVEN["forge"]}/maven-metadata.xml').decode()
        found = [x for x in re.findall(r'<version>([^<]+)</version>', xml) if x == f'{mc}-{version}' or x.startswith(f'{mc}-{version}-')]
        full = found[0] if found else f'{mc}-{version}'
    return download(f'{MAVEN[loader]}/{full}/{loader}-{full}-installer.jar', cache / f'{loader}-{full}-installer.jar')


def legacy_profile(path: Path) -> dict | None:
    """The install profile of an old installer (one with a versionInfo block), or None for a current one."""
    with zipfile.ZipFile(path) as z:
        try:
            profile = json.loads(z.read('install_profile.json'))
        except KeyError:
            return None
    return profile if isinstance(profile.get('versionInfo'), dict) and isinstance(profile.get('install'), dict) else None


def maven_path(name: str) -> str:
    coords, _, ext = name.partition('@')
    parts = coords.split(':')
    classifier = f'-{parts[3]}' if len(parts) > 3 else ''
    return f'{parts[0].replace(".", "/")}/{parts[1]}/{parts[2]}/{parts[1]}-{parts[2]}{classifier}.{ext or "jar"}'


def _lib_url(lib: dict) -> str:
    base = OLD_FORGE_MAVEN.sub('https://maven.minecraftforge.net/', lib.get('url') or LIBRARIES)
    return base.rstrip('/') + '/' + maven_path(lib['name'])


def _universal(installer_path: Path, profile: dict) -> bytes:
    with zipfile.ZipFile(installer_path) as z:
        return z.read(profile['install']['filePath'])


def legacy_server(srv: Path, installer_path: Path, profile: dict, java: str, mem: list[str]) -> list[str]:
    inst, info = profile['install'], profile['versionInfo']
    mc = inst['minecraft']
    (srv / inst['filePath']).write_bytes(_universal(installer_path, profile))
    manifest = get_json('https://piston-meta.mojang.com/mc/game/version_manifest_v2.json')
    entry = next(x for x in manifest['versions'] if x['id'] == mc)  # type: ignore[index]
    server = get_json(entry['url'])['downloads']['server']  # type: ignore[index]
    download(server['url'], srv / f'minecraft_server.{mc}.jar', sha1=server['sha1'])
    for lib in info.get('libraries', []):
        if lib.get('serverreq') and lib['name'] != inst['path']:
            try:
                download(_lib_url(lib), srv / 'libraries' / maven_path(lib['name']))
            except Exception as e:  # noqa: BLE001 - FML reports a missing library itself
                log('library not found', lib['name'], e)
    return [java, *mem, '-jar', inst['filePath'], 'nogui']


def legacy_client(root: Path, installer_path: Path, profile: dict) -> str:
    inst = profile['install']
    info = dict(profile['versionInfo'])
    info.setdefault('inheritsFrom', inst['minecraft'])
    info.setdefault('jar', inst['minecraft'])
    for lib in info.get('libraries', []):
        if lib.get('url'):
            lib['url'] = OLD_FORGE_MAVEN.sub('https://maven.minecraftforge.net/', lib['url'])
    vid = info['id']
    (root / 'versions' / vid).mkdir(parents=True, exist_ok=True)
    (root / 'versions' / vid / f'{vid}.json').write_text(json.dumps(info), 'utf-8')
    target = root / 'libraries' / maven_path(inst['path'])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_universal(installer_path, profile))
    return vid
