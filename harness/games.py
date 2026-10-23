"""Picks what to run the file in: loader, game version and Java."""
from __future__ import annotations

import json
import re
import urllib.error
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .common import Unsupported, get_json, log, request

MOD_LOADERS = ['fabric', 'quilt', 'neoforge', 'forge']
PLUGIN_LOADERS = {'paper': 'paper', 'purpur': 'paper', 'spigot': 'paper', 'bukkit': 'paper', 'folia': 'paper', 'velocity': 'velocity'}


@dataclass
class Plan:
    kind: str  # mods | plugins | proxy
    loader: str  # fabric | quilt | neoforge | forge | paper | velocity | vanilla
    mc: str
    loader_version: str | None = None
    java: int = 21
    client: bool = True
    pack: dict | None = None
    pack_format: str | None = None  # mrpack | curseforge
    notes: list[str] = field(default_factory=list)


def mc_tuple(v: str) -> tuple[int, int, int] | None:
    m = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?$', v)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


def java_for(mc: str) -> int:
    t = mc_tuple(mc) or (99, 0, 0)
    if t[0] >= 26:
        return 25
    if t < (1, 17, 0):
        return 8
    if t < (1, 20, 5):
        return 17
    return 21


def _ordered(versions: list[str]) -> list[str]:
    """Newest release first; snapshots and odd names only if nothing else is declared."""
    releases = sorted({v for v in versions if mc_tuple(v)}, key=mc_tuple, reverse=True)
    return releases or list(versions)


def neoforge_version(mc: str) -> str | None:
    t = mc_tuple(mc)
    if not t:
        return None
    prefix = f'{t[1]}.{t[2]}.' if t[0] == 1 else f'{t[0]}.{t[1]}.{t[2]}.'
    xml = request('https://maven.neoforged.net/releases/net/neoforged/neoforge/maven-metadata.xml').decode()
    found = [v for v in re.findall(r'<version>([^<]+)</version>', xml) if v.startswith(prefix)]
    stable = [v for v in found if '-' not in v]
    return (stable or found or [None])[-1]


def forge_version(mc: str) -> str | None:
    promos = get_json('https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json')['promos']  # type: ignore[index]
    return promos.get(f'{mc}-recommended') or promos.get(f'{mc}-latest')


def loader_version(loader: str, mc: str) -> str | None:
    """The loader version to use for this game version, or None if the loader doesn't support it."""
    try:
        if loader == 'fabric':
            rows = get_json(f'https://meta.fabricmc.net/v2/versions/loader/{mc}')
            stable = [r['loader']['version'] for r in rows if r['loader'].get('stable')]  # type: ignore[union-attr]
            return (stable or [r['loader']['version'] for r in rows] or [None])[0]  # type: ignore[union-attr]
        if loader == 'quilt':
            rows = get_json(f'https://meta.quiltmc.org/v3/versions/loader/{mc}')
            return rows[0]['loader']['version'] if rows else None  # type: ignore[index]
        if loader == 'neoforge':
            return neoforge_version(mc)
        if loader == 'forge':
            t = mc_tuple(mc)
            return forge_version(mc) if t and t >= (1, 7, 10) else None
        if loader == 'paper':
            build = get_json(f'https://fill.papermc.io/v3/projects/paper/versions/{mc}/builds/latest')
            return str(build['id'])  # type: ignore[index]
        if loader == 'vanilla':
            return mc
    except urllib.error.HTTPError as e:
        if e.code in (400, 404):
            return None
        raise
    return None


def _pack_index(path: Path) -> tuple[str, dict]:
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            if 'modrinth.index.json' in names:
                return 'mrpack', json.loads(z.read('modrinth.index.json'))
            if 'manifest.json' in names:
                return 'curseforge', json.loads(z.read('manifest.json'))
    except (zipfile.BadZipFile, ValueError) as e:
        raise Unsupported('the modpack file could not be read') from e
    raise Unsupported('the modpack has neither a modrinth.index.json nor a CurseForge manifest.json')


def plan(project_type: str, loaders: list[str], game_versions: list[str], file: Path) -> Plan:
    if project_type == 'modpack':
        fmt, index = _pack_index(file)
        if fmt == 'curseforge':
            mc_info = index.get('minecraft') or {}
            mc = mc_info.get('version')
            if not mc:
                raise Unsupported('the modpack does not name a game version')
            for entry in mc_info.get('modLoaders') or []:
                name, _, version = str(entry.get('id', '')).partition('-')
                if name in ('forge', 'neoforge', 'fabric', 'quilt'):
                    return Plan('mods', name, mc, version, java_for(mc), pack=index, pack_format=fmt)
            return Plan('mods', 'vanilla', mc, mc, java_for(mc), pack=index, pack_format=fmt)
        deps = index.get('dependencies') or {}
        mc = deps.get('minecraft')
        if not mc:
            raise Unsupported('the modpack does not name a game version')
        for key, loader in (('fabric-loader', 'fabric'), ('quilt-loader', 'quilt'), ('neoforge', 'neoforge'), ('forge', 'forge')):
            if key in deps:
                return Plan('mods', loader, mc, str(deps[key]), java_for(mc), pack=index, pack_format=fmt)
        return Plan('mods', 'vanilla', mc, mc, java_for(mc), pack=index, pack_format=fmt)

    if project_type == 'plugin':
        wanted = [PLUGIN_LOADERS[l] for l in loaders if l in PLUGIN_LOADERS]
        if not wanted:
            raise Unsupported(f'no supported server for loaders {", ".join(loaders) or "(none)"}')
        if 'paper' in wanted:
            for mc in _ordered(game_versions)[:4]:
                if (v := loader_version('paper', mc)):
                    return Plan('plugins', 'paper', mc, v, java_for(mc))
            if 'velocity' not in wanted:
                raise Unsupported('Paper has no build for the declared game versions')
        builds = get_json('https://fill.papermc.io/v3/projects/velocity')
        latest = next(iter(builds['versions'].values()))[0]  # type: ignore[index]
        return Plan('proxy', 'velocity', latest, latest, 21, client=False)

    candidates = [l for l in MOD_LOADERS if l in loaders]
    if not candidates:
        raise Unsupported(f'no supported mod loader among {", ".join(loaders) or "(none)"}')
    for mc in _ordered(game_versions)[:4]:
        for loader in candidates:
            v = loader_version(loader, mc)
            log('loader', loader, mc, '->', v)
            if v:
                return Plan('mods', loader, mc, v, java_for(mc))
    raise Unsupported('none of the declared loaders support the declared game versions')
