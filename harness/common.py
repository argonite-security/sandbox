"""Shared helpers: downloads, hashing, file snapshots, jar metadata and the report."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

UA = 'argonite-sandbox/1'
STARTED = time.monotonic()


def log(*parts: object) -> None:
    print(f'[{time.monotonic() - STARTED:7.1f}s]', *parts, flush=True)


class Unsupported(Exception):
    """The file can't be tested here (loader, game version or format we don't run)."""


def request(url: str, data: bytes | None = None, headers: dict | None = None, timeout: int = 60) -> bytes:
    h = {'User-Agent': UA, **(headers or {})}
    last: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h, method='POST' if data is not None else 'GET'), timeout=timeout) as res:
                return res.read()
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:
                raise
            last = e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
        time.sleep(2 * (attempt + 1))
    raise last  # type: ignore[misc]


def get_json(url: str, headers: dict | None = None) -> object:
    return json.loads(request(url, headers={'Accept': 'application/json', **(headers or {})}))


def download(url: str, dest: Path, sha1: str | None = None, sha256: str | None = None, sha512: str | None = None, max_bytes: int = 1 << 30) -> Path:
    """Downloads to dest, checking whichever hash is given. Existing files with the right hash are kept."""
    want = [(n, v.lower()) for n, v in (('sha1', sha1), ('sha256', sha256), ('sha512', sha512)) if v]
    if dest.exists() and want and all(file_hash(dest, n) == v for n, v in want):
        return dest
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise RuntimeError(f'refusing non-https download: {url}')
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + '.part')
    for attempt in range(4):
        try:
            hashes = {n: hashlib.new(n) for n, _ in want}
            size = 0
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': UA}), timeout=120) as res, open(tmp, 'wb') as out:
                while chunk := res.read(1 << 20):
                    size += len(chunk)
                    if size > max_bytes:
                        raise RuntimeError(f'download too large: {url}')
                    for h in hashes.values():
                        h.update(chunk)
                    out.write(chunk)
            for n, v in want:
                if hashes[n].hexdigest() != v:
                    raise RuntimeError(f'{n} mismatch for {url}')
            os.replace(tmp, dest)
            return dest
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if isinstance(e, urllib.error.HTTPError) and e.code < 500 and e.code != 429:
                raise
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f'download failed: {url}')


def download_many(items: list[tuple[str, Path, str | None]], workers: int = 16) -> None:
    """(url, dest, sha1) triples, in parallel."""
    with ThreadPoolExecutor(workers) as pool:
        for f in [pool.submit(download, u, d, s) for u, d, s in items]:
            f.result()


def file_hash(path: Path, algo: str = 'sha256') -> str:
    h = hashlib.new(algo)
    with open(path, 'rb') as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


SNAPSHOT_SUFFIXES = {'.jar', '.zip', '.class', '.dll', '.so', '.dylib', '.exe', '.sh', '.bat', '.cmd', '.ps1', '.command', '.jnilib'}


def snapshot(root: Path, everything: bool = False) -> dict[str, str]:
    """Hashes of the code-like files under root (or every file)."""
    out: dict[str, str] = {}
    if not root.exists():
        return out
    for dirpath, _, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            if not everything and p.suffix.lower() not in SNAPSHOT_SUFFIXES:
                continue
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                out[str(p)] = file_hash(p)
            except OSError:
                continue
    return out


def changed(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """Files that existed before and were changed or deleted."""
    return sorted(p for p, h in before.items() if after.get(p) != h)


def added(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(p for p in after if p not in before)


# ---- Jar metadata ------------------------------------------------------------------------------

BUILTIN_DEPS = {
    'minecraft', 'java', 'fabricloader', 'fabric-loader', 'quilt_loader', 'quilt-loader', 'forge', 'neoforge', 'fml', 'javafml', 'lowcodefml',
    'mixinextras', 'quilt_base', 'velocity', 'paper', 'spigot', 'bukkit',
}
ALIASES = {'fabric': 'fabric-api', 'quilted_fabric_api': 'qsl', 'fabric_api': 'fabric-api'}


def jar_meta(path: Path) -> dict:
    """Mod ids, names and required dependency ids declared inside a jar."""
    meta = {'ids': [], 'names': [], 'requires': []}
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return meta
    with z:
        names = set(z.namelist())

        def read(n: str) -> str | None:
            if n not in names:
                return None
            info = z.getinfo(n)
            if info.file_size > 2_000_000:
                return None
            return z.read(n).decode('utf-8', 'replace')

        if (t := read('fabric.mod.json')) is not None:
            try:
                d = json.loads(t, strict=False)
                meta['ids'].append(str(d.get('id', '')))
                meta['names'].append(str(d.get('name', '')))
                meta['requires'] += list((d.get('depends') or {}).keys())
            except (ValueError, AttributeError):
                pass
        if (t := read('quilt.mod.json')) is not None:
            try:
                d = json.loads(t, strict=False).get('quilt_loader', {})
                meta['ids'].append(str(d.get('id', '')))
                for dep in d.get('depends') or []:
                    dep_id = dep if isinstance(dep, str) else dep.get('id') if isinstance(dep, dict) and not dep.get('optional') else None
                    if dep_id:
                        meta['requires'].append(str(dep_id).split(':')[-1])
            except (ValueError, AttributeError):
                pass
        for toml_name in ('META-INF/neoforge.mods.toml', 'META-INF/mods.toml'):
            if (t := read(toml_name)) is None:
                continue
            try:
                d = tomllib.loads(t)
            except tomllib.TOMLDecodeError:
                continue
            for m in d.get('mods') or []:
                meta['ids'].append(str(m.get('modId', '')))
                meta['names'].append(str(m.get('displayName', '')))
            for deps in (d.get('dependencies') or {}).values():
                for dep in deps if isinstance(deps, list) else []:
                    required = dep.get('type', '').lower() == 'required' if 'type' in dep else dep.get('mandatory') is True
                    if required and dep.get('side', 'BOTH').upper() != 'CLIENT':
                        meta['requires'].append(str(dep.get('modId', '')))
        for yml in ('plugin.yml', 'paper-plugin.yml', 'velocity-plugin.json'):
            if (t := read(yml)) is None:
                continue
            if yml.endswith('.json'):
                try:
                    d = json.loads(t)
                    meta['ids'].append(str(d.get('id', '')))
                    meta['names'].append(str(d.get('name', '')))
                    meta['requires'] += [str(x.get('id')) for x in d.get('dependencies') or [] if isinstance(x, dict) and not x.get('optional')]
                except ValueError:
                    pass
                continue
            m = re.search(r'^name:\s*["\']?([^"\'\n]+)', t, re.M)
            if m:
                meta['names'].append(m.group(1).strip())
                meta['ids'].append(m.group(1).strip().lower())
            m = re.search(r'^depend:\s*\[([^\]]*)\]', t, re.M)
            if m:
                meta['requires'] += [x.strip().strip('"\'') for x in m.group(1).split(',') if x.strip()]
    meta['ids'] = [i for i in meta['ids'] if i]
    meta['names'] = [n for n in meta['names'] if n]
    # Fabric API's modules are declared one by one but ship as one project.
    req = {'fabric-api' if re.fullmatch(r'fabric-[a-z0-9-]+-v\d+', r) or r == 'fabric-api-base' else ALIASES.get(r, r) for r in meta['requires'] if r and r not in BUILTIN_DEPS}
    meta['requires'] = sorted(req - set(meta['ids']))
    return meta


URL_HOST = re.compile(rb'https?://([a-z0-9][a-z0-9.-]{0,251}[a-z0-9])', re.I)


def jar_hosts(path: Path | io.BytesIO, limit: int = 2000, depth: int = 0) -> set[str]:
    """Websites written in a jar's classes and text files, nested jars included (for dependencies;
    the main file's come from the static scan)."""
    hosts: set[str] = set()
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return hosts
    with z:
        for info in z.infolist():
            if info.file_size > 8_000_000 or info.is_dir():
                continue
            data = z.read(info)
            if info.filename.endswith('.jar') and depth < 3:
                hosts |= jar_hosts(io.BytesIO(data), limit, depth + 1)
                continue
            for m in URL_HOST.finditer(data):
                hosts.add(m.group(1).decode().lower())
            if len(hosts) >= limit:
                break
    return {h for h in hosts if '.' in h}


def tail(path: Path, max_chars: int = 12_000) -> str:
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_chars * 2))
            return f.read().decode('utf-8', 'replace')[-max_chars:]
    except OSError:
        return ''


def wait_for(path: Path, pattern: re.Pattern, timeout: float, alive=lambda: True) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if pattern.search(path.read_text('utf-8', 'replace')):
                return True
        except OSError:
            pass
        if not alive():
            return False
        time.sleep(1)
    return False


def empty_report() -> dict:
    return {
        'outcome': 'error',
        'error': None,
        'env': {'gameVersion': None, 'loader': None, 'java': None, 'deps': []},
        'server': {'started': False, 'crashed': False, 'loaded': None},
        'client': {'started': False, 'joined': False, 'crashed': False, 'loaded': None},
        'dns': [],
        'connections': [],
        'processes': [],
        'bait': [],
        'leaks': [],
        'modified': [],
        'persistence': [],
        'writtenOutside': [],
        'depHosts': [],
        'log': '',
    }


def rmtree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def is_windows() -> bool:
    return sys.platform == 'win32'


def unzip_bytes(data: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(data))
