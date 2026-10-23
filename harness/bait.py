"""Bait: believable credential files with a unique marker in each. Touching one, or a marker showing
up in network traffic, is something no honest mod does."""
from __future__ import annotations

import base64
import io
import json
import secrets
import sqlite3
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Bait:
    kind: str
    path: Path
    marker: str


def _jar(marker: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
        z.writestr('fabric.mod.json', json.dumps({'schemaVersion': 1, 'id': 'betterhud', 'version': '1.4.2', 'name': 'Better HUD'}))
        z.writestr('betterhud/BetterHud.class', bytes.fromhex('cafebabe0000003d') + marker.encode())
    return buf.getvalue()


LAYOUT = {
    'linux': {
        'discord': ['.config/discord/Local Storage/leveldb/000005.ldb'],
        'browser': ['.config/google-chrome/Default/Login Data', '.mozilla/firefox/k3x9p2qd.default-release/logins.json'],
        'ssh': ['.ssh/id_ed25519'],
        'cloud': ['.aws/credentials'],
        'git': ['.git-credentials'],
        'wallet': ['.config/Exodus/exodus.wallet/seed.seco', '.electrum/wallets/default_wallet'],
        'telegram': ['.local/share/TelegramDesktop/tdata/key_datas'],
        'launcher': ['.minecraft/launcher_accounts.json', '.local/share/PrismLauncher/accounts.json'],
        'mc': '.minecraft',
    },
    'windows': {
        'discord': ['AppData/Roaming/discord/Local Storage/leveldb/000005.ldb'],
        'browser': ['AppData/Local/Google/Chrome/User Data/Default/Login Data', 'AppData/Roaming/Mozilla/Firefox/Profiles/k3x9p2qd.default-release/logins.json'],
        'ssh': ['.ssh/id_ed25519'],
        'cloud': ['.aws/credentials'],
        'git': ['.git-credentials'],
        'wallet': ['AppData/Roaming/Exodus/exodus.wallet/seed.seco', 'AppData/Roaming/Electrum/wallets/default_wallet'],
        'telegram': ['AppData/Roaming/Telegram Desktop/tdata/key_datas'],
        'launcher': ['AppData/Roaming/.minecraft/launcher_accounts.json', 'AppData/Roaming/PrismLauncher/accounts.json'],
        'mc': 'AppData/Roaming/.minecraft',
    },
    'macos': {
        'discord': ['Library/Application Support/discord/Local Storage/leveldb/000005.ldb'],
        'browser': ['Library/Application Support/Google/Chrome/Default/Login Data', 'Library/Application Support/Firefox/Profiles/k3x9p2qd.default-release/logins.json'],
        'ssh': ['.ssh/id_ed25519'],
        'cloud': ['.aws/credentials'],
        'git': ['.git-credentials'],
        'wallet': ['Library/Application Support/Exodus/exodus.wallet/seed.seco', '.electrum/wallets/default_wallet'],
        'telegram': ['Library/Application Support/Telegram Desktop/tdata/key_datas'],
        'launcher': ['Library/Application Support/minecraft/launcher_accounts.json', 'Library/Application Support/PrismLauncher/accounts.json'],
        'mc': 'Library/Application Support/minecraft',
    },
}


def _content(kind: str, name: str, m: str) -> bytes | None:
    if name == 'Login Data':
        return None  # written as a database below
    if kind == 'discord':
        return b'\x00\x01_https://discord.com\x00\x01token\x00"' + f'MTA{m}.GxQk2a.{m}'.encode() + b'"\x00'
    if name == 'logins.json':
        return json.dumps({'nextId': 2, 'logins': [{'id': 1, 'hostname': 'https://accounts.google.com', 'encryptedUsername': f'MEIEEPgAAAAA{m}', 'encryptedPassword': f'MEIEEPgAAAAA{m}', 'encType': 1}]}).encode()
    if kind == 'ssh':
        return f'-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n{m}{m}\n-----END OPENSSH PRIVATE KEY-----\n'.encode()
    if kind == 'cloud':
        return f'[default]\naws_access_key_id = AKIA{m[:16].upper()}\naws_secret_access_key = {m}{m[:16]}\n'.encode()
    if kind == 'git':
        return f'https://player:ghp_{m}{m[:12]}@github.com\n'.encode()
    if kind == 'wallet':
        return f'SECO\x00\x00\x00\x01{m}'.encode() if name.endswith('.seco') else json.dumps({'seed_version': 52, 'keystore': {'type': 'bip32', 'xprv': f'xprv9s21ZrQH143K{m}'}}).encode()
    if kind == 'telegram':
        return b'TDF$' + m.encode()
    if kind == 'launcher':
        return json.dumps({'accounts': {'1': {'accessToken': f'eyJraWQiOiJhYzg0YSJ9.{m}', 'minecraftProfile': {'id': '9f1c2b0e4d7a4e3fb5c6a8d7e2f1b0c9', 'name': 'Player'}, 'username': 'player@example.com'}}}).encode()
    return m.encode()


def _login_db(path: Path, m: str) -> None:
    con = sqlite3.connect(path)
    with con:
        con.execute('CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, date_created INTEGER)')
        con.execute('INSERT INTO logins VALUES (?, ?, ?, ?)', ('https://accounts.google.com/', 'player@example.com', b'v10' + m.encode(), 13340000000000000))
    con.close()


def plant(home: Path, os_key: str, mc: str) -> tuple[list[Bait], str]:
    """Plants bait under home. Returns the bait list and the fake session token for the game client."""
    baits: list[Bait] = []
    layout = LAYOUT[os_key]
    for kind, paths in layout.items():
        if kind == 'mc':
            continue
        for rel in paths:
            path = home / rel
            if path.exists():
                continue
            m = secrets.token_hex(12)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = _content(kind, path.name, m)
            if data is None:
                _login_db(path, m)
                (path.parent.parent / 'Local State').write_text(json.dumps({'os_crypt': {'encrypted_key': base64.b64encode(b'DPAPI' + m.encode()).decode()}}))
            else:
                path.write_bytes(data)
            baits.append(Bait(kind, path, m))
    # Jars a worm would infect: another installed mod and the game itself.
    mcdir = home / layout['mc']
    for rel in ('mods/betterhud-1.4.2.jar', f'versions/{mc}/{mc}.jar'):
        p = mcdir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_bytes(_jar(secrets.token_hex(8)))
    session = secrets.token_hex(12)
    token = 'eyJhbGciOiJIUzI1NiJ9.' + base64.urlsafe_b64encode(json.dumps({'xuid': '2535428391827364', 'pfd': [{'type': 'mc', 'id': session}]}).encode()).decode().rstrip('=') + f'.{session}'
    baits.append(Bait('session', Path('<game session token>'), session))
    return baits, token


def _variants(marker: str) -> list[bytes]:
    raw = marker.encode()
    out = [raw]
    # The marker's base64 at each of the three byte alignments, minus the edge characters that depend on its neighbours.
    for k in range(3):
        enc = base64.b64encode(b'\0' * k + raw)
        out.append(enc[(k * 4 + 2) // 3 + 1 : -4])
    return out


def find_leaks(data: bytes, baits: list[Bait]) -> list[str]:
    """Kinds of bait whose marker appears in data (as is, lower-cased, or base64)."""
    lower = data.lower()
    hits = []
    for b in baits:
        if any(v and (v in data or v.lower() in lower) for v in _variants(b.marker)):
            hits.append(b.kind)
    return hits


def kind_of(path: str, baits: list[Bait]) -> str | None:
    norm = path.replace('\\', '/').lower()
    for b in baits:
        if str(b.path).replace('\\', '/').lower() == norm:
            return b.kind
    return None
