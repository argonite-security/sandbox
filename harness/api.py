"""Talks to the Argonite API. The machine proves who it is with a GitHub Actions identity token,
fetched fresh for every call and never handed to anything the tested file can reach."""
from __future__ import annotations

import json
import os
import re
import urllib.parse

from .common import request

API = os.environ.get('ARGONITE_API', 'https://api.argonite.org').rstrip('/')
ID = re.compile(r'^[0-9a-z]{26}$')

# Read once at start-up and dropped from the environment, so nothing started later inherits them.
_TOKEN_URL = os.environ.pop('ACTIONS_ID_TOKEN_REQUEST_URL', '')
_TOKEN_KEY = os.environ.pop('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
_NONCE = os.environ.pop('RUN_NONCE', '')


def identity_token() -> str:
    if not _TOKEN_URL or not _TOKEN_KEY:
        raise RuntimeError('no GitHub Actions identity token available (needs id-token: write)')
    url = f'{_TOKEN_URL}&audience={urllib.parse.quote(API, safe="")}'
    body = json.loads(request(url, headers={'Authorization': f'bearer {_TOKEN_KEY}', 'Accept': 'application/json'}))
    return body['value']


def _post(path: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    res = request(f'{API}{path}', data=data, headers={'Authorization': f'Bearer {identity_token()}', 'Content-Type': 'application/json'}, timeout=120)
    return json.loads(res)


def claim(run_id: str) -> dict | None:
    if not ID.match(run_id):
        raise RuntimeError('bad run id')
    return _post('/internal/sandbox/claim', {'run': run_id, 'nonce': _NONCE}).get('run')


def submit(run_id: str, claim_token: str, report: dict) -> dict:
    return _post('/internal/sandbox/result', {'run': run_id, 'claimToken': claim_token, 'report': report})


def curseforge_files(run_id: str, claim_token: str, ids: list[int]) -> dict:
    """Names, links, SHA-1s and sides of CurseForge files, looked up by the site (which holds the API key)."""
    return _post('/internal/sandbox/curseforge', {'run': run_id, 'claimToken': claim_token, 'files': ids}).get('files') or {}


def resolve(version_id: str, loader: str, game_version: str) -> dict:
    q = urllib.parse.urlencode({'loader': loader, 'gameVersion': game_version})
    return json.loads(request(f'{API}/v1/versions/{version_id}/resolve?{q}', headers={'Accept': 'application/json'}))


def file_url(file_id: str) -> str:
    return f'{API}/v1/download/file/{file_id}'
