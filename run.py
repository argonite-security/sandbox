"""Entry point: python -I run.py <linux|windows|macos> --run <id>"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness import api  # noqa: E402,F401  (reads the identity-token settings and drops them from the environment first)
from harness.session import main  # noqa: E402


def session_class(os_key: str):
    if os_key == 'linux':
        from harness.linux import LinuxSession

        return LinuxSession
    if os_key == 'windows':
        from harness.windows import WindowsSession

        return WindowsSession
    from harness.macos import MacSession

    return MacSession


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('os', choices=['linux', 'windows', 'macos'])
    p.add_argument('--run', required=True)
    p.add_argument('--root', default=None)
    a = p.parse_args()
    default_root = {'linux': '/sbx', 'windows': 'C:/sbx', 'macos': '/Users/Shared/argonite'}[a.os]
    sys.exit(main(a.os, a.run, session_class(a.os), Path(a.root or default_root)))
