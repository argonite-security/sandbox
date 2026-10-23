"""Starts a program as another user and group with no extra groups: drop.py <uid> <gid> <cwd> -- <program> [args]
Run by root (through `launchctl asuser`, so the program also gets that user's desktop session)."""
import os
import sys

uid, gid, cwd = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
cmd = sys.argv[sys.argv.index('--') + 1 :]
os.setgroups([])
os.setgid(gid)
os.setuid(uid)
os.chdir(cwd)
os.execvp(cmd[0], cmd)
