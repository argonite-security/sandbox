"""Windows: start a program without administrator rights (admin group disabled, medium integrity)
inside a job object, so it can't turn off the firewall or the auditing, can't reach into the
runner's own elevated processes, and everything it starts can be listed and killed together."""
from __future__ import annotations

import ctypes
import ctypes.wintypes as w
import msvcrt
import os
import subprocess

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
adv = ctypes.WinDLL('advapi32', use_last_error=True)

H, D, B, P = w.HANDLE, w.DWORD, w.BOOL, ctypes.c_void_p
for fn, res, args in (
    (k32.GetCurrentProcess, H, []),
    (k32.CloseHandle, B, [H]),
    (k32.CreateJobObjectW, H, [P, w.LPCWSTR]),
    (k32.SetInformationJobObject, B, [H, ctypes.c_int, P, D]),
    (k32.QueryInformationJobObject, B, [H, ctypes.c_int, P, D, P]),
    (k32.AssignProcessToJobObject, B, [H, H]),
    (k32.TerminateJobObject, B, [H, ctypes.c_uint]),
    (k32.ResumeThread, D, [H]),
    (k32.WaitForSingleObject, D, [H, D]),
    (k32.GetExitCodeProcess, B, [H, ctypes.POINTER(D)]),
    (k32.OpenProcess, H, [D, B, D]),
    (k32.QueryFullProcessImageNameW, B, [H, D, w.LPWSTR, ctypes.POINTER(D)]),
    (k32.CreateProcessW, B, [w.LPCWSTR, w.LPWSTR, P, P, B, D, P, w.LPCWSTR, P, P]),
    (adv.OpenProcessToken, B, [H, D, ctypes.POINTER(H)]),
    (adv.ConvertStringSidToSidW, B, [w.LPCWSTR, ctypes.POINTER(P)]),
    (adv.GetLengthSid, D, [P]),
    (adv.CreateRestrictedToken, B, [H, D, D, P, D, P, D, P, ctypes.POINTER(H)]),
    (adv.SetTokenInformation, B, [H, ctypes.c_int, P, D]),
    (adv.CreateProcessAsUserW, B, [H, w.LPCWSTR, w.LPWSTR, P, P, B, D, P, w.LPCWSTR, P, P]),
):
    fn.restype, fn.argtypes = res, args

TOKEN_ACCESS = 0x0001 | 0x0002 | 0x0008 | 0x0080 | 0x0100  # assign primary, duplicate, query, adjust default, adjust session
DISABLE_MAX_PRIVILEGE, LUA_TOKEN = 0x1, 0x4
SE_GROUP_INTEGRITY = 0x20
TOKEN_INTEGRITY_LEVEL = 25
CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CREATE_NO_WINDOW = 0x4, 0x400, 0x08000000
STARTF_USESTDHANDLES = 0x100
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_EXTENDED_LIMIT_INFORMATION, JOB_BASIC_PROCESS_ID_LIST = 9, 3


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Sid', ctypes.c_void_p), ('Attributes', w.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [('Label', SID_AND_ATTRIBUTES)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb', w.DWORD), ('lpReserved', w.LPWSTR), ('lpDesktop', w.LPWSTR), ('lpTitle', w.LPWSTR),
        ('dwX', w.DWORD), ('dwY', w.DWORD), ('dwXSize', w.DWORD), ('dwYSize', w.DWORD),
        ('dwXCountChars', w.DWORD), ('dwYCountChars', w.DWORD), ('dwFillAttribute', w.DWORD), ('dwFlags', w.DWORD),
        ('wShowWindow', w.WORD), ('cbReserved2', w.WORD), ('lpReserved2', ctypes.c_void_p),
        ('hStdInput', w.HANDLE), ('hStdOutput', w.HANDLE), ('hStdError', w.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', w.HANDLE), ('hThread', w.HANDLE), ('dwProcessId', w.DWORD), ('dwThreadId', w.DWORD)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ('r', 'w', 'o', 'rb', 'wb', 'ob')]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('PerProcessUserTimeLimit', ctypes.c_int64), ('PerJobUserTimeLimit', ctypes.c_int64), ('LimitFlags', w.DWORD),
        ('MinimumWorkingSetSize', ctypes.c_size_t), ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', w.DWORD),
        ('Affinity', ctypes.c_size_t), ('PriorityClass', w.DWORD), ('SchedulingClass', w.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION), ('IoInfo', IO_COUNTERS),
        ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
        ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t),
    ]


def _check(ok, what: str):
    if not ok:
        raise OSError(ctypes.get_last_error(), f'{what} failed')
    return ok


def _sid(text: str) -> ctypes.c_void_p:
    sid = ctypes.c_void_p()
    _check(adv.ConvertStringSidToSidW(w.LPCWSTR(text), ctypes.byref(sid)), 'ConvertStringSidToSid')
    return sid


def restricted_token() -> w.HANDLE:
    own = w.HANDLE()
    _check(adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_ACCESS, ctypes.byref(own)), 'OpenProcessToken')
    admins = SID_AND_ATTRIBUTES(_sid('S-1-5-32-544'), 0)
    new = w.HANDLE()
    _check(adv.CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 1, ctypes.byref(admins), 0, None, 0, None, ctypes.byref(new)), 'CreateRestrictedToken')
    label = TOKEN_MANDATORY_LABEL(SID_AND_ATTRIBUTES(_sid('S-1-16-8192'), SE_GROUP_INTEGRITY))
    _check(adv.SetTokenInformation(new, TOKEN_INTEGRITY_LEVEL, ctypes.byref(label), ctypes.sizeof(label) + adv.GetLengthSid(label.Label.Sid)), 'SetTokenInformation')
    k32.CloseHandle(own)
    return new


def _job() -> w.HANDLE:
    job = _check(k32.CreateJobObjectW(None, None), 'CreateJobObject')
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    _check(k32.SetInformationJobObject(job, JOB_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)), 'SetInformationJobObject')
    return job


class WinProc:
    """A started program and its job: poll(), kill(), pids(), stdin."""

    def __init__(self, cmd: list[str], cwd: str, env: dict[str, str], log_path: str, restricted: bool = True):
        self.log = open(log_path, 'wb')
        out_h = msvcrt.get_osfhandle(self.log.fileno())
        os.set_handle_inheritable(out_h, True)
        r, wfd = os.pipe()
        in_h = msvcrt.get_osfhandle(r)
        os.set_handle_inheritable(in_h, True)
        self.stdin = os.fdopen(wfd, 'wb', buffering=0)
        self.job = _job()
        self.restricted = restricted
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.dwFlags = STARTF_USESTDHANDLES
        si.hStdInput, si.hStdOutput, si.hStdError = in_h, out_h, out_h
        pi = PROCESS_INFORMATION()
        block = ctypes.create_unicode_buffer(''.join(f'{k}={v}\0' for k, v in sorted(env.items())) + '\0')
        line = ctypes.create_unicode_buffer(subprocess.list2cmdline(cmd))
        flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
        if restricted:
            token = restricted_token()
            _check(adv.CreateProcessAsUserW(token, None, line, None, None, True, flags, block, cwd, ctypes.byref(si), ctypes.byref(pi)), 'CreateProcessAsUser')
            k32.CloseHandle(token)
        else:
            _check(k32.CreateProcessW(None, line, None, None, True, flags, block, cwd, ctypes.byref(si), ctypes.byref(pi)), 'CreateProcess')
        os.close(r)
        _check(k32.AssignProcessToJobObject(self.job, pi.hProcess), 'AssignProcessToJobObject')
        k32.ResumeThread(pi.hThread)
        k32.CloseHandle(pi.hThread)
        self.handle = pi.hProcess
        self.pid = pi.dwProcessId

    def poll(self) -> int | None:
        if k32.WaitForSingleObject(self.handle, 0) != 0:
            return None
        code = w.DWORD()
        k32.GetExitCodeProcess(self.handle, ctypes.byref(code))
        return code.value

    def pids(self) -> list[int]:
        n = 1024

        class LIST(ctypes.Structure):
            _fields_ = [('assigned', w.DWORD), ('listed', w.DWORD), ('ids', ctypes.c_size_t * n)]

        lst = LIST()
        if not k32.QueryInformationJobObject(self.job, JOB_BASIC_PROCESS_ID_LIST, ctypes.byref(lst), ctypes.sizeof(lst), None):
            return []
        return [int(lst.ids[i]) for i in range(min(lst.listed, n))]

    def kill(self) -> None:
        k32.TerminateJobObject(self.job, 1)
        k32.WaitForSingleObject(self.handle, 10_000)
        try:
            self.stdin.close()
        except OSError:
            pass
        self.log.close()


def image_name(pid: int) -> str | None:
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = w.DWORD(1024)
        return buf.value if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) else None
    finally:
        k32.CloseHandle(h)
