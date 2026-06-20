#!/usr/bin/env python3
"""Upload demo/public → REG.RU FTP (Linux-compatible)."""
import ftplib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent / 'public'
SKIP = {'.htpasswd', '.htpasswd.example'}
HOSTS = ['31.31.197.50', 'server299.hosting.reg.ru']
USER = os.environ.get('FTP_USER', 'u3548413')
PASS = os.environ.get('FTP_PASS') or os.environ.get('REG_RU_FTP_PASS')


def walk_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for name in filenames:
            if name in SKIP:
                continue
            full = Path(dirpath) / name
            rel = full.relative_to(ROOT).as_posix()
            yield rel, full


def ensure_dirs(ftp: ftplib.FTP, rel_path: str) -> None:
    parts = rel_path.split('/')[:-1]
    if not parts:
        return
    ftp.cwd('/')
    for part in parts:
        try:
            ftp.cwd(part)
        except ftplib.error_perm:
            ftp.mkd(part)
            ftp.cwd(part)


def upload(host: str) -> bool:
    files = list(walk_files())
    ftp = ftplib.FTP(timeout=120)
    ftp.connect(host, 21)
    ftp.login(USER, PASS)
    print(f'Connected to {host}, pwd={ftp.pwd()}')

    ok = 0
    for rel, local in files:
        ensure_dirs(ftp, rel)
        ftp.cwd('/')
        with open(local, 'rb') as fh:
            ftp.storbinary(f'STOR {rel}', fh)
        ok += 1
        print(f'  ↑ {rel}')

    ftp.quit()
    print(f'\nOK: {ok} files → {USER}@{host}/')
    return True


def main() -> int:
    if not PASS:
        print('Set FTP_PASS or REG_RU_FTP_PASS', file=sys.stderr)
        return 1

    last_err = None
    for host in HOSTS:
        try:
            upload(host)
            return 0
        except Exception as exc:
            last_err = exc
            print(f'Failed on {host}: {exc}', file=sys.stderr)

    print(f'FTP upload failed: {last_err}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
