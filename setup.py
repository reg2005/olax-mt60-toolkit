#!/usr/bin/env python3
"""Download pinned upstream source and create a local Python environment; no USB I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import venv
import zipfile

ROOT = Path(__file__).resolve().parent


def install_runtime(archive, destination):
    pin = json.loads((ROOT / 'upstream.json').read_text())
    if hashlib.sha256(archive.read_bytes()).hexdigest() != pin['archiveSHA256']:
        raise ValueError('UPSTREAM_HASH: архив mtkclient отличается от закреплённого')
    with zipfile.ZipFile(archive) as z:
        prefix = 'mtkclient-' + pin['commit'] + '/'
        for entry in z.infolist():
            if not entry.filename.startswith(prefix):
                raise ValueError('UPSTREAM_PATH')
            relative = PurePosixPath(entry.filename[len(prefix):])
            if '..' in relative.parts or relative.is_absolute() or '\\' in str(relative):
                raise ValueError('UPSTREAM_PATH')
            if entry.is_dir() or str(relative) == '.':
                continue
            path = destination / str(relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(z.read(entry))
    for name in pin['localPatches']:
        shutil.copy2(ROOT / 'patches' / name, destination / name)
    verify_runtime(destination)


def verify_runtime(destination=None):
    destination = destination or ROOT / '.runtime'
    records = json.loads((ROOT / 'upstream-files.json').read_text())
    for name, digest in records.items():
        path = destination / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('RUNTIME_HASH: ' + name)
    # Extra Python modules could override pinned source, so reject them too.
    for path in (destination / 'mtkclient').rglob('*.py'):
        if path.relative_to(destination).as_posix() not in records:
            raise ValueError('RUNTIME_EXTRA_SOURCE')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='Offline copy of the pinned upstream ZIP')
    parser.add_argument('--skip-doctor', action='store_true', help='Offline CI: skip system libusb/adb availability check')
    args = parser.parse_args()
    if not (3, 10) <= sys.version_info[:2] < (3, 14):
        raise SystemExit('Требуется Python 3.10–3.13; рекомендован 3.12')
    if ROOT.joinpath('.runtime').exists():
        verify_runtime()
    else:
        pin = json.loads((ROOT / 'upstream.json').read_text())
        with tempfile.TemporaryDirectory(prefix='olax-setup-', dir=ROOT) as tmp:
            stage = Path(tmp)
            archive = args.archive or stage / 'upstream.zip'
            if not args.archive:
                url = pin['repository'].replace('https://github.com/', 'https://codeload.github.com/') + '/zip/' + pin['commit']
                print('Загрузка закреплённого mtkclient…', flush=True)
                with urllib.request.urlopen(url, timeout=60) as src, archive.open('wb') as dst:
                    size = 0
                    while chunk := src.read(1024 * 1024):
                        size += len(chunk)
                        if size > 64 * 1024 * 1024:
                            raise ValueError('UPSTREAM_TOO_LARGE')
                        dst.write(chunk)
            runtime = stage / 'runtime'
            runtime.mkdir()
            install_runtime(archive, runtime)
            runtime.rename(ROOT / '.runtime')
    env = ROOT / '.venv'
    if not env.exists():
        venv.EnvBuilder(with_pip=True).create(env)
    python = env / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')], check=True)
    if not args.skip_doctor:
        subprocess.run([str(python), str(ROOT / 'olax.py'), 'doctor'], check=True)
    print('SETUP_OK. Далее enroll → unlock → verify; см. README.md.')


if __name__ == '__main__':
    main()
