"""Fetch public AOSP test material, pinned by SHA256. No private signing key."""
import base64
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent / 'vendor'


def main():
    for name, record in json.loads((ROOT/'sources.json').read_text()).items():
        path = ROOT/name
        if not path.exists():
            with urllib.request.urlopen(record['url'], timeout=30) as response:
                encoded = response.read(1024 * 1024)
            data = base64.b64decode(encoded, validate=True)
            if hashlib.sha256(data).hexdigest() != record['sha256']:
                raise ValueError('AOSP hash mismatch: ' + name)
            path.write_bytes(data)
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('AOSP hash mismatch: ' + name)
    print('AOSP_PUBLIC_TEST_MATERIAL_VERIFIED')


if __name__ == '__main__':
    main()
