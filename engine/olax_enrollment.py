"""Verify another identical OLAX against its own immutable Android backups."""
import hashlib
import json
from pathlib import Path
import re
import struct

STOCK_BOOT = 'aea6db447c55a144af61ad9d28bff920b294c7e7f30605ebc8938175c8f3278d'
BOOT0 = 'ce892a49b8811a097ad10e3b5b5401c7cfae3c5a77295223f123a3beec6deefc'


def load_enrollment(directory):
    directory = Path(directory)
    device = json.loads((directory / 'device.json').read_text())
    manifest = json.loads((directory / 'manifest.json').read_text())
    if (device.get('model') != 't60_extchg_k61' or device.get('locked') != '1' or
        device.get('blockSectors') != '14942208' or
        not re.fullmatch('[a-f0-9]{32}', device.get('cid', ''))):
        raise ValueError('Unsupported enrolled hardware/lock state')
    # Fixed firmware pins plus device-specific data. Never use another modem's seccfg.
    for name, size, pin in [('boot.img', 33554432, STOCK_BOOT),
                            ('mmcblk0boot0.img', 4194304, BOOT0),
                            ('seccfg.img', 8388608, None)]:
        path = directory / name
        if path.is_symlink():
            raise ValueError('Backup symlinks are not allowed')
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != size or manifest[name] != {'bytes': size, 'sha256': digest} or (pin and digest != pin):
            raise ValueError('Backup or firmware hash mismatch: ' + name)
        if name == 'seccfg.img' and struct.unpack('<7I', data[:28]) != (0x4d4d4d4d, 4, 60, 1, 0, 0, 0x45454545):
            raise ValueError('Unsupported seccfg header')
    return {'cid': device['cid'], 'seccfg_sha256': manifest['seccfg.img']['sha256']}
