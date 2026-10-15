#!/usr/bin/env python3
"""Offline, pinned MT6761 RAM DA candidate. Never communicates with a device."""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA = 'aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f'
DA1_OFFSET, DA1_LENGTH = 0x60168c, 0x3a628
DA2_OFFSET, DA2_LENGTH = 0x63bcbc, 0x513fc
DA2_UNSIGNED_LENGTH = DA2_LENGTH - 0x100
BINDING_OFFSET = 0x2ac0c
BOOT_HASH_ERROR_OFFSET = 0x5488
SOURCE = Path(__file__).resolve().parents[1] / '.runtime/mtkclient/Loader/MTK_DA_V5.bin'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build_candidate(source):
    if sha(source) != SOURCE_SHA:
        raise ValueError('Unreviewed source DA; refuse pattern-based automatic patching')
    da1 = source[DA1_OFFSET:DA1_OFFSET + DA1_LENGTH]
    da2 = source[DA2_OFFSET:DA2_OFFSET + DA2_LENGTH]
    if da2[BOOT_HASH_ERROR_OFFSET:BOOT_HASH_ERROR_OFFSET + 4] != bytes.fromhex('040007c0'):
        raise ValueError('Reviewed BOOT_TO literal mismatch')
    old_digest = hashlib.sha256(da2[:DA2_UNSIGNED_LENGTH]).digest()
    if da1[BINDING_OFFSET:BINDING_OFFSET + 32] != old_digest:
        raise ValueError('DA1 does not bind the exact expected unsigned DA2')
    candidate = bytearray(source)
    error_absolute = DA2_OFFSET + BOOT_HASH_ERROR_OFFSET
    candidate[error_absolute:error_absolute + 4] = bytes(4)
    new_da2 = candidate[DA2_OFFSET:DA2_OFFSET + DA2_LENGTH]
    binding_absolute = DA1_OFFSET + BINDING_OFFSET
    candidate[binding_absolute:binding_absolute + 32] = hashlib.sha256(new_da2[:DA2_UNSIGNED_LENGTH]).digest()
    changed = [i for i, (old, new) in enumerate(zip(source, candidate)) if old != new]
    allowed = set(range(error_absolute, error_absolute + 4)) | set(range(binding_absolute, binding_absolute + 32))
    if not set(changed) <= allowed or len(candidate) != len(source):
        raise ValueError('Unexpected candidate differences')
    manifest = {
        'purpose': 'RAM-only DA2 BOOT_TO checksum status; no flash writes or security policy patches',
        'source_sha256': sha(source), 'candidate_sha256': sha(candidate), 'length': len(candidate),
        'live_hardware': {'hwcode': '0x717', 'subcode': '0x8a00', 'hwver': '0xca01', 'swver': '0x200'},
        'source_da_entry': 20, 'da_code': '0x6761',
        'da1': {'offset': DA1_OFFSET, 'length': DA1_LENGTH, 'sha256_before': sha(da1),
                'sha256_after': sha(candidate[DA1_OFFSET:DA1_OFFSET + DA1_LENGTH])},
        'da2': {'offset': DA2_OFFSET, 'length': DA2_LENGTH, 'unsigned_length': DA2_UNSIGNED_LENGTH,
                'sha256_before': sha(da2), 'sha256_after': sha(new_da2)},
        'edits': [
            {'stage': 'DA2', 'stage_offset': BOOT_HASH_ERROR_OFFSET, 'container_offset': error_absolute,
             'before': '040007c0', 'after': '00000000', 'meaning': 'BOOT_TO mismatch result literal only'},
            {'stage': 'DA1', 'stage_offset': BINDING_OFFSET, 'container_offset': binding_absolute,
             'before': old_digest.hex(), 'after': hashlib.sha256(new_da2[:DA2_UNSIGNED_LENGTH]).hexdigest(),
             'meaning': 'Rebind SHA256 of modified unsigned DA2; no DA1 code change'}],
        'changed_byte_count': len(changed), 'changed_byte_offsets': changed,
        'da_signature_bytes_unchanged': True,
        'qualification': 'Preloader acceptance of changed unsigned binding remains device-unverified; requires all protection flags false',
    }
    return bytes(candidate), manifest


def validate_candidate(path):
    expected, manifest = build_candidate(SOURCE.read_bytes())
    if path.read_bytes() != expected:
        raise ValueError('Candidate differs from exact reviewed RAM DA recipe')
    return manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    candidate, manifest = build_candidate(SOURCE.read_bytes())
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (a.output / 'MTK_DA_V5-OLAX-RAM.bin').write_bytes(candidate)
    (a.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
