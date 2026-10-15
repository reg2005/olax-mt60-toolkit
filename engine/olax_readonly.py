#!/usr/bin/env python3
"""OLAX flash-read-only diagnostics; optional unchanged SEJ verification in RAM."""
import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import portable_alarm as signal
from runtime_support import usb_backend
import struct
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

ALLOWED = {0x0e8d: {0x2000: -1, 0x0003: -1}}
EXPECTED_HWCODE = 0x717
MAX_SECCFG = 8 * 1024 * 1024
ORIGINAL_SECCFG_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"


class PolicyError(BaseException):
    # Upstream catches Exception around fallbacks; policy violations must escape.
    pass


def denied(*args, **kwargs):
    raise PolicyError("Operation prohibited by OLAX stock read-only policy")


def is_allowed(device):
    return device.idVendor == 0x0e8d and device.idProduct in ALLOWED[0x0e8d]


def filtered_find(original):
    def find(*args, **kwargs):
        if args:
            raise PolicyError("Positional USB discovery is forbidden")
        supplied = kwargs.pop('custom_match', None)
        want_all = kwargs.pop('find_all', False)
        devices = list(original(find_all=True, **kwargs))
        eligible = [d for d in devices if is_allowed(d)]
        if len(eligible) > 1:
            raise PolicyError('More than one eligible MediaTek device; disconnect the others')
        matched = [d for d in eligible if supplied is None or supplied(d)]
        return iter(matched) if want_all else (matched[0] if matched else None)
    return find


def inspect_seccfg(data):
    if len(data) < 512 or len(data) > MAX_SECCFG:
        raise PolicyError("Unexpected seccfg length")
    magic, version, size, lock, verity, runtime, end = struct.unpack('<7I', data[:28])
    if (magic, version, size, end) != (0x4d4d4d4d, 4, 60, 0x45454545):
        raise PolicyError("Unsupported seccfg header")
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'version': version, 'lock_state': lock, 'dm_verity': verity,
            'sboot_runtime': runtime, 'crypto_verified': False}


def unchanged_roundtrip(data, decrypt, encrypt):
    """Validate original bytes only. Never construct a changed lock state."""
    report = inspect_seccfg(data)
    digest = hashlib.sha256(data[:28]).digest()
    if decrypt(data[28:60]) != digest:
        raise PolicyError("Original seccfg checksum did not validate")
    if encrypt(digest) != data[28:60]:
        raise PolicyError("Unchanged seccfg encryption did not reproduce original bytes")
    report['crypto_verified'] = True
    return report


def inspect_offline(data):
    from mtkclient.Library.Hardware.hwcrypto_sej import Sej
    report = inspect_seccfg(data)
    try:
        report = unchanged_roundtrip(data, lambda b: Sej.sej_sec_cfg_sw(b, False),
                                     lambda b: Sej.sej_sec_cfg_sw(b, True))
        report['crypto_method'] = 'SW'
    except PolicyError:
        report['crypto_method'] = 'not SW; hardware verification unavailable in stock read mode'
    return report


def install_guards(stack):
    """Guards last for this process and cover reconnects and DA dispatch layers."""
    import usb.core
    from mtkclient.Library import mtk_class
    from mtkclient.Library.Connection.usblib import UsbClass
    from mtkclient.Library.mtk_preloader import Preloader
    from mtkclient.Library.DA.mtk_daloader import DAloader
    from mtkclient.Library.DA.xflash.xflash_lib import DAXFlash
    from mtkclient.Library.DA.legacy.dalegacy_lib import DALegacy
    from mtkclient.Library.DA.xmlflash.xml_lib import DAXML
    from mtkclient.Library.DA.xflash.extension.xflash import XFlashExt
    from mtkclient.Library.DA.legacy.extension.legacy import LegacyExt
    from mtkclient.Library.DA.xmlflash.extension.v6 import XmlFlashExt
    from mtkclient.config.mtk_config import MtkConfig
    native_write = Preloader.write
    capabilities = {'preloader_read': Preloader.read32,
                    'preloader_write': lambda pl, addr, value: native_write(pl, addr, value, 32),
                    'build_extension': XFlashExt.patch,
                    'read_register': XFlashExt.custom_readregister,
                    'write_register': XFlashExt.custom_writeregister}
    stack.enter_context(patch.object(usb.core, 'find', filtered_find(usb.core.find)))
    stack.enter_context(patch.object(mtk_class, 'default_ids', ALLOWED))
    original_connect = UsbClass.connect
    def connect(self, *args, **kwargs):
        self.portconfig = {v: dict(p) for v, p in ALLOWED.items()}
        return original_connect(self, *args, **kwargs)
    stack.enter_context(patch.object(UsbClass, 'connect', connect))
    original_hwcode = MtkConfig.init_hwcode
    def hwcode(self, code):
        if code != EXPECTED_HWCODE:
            raise PolicyError(f"Unexpected hardware code {code:#x}; expected 0x717")
        return original_hwcode(self, code)
    stack.enter_context(patch.object(MtkConfig, 'init_hwcode', hwcode))
    blocked = {
        mtk_class.Mtk: ('bypass_security', 'crasher', 'patch_preloader_security_da1', 'patch_preloader_security_da2'),
        Preloader: ('reset_to_brom', 'write', 'write16', 'write32', 'writemem',
                    'send_partition_data', 'handle_sla'),
        DAloader: ('writeflash', 'formatflash', 'seccfg', 'poke', 'keys', 'keyserver', 'setmetamode'),
        DAXFlash: ('writeflash', 'formatflash', 'cmd_write_data', 'patch_da', 'handle_sla'),
        DALegacy: ('writeflash', 'formatflash'),
        DAXML: ('writeflash', 'formatflash'),
    }
    for cls in (XFlashExt, LegacyExt, XmlFlashExt):
        blocked[cls] = tuple(n for n in dir(cls) if any(s in n.lower() for s in
            ('write', 'erase', 'seccfg', 'patch', 'auth_rpmb', 'custom_rpmb_init')))
    for cls, names in blocked.items():
        for name in names:
            if hasattr(cls, name):
                stack.enter_context(patch.object(cls, name, denied))
    original_set_da = DAloader.set_da
    def set_da(self):
        original_set_da(self)
        if type(self.da) is not DAXFlash:
            raise PolicyError('Only reviewed MT6761 XFLASH stock protocol is permitted')
    stack.enter_context(patch.object(DAloader, 'set_da', set_da))
    original_upload = DAXFlash.upload_da
    def upload(self):
        if not self.config.stock or self.mtk.daloader.patch:
            raise PolicyError('Only unpatched stock DA is permitted')
        self.kamakiri_pl = self.carbonara = None
        return original_upload(self)
    stack.enter_context(patch.object(DAXFlash, 'upload_da', upload))
    return capabilities


def read_partition(mtk):
    found, part = mtk.daloader.detect_partition('seccfg', parttype='user')
    if not found:
        raise PolicyError('seccfg partition not found')
    pagesize = mtk.daloader.daconfig.pagesize
    length = part.sectors * pagesize
    if length != MAX_SECCFG or part.sector < 34:
        raise PolicyError('Unexpected seccfg GPT bounds')
    data = mtk.daloader.readflash(addr=part.sector * pagesize, length=length,
                                filename='', parttype='user', display=False)
    if not isinstance(data, (bytes, bytearray)) or len(data) != length:
        raise PolicyError('Incomplete seccfg read')
    return bytes(data)


def require_unprotected(config):
    flags = config.target_config
    required = {'sbc', 'sla', 'daa', 'epp', 'cert', 'memread', 'memwrite', 'cmdC8'}
    if config.hwcode != EXPECTED_HWCODE or not isinstance(flags, dict) or set(flags) != required:
        raise PolicyError('Unrecognized hardware/security configuration')
    if any(value is not False for value in flags.values()):
        raise PolicyError('RAM extension permitted only on confirmed unprotected target')


def register_access(extension, capabilities):
    from mtkclient.Library.Hardware.hwcrypto_sej import regval
    allowed = {0x1000a000 + offset for offset in regval.values()}
    def read(addr):
        if addr not in allowed:
            raise PolicyError('SEJ read outside reviewed register map')
        result = capabilities['read_register'](extension, addr, 1)
        if not isinstance(result, int):
            raise PolicyError('SEJ register read failed')
        return result
    def write(addr, value):
        if addr not in allowed or not isinstance(value, int) or not 0 <= value <= 0xffffffff:
            raise PolicyError('SEJ write outside reviewed register map')
        if capabilities['write_register'](extension, addr, value) is not True:
            raise PolicyError('SEJ register write failed')
        return True
    return read, write


def preloader_hardware_roundtrip(mtk, reference, capabilities):
    from mtkclient.Library.Hardware.hwcrypto_sej import Sej
    require_unprotected(mtk.config)
    if mtk.config.is_brom:
        raise PolicyError('This reviewed native path requires preloader mode')
    if len(reference) != MAX_SECCFG or hashlib.sha256(reference).hexdigest() != ORIGINAL_SECCFG_SHA256:
        raise PolicyError('Native SEJ check requires the pinned original OLAX backup')
    if mtk.config.chipconfig.sej_base != 0x1000a000:
        raise PolicyError('Unexpected SEJ base')
    # The capability shares the same exact HACC map as the DA extension path.
    native_caps = {
        'read_register': lambda pl, addr, words: capabilities['preloader_read'](pl, addr, words),
        'write_register': capabilities['preloader_write'],
    }
    read, write = register_access(mtk.preloader, native_caps)
    # Probe read access before touching any hardware register.
    read(0x1000a000)
    setup = SimpleNamespace(hwcode=EXPECTED_HWCODE, sej_base=0x1000a000, read32=read, write32=write)
    report = verify_variants(reference, Sej(setup, loglevel=logging.WARNING))
    report['crypto_transport'] = 'native preloader READ32/WRITE32; exact SEJ registers only'
    report['flash_recheck_pending'] = True
    return report


def verify_variants(data, sej):
    report = inspect_seccfg(data)
    digest = hashlib.sha256(data[:28]).digest()
    ciphertext = data[28:60]
    variants = (
        ('SW', lambda b, enc: sej.sej_sec_cfg_sw(b, enc)),
        ('V3', lambda b, enc: sej.sej_sec_cfg_hw_V3(b, enc, legacy=False)),
        ('V4', lambda b, enc: sej.sej_sec_cfg_hw_V3(b, enc, legacy=True)),
        ('V2', lambda b, enc: sej.sej_sec_cfg_hw(b, enc)),
    )
    report['crypto_attempts'] = []
    matches = []
    for name, transform in variants:
        decrypted = bytes(transform(ciphertext, False))
        decrypt_matches = decrypted == digest
        reproduced = bytes(transform(digest, True)) if decrypt_matches else None
        reproduced_matches = reproduced == ciphertext
        report['crypto_attempts'].append({'method': name, 'decrypt_matches': decrypt_matches,
                                         'unchanged_encrypt_matches': reproduced_matches})
        if decrypt_matches and reproduced_matches:
            matches.append(name)
    report['crypto_verified'] = bool(matches)
    report['crypto_methods'] = matches
    return report


def hardware_roundtrip(mtk, data, reference, capabilities):
    from mtkclient.Library.DA.xflash.extension.xflash import XCmd
    from mtkclient.Library.Hardware.hwcrypto_sej import Sej
    require_unprotected(mtk.config)
    inspect_seccfg(data)
    if data != reference:
        raise PolicyError('Original seccfg must exactly match reference before RAM extension')
    if mtk.config.chipconfig.sej_base != 0x1000a000:
        raise PolicyError('Unexpected SEJ base')
    da, extension = mtk.daloader.da, mtk.daloader.xft
    # Resolve the upstream extension into RAM; never patch DA1/DA2 or flash.
    payload = capabilities['build_extension'](extension)
    if not payload:
        raise PolicyError('No RAM extension payload')
    from mtkclient.config.payloads import PathConfig
    template = (Path(PathConfig().get_payloads_path()) / 'da_x.bin').read_bytes()
    marker = template.find(bytes.fromhex('11111111'))
    pointer = int.from_bytes(payload[marker:marker + 4], 'little') if marker >= 0 else 0
    base = extension.da2address
    if not pointer & 1 or not base <= (pointer & ~1) < base + len(extension.da2):
        raise PolicyError('Stock DA has no valid resolved extension registration function')
    if not da.boot_to(addr=da.extensions_address, da=payload):
        raise PolicyError('Stock DA refused RAM extension; no patch fallback attempted')
    ack = da.send_devctrl(XCmd.CUSTOM_ACK)
    if da.status() != 0 or ack != bytes.fromhex('a4a3a2a1'):
        raise PolicyError('RAM extension acknowledgement failed')
    read, write = register_access(extension, capabilities)
    setup = SimpleNamespace(hwcode=EXPECTED_HWCODE, sej_base=0x1000a000,
                            read32=read, write32=write)
    report = verify_variants(data, Sej(setup, loglevel=logging.WARNING))
    report['extension_sha256'] = hashlib.sha256(payload).hexdigest()
    report['flash_unchanged_after_crypto'] = read_partition(mtk) == data
    if not report['flash_unchanged_after_crypto']:
        raise PolicyError('Post-verification read differs from original seccfg')
    return report


def validate_ram_target(config):
    require_unprotected(config)
    if config.is_brom or (config.hw_sub_code, config.hwver, config.swver) != (0x8a00, 0xca01, 0x200):
        raise PolicyError('RAM DA candidate requires the exact reviewed preloader target')


def resume_preloader(mtk, directory):
    # Skip only the already-completed sync bytes; init still re-reads all identity,
    # version and target-security responses, including GET_HW_CODE before upload.
    mtk.port.cdc.devclass = 0x0a
    if not mtk.port.cdc.connect():
        raise PolicyError('Reviewed USB preloader not present for resume')
    with patch.object(mtk.port, 'handshake', return_value=True):
        if not mtk.preloader.init(display=False, directory=str(directory)):
            raise PolicyError('Already-handshaken preloader did not answer fresh identification')


def finish_da_session(mtk, report, output):
    # Bound cleanup independently, even after the main session timeout expired.
    signal.alarm(10)
    report['android_boot_confirmed'] = False
    try:
        report['da_shutdown_accepted'] = bool(mtk.daloader.shutdown(bootmode=1))
    except (PolicyError, Exception) as exc:
        report['da_shutdown_accepted'] = False
        report['shutdown_error'] = str(exc)
    finally:
        signal.alarm(0)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


def record_service_retained(report, output):
    # Explicit coordinator request: skip shutdown, do not claim USB still answers.
    report['da_shutdown_skipped'] = True
    report['android_boot_confirmed'] = False
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


def live(args):
    ram_manifest = None
    if args.command == 'verify-ram-da-hw':
        from olax_ram_da import validate_candidate
        try:
            ram_manifest = validate_candidate(args.loader)
        except ValueError as exc:
            raise PolicyError(str(exc))
    # Exclusive directory creation prevents state reuse and backup overwrite.
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.umask(0o077)
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.config.mtk_config import MtkConfig
    from mtkclient.Library.Partitions.gpt import GptSettings
    import usb.backend.libusb1
    backend = usb_backend(args.libusb)
    if backend is None:
        raise PolicyError('libusb backend unavailable')
    with ExitStack() as stack:
        capabilities = install_guards(stack)
        config = MtkConfig(loglevel=logging.WARNING)
        config.stock = True
        config.skipwdt = True
        config.reconnect = False
        config.hwparam_path = str(args.output)
        config.gpt_settings = GptSettings(0, 0, 0)
        if args.loader:
            config.loader = str(args.loader.resolve())
        if args.preloader:
            config.preloader = args.preloader.read_bytes()
        mtk = Mtk(config, loglevel=logging.WARNING)
        mtk.port.cdc.backend = backend
        stack.callback(mtk.port.close)
        def timeout(signum, frame):
            raise PolicyError('Read-only session timeout; no write or erase was requested')
        old_handler = signal.signal(signal.SIGALRM, timeout)
        stack.callback(signal.signal, signal.SIGALRM, old_handler)
        stack.callback(signal.alarm, 0)
        signal.alarm(args.timeout)
        if args.resume_preloader:
            resume_preloader(mtk, args.output)
        elif not mtk.preloader.init(display=False, directory=str(args.output)):
            raise PolicyError('Stock handshake failed')
        if ram_manifest is not None:
            validate_ram_target(config)
        report = {'hwcode': hex(config.hwcode), 'is_brom': config.is_brom,
                  'target_config': config.target_config, 'stock': ram_manifest is None}
        if ram_manifest is not None:
            report['ram_da_manifest'] = ram_manifest
        (args.output / 'handshake.json').write_text(json.dumps(report, indent=2) + '\n')
        native_report = None
        if args.command == 'verify-preloader-hw':
            native_report = preloader_hardware_roundtrip(mtk, args.reference.read_bytes(), capabilities)
            report.update(native_report)
            (args.output / 'native-crypto.json').write_text(json.dumps(report, indent=2) + '\n')
        if args.command in ('read-seccfg', 'verify-hw', 'verify-preloader-hw', 'verify-ram-da-hw'):
            # Never call DaHandler.configure_da: it has automatic fallback paths.
            if not mtk.daloader.upload_da(preloader=config.preloader):
                raise PolicyError('Stock DA rejected/unavailable; no bypass attempted')
            if args.keep_service:
                stack.callback(record_service_retained, report, args.output)
            else:
                stack.callback(finish_da_session, mtk, report, args.output)
            data = read_partition(mtk)
            report.update(inspect_offline(data))
            (args.output / 'seccfg.bin').write_bytes(data)
            if args.reference:
                report['reference_matches'] = data == args.reference.read_bytes()
                if not report['reference_matches']:
                    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
                    raise PolicyError('Read differs from reference; saved for investigation')
            if native_report is not None:
                report.update(native_report)
                report['flash_recheck_pending'] = False
                report['flash_unchanged_after_crypto'] = report['reference_matches']
                if not report['crypto_verified']:
                    raise PolicyError('No native SEJ variant reproduced the unchanged seccfg')
            if args.command in ('verify-hw', 'verify-ram-da-hw'):
                report.update(hardware_roundtrip(mtk, data, args.reference.read_bytes(), capabilities))
                if not report['crypto_verified']:
                    raise PolicyError('No hardware variant reproduced the unchanged seccfg')
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    offline = sub.add_parser('inspect', help='Offline structure/SW unchanged roundtrip only; no USB')
    offline.add_argument('image', type=Path)
    for name in ('handshake', 'read-seccfg', 'verify-hw', 'verify-preloader-hw', 'verify-ram-da-hw'):
        p = sub.add_parser(name)
        p.add_argument('--output', type=Path, required=True, help='New private directory, must not exist')
        p.add_argument('--timeout', type=int, default=90)
        p.add_argument('--libusb', type=Path, default=None)
        p.add_argument('--loader', type=Path)
        p.add_argument('--preloader', type=Path)
        p.add_argument('--reference', type=Path)
        p.add_argument('--keep-service', action='store_true',
                       help='Only verify-ram-da-hw: skip DA shutdown for coordinator continuation')
        p.add_argument('--resume-preloader', action='store_true',
                       help='Only verify-ram-da-hw: explicitly resume a previously handshaken preloader')
    args = parser.parse_args()
    try:
        if args.command == 'inspect':
            print(json.dumps(inspect_offline(args.image.read_bytes()), indent=2))
        else:
            if not 1 <= args.timeout <= 300:
                parser.error('timeout must be 1..300 seconds')
            if args.keep_service and args.command != 'verify-ram-da-hw':
                parser.error('--keep-service requires verify-ram-da-hw')
            if args.resume_preloader and args.command != 'verify-ram-da-hw':
                parser.error('--resume-preloader requires verify-ram-da-hw')
            if args.command == 'verify-ram-da-hw' and args.loader is None:
                parser.error('verify-ram-da-hw requires the reviewed --loader artifact')
            if args.command in ('verify-hw', 'verify-preloader-hw', 'verify-ram-da-hw') and args.reference is None:
                parser.error('Hardware verification requires the original --reference')
            for file in (args.loader, args.preloader, args.reference):
                if file and not file.is_file():
                    parser.error(f'Input file does not exist: {file}')
            live(args)
    except (PolicyError, OSError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
