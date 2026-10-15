#!/usr/bin/env python3
"""Coordinator-only seccfg sector transaction on the already verified running DA."""
import argparse
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import json
import logging
import os
from pathlib import Path
import portable_alarm as signal
from runtime_support import usb_backend, durable_report
import time
from types import SimpleNamespace
from unittest.mock import patch

from olax_readonly import (PolicyError, install_guards, register_access,
                           read_partition, validate_ram_target)
from olax_ram_da import validate_candidate
from olax_seccfg_plan import build_unlock_plan, ORIGINAL_SHA256, IMAGE_SIZE
from olax_seccfg_apply import apply_unlock_plan


class SectorWriteError(RuntimeError):
    pass


def checked_geometry(mtk):
    found, part = mtk.daloader.detect_partition('seccfg', parttype='user')
    if not found or part.name.lower() != 'seccfg':
        raise PolicyError('Exact seccfg GPT entry missing')
    if mtk.daloader.daconfig.pagesize != 512 or part.sectors != IMAGE_SIZE // 512:
        raise PolicyError('Unexpected seccfg size or sector size')
    start = part.sector * 512
    if start < 34 * 512 or start + IMAGE_SIZE > mtk.daloader.da.emmc.user_size:
        raise PolicyError('seccfg is outside validated user storage')
    return start, IMAGE_SIZE


def checked_identity(da, profile):
    chip = da.chipid
    if chip is None or (chip.hw_code, chip.hw_sub_code, chip.hw_version, chip.sw_version) != (0x717, 0x8a00, 0xca01, 0x200):
        raise PolicyError('Running DA hardware identity differs from reviewed target')
    emmc = da.emmc
    if emmc is None or emmc.type == 0 or emmc.block_size != 512 or emmc.user_size != 0x1c8000000:
        raise PolicyError('Running DA eMMC geometry differs from reviewed target')
    if profile.get('hwcode') != '0x717' or emmc.cid.hex() != profile.get('cid'):
        raise PolicyError('Running DA eMMC CID differs from recorded owner device')


def sector_writer(da, start, candidate, original, raw_write, raw_command, check_geometry, on_attempt=lambda n: None):
    """Only candidate once, then original once; every low-level command is scoped."""
    attempts = 0
    def write(sector):
        nonlocal attempts
        expected = candidate if attempts == 0 else original
        if attempts >= 2 or type(sector) is not bytes or len(sector) != 512 or sector != expected:
            raise PolicyError('Unexpected sector data or repeated transaction')
        if check_geometry() != (start, IMAGE_SIZE):
            raise PolicyError('GPT geometry changed before sector write')
        attempts += 1
        on_attempt(attempts)
        commands = 0
        def command(addr, size, storage=1, parttype=8):
            nonlocal commands
            if commands != 0 or (addr, size, storage, parttype) != (start, 512, 1, 8):
                raise PolicyError('Low-level flash command outside single seccfg sector')
            commands += 1
            return raw_command(da, addr=addr, size=size, storage=storage, parttype=parttype)
        with patch.object(da, 'cmd_write_data', command):
            result = raw_write(da, addr=start, length=512, filename='', offset=0,
                               parttype='user', wdata=sector, display=False)
        if commands != 1:
            raise SectorWriteError('Writer did not issue exactly one scoped command')
        return result
    return write


def checked_prior(report, profile, candidate_manifest, expected_hash=None):
    if (report.get('hwcode') != '0x717' or report.get('is_brom') is not False or
        report.get('sha256') != (expected_hash or ORIGINAL_SHA256) or report.get('crypto_methods') != ['V4'] or
        report.get('crypto_verified') is not True or report.get('reference_matches') is not True or
        report.get('flash_unchanged_after_crypto') is not True or report.get('da_shutdown_skipped') is not True or
        report.get('ram_da_manifest', {}).get('candidate_sha256') != candidate_manifest['candidate_sha256']):
        raise PolicyError('Prior verified RAM DA session is not the expected one')
    if profile.get('hwcode') != '0x717' or not isinstance(profile.get('cid'), str) or len(profile['cid']) != 32:
        raise PolicyError('Missing recorded eMMC identity')


def execute(args):
    manifest = validate_candidate(args.loader)
    if not getattr(args, 'enrollment', None):
        raise PolicyError('Device enrollment is required')
    enrollment = None
    expected_hash = ORIGINAL_SHA256
    if getattr(args, 'enrollment', None):
        from olax_enrollment import load_enrollment
        enrollment = load_enrollment(args.enrollment)
        if args.reference.resolve() != (args.enrollment / 'seccfg.img').resolve():
            raise PolicyError('Reference is not this enrolled device backup')
        expected_hash = enrollment['seccfg_sha256']
    original = args.reference.read_bytes()
    if len(original) != IMAGE_SIZE or hashlib.sha256(original).hexdigest() != expected_hash:
        raise PolicyError('Original backup SHA mismatch')
    prior = json.loads((args.session / 'report.json').read_text())
    profile = json.loads((args.session / 'hwparam.json').read_text())
    checked_prior(prior, profile, manifest, expected_hash)
    if enrollment and profile.get('cid') != enrollment['cid']:
        raise PolicyError('RAM session belongs to a different enrolled modem')
    os.umask(0o077)
    args.output.mkdir(mode=0o700, exist_ok=False)
    report = {'status': 'unknown', 'write_attempted': False, 'write_attempt_count': 0,
              'da_shutdown_skipped': True, 'android_boot_confirmed': False}
    try:
        from mtkclient.Library.mtk_class import Mtk
        from mtkclient.config.mtk_config import MtkConfig
        from mtkclient.Library.Partitions.gpt import GptSettings
        from mtkclient.Library.DA.xflash.xflash_lib import DAXFlash
        from mtkclient.Library.DA.xflash.extension.xflash import XCmd
        from mtkclient.Library.Hardware.hwcrypto_sej import Sej
        import usb.backend.libusb1
        # Capture only these two reviewed methods before installing global denial.
        raw_write, raw_command = DAXFlash.writeflash, DAXFlash.cmd_write_data
        deadline = time.monotonic() + args.timeout
        def timed_out(signum, frame):
            raise TimeoutError('Bounded device operation timed out')
        def bounded(fn, seconds=30):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Transaction deadline expired')
            signal.alarm(max(1, min(seconds, int(remaining))))
            try:
                return fn()
            finally:
                signal.alarm(0)
        with ExitStack() as stack:
            old_handler = signal.signal(signal.SIGALRM, timed_out)
            stack.callback(signal.signal, signal.SIGALRM, old_handler)
            stack.callback(signal.alarm, 0)
            capabilities = install_guards(stack)
            config = MtkConfig(loglevel=logging.WARNING)
            config.stock, config.skipwdt, config.reconnect = True, True, False
            config.loader = str(args.loader.resolve())
            config.init_hwcode(0x717)
            config.hw_sub_code, config.hwver, config.swver = 0x8a00, 0xca01, 0x200
            config.is_brom = False
            config.target_config = prior['target_config']
            validate_ram_target(config)
            config.gpt_settings = GptSettings(0, 0, 0)
            config.hwparam_path = str(args.output)
            mtk = Mtk(config, loglevel=logging.WARNING)
            stack.callback(mtk.port.close)
            mtk.port.cdc.devclass = 0x0a
            mtk.port.cdc.backend = usb_backend(args.libusb)
            if mtk.port.cdc.backend is None or not bounded(mtk.port.cdc.connect):
                raise PolicyError('Recorded running DA USB transport unavailable')
            mtk.daloader.daconfig.setup()
            mtk.daloader.set_da()  # Local object construction only: never upload or handshake.
            da = mtk.daloader.da
            bounded(lambda: da.reinit(False), 45)
            checked_identity(da, profile)
            ack = bounded(lambda: da.send_devctrl(XCmd.CUSTOM_ACK))
            if bounded(da.status) != 0 or ack != bytes.fromhex('a4a3a2a1'):
                raise PolicyError('Previously verified RAM extension is not active')
            start, length = bounded(lambda: checked_geometry(mtk))
            if bounded(lambda: read_partition(mtk)) != original:
                raise PolicyError('Fresh full seccfg differs from pinned original; nothing written')
            report.update({'identity_verified': True, 'partition_start': start, 'partition_length': length})
            read, write = register_access(mtk.daloader.xft, capabilities)
            sej = Sej(SimpleNamespace(hwcode=0x717, sej_base=0x1000a000, read32=read, write32=write),
                      loglevel=logging.WARNING)
            # Planner proves unchanged decrypt+reencrypt and candidate decrypt.
            plan = bounded(lambda: build_unlock_plan(original, expected_source_sha256=expected_hash,
                encrypt_digest=lambda b: bytes(sej.sej_sec_cfg_hw_V3(b, True, legacy=True)),
                decrypt_cipher=lambda b: bytes(sej.sej_sec_cfg_hw_V3(b, False, legacy=True))), 90)
            (args.output / 'original-sector.bin').write_bytes(original[:512])
            (args.output / 'candidate-sector.bin').write_bytes(plan.sector)
            report['plan'] = {'original_sha256': plan.original_sha256, 'expected_sha256': plan.expected_sha256,
                              'proof': asdict(plan.proof), 'crypto_method': 'V4', 'fresh_crypto_verified': True}
            durable_report(args.output / 'report.json', report)
            def journal_attempt(number):
                report['write_attempted'] = True
                report['write_attempt_count'] = number
                durable_report(args.output / 'report.json', report)
            scoped_write = sector_writer(da, start, plan.sector, original[:512], raw_write, raw_command,
                                         lambda: checked_geometry(mtk), journal_attempt)
            result = apply_unlock_plan(original, plan, expected_source_sha256=expected_hash,
                read_full=lambda: bounded(lambda: read_partition(mtk)),
                write_first_sector=lambda sector: bounded(lambda: scoped_write(sector), 30))
            report.update(asdict(result))
            return report
    except (PolicyError, Exception) as exc:
        report['error'] = str(exc)
        raise
    finally:
        durable_report(args.output / 'report.json', report)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apply', action='store_true', required=True)
    for name in ('loader', 'reference', 'session', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--enrollment', type=Path, required=True, help='Verified device-specific backup directory for another identical OLAX')
    p.add_argument('--libusb', type=Path, default=None)
    p.add_argument('--timeout', type=int, default=240)
    args = p.parse_args()
    if not 1 <= args.timeout <= 300:
        p.error('timeout must be 1..300 seconds')
    try:
        report = execute(args)
        print(json.dumps(report, indent=2))
        if report['status'] != 'success':
            p.exit(1, 'Transaction did not confirm candidate; inspect private report before any reboot.\n')
    except (PolicyError, Exception) as exc:
        p.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
