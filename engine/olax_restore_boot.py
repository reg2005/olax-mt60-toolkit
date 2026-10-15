#!/usr/bin/env python3
"""Owner-specific stock-boot recovery preparation; never unlock, erase or patch DA."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import logging
import os
from pathlib import Path
import portable_alarm as signal
from runtime_support import usb_backend, durable_report
from unittest.mock import patch

import olax_readonly as readonly
from olax_readonly import PolicyError, install_guards, validate_ram_target


BOOT_SIZE = 32 * 1024 * 1024
USER_SIZE = 0x1C8000000
STOCK_SHA = "aea6db447c55a144af61ad9d28bff920b294c7e7f30605ebc8938175c8f3278d"
CANDIDATE_SHAS = frozenset(("02b4337e75e0b088813b83280f93ef9fb908af96adcac5d1c0358884deba1feb",))
LOADER_SHA = "aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f"
LOADER_SIZE = 22483280
EMI_SHA = "ce892a49b8811a097ad10e3b5b5401c7cfae3c5a77295223f123a3beec6deefc"
OWNER_CID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HW_ID = (0x717, 0x8A00, 0xCA01, 0x200)


def pinned(data, length, digest, label):
    if type(data) is not bytes or len(data) != length or hashlib.sha256(data).hexdigest() != digest:
        raise PolicyError("Не совпадает закреплённая копия: " + label)
    return data


def checked_profile(profile, expected_cid=OWNER_CID):
    if profile.get('hwcode') != '0x717' or profile.get('cid') != expected_cid:
        raise PolicyError('Профиль не принадлежит проверенному OLAX владельца')


def checked_identity(da, expected_cid=OWNER_CID):
    chip, emmc = da.chipid, da.emmc
    if chip is None or (chip.hw_code, chip.hw_sub_code, chip.hw_version, chip.sw_version) != HW_ID:
        raise PolicyError('Аппаратный идентификатор DA не совпадает с OLAX владельца')
    if (emmc is None or emmc.type == 0 or emmc.block_size != 512 or
            emmc.user_size != USER_SIZE or bytes(emmc.cid).hex() != expected_cid):
        raise PolicyError('CID или геометрия eMMC не совпадают с OLAX владельца')


def checked_geometry(mtk):
    # detect_partition issues a fresh GPT read; never reuse saved DA/GPT state.
    found, part = mtk.daloader.detect_partition('boot', parttype='user')
    if not found or part.name != 'boot':
        raise PolicyError('В свежем GPT отсутствует точный раздел boot')
    if (mtk.daloader.daconfig.pagesize != 512 or type(part.sector) is not int or
            type(part.sectors) is not int or part.sectors != BOOT_SIZE // 512):
        raise PolicyError('Размер или выравнивание раздела boot не совпадает')
    start = part.sector * 512
    if start < 34 * 512 or start % 512 or start + BOOT_SIZE > USER_SIZE:
        raise PolicyError('Раздел boot выходит за границы проверенного user-раздела eMMC')
    return start, BOOT_SIZE


def read_boot(mtk, start, expected_cid=OWNER_CID):
    checked_identity(mtk.daloader.da, expected_cid)
    if checked_geometry(mtk) != (start, BOOT_SIZE):
        raise PolicyError('Геометрия GPT изменилась перед чтением boot')
    data = mtk.daloader.readflash(addr=start, length=BOOT_SIZE, filename='',
                                 parttype='user', display=False)
    if not isinstance(data, (bytes, bytearray)) or len(data) != BOOT_SIZE:
        raise PolicyError('Неполное чтение boot')
    return bytes(data)


def stock_writer(da, start, stock, raw_write, raw_command, check_geometry,
                 check_identity, on_attempt=lambda: None, target_sha=None):
    """One capability: exactly the pinned stock boot, once, in user eMMC."""
    target_sha = target_sha or STOCK_SHA
    pinned(stock, BOOT_SIZE, target_sha, 'target boot')
    attempted = False

    def write(data):
        nonlocal attempted
        if attempted or type(data) is not bytes or data != stock:
            raise PolicyError('Разрешена только одна запись точной stock-копии boot')
        check_identity()
        if check_geometry() != (start, BOOT_SIZE):
            raise PolicyError('Геометрия boot изменилась перед записью')
        attempted = True  # An exception/timeout also consumes the capability.
        on_attempt()
        commands = 0

        def command(addr, size, storage=1, parttype=8):
            nonlocal commands
            if commands != 0 or (addr, size, storage, parttype) != (start, BOOT_SIZE, 1, 8):
                raise PolicyError('Низкоуровневая запись выходит за единственный разрешённый boot')
            commands += 1
            return raw_command(da, addr=addr, size=size, storage=storage, parttype=parttype)

        with patch.object(da, 'cmd_write_data', command):
            result = raw_write(da, addr=start, length=BOOT_SIZE, filename='', offset=0,
                               parttype='user', wdata=stock, display=False)
        if commands != 1:
            raise PolicyError('Запись не выполнила единственную разрешённую команду boot')
        return result
    return write


def restore_transaction(stock, read_full, write_stock, report, persist=lambda: None, target_sha=None):
    """One full write at most; final complete bytes, not write ACK, decide success."""
    target_sha = target_sha or STOCK_SHA
    pinned(stock, BOOT_SIZE, target_sha, 'target boot')
    before = read_full()
    if type(before) is not bytes or len(before) != BOOT_SIZE:
        raise PolicyError('Неполная исходная проверка boot')
    report['before_sha256'] = hashlib.sha256(before).hexdigest()
    persist()
    if before == stock:
        report.update(status='already_stock', stock_verified=target_sha==STOCK_SHA, target_verified=True)
        persist()
        return report
    if report['before_sha256'] not in CANDIDATE_SHAS:
        raise PolicyError('Текущий boot неизвестен; восстановление запрещено без отдельного разбора')
    report['write_attempted'] = True
    persist()
    try:
        ack = write_stock(stock)
        report['write_ack'] = ack is True
    except Exception as exc:
        report['write_exception_type'] = type(exc).__name__
    # PolicyError/timeout escape upstream exception recovery. A coordinator must
    # inspect uncertainty rather than retry a write or exhaust a expired timeout.
    after = read_full()
    if type(after) is not bytes or len(after) != BOOT_SIZE:
        raise PolicyError('Неполная проверка boot после записи; результат неизвестен')
    report['after_sha256'] = hashlib.sha256(after).hexdigest()
    report['target_verified'] = after == stock
    report['stock_verified'] = target_sha == STOCK_SHA and after == stock
    report['status'] = 'restored' if report['target_verified'] else 'unknown'
    persist()
    return report


def execute(args):
    # Validate every local input before creating a USB object.
    stock = pinned(args.stock_boot.read_bytes(), BOOT_SIZE, STOCK_SHA, 'stock boot')
    loader = pinned(args.loader.read_bytes(), LOADER_SIZE, LOADER_SHA, 'MTK_DA_V5')
    emi = pinned(args.preloader.read_bytes(), 4 * 1024 * 1024, EMI_SHA, 'original boot0 EMI')
    if not getattr(args, 'enrollment', None):
        raise PolicyError('Device enrollment required')
    expected_cid = OWNER_CID
    if getattr(args, 'enrollment', None):
        from olax_enrollment import load_enrollment
        expected_cid = load_enrollment(args.enrollment)['cid']
        if args.stock_boot.resolve() != (args.enrollment / 'boot.img').resolve():
            raise PolicyError('Stock boot must be the enrolled device backup')
    checked_profile(json.loads((args.session / 'hwparam.json').read_text()), expected_cid)
    target_sha = STOCK_SHA
    if not 1 <= args.timeout <= 600:
        raise PolicyError('Тайм-аут должен быть от1 до600 секунд')
    os.umask(0o077)
    args.output.mkdir(mode=0o700, exist_ok=False)
    report = {'status': 'unknown', 'write_attempted': False, 'stock_verified': False,
              'stock_sha256': STOCK_SHA, 'loader_sha256': LOADER_SHA,
              'da_uploaded': False, 'da_shutdown_skipped': True,
              'android_boot_confirmed': False, 'target_sha256': target_sha,
              'image_purpose': 'temporary_adb_rescue' if target_sha != STOCK_SHA else 'stock_recovery'}

    def persist():
        durable_report(args.output / 'report.json', report)

    try:
        # Private immutable-source snapshot avoids re-reading an unpinned loader
        # path during upload. It contains stock DA bytes, never a patched DA.
        snapshot = args.output / 'stock-MTK_DA_V5.bin'
        snapshot.write_bytes(loader)
        from mtkclient.Library.mtk_class import Mtk
        from mtkclient.config.mtk_config import MtkConfig
        from mtkclient.Library.Partitions.gpt import GptSettings
        from mtkclient.Library.DA.xflash.xflash_lib import DAXFlash
        import usb.backend.libusb1
        raw_write, raw_command = DAXFlash.writeflash, DAXFlash.cmd_write_data
        with ExitStack() as stack:
            # This recovery starts only in preloader, never BROM or a saved DA.
            stack.enter_context(patch.object(readonly, 'ALLOWED', {0x0E8D: {0x2000: -1}}))
            install_guards(stack)
            def timeout(signum, frame):
                raise PolicyError('Истёк предел времени recovery; повторная запись не выполняется')
            old_handler = signal.signal(signal.SIGALRM, timeout)
            stack.callback(signal.signal, signal.SIGALRM, old_handler)
            stack.callback(signal.alarm, 0)
            signal.alarm(args.timeout)
            config = MtkConfig(loglevel=logging.WARNING)
            config.stock, config.skipwdt, config.reconnect = True, True, False
            config.loader, config.preloader = str(snapshot.resolve()), emi
            config.hwparam_path = str(args.output)
            config.gpt_settings = GptSettings(0, 0, 0)
            mtk = Mtk(config, loglevel=logging.WARNING)
            stack.callback(mtk.port.close)
            mtk.port.cdc.backend = usb_backend(args.libusb)
            if mtk.port.cdc.backend is None:
                raise PolicyError('libusb недоступен')
            if not mtk.preloader.init(display=False, directory=str(args.output)):
                raise PolicyError('Свежий handshake preloader не прошёл')
            validate_ram_target(config)
            report['handshake_verified'] = True
            persist()
            if not mtk.daloader.upload_da(preloader=emi):
                raise PolicyError('Заводской DA не принят; обход и модификация DA запрещены')
            report['da_uploaded'] = True
            da = mtk.daloader.da
            checked_identity(da, expected_cid)
            report['owner_identity_verified'] = True
            start, length = checked_geometry(mtk)
            report.update(partition='boot', partition_start=start, partition_length=length)
            persist()
            def attempt():
                report['write_attempt_count'] = 1
                persist()
            writer = stock_writer(da, start, stock, raw_write, raw_command,
                                  lambda: checked_geometry(mtk), lambda: checked_identity(da, expected_cid), attempt, target_sha=target_sha)
            return restore_transaction(stock, lambda: read_boot(mtk, start, expected_cid), writer, report, persist, target_sha=target_sha)
    except (PolicyError, Exception) as exc:
        report['error_type'] = type(exc).__name__
        raise
    finally:
        persist()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restore-stock', action='store_true', required=True)
    for name in ('stock-boot', 'loader', 'preloader', 'session', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--libusb', type=Path, default=None)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--enrollment', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = execute(args)
        print(json.dumps(report, indent=2))
        if report['status'] not in ('restored', 'already_stock'):
            parser.exit(1, 'Stock boot не подтверждён. Сохраните service mode и изучите отчёт.\n')
    except (PolicyError, Exception) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
