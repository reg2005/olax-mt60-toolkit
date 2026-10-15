#!/usr/bin/env python3
"""OLAX MT60 kernel toolkit. Explicit stages; no automatic flash retries."""
import argparse
import base64
from contextlib import contextmanager
import getpass
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / 'engine'), str(ROOT / '.runtime')]
from olax_enrollment import load_enrollment, STOCK_BOOT, BOOT0
from runtime_support import durable_report
from setup import verify_runtime

FIXED_BOOT = '02b4337e75e0b088813b83280f93ef9fb908af96adcac5d1c0358884deba1feb'
RECOVERY = '9a82a9dcb915efc78ce02e98c36fb45c82f087307882f7cb1585d8813b63ffc1'
PART = '/dev/block/platform/bootdevice/by-name/'
PARTITIONS = ('boot', 'recovery', 'seccfg', 'lk', 'lk2', 'frp', 'nvram', 'nvdata', 'nvcfg', 'proinfo', 'protect1', 'protect2')
REQUIRED = tuple(x + '.img' for x in PARTITIONS + ('mmcblk0boot0', 'mmcblk0boot1')) + ('stock-ROOT.war.img',)


class Stop(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Stop('HTTP_REDIRECT: перенаправление панели запрещено')


def digest(path):
    with path.open('rb') as f:
        h = hashlib.sha256()
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def validate_host(value):
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise argparse.ArgumentTypeError('Укажите IPv4 роутера, например 192.168.0.1')
    if not any(ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise argparse.ArgumentTypeError('Разрешён только локальный RFC1918 адрес роутера')
    return str(ip)


def run(args, timeout=30):
    result = subprocess.run(list(map(str, args)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise Stop('COMMAND_FAILED: ' + Path(str(args[0])).name + ' (вывод скрыт: может содержать идентификаторы)')
    return result.stdout.decode('utf-8', errors='strict').strip()


@contextmanager
def state_lock(state):
    if state.is_symlink() or state == ROOT or ROOT in state.resolve().parents:
        raise Stop('PRIVATE_STATE: --state должен быть вне папки опубликованного проекта')
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = state / '.operation-lock'
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise Stop('STATE_BUSY: операция идёт либо была прервана. Сначала изучите journal.json; не повторяйте запись.')
    try:
        yield
    finally:
        lock.rmdir()


class Toolkit:
    def __init__(self, args):
        self.args = args
        self.state = args.state.resolve()
        self.backup = self.state / 'backup'
        self.journal = self.state / 'journal.json'
        self.data = json.loads(self.journal.read_text()) if self.journal.exists() else {'schema': 1}
        self.serial = args.host + ':5555'  # Never auto-select among USB ADB devices.
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def record(self, event, **fields):
        self.data.update(fields)
        self.data['event'] = event
        self.data['updatedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        durable_report(self.journal, self.data)
        print(event, flush=True)

    def adb(self, *args, timeout=30):
        return run(['adb', '-s', self.serial, *args], timeout)

    def shell(self, command):
        return self.adb('shell', 'set -e\n' + command)

    def request(self, path, body=None):
        with self.http.open('http://' + self.args.host + path, body, timeout=15) as response:
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise Stop('HTTP_TOO_LARGE')
            return data

    def login(self):
        password = getpass.getpass('Пароль admin роутера (не сохраняется): ')
        credential = base64.b64encode(('admin\n' + password).encode()).decode()
        form = urllib.parse.urlencode({'isTest': 'false', 'goformId': 'LOGIN', 'password': credential}).encode()
        result = json.loads(self.request('/goform/goform_set_cmd_process', form))
        if str(result.get('result')) not in ('0', '4'):
            raise Stop('LOGIN_FAILED: панель отклонила пароль')

    def identity(self):
        if self.shell('getprop ro.product.model') != 't60_extchg_k61' or self.shell('id -u') != '0':
            raise Stop('WRONG_DEVICE: требуется t60_extchg_k61 и root ADB')
        cid = self.shell('cat /sys/block/mmcblk0/device/cid')
        if not re.fullmatch('[a-f0-9]{32}', cid) or self.shell('cat /sys/block/mmcblk0/size') != '14942208':
            raise Stop('WRONG_EMMC')
        if self.data.get('cid', cid) != cid:
            raise Stop('WRONG_CID: подключён другой модем')
        if (self.backup / 'device.json').exists() and json.loads((self.backup / 'device.json').read_text())['cid'] != cid:
            raise Stop('WRONG_CID: резервная копия другого модема')
        self.record('IDENTITY_OK', cid=cid)
        return cid

    def connect(self):
        run(['adb', 'connect', self.serial], timeout=10)
        try:
            self.adb('get-state', timeout=5)
        except (Stop, subprocess.TimeoutExpired):
            self.login()
            self.request('/adbWifiDebugForm.do?adb=1')
            self.record('ADB_ENABLED', adbEnabled=True)
            time.sleep(2)
            run(['adb', 'disconnect', self.serial], timeout=10)
            run(['adb', 'connect', self.serial], timeout=10)
            self.adb('get-state', timeout=5)
        return self.identity()

    def remote_hash(self, path):
        result = self.shell('sha256sum ' + path).split()[0]
        if not re.fullmatch('[a-f0-9]{64}', result):
            raise Stop('INVALID_HASH')
        return result

    def backups_valid(self):
        enrolled = load_enrollment(self.backup)
        if enrolled['cid'] != self.data.get('cid'):
            raise Stop('BACKUP_CID_MISMATCH')
        records = json.loads((self.backup / 'manifest.json').read_text())
        for name in REQUIRED:
            p = self.backup / name
            if p.is_symlink() or not p.is_file() or records.get(name) != {'bytes': p.stat().st_size, 'sha256': digest(p)}:
                raise Stop('BACKUP_INVALID: ' + name)
        if records['recovery.img']['sha256'] != RECOVERY:
            raise Stop('RECOVERY_UNKNOWN')
        if not self.data.get('backupComplete'):
            raise Stop('BACKUP_INCOMPLETE: автоматического продолжения неполной копии нет')

    def enroll(self):
        self.connect()
        if self.backup.exists():
            self.backups_valid()
            print('BACKUP_ALREADY_VERIFIED')
            return
        if self.shell('getprop ro.boot.flash.locked') != '1':
            raise Stop('LOCK_STATE: нужен новый заводской locked роутер')
        for remote, pin in [(PART + 'boot', STOCK_BOOT), (PART + 'recovery', RECOVERY), ('/dev/block/mmcblk0boot0', BOOT0)]:
            if self.remote_hash(remote) != pin:
                raise Stop('UNKNOWN_FIRMWARE: эта сборка не поддерживается, запись запрещена')
        if shutil.disk_usage(self.state).free < 1024**3:
            raise Stop('DISK_SPACE: нужен минимум 1 GiB для резервных копий')
        self.backup.mkdir(mode=0o700)
        device = {'model': 't60_extchg_k61', 'cid': self.data['cid'], 'locked': '1', 'blockSectors': '14942208',
                  'fingerprint': self.shell('getprop ro.build.fingerprint')}
        durable_report(self.backup / 'device.json', device)
        records = {}
        sources = [(p, PART + p) for p in PARTITIONS] + [(p, '/dev/block/' + p) for p in ('mmcblk0boot0', 'mmcblk0boot1')]
        sources += [('stock-ROOT.war', '/data/media/0/lrserver/webapps/ROOT.war')]
        self.record('BACKUP_STARTED')
        for name, remote in sources:
            print('Сохраняю ' + name, flush=True)
            before = self.remote_hash(remote)
            path = self.backup / (name + '.img')
            with path.open('xb') as stream:
                subprocess.run(['adb', '-s', self.serial, 'exec-out', 'cat', remote], stdout=stream,
                               stderr=subprocess.PIPE, timeout=180, check=True)
                stream.flush()
                os.fsync(stream.fileno())
            if digest(path) != before or self.remote_hash(remote) != before:
                raise Stop('BACKUP_CHANGED: ' + name)
            records[path.name] = {'bytes': path.stat().st_size, 'sha256': before}
            durable_report(self.backup / 'manifest.json', records)
        load_enrollment(self.backup)
        self.record('BACKUP_COMPLETE', backupComplete=True)
        self.backups_valid()

    def child(self, script, extra, log, timeout):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT/'engine'), str(ROOT/'.runtime')]))
        command = [sys.executable, str(ROOT/'engine'/script), *map(str, extra)]
        if self.args.libusb:
            command += ['--libusb', str(self.args.libusb.resolve())]
        with (self.state/log).open('xb') as output:
            try:
                result = subprocess.run(command, cwd=self.state, env=env, stdout=output,
                                        stderr=subprocess.STDOUT, timeout=timeout)
            except subprocess.TimeoutExpired:
                self.record('UNKNOWN_TIMEOUT')
                raise Stop('UNKNOWN: таймаут; не повторять запись и не отключать питание. Сохраните отчёты.')
        if result.returncode:
            self.record('SERVICE_STOPPED', serviceExitCode=result.returncode)
            raise Stop('SERVICE_STOPPED: изучите приватный журнал. Автоматического повтора нет.')

    def unlock(self):
        self.backups_valid()
        # A previous pending attempt is never inferred safe from process exit alone.
        if self.data.get('serviceStarted') or (self.state/'ram-session').exists() or (self.state/'unlock-result').exists():
            raise Stop('ALREADY_ATTEMPTED: сначала verify или инженерный разбор journal.json; повтор запрещён')
        verify_runtime()
        from runtime_support import usb_backend
        usb_backend(self.args.libusb)
        from olax_ram_da import build_candidate, SOURCE
        candidate, manifest = build_candidate(SOURCE.read_bytes())
        loader = self.state / 'ram-da.bin'
        print('Отключите другие MediaTek-устройства. Выключите OLAX и отсоедините USB.\n'
              'После Enter начнётся ожидание: подключите USB с установленной батареей; Reset не удерживать.\n'
              'Будет изменён только первый сектор собственного seccfg. Риск потери данных/загрузки остаётся.')
        if input('Для этой операции введите UNLOCK: ').strip() != 'UNLOCK':
            raise Stop('CANCELLED: запись не запускалась')
        with loader.open('xb') as stream:
            stream.write(candidate)
        durable_report(self.state/'ram-da-manifest.json', manifest)
        self.record('SERVICE_STARTED', serviceStarted=True)
        session = self.state/'ram-session'
        self.child('olax_readonly.py', ['verify-ram-da-hw', '--output', session, '--timeout', '180',
                   '--loader', loader, '--preloader', self.backup/'mmcblk0boot0.img',
                   '--reference', self.backup/'seccfg.img', '--keep-service'], 'ram-session.log', 210)
        self.record('WRITE_PENDING', writePending=True)
        self.child('olax_unlock_once.py', ['--apply', '--loader', loader, '--reference', self.backup/'seccfg.img',
                   '--session', session, '--enrollment', self.backup, '--output', self.state/'unlock-result',
                   '--timeout', '240'], 'unlock.log', 270)
        report = json.loads((self.state/'unlock-result/report.json').read_text())
        if report.get('status') != 'success':
            raise Stop('WRITE_UNCONFIRMED: не перезагружать до разбора отчёта')
        self.record('SECTOR_VERIFIED', writePending=False, sectorVerified=True)
        print('Сектор прочитан обратно и совпал. Отключите USB и аккумулятор на несколько секунд,\n'
              'верните аккумулятор, включите OLAX, восстановите сеть и запустите verify.\n'
              'Это ещё не подтверждение загрузки и не установка ядра.')

    def verify(self):
        self.backups_valid()
        report = json.loads((self.state/'unlock-result/report.json').read_text())
        if report.get('status') != 'success':
            raise Stop('UNCONFIRMED_REPORT: нужен инженерный разбор, без reboot')
        self.connect()
        if self.shell('getprop ro.boot.flash.locked') != '0' or self.shell('getprop ro.boot.verifiedbootstate') != 'orange':
            raise Stop('UNLOCK_NOT_CONFIRMED')
        if self.remote_hash(PART+'seccfg') != report['expected_sha256']:
            raise Stop('SECCFG_CHANGED')
        target = FIXED_BOOT if self.args.kernel else STOCK_BOOT
        if self.remote_hash(PART+'boot') != target or self.remote_hash(PART+'recovery') != RECOVERY:
            raise Stop('BOOT_OR_RECOVERY_CHANGED')
        self.record('KERNEL_HASH_VERIFIED' if self.args.kernel else 'UNLOCK_VERIFIED', unlocked=True, kernelVerified=self.args.kernel, writePending=False, sectorVerified=True)
        print('SUCCESS: ' + ('загрузилось исправленное ядро; это не проверка зарядного цикла.' if self.args.kernel else 'разблокировка подтверждена после загрузки. Можно переходить к OTA-инструкции.'))

    def restore(self):
        self.backups_valid()
        verify_runtime()
        if self.data.get('restoreStarted') or (self.state/'stock-restore').exists():
            raise Stop('RESTORE_ATTEMPTED: сначала разбор отчёта; автоматического повтора нет')
        if not (self.state/'ram-session/hwparam.json').is_file():
            raise Stop('SESSION_MISSING: нет привязки сервисной сессии к этому модему')
        print('Восстановление только boot из собственной копии; загрузчик остаётся разблокирован.\n'
              'Нужен выключенный модем. После подтверждения подключите USB; Reset не нажимать.\n'
              'Неизвестный или частично записанный boot будет отклонён; это не универсальное unbrick.')
        if input('Введите RESTORE: ').strip() != 'RESTORE':
            raise Stop('CANCELLED')
        self.record('RESTORE_PENDING', restoreStarted=True)
        self.child('olax_restore_boot.py', ['--restore-stock', '--stock-boot', self.backup/'boot.img',
                   '--loader', ROOT/'.runtime/mtkclient/Loader/MTK_DA_V5.bin',
                   '--preloader', self.backup/'mmcblk0boot0.img', '--session', self.state/'ram-session',
                   '--enrollment', self.backup, '--output', self.state/'stock-restore'], 'restore.log', 330)
        report = json.loads((self.state/'stock-restore/report.json').read_text())
        if report.get('status') not in ('restored', 'already_stock') or not report.get('stock_verified'):
            raise Stop('RESTORE_UNKNOWN: не отключать питание; сначала разбор отчёта')
        self.record('STOCK_READBACK_VERIFIED')
        print('Stock boot прочитан обратно. Выполните полный цикл питания и verify без --kernel.')

    def close(self):
        self.connect()
        self.login()
        self.request('/adbWifiDebugForm.do?adb=0')
        time.sleep(2)
        run(['adb', 'disconnect', self.serial], timeout=10)
        run(['adb', 'connect', self.serial], timeout=10)
        try:
            self.adb('get-state', timeout=5)
        except (Stop, subprocess.TimeoutExpired):
            self.record('ADB_CLOSED', adbEnabled=False)
            return
        raise Stop('ADB_STILL_OPEN: выключите USB/Wi-Fi debugging в штатной панели')


def doctor(args):
    verify_runtime()
    from runtime_support import usb_backend
    usb_backend(args.libusb)
    from mtkclient.Library.mtk_class import Mtk  # Import compatibility, no device construction.
    if not shutil.which('adb'):
        raise Stop('ADB_MISSING: установите Android platform-tools и добавьте adb в PATH')
    print('DOCTOR_OK: зависимости и libusb загружаются; устройства не проверялись и не изменялись.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['doctor', 'enroll', 'unlock', 'verify', 'close', 'status', 'restore'])
    parser.add_argument('--host', type=validate_host, default='192.168.0.1', help='Адрес панели OLAX, только RFC1918 IPv4')
    parser.add_argument('--state', type=Path, help='Отдельная приватная папка вне проекта для каждого модема')
    parser.add_argument('--libusb', type=Path, help='Явный путь libusb, если автоопределение не сработало')
    parser.add_argument('--kernel', action='store_true', help='verify: проверять установленное исправленное ядро')
    args = parser.parse_args()
    if args.kernel and args.command != 'verify':
        parser.error('--kernel допустим только с verify')
    if args.command != 'doctor' and args.state is None:
        parser.error('--state обязателен')
    os.umask(0o077)
    try:
        if args.command == 'doctor':
            doctor(args)
        else:
            with state_lock(args.state):
                tool = Toolkit(args)
                if args.command == 'status':
                    print(json.dumps({k: v for k, v in tool.data.items() if k != 'cid'}, ensure_ascii=False, indent=2))
                else:
                    getattr(tool, args.command)()
    except (Stop, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        # Do not expose upstream/HTTP errors, which can contain secret URLs or device IDs.
        message = str(exc) if isinstance(exc, Stop) else type(exc).__name__ + ': см. инструкцию диагностики'
        print('STOP: ' + message, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('INTERRUPTED: проверьте journal.json; запись не повторять автоматически.', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())
