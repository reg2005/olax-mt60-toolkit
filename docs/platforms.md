# Подготовка ОС

Рекомендован Python **3.12 x64**. Скрипт setup поддерживает 3.10–3.13.
Установка создаёт `.venv`, скачивает mtkclient по фиксированному commit и SHA256,
применяет два локальных USB-fix и проверяет хэши файлов. GUI/PySide/FUSE не нужны.
Сообщение upstream `fuse library not installed` не мешает этому CLI.

## Linux (Ubuntu / Debian)

```sh
sudo apt update
sudo apt install python3 python3-venv python3-pip libusb-1.0-0 adb
```

Используйте установленный Python поддерживаемой версии; при необходимости:
`OLAX_PYTHON=python3.12 ./olax.sh setup`.

Для доступа активного локального пользователя к двум сервисным USB PID создайте
`/etc/udev/rules.d/70-olax-mt60.rules` с содержимым:

```udev
SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", ATTR{idProduct}=="2000", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", ATTR{idProduct}=="0003", TAG+="uaccess"
```

```sh
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Затем переподключите устройство. `uaccess` предполагает активную локальную сессию
systemd-logind; для headless-сервера настройте отдельную группу с MODE=0660.
Не запускайте pip под sudo. ModemManager может перехватывать preloader;
если это подтверждается журналом, временно остановите его и верните после работы.
Не требуется модифицировать ядро Linux или устанавливать kamakiri.

## macOS

При наличии Homebrew:

```sh
brew install python@3.12 libusb android-platform-tools
./olax.sh setup
```

Для доступа к админке проще подключиться к Wi-Fi OLAX; при сервисной операции
всё равно нужен USB-кабель с линиями данных. Если используете USB RNDIS на Mac,
нужен отдельно установленный совместимый сетевой драйвер. В нашей лаборатории
использовался `tetherkit-cli`; его права администратора относятся к созданию
USB-сети, а не к записи пароля в toolkit. Установка этого драйвера не включена.

libusb ищется через систему, затем `/opt/homebrew/lib` и `/usr/local/lib`.
Можно передать `--libusb /absolute/path/libusb-1.0.dylib` командам `doctor`,
`unlock`, `restore`. Если macOS требует разрешить USB-аксессуар, разрешите его
в системном окне. Не отключайте SIP и не сохраняйте пароль sudo в скриптах.

## Windows 10/11 x64

1. Установите Python 3.12 **x64** с [python.org](https://www.python.org/downloads/windows/)
   и launcher `py`. `olax.cmd setup` использует `py -3.12`.
2. Установите [Android platform-tools](https://developer.android.com/tools/releases/platform-tools),
   распакуйте и добавьте каталог с `adb.exe` в PATH. Проверьте `adb version`.
3. Установите **UsbDk x64** из [официальных релизов](https://github.com/daynix/UsbDk/releases).
   Для сервиса MediaTek должен быть доступен штатный serial/COM-драйвер без
   ошибки в диспетчере устройств. Официальная инструкция основы:
   [mtkclient README-WINDOWS](https://github.com/bkerler/mtkclient/blob/cd25cf9c1ff6d36e82697ac2c798e69e9cfb78c3/README-WINDOWS.md).
4. Перезагрузите Windows, если установщик драйвера этого требует. Запустите setup
   из обычного `cmd.exe`. При отказе доступа к UsbDk повторите **сервисную команду**
   из консоли администратора; пароль не передаётся toolkit.
5. Не заменяйте RNDIS-драйвер сетевого интерфейса через Zadig: для этой реализации
   используется UsbDk. В native Windows скачивается закреплённая x64 libusb DLL
   из mtkclient и явно включается UsbDk backend.

Виртуальная машина/WSL не считаются проверенным USB-окружением: устройство
переопределяется между Android/preloader/DA и может потеряться при USB passthrough.
Сначала используйте физическую ОС.

## Проверка установки

`./olax.sh doctor` или `olax.cmd doctor` проверяет hashes зависимостей,
импорт библиотек, загрузку libusb и наличие adb. **Не открывает устройство**
и не подтверждает корректность аппаратного драйвера.

Для CI без драйверов: `python setup.py --skip-doctor`, затем `scripts/test.py`.
Это не способ обойти проверки перед unlock: они выполняются снова.
