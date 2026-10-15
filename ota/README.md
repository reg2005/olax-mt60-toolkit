# Ядро через штатное web OTA — эксперимент 0.1.0

**Аппаратная установка этих ZIP ещё не проверена.** Ранее проверено само ядро,
установленное другим способом. ZIP не разблокирует загрузчик; сначала выполните
`enroll → unlock → verify` из [основной инструкции](../README.md).
Не проверяйте сразу оба новых устройства: сначала один полный цикл с журналами.

## Файлы релиза

- `OLAX-MT60-01-CHECK-FIRST-0.1.0.zip`: проверка совместимости без boot.img.
- `OLAX-MT60-02-KERNEL-UNLOCKED-ONLY-0.1.0.zip`: исправленное ядро, только для
  подтверждённо разблокированного поддерживаемого устройства.
- `manifest.json` и `SHA256SUMS`: размеры и контрольные суммы.

Скачать из [GitHub Releases](https://github.com/reg2005/olax-mt60-toolkit/releases).
Проверка SHA: Linux `sha256sum`, macOS `shasum -a 256`, PowerShell
`Get-FileHash -Algorithm SHA256 .\имя.zip`. Сопоставьте результат с SHA256SUMS.
Не распаковывайте и не перепаковывайте ZIP перед загрузкой.

## Проверка штатного recovery

1. Подготовьте собственные backup, аккумулятор минимум 50%, постоянное USB-питание.
2. В штатной панели откройте локальное обновление и выберите **01-CHECK-FIRST**.
3. Дождитесь recovery и обычной загрузки. Если появилось меню recovery, выбирайте
   обычную перезагрузку системы. Не выбирайте wipe/factory reset.
4. Включите диагностический доступ повторным `verify`, если ADB выключен.
5. Сохраните журнал при известном адресе ADB:

```sh
python3 ota/collect.py --serial 192.168.0.1:5555 --out /PRIVATE/ota-probe.json
```

В Windows: `py -3.12 ota\collect.py --serial 192.168.0.1:5555 --out C:\PRIVATE\ota-probe.json`.
Укажите существующий приватный каталог и новое имя файла; collector не включает
ADB сам и не выбирает устройство автоматически.

В `/cache/recovery/last_log` нужны `OLAX kernel-only OTA`, `PROBE_COMPLETE` и
`INSTALL_ELIGIBLE`. Сообщение браузера об успешной загрузке ZIP недостаточно.
`INSTALL_BLOCKED: BOOTLOADER_LOCKED_OR_UNKNOWN` означает, что ставить ядро нельзя.
Если updater не запустился, несовместимы подпись или recovery — сохраните лог,
не пробуйте следующий ZIP наугад.

**Особенность OEM:** штатный обработчик до входа в recovery удаляет каталог
`lrserver` веб-панели. Даже проверочный ZIP не отменяет этот побочный эффект.
Комплект enroll сохраняет собственный `stock-ROOT.war.img`; если stock-восстановление
панели не сработало, потребуется сервисный разбор. На этой новой OTA-процедуре
восстановление панели ещё не проверено. [План восстановления](../docs/recovery.md).

## Установка

После подтверждённого `INSTALL_ELIGIBLE` загрузите **02-KERNEL-UNLOCKED-ONLY**
через тот же пункт. Updater разрешает запись только при точной модели, известных
SHA boot/recovery, cmdline `androidboot.flash.locked=0`,
`androidboot.verifiedbootstate=orange`, наличии батареи с уровнем 50–100%,
USB online и настоящего ext4 `/cache`.

Он сохраняет stock boot в `/cache/recovery/olax-kernel/stock-boot.img`, проверяет
копию, записывает только boot и читает SHA обратно. `BOOT_WRITE_VERIFIED` означает
совпадение записи. При ошибке выполняется одна попытка возврата stock boot с
проверкой, если процесс продолжает работать. Это не защита от отключения питания
и не автоматический откат после bootloop. Неизвестный образ отклоняется.

После загрузки:

```sh
./olax.sh verify --kernel --host 192.168.0.1 --state "$HOME/.local/share/olax/unit01"
```

Затем проверьте сеть/панель/экран и нагрузку PMIC/gauge в `top` в течение хотя бы
минуты. Запишите факт перегрева/самоперезапуска, отдельно наблюдайте зарядку.
Завершите `close` по основной инструкции. `verify --kernel` проверяет lock, CID
и hashes; он не заменяет тепловой тест или полный цикл аккумулятора.

## Сборка

Нужны Python, Go 1.24+ и OpenSSL. Подготовьте копии своего заводского boot и recovery:

```sh
python3 ota/fetch_vendor.py
python3 ota/build.py --stock-boot /PRIVATE/backup/boot.img \
  --recovery /PRIVATE/backup/recovery.img --out /PRIVATE/ota-release
go -C ota test -race ./...
go -C ota vet ./...
cd ota
python3 -m unittest -v test_ota_sign.py
```

`patch_boot.py` проверяет полный stock SHA и исходные инструкции, воспроизводит
ровно проверенный boot SHA `02b4337e75e0b088813b83280f93ef9fb908af96adcac5d1c0358884deba1feb`.
Меняются три ARM-инструкции внутри сжатого ядра и mkbootimg ID; ramdisk, DTB,
размер и остальные байты сохраняются. Если версия zlib даёт иной итоговый SHA,
сборка останавливается. Не заменяйте ожидаемый SHA для обхода проверки.

`build.py` запускает Go tests/vet, собирает статический ARMv7 updater без CGO,
создаёт ZIP с фиксированной датой и проверяет подпись. Зависимости AOSP закреплены
в vendor/sources.json. Повторная сборка после fetch не требует сети.

Подпись — Android whole-file SHA1/RSA exponent3 с **публичным AOSP testkey**,
соответствующим ключу сохранённого stock recovery. Проверяются footer, ZIP CRC,
OpenSSL CMS и извлечённая RSA-подпись в формате recovery. Это не выполнение
настоящего recovery verifier на модеме. Публичный ключ совместимости не подтверждает
авторство пакета; используйте доверенный источник GitHub Release и SHA256.
