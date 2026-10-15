"""Platform USB loading and durable local transaction evidence."""
import ctypes.util
import json
import os
from pathlib import Path
import struct
import sys


def durable_report(path, value):
    path = Path(path)
    temp = path.with_suffix('.pending')
    with temp.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    if os.name != 'nt':
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def usb_backend(explicit=None):
    import usb.backend.libusb1
    if explicit:
        library = str(explicit.resolve())
    elif os.name == 'nt':
        if struct.calcsize('P') != 8:
            raise RuntimeError('Требуется 64-bit Python')
        library = str(Path(__file__).resolve().parents[1] / '.runtime/mtkclient/Windows/libusb-1.0.dll')
    else:
        library = ctypes.util.find_library('usb-1.0')
        if not library and sys.platform == 'darwin':
            library = next((p for p in ('/opt/homebrew/lib/libusb-1.0.dylib', '/usr/local/lib/libusb-1.0.dylib') if Path(p).is_file()), None)
    if not library:
        raise RuntimeError('LIBUSB_MISSING: установите libusb (см. docs/platforms.md)')
    backend = usb.backend.libusb1.get_backend(find_library=lambda _: library)
    if backend is None:
        raise RuntimeError('LIBUSB_LOAD: библиотека не загружается')
    if os.name == 'nt':
        from ctypes import c_void_p, c_int
        backend.lib.libusb_set_option.argtypes = [c_void_p, c_int]
        # LIBUSB_OPTION_USE_USBDK. Do not silently switch to a different driver.
        if backend.lib.libusb_set_option(backend.ctx, 1) != 0:
            raise RuntimeError('USBDK_MISSING: установите UsbDk x64')
    return backend
