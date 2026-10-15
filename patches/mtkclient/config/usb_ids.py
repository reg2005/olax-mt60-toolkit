default_ids = {
    0x0E8D: {0x0003: -1,  # MTK Brom
             0x6000: 2,  # MTK Preloader
             0x2000: -1,  # MTK Preloader
             0x2001: -1,  # MTK Preloader
             0x20FF: -1,  # MTK Preloader
             0x3000: -1},  # MTK Preloader
    0x1004: {0x6000: 2},  # LG Preloader
    0x22d9: {0x0006: -1},  # OPPO Preloader
    0x0FCE: {0xF200, -1,  # Sony Brom
             0xD1E9, -1,  # Sony Brom XA1
             0xD1E2, -1,  # Sony Brom
             0xD1EC, -1,  # Sony Brom L1
             0xD1DD, -1},  # Sony F3111
    0x0403: {0x6001, -1},  # FTDI
    0x1a86: {0x55d3, -1,  # QinHeng Electronics USB Single Serial CH343G
             0x7523, -1,  # QinHeng Electronics USB Single Serial CH340C
             0x5523, -1,  # CH341
             0x5512, -1},  # QinHeng Electronics USB Single Serial CH341A
    0x4348: {0x5523, -1},  # WCH CH340
    0x10C4: {0xEA60, -1},  # CP2102
    0x11CA: {0x0211, -1}  # CP2102
}


def selected_ids(defaults, vid=-1, pid=-1, interface=-1):
    """Build the dict expected by USB transport; partial filters fail closed."""
    if (vid == -1) != (pid == -1):
        raise ValueError("USB vendor and product must be supplied together")
    if vid == -1:
        return defaults
    if not (0 <= vid <= 0xffff and 0 <= pid <= 0xffff):
        raise ValueError("USB identifiers must be 16-bit integers")
    known = defaults.get(vid, {})
    if interface == -1 and isinstance(known, dict):
        interface = known.get(pid, -1)
    return {vid: {pid: interface}}
