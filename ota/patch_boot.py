"""Reproduce the three reviewed ARM instruction edits from the exact stock image."""
import hashlib
import struct
import zlib

STOCK = 'aea6db447c55a144af61ad9d28bff920b294c7e7f30605ebc8938175c8f3278d'
FIXED = '02b4337e75e0b088813b83280f93ef9fb908af96adcac5d1c0358884deba1feb'
PAYLOAD = '4495ae3cc2203de63bc773bd104f081e8faa297d83ac15107b96eaab9782d699'
PATCHES = ((0xc0a842c8, '4c0087e5', '0000a0e1'),
           (0xc0a8439c, '4c0087e5', '0000a0e1'),
           (0xc0726a80, '1f10a0e3', '1210a0e3'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def boot_id(boot):
    page = struct.unpack_from('<I', boot, 36)[0]
    sizes = [struct.unpack_from('<I', boot, off)[0] for off in (8, 16, 24)]
    h, pos = hashlib.sha1(), page
    for size in sizes:
        h.update(boot[pos:pos+size])
        h.update(struct.pack('<I', size))
        pos += (size + page - 1) // page * page
    return h.digest() + bytes(12)


def make_stream(image, header, size):
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    raw = compressor.compress(image) + compressor.flush(zlib.Z_SYNC_FLUSH)
    final = bytes.fromhex('010000ffff')
    gap = size - len(header) - len(raw) - len(final) - 8
    six = gap % 5
    five = (gap - six * 6) // 5
    require(five >= 0, 'Compressed stream exceeds stock extent')
    stream = header + raw + bytes.fromhex('02000000ffff') * six + bytes.fromhex('000000ffff') * five + final + struct.pack('<II', zlib.crc32(image), len(image))
    require(len(stream) == size and zlib.decompress(stream, 31) == image, 'Gzip verification failed')
    return stream


def patch(boot):
    require(len(boot) == 33554432 and sha(boot) == STOCK, 'Unknown stock boot: no pattern fallback')
    require(boot[:8] == b'ANDROID!' and boot[576:608] == boot_id(boot), 'Boot header mismatch')
    size, page = struct.unpack_from('<I', boot, 8)[0], struct.unpack_from('<I', boot, 36)[0]
    require(size == 8137007 and page == 2048, 'Unexpected section size')
    payload = boot[page:page+size]
    require(sha(payload) == PAYLOAD, 'Payload mismatch')
    start = 18556
    require(payload[start:start+10] == bytes.fromhex('1f8b0800000000000203'), 'Gzip header mismatch')
    decompressor = zlib.decompressobj(31)
    original = decompressor.decompress(payload[start:])
    extent = len(payload) - start - len(decompressor.unused_data)
    require(decompressor.eof and len(original) == 22405120, 'Image mismatch')
    modified = bytearray(original)
    for address, before, after in PATCHES:
        offset = address - 0xc0008000
        require(modified[offset:offset+4] == bytes.fromhex(before), 'Instruction mismatch')
        modified[offset:offset+4] = bytes.fromhex(after)
    stream = make_stream(bytes(modified), payload[start:start+10], extent)
    candidate = bytearray(boot)
    candidate[page+start:page+start+extent] = stream
    candidate[576:608] = boot_id(candidate)
    require(candidate[:576] == boot[:576] and candidate[608:page+start] == boot[608:page+start] and candidate[page+start+extent:] == boot[page+start+extent:], 'Unexpected change outside gzip/header ID')
    require(sha(candidate) == FIXED, 'Output differs from reviewed image (check Python/zlib build); do not flash')
    return bytes(candidate)
