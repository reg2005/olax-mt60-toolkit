"""Pure, pinned OLAX seccfg planning. No file, device or flash operations.

Callbacks must be the coordinator's already selected encryption/decryption pair.
They are not discovered here. This module cannot certify their hardware origin.
An already unlocked image is deliberately rejected, not treated as a new source.
"""

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from struct import Struct, pack_into
from typing import Callable, Tuple


ORIGINAL_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
IMAGE_SIZE = 8 * 1024 * 1024
SECTOR_SIZE = 512
HEADER = Struct("<7I")
EXPECTED_HEADER = (0x4D4D4D4D, 4, 60, 1, 0, 0, 0x45454545)
ALLOWED_RANGES = ((0x0C, 0x10), (0x1C, 0x3C))  # Half-open offsets.
Crypto = Callable[[bytes], bytes]


class PlanError(ValueError):
    """Fail-closed planning error, with a stable machine-readable code."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class OffsetProof:
    allowed_ranges: Tuple[Tuple[int, int], ...]
    changed_offsets: Tuple[int, ...]
    preserved_ranges: Tuple[Tuple[int, int], ...]
    tail_sha256: str


@dataclass(frozen=True)
class UnlockPlan:
    sector: bytes
    original_sha256: str
    expected_sha256: str
    proof: OffsetProof


def _crypto(callback: Crypto, value: bytes, stage: str) -> bytes:
    try:
        result = callback(value)
    except Exception:
        # Do not surface callback exception text: it can include crypto material.
        raise PlanError("CRYPTO_CALLBACK", "Ошибка криптографической проверки: " + stage) from None
    if type(result) is not bytes or len(result) != 32:
        raise PlanError("CRYPTO_OUTPUT", "Криптографический результат должен содержать 32 байта: " + stage)
    return result


def build_unlock_plan(original: bytes, *, encrypt_digest: Crypto,
                      decrypt_cipher: Crypto, expected_source_sha256: str | None = None) -> UnlockPlan:
    """Return one sector plus a full-image hash, only for the pinned original.

    Never returns a full rewritten partition. The caller owns authorization,
    hardware identity, fresh reads, crypto provenance and eventual readback.
    """
    if type(original) is not bytes or len(original) != IMAGE_SIZE:
        raise PlanError("IMAGE_SIZE", "Нужен неизменяемый исходный образ размером ровно 8 МиБ.")
    original_hash = sha256(original).hexdigest()
    if not compare_digest(original_hash, expected_source_sha256 if expected_source_sha256 is not None else ORIGINAL_SHA256):
        raise PlanError("ORIGINAL_HASH", "Образ не совпадает с закреплённой исходной копией OLAX.")
    if HEADER.unpack_from(original) != EXPECTED_HEADER:
        raise PlanError("HEADER", "Заголовок исходного seccfg не соответствует ожидаемому заблокированному состоянию.")

    original_digest = sha256(original[:HEADER.size]).digest()
    original_cipher = original[0x1C:0x3C]
    if not compare_digest(_crypto(decrypt_cipher, original_cipher, "исходное расшифрование"), original_digest):
        raise PlanError("ORIGINAL_DECRYPT", "Исходная контрольная сумма не прошла расшифрование.")
    if not compare_digest(_crypto(encrypt_digest, original_digest, "исходное шифрование"), original_cipher):
        raise PlanError("ORIGINAL_ENCRYPT", "Повторное шифрование не воспроизводит исходную контрольную сумму.")

    # Only construct a changed header after BOTH unchanged checks succeeded.
    sector = bytearray(original[:SECTOR_SIZE])
    pack_into("<I", sector, 0x0C, 3)
    new_digest = sha256(sector[:HEADER.size]).digest()
    new_cipher = _crypto(encrypt_digest, new_digest, "новое шифрование")
    if not compare_digest(_crypto(decrypt_cipher, new_cipher, "новое расшифрование"), new_digest):
        raise PlanError("CANDIDATE_DECRYPT", "Новая контрольная сумма не прошла обратную проверку.")
    sector[0x1C:0x3C] = new_cipher
    candidate = bytes(sector)

    changed = tuple(i for i, (old, new) in enumerate(zip(original[:SECTOR_SIZE], candidate)) if old != new)
    if not changed or any(not any(start <= i < end for start, end in ALLOWED_RANGES) for i in changed):
        raise PlanError("OFFSET_PROOF", "Изменения выходят за разрешённые поля seccfg.")
    if candidate[:0x0C] != original[:0x0C] or candidate[0x10:0x1C] != original[0x10:0x1C] or candidate[0x3C:] != original[0x3C:SECTOR_SIZE]:
        raise PlanError("OFFSET_PROOF", "Защищённые байты исходного сектора изменены.")

    tail = memoryview(original)[SECTOR_SIZE:]
    expected_hash = sha256(candidate)
    expected_hash.update(tail)
    return UnlockPlan(
        sector=candidate,
        original_sha256=original_hash,
        expected_sha256=expected_hash.hexdigest(),
        proof=OffsetProof(
            allowed_ranges=ALLOWED_RANGES,
            changed_offsets=changed,
            preserved_ranges=((0, 0x0C), (0x10, 0x1C), (0x3C, IMAGE_SIZE)),
            tail_sha256=sha256(tail).hexdigest(),
        ),
    )
