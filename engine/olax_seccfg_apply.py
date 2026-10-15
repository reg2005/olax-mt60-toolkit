"""Bounded seccfg callback coordinator; no CLI, transport or filesystem access.

This is prepared logic, not device authorization. The root coordinator must own
the transport exclusively and supply exact partition/sector-scoped callbacks.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Optional, Tuple

import olax_seccfg_plan as planner


@dataclass(frozen=True)
class ApplyResult:
    status: str  # success, stock_restored, unknown
    reason: str
    original_sha256: str
    expected_sha256: str
    observed_sha256: Optional[str]
    read_attempts: int
    write_attempts: int
    rollback_attempted: bool
    events: Tuple[str, ...]


def _validate(original: bytes, plan: planner.UnlockPlan, expected_source_sha256: str | None = None) -> None:
    """Reject forged/stale plan metadata before invoking any callback."""
    if type(original) is not bytes or len(original) != planner.IMAGE_SIZE:
        raise planner.PlanError("APPLY_ORIGINAL", "Нужна исходная копия размером ровно 8 МиБ.")
    source_hash = sha256(original).hexdigest()
    if source_hash != (expected_source_sha256 if expected_source_sha256 is not None else planner.ORIGINAL_SHA256) or planner.HEADER.unpack_from(original) != planner.EXPECTED_HEADER:
        raise planner.PlanError("APPLY_ORIGINAL", "Исходная копия не совпадает с закреплённым образом OLAX.")
    if type(plan) is not planner.UnlockPlan or type(plan.sector) is not bytes or len(plan.sector) != planner.SECTOR_SIZE:
        raise planner.PlanError("APPLY_PLAN", "План должен содержать ровно один неизменяемый сектор512.")
    expected_header = list(planner.EXPECTED_HEADER)
    expected_header[3] = 3
    if planner.HEADER.unpack_from(plan.sector) != tuple(expected_header):
        raise planner.PlanError("APPLY_HEADER", "Заголовок кандидата содержит недопустимые изменения.")
    changed = tuple(i for i, (old, new) in enumerate(zip(original[:512], plan.sector)) if old != new)
    if any(not any(start <= offset < end for start, end in planner.ALLOWED_RANGES) for offset in changed):
        raise planner.PlanError("APPLY_OFFSETS", "Кандидат изменяет байты вне разрешённых полей.")
    if plan.sector[28:60] == original[28:60]:
        raise planner.PlanError("APPLY_CHECKSUM", "Контрольная сумма кандидата не была обновлена.")
    expected = sha256(plan.sector)
    expected.update(memoryview(original)[512:])
    if plan.original_sha256 != source_hash or plan.expected_sha256 != expected.hexdigest():
        raise planner.PlanError("APPLY_HASH", "Хеши плана не соответствуют исходному образу и кандидату.")
    proof = planner.OffsetProof(
        allowed_ranges=planner.ALLOWED_RANGES,
        changed_offsets=changed,
        preserved_ranges=((0, 12), (16, 28), (60, planner.IMAGE_SIZE)),
        tail_sha256=sha256(memoryview(original)[512:]).hexdigest(),
    )
    if type(plan.proof) is not planner.OffsetProof or plan.proof != proof:
        raise planner.PlanError("APPLY_PROOF", "Доказательство допустимых смещений не соответствует кандидату.")


def apply_unlock_plan(original: bytes, plan: planner.UnlockPlan, *,
                      read_full: Callable[[], bytes],
                      write_first_sector: Callable[[bytes], object],
                      expected_source_sha256: str | None = None) -> ApplyResult:
    """At most two sector writes and five full reads, with verified rollback.

    Callbacks must have transport timeouts: call counts are bounded here, but a
    synchronous callback that hangs cannot be interrupted safely by this helper.
    Full reads must return immutable bytes, exactly8MiB. A successful full read
    establishes transport usability for a subsequent rollback; any read failure
    gets at most one assessment retry. Never retry an ambiguous write blindly.
    """
    _validate(original, plan, expected_source_sha256)
    reads = writes = 0
    rollback = False
    observed = None
    events = []

    def read(stage: str, attempts: int) -> Optional[bytes]:
        nonlocal reads, observed
        for _ in range(attempts):
            reads += 1
            try:
                value = read_full()
            except Exception:
                observed = None
                events.append(stage + "_read_exception")
                continue
            if type(value) is not bytes or len(value) != planner.IMAGE_SIZE:
                observed = None
                events.append(stage + "_read_invalid")
                continue
            observed = sha256(value).hexdigest()
            events.append(stage + "_read_ok")
            return value
        return None

    def write(sector: bytes, stage: str) -> None:
        nonlocal writes
        writes += 1
        try:
            value = write_first_sector(sector)
        except Exception:
            events.append(stage + "_write_exception")
        else:
            events.append(stage + ("_write_false" if value is False else "_write_returned"))

    def result(status: str, reason: str) -> ApplyResult:
        return ApplyResult(status, reason, plan.original_sha256, plan.expected_sha256,
                           observed, reads, writes, rollback, tuple(events))

    def is_candidate(value: bytes) -> bool:
        return value[:512] == plan.sector and memoryview(value)[512:] == memoryview(original)[512:]

    fresh = read("initial", 1)
    if fresh is None:
        return result("unknown", "INITIAL_READ_UNAVAILABLE")
    if is_candidate(fresh):
        return result("success", "ALREADY_APPLIED")
    if fresh != original:
        return result("unknown", "INITIAL_STATE_MISMATCH")

    write(plan.sector, "candidate")
    after = read("candidate", 2)
    if after is None:
        return result("unknown", "READBACK_UNAVAILABLE")
    if is_candidate(after):
        return result("success", "CANDIDATE_VERIFIED")
    if after == original:
        return result("stock_restored", "ORIGINAL_VERIFIED_WITHOUT_ROLLBACK")
    if memoryview(after)[512:] != memoryview(original)[512:]:
        return result("unknown", "TAIL_CHANGED_NO_ROLLBACK")

    # A complete readable image and unchanged tail establish a recoverable
    # first-sector mismatch. Only one rollback write is permitted.
    rollback = True
    write(original[:512], "rollback")
    restored = read("rollback", 2)
    if restored is None:
        return result("unknown", "ROLLBACK_READBACK_UNAVAILABLE")
    if restored == original:
        return result("stock_restored", "ROLLBACK_VERIFIED")
    if is_candidate(restored):
        return result("success", "CANDIDATE_VERIFIED_AFTER_ROLLBACK_ATTEMPT")
    return result("unknown", "ROLLBACK_MISMATCH")
