"""In-memory mock-device tests; no real backup, crypto, USB or flash."""

from dataclasses import replace
from hashlib import sha256
import unittest
from unittest.mock import Mock, patch

import olax_seccfg_apply as apply
import olax_seccfg_plan as planner


def fixture_crypto(data):
    return bytes(value ^ 0xA5 for value in data)


class ApplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = bytearray(bytes(range(256)) * (planner.IMAGE_SIZE // 256))
        data[:28] = planner.HEADER.pack(*planner.EXPECTED_HEADER)
        data[28:60] = fixture_crypto(sha256(data[:28]).digest())
        cls.original = bytes(data)

    def setUp(self):
        self.pin = patch.object(planner, "ORIGINAL_SHA256", sha256(self.original).hexdigest())
        self.pin.start()
        self.addCleanup(self.pin.stop)
        self.plan = planner.build_unlock_plan(self.original, encrypt_digest=fixture_crypto,
                                             decrypt_cipher=fixture_crypto)
        self.candidate = self.plan.sector + self.original[512:]
        partial = bytearray(self.original)
        partial[12] = 3
        self.partial = bytes(partial)

    def run_apply(self, reads, writes=None, plan=None, original=None):
        reader = Mock(side_effect=reads)
        writer = Mock(side_effect=writes) if writes is not None else Mock(return_value=True)
        result = apply.apply_unlock_plan(self.original if original is None else original,
                                        self.plan if plan is None else plan,
                                        read_full=reader, write_first_sector=writer)
        self.assertLessEqual(reader.call_count, 5)
        self.assertLessEqual(writer.call_count, 2)
        self.assertEqual(result.read_attempts, reader.call_count)
        self.assertEqual(result.write_attempts, writer.call_count)
        for call in writer.call_args_list:
            self.assertEqual(len(call.args), 1)
            self.assertEqual(len(call.args[0]), 512)
            self.assertIn(call.args[0], (self.plan.sector, self.original[:512]))
        return result, reader, writer

    def test_success_exact_callback_sequence(self):
        calls = []
        state = [self.original]
        def read():
            calls.append("read")
            return state[0]
        def write(sector):
            calls.append("write")
            state[0] = sector + state[0][512:]
        result = apply.apply_unlock_plan(self.original, self.plan, read_full=read, write_first_sector=write)
        self.assertEqual(calls, ["read", "write", "read"])
        self.assertEqual(result.status, "success")
        self.assertEqual(result.observed_sha256, self.plan.expected_sha256)
        self.assertFalse(result.rollback_attempted)

    def test_already_applied_is_read_only_success(self):
        result, _, writer = self.run_apply([self.candidate])
        self.assertEqual(result.reason, "ALREADY_APPLIED")
        writer.assert_not_called()

    def test_initial_unknown_or_unavailable_never_writes(self):
        for first in (self.partial, RuntimeError("secret"), b"short", bytearray(self.original)):
            result, _, writer = self.run_apply([first])
            self.assertEqual(result.status, "unknown")
            writer.assert_not_called()
            self.assertNotIn("secret", repr(result))

    def test_false_or_raised_write_can_have_succeeded(self):
        for reply in (False, RuntimeError("usb secret")):
            result, _, writer = self.run_apply([self.original, self.candidate], [reply])
            self.assertEqual(result.status, "success")
            self.assertEqual(writer.call_count, 1)
            self.assertNotIn("usb secret", repr(result))

    def test_failed_write_leaving_original_needs_no_rollback(self):
        result, _, writer = self.run_apply([self.original, self.original], [False])
        self.assertEqual(result.status, "stock_restored")
        self.assertEqual(writer.call_count, 1)
        self.assertFalse(result.rollback_attempted)

    def test_bad_readback_after_reported_success_rolls_back_once(self):
        result, _, writer = self.run_apply([self.original, self.partial, self.original])
        self.assertEqual(result.status, "stock_restored")
        self.assertEqual(result.reason, "ROLLBACK_VERIFIED")
        self.assertTrue(result.rollback_attempted)
        self.assertEqual(writer.call_args_list[1].args, (self.original[:512],))

    def test_write_exception_partial_write_rolls_back_after_assessment(self):
        result, _, _ = self.run_apply([self.original, self.partial, self.original], [RuntimeError(), None])
        self.assertEqual(result.status, "stock_restored")
        self.assertEqual(result.write_attempts, 2)

    def test_one_failed_read_then_valid_candidate_does_not_rollback(self):
        result, _, _ = self.run_apply([self.original, RuntimeError(), self.candidate], [False])
        self.assertEqual(result.status, "success")
        self.assertEqual(result.read_attempts, 3)
        self.assertEqual(result.write_attempts, 1)

    def test_readback_unavailable_prevents_blind_rollback(self):
        result, _, _ = self.run_apply([self.original, RuntimeError(), b"short"], [RuntimeError()])
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.reason, "READBACK_UNAVAILABLE")
        self.assertEqual(result.write_attempts, 1)
        self.assertFalse(result.rollback_attempted)
        self.assertIsNone(result.observed_sha256)

    def test_tail_change_cannot_be_repaired_with_first_sector(self):
        foreign = bytearray(self.partial)
        foreign[512] ^= 1
        result, _, _ = self.run_apply([self.original, bytes(foreign)])
        self.assertEqual(result.reason, "TAIL_CHANGED_NO_ROLLBACK")
        self.assertEqual(result.write_attempts, 1)

    def test_rollback_false_or_exception_with_successful_readback(self):
        for reply in (False, RuntimeError()):
            result, _, _ = self.run_apply([self.original, self.partial, self.original], [True, reply])
            self.assertEqual(result.status, "stock_restored")
            self.assertEqual(result.reason, "ROLLBACK_VERIFIED")

    def test_rollback_does_not_retry_writing(self):
        for final in (self.partial, RuntimeError()):
            result, _, _ = self.run_apply([self.original, self.partial, final, RuntimeError()], [False, False])
            self.assertEqual(result.status, "unknown")
            self.assertEqual(result.write_attempts, 2)

    def test_both_read_retries_bounded_to_five_calls(self):
        result, _, _ = self.run_apply([self.original, RuntimeError(), self.partial,
                                      RuntimeError(), self.original])
        self.assertEqual(result.status, "stock_restored")
        self.assertEqual(result.read_attempts, 5)
        self.assertEqual(result.write_attempts, 2)

    def test_verified_candidate_after_rollback_attempt_reported_truthfully(self):
        result, _, _ = self.run_apply([self.original, self.partial, self.candidate], [False, False])
        self.assertEqual(result.status, "success")
        self.assertEqual(result.reason, "CANDIDATE_VERIFIED_AFTER_ROLLBACK_ATTEMPT")
        self.assertTrue(result.rollback_attempted)

    def test_forged_plan_fields_rejected_before_callbacks(self):
        reader, writer = Mock(), Mock()
        bad_sector = bytearray(self.plan.sector)
        bad_sector[60] ^= 1
        wrong_header = bytearray(self.plan.sector)
        wrong_header[16] = 1
        plans = [None, replace(self.plan, sector=b"short"),
                 replace(self.plan, sector=bytes(bad_sector)),
                 replace(self.plan, sector=bytes(wrong_header)),
                 replace(self.plan, original_sha256="a" * 64),
                 replace(self.plan, expected_sha256="a" * 64),
                 replace(self.plan, proof=replace(self.plan.proof, changed_offsets=(12,))),
                 replace(self.plan, proof=replace(self.plan.proof, allowed_ranges=((0, 512),))),
                 replace(self.plan, proof=replace(self.plan.proof, tail_sha256="a" * 64)),
                 replace(self.plan, proof=replace(self.plan.proof, preserved_ranges=()))]
        for plan in plans:
            with self.assertRaises(planner.PlanError):
                apply.apply_unlock_plan(self.original, plan, read_full=reader, write_first_sector=writer)
        reader.assert_not_called()
        writer.assert_not_called()

    def test_foreign_original_and_unchanged_checksum_rejected(self):
        reader, writer = Mock(), Mock()
        for original in (self.candidate, bytearray(self.original), self.original[:-1]):
            with self.assertRaises(planner.PlanError):
                apply.apply_unlock_plan(original, self.plan, read_full=reader, write_first_sector=writer)
        stale = self.plan.sector[:28] + self.original[28:60] + self.plan.sector[60:]
        with self.assertRaises(planner.PlanError):
            apply.apply_unlock_plan(self.original, replace(self.plan, sector=stale),
                                    read_full=reader, write_first_sector=writer)
        reader.assert_not_called()
        writer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
