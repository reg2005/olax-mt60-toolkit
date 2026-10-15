"""Offline fixtures only: XOR below is a test double, never device crypto."""

import ast
from dataclasses import FrozenInstanceError
from hashlib import sha256
from pathlib import Path
import struct
import unittest
from unittest.mock import Mock, patch

import olax_seccfg_plan as planner


def fixture_crypto(value):
    return bytes(b ^ 0xA5 for b in value)


class SeccfgPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = bytearray(bytes(range(256)) * (planner.IMAGE_SIZE // 256))
        data[:28] = planner.HEADER.pack(*planner.EXPECTED_HEADER)
        data[28:60] = fixture_crypto(sha256(data[:28]).digest())
        cls.original = bytes(data)
        cls.fixture_hash = sha256(cls.original).hexdigest()

    def build(self, data=None, encrypt=fixture_crypto, decrypt=fixture_crypto):
        # Production has no pin override argument. Only synthetic tests patch it.
        with patch.object(planner, "ORIGINAL_SHA256", self.fixture_hash):
            return planner.build_unlock_plan(self.original if data is None else data,
                                             encrypt_digest=encrypt, decrypt_cipher=decrypt)

    def assert_code(self, code, action):
        with self.assertRaises(planner.PlanError) as caught:
            action()
        self.assertEqual(code, caught.exception.code)

    def test_success_preserves_every_other_byte_and_full_tail(self):
        plan = self.build()
        full = plan.sector + self.original[512:]
        self.assertEqual(len(plan.sector), 512)
        self.assertEqual(struct.unpack_from("<I", plan.sector, 12)[0], 3)
        self.assertEqual(planner.HEADER.unpack_from(plan.sector), (0x4D4D4D4D, 4, 60, 3, 0, 0, 0x45454545))
        self.assertEqual(fixture_crypto(plan.sector[28:60]), sha256(plan.sector[:28]).digest())
        self.assertEqual(plan.expected_sha256, sha256(full).hexdigest())
        self.assertEqual(plan.original_sha256, self.fixture_hash)
        self.assertEqual(plan.proof.tail_sha256, sha256(self.original[512:]).hexdigest())
        actual_changes = tuple(i for i, pair in enumerate(zip(self.original, full)) if pair[0] != pair[1])
        self.assertEqual(plan.proof.changed_offsets, actual_changes)
        self.assertEqual(plan.proof.allowed_ranges, ((12, 16), (28, 60)))
        for start, end in plan.proof.preserved_ranges:
            self.assertEqual(full[start:end], self.original[start:end])
        self.assertTrue(self.original[60:512].strip(b"\0"))  # Detect upstream zero-padding regression.
        with self.assertRaises(FrozenInstanceError):
            plan.sector = bytes(512)

    def test_repeated_plans_are_deterministic_but_unlocked_source_rejected(self):
        plan = self.build()
        self.assertEqual(plan, self.build())
        self.assert_code("ORIGINAL_HASH", lambda: self.build(plan.sector + self.original[512:]))

    def test_real_pin_rejects_fixture_before_crypto(self):
        encrypt = Mock()
        decrypt = Mock()
        self.assert_code("ORIGINAL_HASH", lambda: planner.build_unlock_plan(
            self.original, encrypt_digest=encrypt, decrypt_cipher=decrypt))
        encrypt.assert_not_called()
        decrypt.assert_not_called()

    def test_wrong_size_or_mutable_input_rejected_before_crypto(self):
        crypto = Mock()
        for data in (self.original[:-1], self.original + b"x", bytearray(self.original), None):
            with self.subTest(type=type(data)):
                self.assert_code("IMAGE_SIZE", lambda: self.build(data, crypto, crypto) if data is not None
                                 else planner.build_unlock_plan(data, encrypt_digest=crypto, decrypt_cipher=crypto))
        crypto.assert_not_called()

    def test_tampering_any_region_rejected_before_crypto(self):
        crypto = Mock()
        for offset in (0, 12, 16, 24, 28, 59, 60, 511, 512, len(self.original) - 1):
            data = bytearray(self.original)
            data[offset] ^= 1
            with self.subTest(offset=offset):
                self.assert_code("ORIGINAL_HASH", lambda: self.build(bytes(data), crypto, crypto))
        crypto.assert_not_called()

    def test_all_header_fields_fail_closed_even_with_mock_pin(self):
        crypto = Mock()
        for field in range(7):
            data = bytearray(self.original)
            data[field * 4] ^= 2
            data = bytes(data)
            with patch.object(planner, "ORIGINAL_SHA256", sha256(data).hexdigest()):
                self.assert_code("HEADER", lambda: planner.build_unlock_plan(
                    data, encrypt_digest=crypto, decrypt_cipher=crypto))
        crypto.assert_not_called()

    def test_bad_original_decrypt_never_encrypts(self):
        encrypt = Mock()
        self.assert_code("ORIGINAL_DECRYPT", lambda: self.build(encrypt=encrypt, decrypt=lambda _: bytes(32)))
        encrypt.assert_not_called()

    def test_bad_original_reencrypt_never_constructs_candidate(self):
        encrypt = Mock(return_value=bytes(32))
        decrypt = Mock(side_effect=fixture_crypto)
        self.assert_code("ORIGINAL_ENCRYPT", lambda: self.build(encrypt=encrypt, decrypt=decrypt))
        encrypt.assert_called_once_with(sha256(self.original[:28]).digest())
        decrypt.assert_called_once_with(self.original[28:60])

    def test_candidate_roundtrip_failure_returns_no_plan(self):
        decrypt = Mock(side_effect=[sha256(self.original[:28]).digest(), bytes(32)])
        self.assert_code("CANDIDATE_DECRYPT", lambda: self.build(decrypt=decrypt))
        self.assertEqual(decrypt.call_count, 2)

    def test_required_crypto_call_order(self):
        calls = []
        def encrypt(value):
            calls.append(("encrypt", value))
            return fixture_crypto(value)
        def decrypt(value):
            calls.append(("decrypt", value))
            return fixture_crypto(value)
        plan = self.build(encrypt=encrypt, decrypt=decrypt)
        self.assertEqual(calls, [
            ("decrypt", self.original[28:60]),
            ("encrypt", sha256(self.original[:28]).digest()),
            ("encrypt", sha256(plan.sector[:28]).digest()),
            ("decrypt", plan.sector[28:60]),
        ])

    def test_crypto_bad_types_sizes_and_exceptions(self):
        for bad in (b"", bytes(31), bytes(33), bytearray(32), "secret", None):
            self.assert_code("CRYPTO_OUTPUT", lambda: self.build(decrypt=lambda _: bad))
        self.assert_code("CRYPTO_OUTPUT", lambda: self.build(encrypt=lambda _: b"short"))
        crypto = Mock(side_effect=RuntimeError("private key must not leak"))
        with self.assertRaises(planner.PlanError) as caught:
            self.build(decrypt=crypto)
        self.assertEqual(caught.exception.code, "CRYPTO_CALLBACK")
        self.assertNotIn("private key", str(caught.exception))

    def test_planner_has_no_io_device_or_upstream_imports(self):
        tree = ast.parse(Path(planner.__file__).read_text())
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imported, {"dataclasses", "hashlib", "hmac", "struct", "typing"})
        self.assertFalse(any(isinstance(node, ast.Import) for node in ast.walk(tree)))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in {"open", "eval", "exec", "__import__"} for node in ast.walk(tree)))


if __name__ == "__main__":
    unittest.main()
