import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mtkclient.Library.mtk_class import Mtk
from olax_ram_da import (SOURCE, build_candidate, validate_candidate, DA1_OFFSET,
                        DA1_LENGTH, DA2_OFFSET, DA2_LENGTH, DA2_UNSIGNED_LENGTH,
                        BINDING_OFFSET, BOOT_HASH_ERROR_OFFSET)
from olax_readonly import PolicyError, validate_ram_target, resume_preloader, record_service_retained


class RamCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.candidate, cls.manifest = build_candidate(cls.source)

    def test_exact_minimal_differences_and_binding(self):
        a, b = DA1_OFFSET + BINDING_OFFSET, DA2_OFFSET + BOOT_HASH_ERROR_OFFSET
        allowed = set(range(a, a + 32)) | set(range(b, b + 4))
        changed = {i for i, (x, y) in enumerate(zip(self.source, self.candidate)) if x != y}
        self.assertEqual(len(changed), 35)
        self.assertTrue(changed <= allowed)
        self.assertEqual(self.candidate[b:b + 4], bytes(4))
        self.assertEqual(self.candidate[a:a + 32], hashlib.sha256(
            self.candidate[DA2_OFFSET:DA2_OFFSET + DA2_UNSIGNED_LENGTH]).digest())
        for offset, length in ((DA1_OFFSET, DA1_LENGTH), (DA2_OFFSET, DA2_LENGTH)):
            self.assertEqual(self.candidate[offset + length - 256:offset + length],
                             self.source[offset + length - 256:offset + length])

    def test_unreviewed_source_and_modified_candidate_rejected(self):
        with self.assertRaises(ValueError):
            build_candidate(b'unreviewed')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'da.bin'
            path.write_bytes(self.candidate)
            self.assertEqual(validate_candidate(path)['changed_byte_count'], 35)
            with path.open('r+b') as stream:
                stream.write(b'\x00')
            with self.assertRaises(ValueError):
                validate_candidate(path)

    def test_exact_live_hardware_and_security_required(self):
        flags = dict.fromkeys(('sbc', 'sla', 'daa', 'epp', 'cert', 'memread', 'memwrite', 'cmdC8'), False)
        cfg = SimpleNamespace(hwcode=0x717, hw_sub_code=0x8a00, hwver=0xca01,
                              swver=0x200, is_brom=False, target_config=flags)
        validate_ram_target(cfg)
        for attr in ('hw_sub_code', 'hwver', 'swver'):
            old = getattr(cfg, attr)
            setattr(cfg, attr, 0)
            with self.assertRaises(PolicyError):
                validate_ram_target(cfg)
            setattr(cfg, attr, old)

    def test_resume_reidentifies_without_replaying_sync(self):
        mtk = SimpleNamespace(port=Mock(), preloader=Mock())
        mtk.port.cdc.connect.return_value = True
        def reidentify(**kw):
            self.assertTrue(mtk.port.handshake())
            return True
        mtk.preloader.init.side_effect = reidentify
        resume_preloader(mtk, Path('/not-written'))
        self.assertEqual(mtk.port.cdc.devclass, 0x0a)
        mtk.preloader.init.assert_called_once()
        mtk.port.handshake.assert_not_called()
        mtk.port.cdc.connect.return_value = False
        with self.assertRaises(PolicyError):
            resume_preloader(mtk, Path('/not-written'))

    def test_explicit_retention_only_records_skipped_shutdown(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            report = {'crypto_verified': True}
            record_service_retained(report, Path(directory))
            saved = json.loads((Path(directory) / 'report.json').read_text())
            self.assertTrue(saved['da_shutdown_skipped'])
            self.assertFalse(saved['android_boot_confirmed'])
            self.assertNotIn('da_shutdown_accepted', saved)


if __name__ == '__main__':
    unittest.main()
