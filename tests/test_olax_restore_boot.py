"""No USB: exercise captured upstream write methods with an in-memory transport."""
from contextlib import ExitStack
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from mtkclient.Library.DA.xflash.xflash_lib import DAXFlash
from mtkclient.Library.DA.xflash.xflash_param import Cmd
from olax_readonly import PolicyError, install_guards
import olax_restore_boot as recovery


class RestoreBootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock = b'S' * recovery.BOOT_SIZE
        cls.candidate = b'C' * recovery.BOOT_SIZE
        cls.foreign = b'X' * recovery.BOOT_SIZE

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(recovery, 'STOCK_SHA', hashlib.sha256(self.stock).hexdigest()))
        self.stack.enter_context(patch.object(recovery, 'CANDIDATE_SHAS', frozenset((hashlib.sha256(self.candidate).hexdigest(),))))
        self.start = 0x4000000

    def fake_da(self):
        return SimpleNamespace(
            chipid=SimpleNamespace(hw_code=0x717, hw_sub_code=0x8a00, hw_version=0xca01, sw_version=0x200),
            emmc=SimpleNamespace(type=1, block_size=512, user_size=recovery.USER_SIZE,
                                 cid=bytes.fromhex(recovery.OWNER_CID)),
            mtk=SimpleNamespace(config=SimpleNamespace(guiprogress=None)),
            daconfig=SimpleNamespace(storage=SimpleNamespace(get_storage=Mock(return_value=(1, 8, recovery.BOOT_SIZE)))),
            get_packet_length=Mock(return_value=SimpleNamespace(write_packet_length=recovery.BOOT_SIZE)),
            cmd_write_data=Mock(), cmd=Cmd(), xsend=Mock(return_value=True),
            send_param=Mock(return_value=True), status=Mock(return_value=0),
            send_devctrl=Mock(return_value=b''), error=Mock())

    def writer(self, da, raw_write, raw_command, geometry=None, identity=None, journal=None):
        return recovery.stock_writer(da, self.start, self.stock, raw_write, raw_command,
            geometry or (lambda: (self.start, recovery.BOOT_SIZE)),
            identity or (lambda: recovery.checked_identity(da)), journal or (lambda: None))

    def test_real_upstream_write_only_pinned_stock_once_under_global_denials(self):
        raw_write, raw_command = DAXFlash.writeflash, DAXFlash.cmd_write_data
        da = self.fake_da()
        with ExitStack() as stack:
            install_guards(stack)
            with self.assertRaises(PolicyError):
                DAXFlash.writeflash(da, 0, recovery.BOOT_SIZE)
            write = self.writer(da, raw_write, raw_command)
            self.assertTrue(write(self.stock))
            header = da.send_param.call_args_list[0].args[0]
            self.assertEqual(header[:24].hex(), '010000000800000000000004000000000000000200000000')
            self.assertEqual(da.send_param.call_args_list[1].args[0][2], self.stock)
            with self.assertRaises(PolicyError):
                write(self.stock)
        self.assertEqual(da.xsend.call_count, 1)
        da.cmd_write_data.assert_not_called()

    def test_nonstock_and_changed_geometry_refused_before_transport(self):
        raw = Mock()
        da = self.fake_da()
        write = self.writer(da, raw, Mock())
        for data in (self.candidate, self.stock[:-1], bytearray(self.stock)):
            with self.assertRaises(PolicyError):
                write(data)
        write = self.writer(da, raw, Mock(), geometry=lambda: (self.start + 512, recovery.BOOT_SIZE))
        with self.assertRaises(PolicyError):
            write(self.stock)
        raw.assert_not_called()

    def test_low_level_address_length_storage_partition_and_repeat_gated(self):
        for args in ((0, recovery.BOOT_SIZE, 1, 8), (self.start, 512, 1, 8),
                     (self.start, recovery.BOOT_SIZE, 1, 1), (self.start, recovery.BOOT_SIZE, 2, 8)):
            da, command = self.fake_da(), Mock()
            def malicious(self, **kw):
                return self.cmd_write_data(*args)
            with self.assertRaises(PolicyError):
                self.writer(da, malicious, command)(self.stock)
            command.assert_not_called()
        da, command = self.fake_da(), Mock(return_value=True)
        def repeated(self, **kw):
            for _ in range(2):
                self.cmd_write_data(kw['addr'], kw['length'], 1, 8)
        with self.assertRaises(PolicyError):
            self.writer(da, repeated, command)(self.stock)
        command.assert_called_once()

    def test_timeout_consumes_capability_and_journals_first(self):
        events = []
        def fail(*a, **kw):
            events.append('transport')
            raise TimeoutError()
        write = self.writer(self.fake_da(), fail, Mock(), journal=lambda: events.append('journal'))
        with self.assertRaises(TimeoutError):
            write(self.stock)
        with self.assertRaises(PolicyError):
            write(self.stock)
        self.assertEqual(events, ['journal', 'transport'])

    def test_owner_hardware_cid_and_storage_exact(self):
        recovery.checked_identity(self.fake_da())
        for field, value in (('cid', bytes(16)), ('user_size', recovery.USER_SIZE + 512),
                             ('block_size', 4096), ('type', 0)):
            da = self.fake_da()
            setattr(da.emmc, field, value)
            with self.assertRaises(PolicyError):
                recovery.checked_identity(da)
        da = self.fake_da()
        da.chipid.hw_sub_code = 0
        with self.assertRaises(PolicyError):
            recovery.checked_identity(da)
        with self.assertRaises(PolicyError):
            recovery.checked_profile({'hwcode': '0x717', 'cid': '0' * 32})

    def test_fresh_gpt_exact_name_size_alignment_and_bounds(self):
        part = SimpleNamespace(name='boot', sector=self.start // 512, sectors=recovery.BOOT_SIZE // 512)
        detect = Mock(return_value=(True, part))
        mtk = SimpleNamespace(daloader=SimpleNamespace(detect_partition=detect,
                                                       daconfig=SimpleNamespace(pagesize=512)))
        self.assertEqual(recovery.checked_geometry(mtk), (self.start, recovery.BOOT_SIZE))
        detect.assert_called_once_with('boot', parttype='user')
        for field, value in (('name', 'boot_a'), ('sectors', 1), ('sector', 0),
                             ('sector', recovery.USER_SIZE // 512), ('sector', 1.5)):
            old = getattr(part, field)
            setattr(part, field, value)
            with self.assertRaises(PolicyError):
                recovery.checked_geometry(mtk)
            setattr(part, field, old)
        mtk.daloader.daconfig.pagesize = 4096
        with self.assertRaises(PolicyError):
            recovery.checked_geometry(mtk)

    def transaction(self, reads, replies=None):
        read = Mock(side_effect=reads)
        write = Mock(side_effect=replies) if replies else Mock(return_value=True)
        report = {'status': 'unknown', 'write_attempted': False}
        result = recovery.restore_transaction(self.stock, read, write, report)
        self.assertLessEqual(write.call_count, 1)
        self.assertLessEqual(read.call_count, 2)
        return result, write

    def test_already_stock_never_writes(self):
        report, write = self.transaction([self.stock])
        self.assertEqual(report['status'], 'already_stock')
        write.assert_not_called()

    def test_known_candidate_restored_and_full_readback_verified(self):
        report, write = self.transaction([self.candidate, self.stock])
        self.assertEqual(report['status'], 'restored')
        self.assertEqual(report['after_sha256'], recovery.STOCK_SHA)
        write.assert_called_once_with(self.stock)

    def test_false_and_raised_write_require_readback_not_retry(self):
        for reply in (False, RuntimeError('private material')):
            report, write = self.transaction([self.candidate, self.stock], [reply])
            self.assertEqual(report['status'], 'restored')
            self.assertNotIn('private material', str(report))
            self.assertEqual(write.call_count, 1)

    def test_unknown_current_or_incomplete_read_refused(self):
        for before in (self.foreign, b'short', bytearray(self.stock)):
            write = Mock()
            with self.assertRaises(PolicyError):
                recovery.restore_transaction(self.stock, Mock(return_value=before), write, {})
            write.assert_not_called()

    def test_mismatched_readback_reports_unknown_without_second_write(self):
        report, write = self.transaction([self.candidate, self.foreign])
        self.assertEqual(report['status'], 'unknown')
        self.assertFalse(report['stock_verified'])
        self.assertEqual(write.call_count, 1)

    def test_wrong_stock_pin_refuses_even_before_read(self):
        read, write = Mock(), Mock()
        with self.assertRaises(PolicyError):
            recovery.restore_transaction(self.foreign, read, write, {})
        read.assert_not_called()
        write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
