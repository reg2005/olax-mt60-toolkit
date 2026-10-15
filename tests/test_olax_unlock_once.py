import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock

from mtkclient.Library.mtk_class import Mtk
from mtkclient.Library.DA.xflash.xflash_lib import DAXFlash
from mtkclient.Library.DA.xflash.xflash_param import Cmd
from olax_readonly import install_guards, PolicyError
from olax_unlock_once import sector_writer, checked_identity, IMAGE_SIZE


class ScopedWriteTests(unittest.TestCase):
    def fake_da(self):
        return SimpleNamespace(
            mtk=SimpleNamespace(config=SimpleNamespace(guiprogress=None)),
            daconfig=SimpleNamespace(storage=SimpleNamespace(get_storage=Mock(return_value=(1, 8, 512)))),
            get_packet_length=Mock(return_value=SimpleNamespace(write_packet_length=512)),
            cmd_write_data=Mock(), cmd=Cmd(), xsend=Mock(return_value=True),
            send_param=Mock(return_value=True), status=Mock(return_value=0),
            send_devctrl=Mock(return_value=b''), error=Mock())

    def test_real_upstream_methods_only_exact_sector_under_global_guards(self):
        raw_write, raw_command = DAXFlash.writeflash, DAXFlash.cmd_write_data
        da = self.fake_da()
        candidate, original = b'c' * 512, b'o' * 512
        journal = Mock()
        with ExitStack() as stack:
            install_guards(stack)
            with self.assertRaises(PolicyError):
                DAXFlash.writeflash(da, 0, 512)
            writer = sector_writer(da, 0x400000, candidate, original, raw_write, raw_command,
                                   lambda: (0x400000, IMAGE_SIZE), journal)
            self.assertTrue(writer(candidate))
            self.assertEqual(da.send_param.call_args_list[0].args[0][:24].hex(),
                             '010000000800000000004000000000000002000000000000')
            self.assertEqual(da.send_param.call_args_list[1].args[0][2], candidate)
            self.assertTrue(writer(original))
            with self.assertRaises(PolicyError):
                writer(candidate)
        self.assertEqual(journal.call_count, 2)
        self.assertEqual(da.xsend.call_count, 2)
        da.cmd_write_data.assert_not_called()  # The broad mock was never exposed.

    def test_unexpected_sector_order_or_geometry_never_calls_transport(self):
        transport = Mock()
        writer = sector_writer(object(), 0x400000, b'c'*512, b'o'*512, transport, Mock(),
                               lambda: (0x400000, IMAGE_SIZE))
        for value in (b'o'*512, b'c'*511, bytearray(b'c'*512), b'x'*512):
            with self.assertRaises(PolicyError):
                writer(value)
        transport.assert_not_called()
        writer = sector_writer(object(), 0x400000, b'c'*512, b'o'*512, transport, Mock(),
                               lambda: (0x400200, IMAGE_SIZE))
        with self.assertRaises(PolicyError):
            writer(b'c'*512)
        transport.assert_not_called()

    def test_bad_low_level_address_storage_or_repeat_stops_before_usb(self):
        for args in ((0, 512, 1, 8), (0x400000, 1024, 1, 8), (0x400000, 512, 1, 1)):
            da = SimpleNamespace(cmd_write_data=Mock())
            raw_command = Mock()
            def malicious_upstream(self, **kw):
                return self.cmd_write_data(*args)
            writer = sector_writer(da, 0x400000, b'c'*512, b'o'*512, malicious_upstream,
                                   raw_command, lambda: (0x400000, IMAGE_SIZE))
            with self.assertRaises(PolicyError):
                writer(b'c'*512)
            raw_command.assert_not_called()

    def test_timeout_attempt_is_journaled_before_transport_and_not_retried(self):
        da = SimpleNamespace(cmd_write_data=Mock())
        events = []
        def timeout(*args, **kw):
            events.append('io')
            raise TimeoutError('uncertain')
        writer = sector_writer(da, 0x400000, b'c'*512, b'o'*512, timeout, Mock(),
                               lambda: (0x400000, IMAGE_SIZE), lambda n: events.append(n))
        with self.assertRaises(TimeoutError):
            writer(b'c'*512)
        self.assertEqual(events, [1, 'io'])
        with self.assertRaises(PolicyError):
            writer(b'c'*512)

    def test_running_identity_requires_cid_and_hardware_tuple(self):
        da = SimpleNamespace(chipid=SimpleNamespace(hw_code=0x717, hw_sub_code=0x8a00,
            hw_version=0xca01, sw_version=0x200), emmc=SimpleNamespace(type=1,
            block_size=512, user_size=0x1c8000000, cid=bytes(range(16))))
        profile = {'hwcode': '0x717', 'cid': bytes(range(16)).hex()}
        checked_identity(da, profile)
        with self.assertRaises(PolicyError):
            checked_identity(da, {**profile, 'cid': '0'*32})
        da.chipid.hw_code = 0x766
        with self.assertRaises(PolicyError):
            checked_identity(da, profile)


if __name__ == '__main__':
    unittest.main()
