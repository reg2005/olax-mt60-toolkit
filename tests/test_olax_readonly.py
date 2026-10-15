import hashlib
from contextlib import ExitStack
from types import SimpleNamespace
import struct
import unittest
from unittest.mock import Mock, patch

from mtkclient.Library.mtk_class import Mtk  # Import before unittest captures stderr.
from mtkclient.config.usb_ids import selected_ids
from olax_readonly import (ALLOWED, PolicyError, filtered_find, install_guards,
                           inspect_seccfg, read_partition, unchanged_roundtrip, require_unprotected,
                           register_access, verify_variants, hardware_roundtrip, finish_da_session,
                           preloader_hardware_roundtrip)


def image():
    header = struct.pack('<7I', 0x4d4d4d4d, 4, 60, 1, 0, 0, 0x45454545)
    return header + hashlib.sha256(header).digest() + bytes(512 - 60)


class GuardTests(unittest.TestCase):
    def test_explicit_filter_uses_dict_and_interface(self):
        self.assertEqual(selected_ids({0xe8d: {0x2000: 2}}, 0xe8d, 0x2000), {0xe8d: {0x2000: 2}})
        self.assertEqual(selected_ids({}, 0xe8d, 3), {0xe8d: {3: -1}})
        for vid, pid in ((0xe8d, -1), (-1, 3)):
            with self.assertRaises(ValueError):
                selected_ids(ALLOWED, vid, pid)

    def test_mtk_setup_passes_strict_mapping_to_transport(self):
        from mtkclient.config.mtk_config import MtkConfig
        config = MtkConfig()
        config.vid, config.pid = 0xe8d, 0x2000
        with patch('mtkclient.Library.mtk_class.Port') as port, \
             patch('mtkclient.Library.mtk_class.Preloader'), \
             patch('mtkclient.Library.mtk_class.DAloader'):
            Mtk(config)
        self.assertEqual(port.call_args.kwargs['portconfig'], {0xe8d: {0x2000: -1}})

    def test_find_filters_before_claim(self):
        devices = [SimpleNamespace(idVendor=v, idProduct=p) for v, p in
                   ((0x18d1, 0x4ee7), (0xe8d, 0x2004), (0xe8d, 0x2001), (0xe8d, 0x2000), (0xe8d, 3))]
        fake_find = lambda **kw: devices
        with self.assertRaises(PolicyError):
            filtered_find(fake_find)(find_all=True)
        devices.pop()
        self.assertEqual(list(filtered_find(fake_find)(find_all=True)), devices[-1:])
        self.assertEqual(list(filtered_find(fake_find)(find_all=True, custom_match=lambda d: d.idProduct == 3)), [])

    def test_usb_transport_never_opens_wrong_devices(self):
        from mtkclient.Library.Connection.usblib import UsbClass
        devices = [Mock(idVendor=v, idProduct=p) for v, p in
                   ((0x18d1, 0x4ee7), (0xe8d, 0x2004), (0xe8d, 0x2001))]
        usb = UsbClass(portconfig=ALLOWED)
        with patch('usb.core.find', return_value=devices):
            self.assertFalse(usb.connect())
        for device in devices:
            device.get_active_configuration.assert_not_called()
            device.set_configuration.assert_not_called()
            device.detach_kernel_driver.assert_not_called()

    def test_mutation_and_exploit_guards_are_fail_closed(self):
        from mtkclient.Library.DA.mtk_daloader import DAloader
        from mtkclient.Library.DA.xflash.xflash_lib import DAXFlash
        from mtkclient.Library.DA.xflash.extension.xflash import XFlashExt
        from mtkclient.Library.mtk_class import Mtk
        from mtkclient.config.mtk_config import MtkConfig
        with ExitStack() as stack:
            install_guards(stack)
            for cls, names in ((DAloader, ('writeflash', 'formatflash', 'seccfg', 'poke')),
                               (DAXFlash, ('cmd_write_data', 'handle_sla', 'patch_da')),
                               (XFlashExt, ('custom_rpmb_write', 'erase_rpmb', 'seccfg')),
                               (Mtk, ('bypass_security', 'crasher'))):
                for name in names:
                    with self.subTest(cls=cls.__name__, method=name), self.assertRaises(PolicyError):
                        getattr(cls, name)(None)
            with self.assertRaises(PolicyError):
                MtkConfig.init_hwcode(None, 0x766)

    def test_original_roundtrip_and_tamper(self):
        data = image()
        self.assertTrue(unchanged_roundtrip(data, lambda b:b, lambda b:b)['crypto_verified'])
        self.assertEqual(inspect_seccfg(data)['lock_state'], 1)
        for decrypt, encrypt in ((lambda b:bytes(32), lambda b:b), (lambda b:b, lambda b:bytes(32))):
            with self.assertRaises(PolicyError):
                unchanged_roundtrip(data, decrypt, encrypt)
        with self.assertRaises(PolicyError):
            inspect_seccfg(b'bad')

    def test_partition_read_bounds_and_truncation(self):
        loader = Mock()
        loader.daconfig.pagesize = 512
        loader.detect_partition.return_value = (True, SimpleNamespace(sector=4096, sectors=1))
        mtk = SimpleNamespace(daloader=loader)
        with self.assertRaises(PolicyError):
            read_partition(mtk)
        loader.readflash.assert_not_called()
        loader.detect_partition.return_value = (True, SimpleNamespace(sector=4096, sectors=16384))
        loader.readflash.return_value = bytes(512)
        with self.assertRaises(PolicyError):
            read_partition(mtk)
        loader.writeflash.assert_not_called()
        loader.readflash.return_value = bytes(8 * 1024 * 1024)
        self.assertEqual(len(read_partition(mtk)), 8 * 1024 * 1024)
        self.assertEqual(loader.readflash.call_args.kwargs['addr'], 4096 * 512)

    def test_hardware_mode_rejects_missing_or_enabled_protection(self):
        flags = dict.fromkeys(('sbc', 'sla', 'daa', 'epp', 'cert', 'memread', 'memwrite', 'cmdC8'), False)
        config = SimpleNamespace(hwcode=0x717, target_config=flags)
        require_unprotected(config)
        for key in flags:
            with self.subTest(key=key):
                with self.assertRaises(PolicyError):
                    require_unprotected(SimpleNamespace(hwcode=0x717, target_config={**flags, key: True}))
        with self.assertRaises(PolicyError):
            require_unprotected(SimpleNamespace(hwcode=0x717, target_config={}))

    def test_sej_register_writes_cannot_reach_flash_controller_or_other_memory(self):
        caps = {'read_register': Mock(return_value=0x80008000), 'write_register': Mock(return_value=True)}
        read, write = register_access(object(), caps)
        for addr in (0, 0x1000a001, 0x1000a0c0, 0x11230000, 0x48000000):
            with self.assertRaises(PolicyError):
                write(addr, 0)
            with self.assertRaises(PolicyError):
                read(addr)
        caps['write_register'].assert_not_called()
        self.assertTrue(write(0x1000a008, 1))

    def test_all_real_sej_variants_fit_reviewed_register_map_offline(self):
        from mtkclient.Library.Hardware.hwcrypto_sej import Sej
        caps = {'read_register': Mock(return_value=0x80008000), 'write_register': Mock(return_value=True)}
        read, write = register_access(object(), caps)
        sej = Sej(SimpleNamespace(hwcode=0x717, sej_base=0x1000a000, read32=read, write32=write))
        report = verify_variants(image(), sej)
        self.assertEqual([a['method'] for a in report['crypto_attempts']], ['SW', 'V3', 'V4', 'V2'])
        self.assertFalse(report['crypto_verified'])
        self.assertGreater(caps['write_register'].call_count, 30)

    def test_roundtrip_requires_matching_reencryption_not_just_decryption(self):
        digest = hashlib.sha256(image()[:28]).digest()
        sej = Mock()
        sej.sej_sec_cfg_sw.side_effect = lambda b, enc: bytes(32) if enc else digest
        sej.sej_sec_cfg_hw_V3.side_effect = lambda b, enc, legacy: digest
        sej.sej_sec_cfg_hw.side_effect = lambda b, enc: bytes(32)
        report = verify_variants(image(), sej)
        self.assertEqual(report['crypto_methods'], ['V3', 'V4'])
        self.assertFalse(report['crypto_attempts'][0]['unchanged_encrypt_matches'])

    def test_reference_mismatch_rejected_before_extension_upload(self):
        config = SimpleNamespace(hwcode=0x717, target_config=dict.fromkeys(
            ('sbc', 'sla', 'daa', 'epp', 'cert', 'memread', 'memwrite', 'cmdC8'), False))
        caps = {'build_extension': Mock()}
        with self.assertRaises(PolicyError):
            hardware_roundtrip(SimpleNamespace(config=config), image(), bytes(512), caps)
        caps['build_extension'].assert_not_called()

    def test_cleanup_requests_home_screen_without_flash_write(self):
        import tempfile
        from pathlib import Path
        mtk = SimpleNamespace(daloader=Mock())
        mtk.daloader.shutdown.return_value = True
        with tempfile.TemporaryDirectory() as directory, patch('portable_alarm.alarm'):
            report = {}
            finish_da_session(mtk, report, Path(directory))
            self.assertTrue(report['da_shutdown_accepted'])
        mtk.daloader.shutdown.assert_called_once_with(bootmode=1)
        mtk.daloader.writeflash.assert_not_called()

    def test_native_preloader_variant_path_and_reference_gate(self):
        config = SimpleNamespace(hwcode=0x717, is_brom=False, chipconfig=SimpleNamespace(sej_base=0x1000a000),
            target_config=dict.fromkeys(('sbc', 'sla', 'daa', 'epp', 'cert', 'memread', 'memwrite', 'cmdC8'), False))
        mtk = SimpleNamespace(config=config, preloader=object())
        caps = {'preloader_read': Mock(return_value=0x80008000), 'preloader_write': Mock(return_value=True)}
        with self.assertRaises(PolicyError):
            preloader_hardware_roundtrip(mtk, image(), caps)
        caps['preloader_read'].assert_not_called()
        reference = image() + bytes(8 * 1024 * 1024 - 512)
        with patch('olax_readonly.ORIGINAL_SECCFG_SHA256', hashlib.sha256(reference).hexdigest()):
            report = preloader_hardware_roundtrip(mtk, reference, caps)
        self.assertTrue(report['flash_recheck_pending'])
        self.assertEqual(len(report['crypto_attempts']), 4)
        self.assertFalse(report['crypto_verified'])
        self.assertGreater(caps['preloader_write'].call_count, 30)

    def test_native_preloader_probe_failure_does_not_write(self):
        config = SimpleNamespace(hwcode=0x717, is_brom=False, chipconfig=SimpleNamespace(sej_base=0x1000a000),
            target_config=dict.fromkeys(('sbc', 'sla', 'daa', 'epp', 'cert', 'memread', 'memwrite', 'cmdC8'), False))
        caps = {'preloader_read': Mock(return_value=[]), 'preloader_write': Mock(return_value=True)}
        reference = image() + bytes(8 * 1024 * 1024 - 512)
        with patch('olax_readonly.ORIGINAL_SECCFG_SHA256', hashlib.sha256(reference).hexdigest()):
            with self.assertRaises(PolicyError):
                preloader_hardware_roundtrip(SimpleNamespace(config=config, preloader=object()), reference, caps)
        caps['preloader_write'].assert_not_called()


if __name__ == '__main__':
    unittest.main()
