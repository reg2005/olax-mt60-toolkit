import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import olax
import portable_alarm
from runtime_support import durable_report


class ToolkitTests(unittest.TestCase):
    def make(self, directory):
        args = SimpleNamespace(state=Path(directory), host='192.168.0.1', libusb=None, kernel=False)
        return olax.Toolkit(args)

    def test_host_rejects_shell_urls_public_and_loopback(self):
        for value in ['127.0.0.1', '8.8.8.8', '192.168.0.1;reboot', 'http://192.168.0.1', '192.168.0.1:5555', 'router']:
            with self.assertRaises(argparse.ArgumentTypeError):
                olax.validate_host(value)
        self.assertEqual(olax.validate_host('192.168.42.1'), '192.168.42.1')

    def test_state_lock_is_exclusive_and_not_inside_public_tree(self):
        with self.assertRaises(olax.Stop):
            with olax.state_lock(olax.ROOT / 'private-test'):
                self.fail('Must not create private artifacts under repo')
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            with olax.state_lock(state):
                with self.assertRaises(olax.Stop):
                    with olax.state_lock(state):
                        self.fail('Duplicate lock')
            self.assertFalse((state/'.operation-lock').exists())

    def test_unknown_previous_attempt_never_runs_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = self.make(tmp)
            tool.data['serviceStarted'] = True
            with patch.object(tool, 'backups_valid'), patch.object(tool, 'child') as child:
                with self.assertRaisesRegex(olax.Stop, 'ALREADY_ATTEMPTED'):
                    tool.unlock()
                child.assert_not_called()

    def test_foreign_cid_stops_before_flash(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = self.make(tmp)
            tool.data['cid'] = 'a'*32
            with patch.object(tool, 'shell', side_effect=['t60_extchg_k61','0','b'*32,'14942208']):
                with self.assertRaisesRegex(olax.Stop, 'WRONG_CID'):
                    tool.identity()

    def test_verify_requires_readback_report_before_contacting_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = self.make(tmp)
            result = Path(tmp)/'unlock-result'
            result.mkdir()
            durable_report(result/'report.json', {'status':'unknown'})
            with patch.object(tool, 'backups_valid'), patch.object(tool, 'connect') as connect:
                with self.assertRaisesRegex(olax.Stop, 'UNCONFIRMED_REPORT'):
                    tool.verify()
                connect.assert_not_called()

    def test_child_timeout_records_unknown_and_no_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = self.make(tmp)
            with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('child', 1)) as run:
                with self.assertRaisesRegex(olax.Stop, 'UNKNOWN'):
                    tool.child('olax_unlock_once.py', [], 'test.log', 1)
                self.assertEqual(run.call_count, 1)
            self.assertEqual(json.loads(tool.journal.read_text())['event'], 'UNKNOWN_TIMEOUT')

    def test_child_crash_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = self.make(tmp)
            with patch('subprocess.run', return_value=SimpleNamespace(returncode=124)):
                with self.assertRaisesRegex(olax.Stop, 'SERVICE_STOPPED'):
                    tool.child('olax_unlock_once.py', [], 'test.log', 1)
            self.assertEqual(tool.data['serviceExitCode'], 124)

    def test_atomic_report_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'journal.json'
            durable_report(path, {'writePending':True})
            durable_report(path, {'writePending':False})
            self.assertEqual(json.loads(path.read_text()), {'writePending':False})
            self.assertFalse(path.with_suffix('.pending').exists())

    def test_windows_cancelled_timer_cannot_kill_new_operation(self):
        timers = []
        class Timer:
            def __init__(self, seconds, callback): self.callback = callback; timers.append(self)
            def cancel(self): pass
            def start(self): pass
        fake_os = SimpleNamespace(name='nt', _exit=Mock())
        with patch.object(portable_alarm, 'os', fake_os), patch.object(portable_alarm.threading, 'Timer', Timer):
            portable_alarm.alarm(10)
            portable_alarm.alarm(0)
            timers[0].callback()
            fake_os._exit.assert_not_called()
            portable_alarm.alarm(10)
            timers[-1].callback()
            fake_os._exit.assert_called_once_with(124)
            portable_alarm.alarm(0)

    def test_unlock_requires_enrollment_even_when_called_directly(self):
        import olax_unlock_once
        with patch.object(olax_unlock_once, 'validate_candidate', return_value={}):
            with self.assertRaisesRegex(BaseException, 'enrollment'):
                olax_unlock_once.execute(SimpleNamespace(loader=Path('none')))


if __name__ == '__main__':
    unittest.main()
