"""POSIX callback alarms; Windows fails closed instead of interrupting USB threads."""
import os
import signal as native
import threading

SIGALRM = getattr(native, 'SIGALRM', 14)
_timer = None
_handler = None
_lock = threading.Lock()
_generation = 0


def signal(number, handler):
    global _handler
    if os.name != 'nt':
        return native.signal(number, handler)
    previous, _handler = _handler, handler
    return previous


def alarm(seconds):
    global _timer, _generation
    if os.name != 'nt':
        return native.alarm(seconds)
    # Raising in a worker thread cannot abort a synchronous USB transaction.
    # The parent journals UNKNOWN before starting this process, never retries it.
    with _lock:
        _generation += 1
        generation = _generation
        if _timer:
            _timer.cancel()
            _timer = None
        if seconds:
            def expired():
                with _lock:
                    if generation == _generation:
                        os._exit(124)
            _timer = threading.Timer(seconds, expired)
            _timer.daemon = True
            _timer.start()
    return 0
