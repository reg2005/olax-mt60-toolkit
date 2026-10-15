"""Run offline Python tests with the pinned upstream on all three platforms."""
import os
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(root), str(root/'engine'), str(root/'.runtime')]))
subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(root/'tests'), '-v'], cwd=root, env=env, check=True)
