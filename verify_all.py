"""Rebuild the Windows EXE and run bounded native tests on Linux.

Mocked Win32/J2534 execution is not a physical Windows/OpenPort test.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / 'build'
BUILD.mkdir(exist_ok=True)
subprocess.run([sys.executable, str(ROOT / 'build_windows.py')], check=True)
checks = []
for name in ['test_sender_core', 'test_frontend']:
    command = ['gcc', '-std=c99', '-O1', '-g', '-fsanitize=address,undefined',
               '-fno-omit-frame-pointer', '-Wall', '-Wextra',
               '-Wno-misleading-indentation', '-Wno-unused-function',
               str(ROOT / 'tests' / (name + '.c')), '-o', str(BUILD / name)]
    subprocess.run(command, check=True)
    environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
    # LeakSanitizer cannot enumerate threads in this container; ASan and UBSan remain on.
    result = subprocess.run([str(BUILD / name)], check=True, text=True,
                            capture_output=True, env=environment)
    checks.append({'test': name, 'result': 'PASS', 'output': result.stdout.strip()})
    print(result.stdout, end='')
report = {
    'result': 'PASS',
    'exe_sha256': hashlib.sha256((ROOT / 'OPENPORT_TEST_TABLE.exe').read_bytes()).hexdigest(),
    'checks': checks,
    'sanitizers': ['AddressSanitizer', 'UndefinedBehaviorSanitizer'],
    'leak_sanitizer': 'disabled due to container thread enumeration restriction',
    'physical_OpenPort_or_cluster_tested': False,
    'actual_Windows_GUI_tested': False,
}
(ROOT / 'verification_tests.json').write_text(json.dumps(report, indent=2) + '\n')
