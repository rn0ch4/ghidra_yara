import os
from subprocess import Popen, PIPE
import sys


def get_fname_headless_analyzer():
    fname = 'analyzeHeadless'
    if os.name == 'nt':
        fname += '.bat'
    return fname


def get_fpath_headless_analyzer():
    fname = get_fname_headless_analyzer()
    return os.path.join(os.environ['GHIDRA_INSTALL_DIR'], 'support', fname)


def run_test_headless_analyzer(project_location, project_name, fpath_import, dir_script, fname_pre_script, script_args):
    fpath_headless_analyzer = get_fpath_headless_analyzer()
    commands = [
        fpath_headless_analyzer, project_location, project_name,
        '-import', fpath_import, '-readOnly', '-noanalysis',
        '-scriptPath', dir_script,
        '-preScript', fname_pre_script, *script_args
    ]
    proc = Popen(commands, stderr=PIPE)
    _, result = proc.communicate()
    return result.decode()


def is_test_ok(result):
    return 'OK' in result.splitlines()


def run(fpath_yara_scanner):
    result = run_test_headless_analyzer(
        project_location='tests',
        project_name='ghidra_yara_test',
        fpath_import='tests/test.exe',
        dir_script='tests',
        fname_pre_script='test_ghidra_yara.py',
        script_args=[fpath_yara_scanner]
    )
    print('*'*20 + ' [TEST RESULT] ' + '*'*20)
    print(result)
    if is_test_ok(result):
        sys.exit(0)
    sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('{} <fpath_yara_scanner>'.format(sys.argv[0]))
        sys.exit(-1)
    run(sys.argv[1])
