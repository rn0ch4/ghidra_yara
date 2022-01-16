import __main__ as script_api
from datetime import datetime
import jarray
import json
import os
import subprocess
from subprocess import PIPE, Popen
import sys
import tempfile
import traceback
import uuid
from ghidra.util.exception import CancelledException


DIR_GHIDRA = os.path.join('C:', 'Ghidra')
KEY = 'Allsafe!'


class YaraScannerExecError(Exception):
    def __init__(self, message):
        self.message = '[!] failed to execute yara_scanner ({})'.format(message)


class YaraScannerResponseError(Exception):
    def __init__(self, message):
        self.message = '[!] failed to parse yara_scanner\'s result ({})'.format(message)


class YaraScannerRuntimeError(Exception):
    def __init__(self, message):
        self.message = message


def ask_fpath(title, button):
    try:
        f = script_api.askFile(title, button)
        if f:
            return f.getPath()
    except CancelledException:
        pass


def get_fpath_yara_scanner():
    fpath_yara_scanner = os.path.join(DIR_GHIDRA, 'yara_scanner.exe')
    if not os.path.exists(fpath_yara_scanner):
        fpath_yara_scanner = ask_fpath('Choose yara_scanner.exe', 'Use this EXE')
    return fpath_yara_scanner


def get_fpath_yara_rule():
    fpath_yara_rule = os.path.join(DIR_GHIDRA, 'rule.yara')
    if not os.path.exists(fpath_yara_rule):
        fpath_yara_rule = ask_fpath('Choose your YARA rule file', 'Use this rule')
    return fpath_yara_rule


def generate_fpath_enc_target():
    return os.path.join(tempfile.gettempdir(), '{}.allsafe'.format(uuid.uuid4()))


'''
https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_10.1.1_build
/Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/AbstractLoaderExporter.java
'''
def relocate_from_memory_to_file_layout(program, memory_content):
    file_content = bytearray(memory_content)
    relocs = program.getRelocationTable().getRelocations()
    for reloc in relocs:
        addr = reloc.getAddress()
        addr_source_info = program.getMemory().getAddressSourceInfo(addr)
        if not addr_source_info:
            continue
        offset = addr_source_info.getFileOffset()
        if offset >= 0:
            mem_source_info = addr_source_info.getMemoryBlockSourceInfo()
            buf = reloc.getBytes()
            size = min(len(buf), mem_source_info.getMaxAddress().subtract(addr) + 1)
            file_content[offset: offset+size] = buf[:size]
    return bytes(file_content)


def get_content_as_memory_layout(program):
    content = program.getMemory().getAllFileBytes()[0]
    memory_content = jarray.zeros(content.getSize(), 'b')
    content.getModifiedBytes(0, memory_content)
    return memory_content.tostring()


def get_content_as_file_layout(program):
    memory_content = get_content_as_memory_layout(program)
    file_content = relocate_from_memory_to_file_layout(program, memory_content)
    return file_content


def encode(raw, key):
    return ''.join([
        chr(ord(raw[i]) ^ ord(key[i%len(key)]))
        for i in range(len(raw))
    ])


def encode_myself_and_save(fpath_target):
    raw = get_content_as_file_layout(script_api.currentProgram)
    enc = encode(raw, KEY)
    with open(fpath_target, 'wb') as f:
        f.write(enc)


def get_fname_of_python3_interpreter():
    names = ['python', 'python3', 'py']
    for name in names:
        try:
            version = subprocess.call([name, '-c', 'import sys; sys.exit(sys.version_info[0])'])
        except OSError:
            continue
        if version == 3:
            return name


def run_yara_scanner(fpath_yara_scanner, fpath_rule, fpath_enc_target):
    try:
        if fpath_yara_scanner.endswith('.py'):
            fname_python3 = get_fname_of_python3_interpreter()
            if not fname_python3:
                raise Exception('no python3 interpreter was found')
            proc = Popen([fname_python3, fpath_yara_scanner, fpath_rule, fpath_enc_target], stdout=PIPE, stderr=PIPE)
        else:
            proc = Popen([fpath_yara_scanner, fpath_rule, fpath_enc_target], stdout=PIPE, stderr=PIPE)
        stdout, _ = proc.communicate()
        return stdout
    except Exception as e:
        raise YaraScannerExecError(e)


def parse_yara_scanner_result(text):
    try:
        result = json.loads(text)
    except Exception as e:
        raise YaraScannerResponseError(e)

    if 'status' not in result or 'info' not in result:
        raise YaraScannerResponseError('invalid key format')

    if result['status'] != 'success':
        raise YaraScannerRuntimeError(result['info'])

    return result


def generate_scan_id():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def convert_file_offset_to_va(file_offset):
    mem = script_api.currentProgram.getMemory()
    vas = mem.locateAddressesForFileOffset(file_offset)
    if len(vas) == 1:
        return vas[0]


def render_scan_result(matched_info):
    scan_id = generate_scan_id()
    for rule_id, matches in matched_info.items():
        print('[+] "{}" rule matched!'.format(rule_id))
        for match in matches:
            file_offset = match['offset']
            string_id = match['string_id']
            comment = '[{}] {} ({})'.format(scan_id, rule_id, string_id)
            address = convert_file_offset_to_va(file_offset)
            if not address:
                address = script_api.toAddr(file_offset)
                comment = '{} (file offset)'.format(comment)
            script_api.createBookmark(address, 'ghidra_yara', comment)


def run(fpath_yara_scanner='', fpath_rule=''):
    fpath_yara_rule = fpath_yara_scanner or get_fpath_yara_scanner()
    if not fpath_yara_scanner:
        return
    print('[*] yara_scanner: {}'.format(fpath_yara_scanner))

    fpath_rule = fpath_rule or get_fpath_yara_rule()
    if not fpath_rule:
        return
    print('[*] yara_rule: {}'.format(fpath_rule))

    fpath_enc_target = generate_fpath_enc_target()
    # print('[*] enc_target (temporary): {}'.format(fpath_enc_target))

    try:
        encode_myself_and_save(fpath_enc_target)
        result = run_yara_scanner(fpath_yara_scanner, fpath_rule, fpath_enc_target)
        parsed_result = parse_yara_scanner_result(result)

        if parsed_result['info']:
            render_scan_result(parsed_result['info'])
            print('[*] See Bookmarks window for more information (Filter: ghidra_yara)')
        else:
            print('[-] No rule matched...')

    except (YaraScannerExecError, YaraScannerResponseError, YaraScannerRuntimeError) as e:
        print(e.message)
    except Exception as e:
        print('[!] Unknown error ({})'.format(e))

    finally:
        if os.path.exists(fpath_enc_target):
            os.remove(fpath_enc_target)


def get_env_var_from_ghidra_state(key):
    return script_api.state.getEnvironmentVar(key)


def main():
    args = script_api.getScriptArgs()
    if len(args) == 2:
        # executed via headless analyzer
        fpath_yara_scanner, fpath_rule = args
    else:
        # executed via runScript with arguments or Script Manager
        fpath_yara_scanner = get_env_var_from_ghidra_state('fpath_yara_scanner')
        fpath_rule = get_env_var_from_ghidra_state('fpath_rule')
    run(fpath_yara_scanner, fpath_rule)


if __name__ == '__main__':
    main()
