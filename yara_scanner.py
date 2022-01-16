import json
import sys
import yara


KEY = b'Allsafe!'


class YaraCompileRuleError(Exception):
    def __init__(self, message):
        self.message = '[!] failed to compile YARA rule ({})'.format(message)


class FileDecodeError(Exception):
    def __init__(self, fpath_enc_target):
        self.message = '[!] failed to load target file ({})'.format(fpath_enc_target)


class YaraMatchRuntimeError(Exception):
    def __init__(self, message):
        self.message = '[!] failed to scan target file ({})'.format(message)


def decode(enc, key):
    return bytes([
        enc[i] ^ key[i%len(key)]
        for i in range(len(enc))
    ])


def read_file(fpath):
    with open(fpath, 'rb') as f:
        content = f.read()
    return content


def read_file_and_decode(fpath, key):
    enc = read_file(fpath)
    dec = decode(enc, key)
    return dec


def compile_rule(fpath_rule):
    content = read_file(fpath_rule)
    rule = yara.compile(source=content.decode())
    return rule


def scan_encoded_file(fpath_rule, fpath_enc_target):
    try:
        rule = compile_rule(fpath_rule)
    except Exception as e:
        raise YaraCompileRuleError(e)
    try:
        content = read_file_and_decode(fpath_enc_target, KEY)
    except Exception as e:
        raise FileDecodeError(fpath_enc_target)
    try:
        results = rule.match(data=content)
    except Exception as e:
        raise YaraMatchRuntimeError(e)
    return results


def format_response(status, info):
    result = {}
    result['status'] = status
    result['info'] = info
    return result


def format_success_response(info):
    return format_response('success', info)


def format_error_response(info):
    return format_response('error', info)


def parse_matched_results(matched_results):
    parsed_result = {}
    for matched_result in matched_results:
        # info[0] -> file offset, info[1] -> string_id, info[2] -> matched content
        parsed_result.update({
            matched_result.rule: [
                {'offset': info[0], 'string_id': info[1]}
                for info in matched_result.strings
            ]
        })
    return parsed_result


def run(fpath_rule, fpath_enc_target):
    try:
        matched_results = scan_encoded_file(fpath_rule, fpath_enc_target)
        if matched_results:
            parsed_result = parse_matched_results(matched_results)
            return format_success_response(parsed_result)
        return format_success_response(None)
    except (YaraCompileRuleError, FileDecodeError, YaraMatchRuntimeError) as e:
        return format_error_response(e.message)
    except Exception as e:
        return format_error_response('[!] unexpected error ({})'.format(e))


def main(fpath_rule, fpath_enc_target):
    result = run(fpath_rule, fpath_enc_target)
    open('/tmp/result.json', 'w').write(json.dumps(result))
    print(json.dumps(result))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(format_error_response('[!] invalid arguments (should be <RULE> <TARGET>)'.format(sys.argv[0])))
        sys.exit(-1)
    fpath_rule, fpath_enc_target = sys.argv[1:]
    main(fpath_rule, fpath_enc_target)
