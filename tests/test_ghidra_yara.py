from StringIO import StringIO
import contextlib
import re
import sys
import unittest


# https://stackoverflow.com/questions/44226221/contextlib-redirect-stdout-in-python2-7
@contextlib.contextmanager
def redirect_stdout(target):
    original = sys.stdout
    try:
        sys.stdout = target
        yield
    finally:
        sys.stdout = original


def get_ghidra_yara_results_from_bookmarks(program):
    results = [
        bm for bm in program.getBookmarkManager().getBookmarksIterator('Note')
        if bm.getCategory() == 'ghidra_yara'
    ]
    return results


def remove_ghidra_yara_results_from_bookmarks(program):
    manager = program.getBookmarkManager()
    for bookmark in get_ghidra_yara_results_from_bookmarks(program):
        manager.removeBookmark(bookmark)


def run_ghidra_yara(state, fpath_yara_scanner, fpath_rule):
    state.addEnvironmentVar('fpath_yara_scanner', fpath_yara_scanner)
    state.addEnvironmentVar('fpath_rule', fpath_rule)
    runScript('../ghidra_yara.py', state)


class TestGhidraScript(unittest.TestCase):
    # file path of yara scanner
    VALID_YARA_SCANNER = 'yara_scanner.py'
    NON_YARA_SCANNER = 'tests/non_yara_scanner.py'
    CORRUPTED_YARA_SCANNER = 'tests/corrupted_yara_scanner.py'
    # file path of YARA rules
    SINGLE_MATCH_RULE = 'tests/single_match_rule.yara'
    TWO_MATCH_RULE = 'tests/two_match_rule.yara'
    NO_MATCH_RULE = 'tests/no_match_rule.yara'
    INVALID_RULE = 'tests/invalid_rule.yara'
    # YARA rule id
    RULE_ID_SINGLE_MATCH = 'RULE_ID_SINGLE_MATCH'
    RULE_ID_MATCH_1 = 'RULE_ID_MATCH_1'
    RULE_ID_MATCH_2 = 'RULE_ID_MATCH_2'
    RULE_ID_NOT_MATCH = 'RULE_ID_NOT_MATCH'
    # YARA string id
    STRING_ID_SINGLE_MATCH = '$this_is_a_string_id'
    # YARA hit address (VA)
    ADDR_SINGLE_MATCH = 0x404000
    # console output
    CONSOLE_OUTPUT_MATCHED = '[+] "{}" rule matched!'
    CONSOLE_OUTPUT_NOT_MATCHED = '[-] No rule matched...'
    CONSOLE_OUTPUT_FAILED_COMPILE = '[!] failed to compile YARA rule'
    CONSOLE_OUTPUT_INVALID_SCANNER = "[!] failed to parse yara_scanner's result (No JSON object could be decoded)"
    CONSOLE_OUTPUT_INVALID_RESPONSE = "[!] failed to parse yara_scanner's result (invalid key format)"

    def setUp(self):
        self.console_output = StringIO()

    def tearDown(self):
        remove_ghidra_yara_results_from_bookmarks(currentProgram)
        state.removeEnvironmentVar('fpath_yara_scanner')
        state.removeEnvironmentVar('fpath_rule')

    def test_single_rule_matched(self):

        with redirect_stdout(self.console_output):
            run_ghidra_yara(state, self.VALID_YARA_SCANNER, self.SINGLE_MATCH_RULE)

        self.assertIn(self.CONSOLE_OUTPUT_MATCHED.format(self.RULE_ID_SINGLE_MATCH), self.console_output.getvalue())

        scan_results = get_ghidra_yara_results_from_bookmarks(currentProgram)
        self.assertEqual(1, len(scan_results))

        ghidra_yara_bookmark = scan_results[0]

        matched_addr = ghidra_yara_bookmark.getAddress().getOffset()
        self.assertEqual(self.ADDR_SINGLE_MATCH, matched_addr)

        matched_rule_info = ghidra_yara_bookmark.getComment()
        self.assertIn(self.RULE_ID_SINGLE_MATCH, matched_rule_info)
        self.assertIn(self.STRING_ID_SINGLE_MATCH, matched_rule_info)

    def test_two_rule_matched(self):
        with redirect_stdout(self.console_output):
            run_ghidra_yara(state, self.VALID_YARA_SCANNER, self.TWO_MATCH_RULE)

        self.assertIn(self.CONSOLE_OUTPUT_MATCHED.format(self.RULE_ID_MATCH_1), self.console_output.getvalue())
        self.assertIn(self.CONSOLE_OUTPUT_MATCHED.format(self.RULE_ID_MATCH_2), self.console_output.getvalue())
        self.assertNotIn(self.CONSOLE_OUTPUT_MATCHED.format(self.RULE_ID_NOT_MATCH), self.console_output.getvalue())

        scan_results = get_ghidra_yara_results_from_bookmarks(currentProgram)
        self.assertEqual(0, len(scan_results))

    def test_no_rule_matched(self):
        with redirect_stdout(self.console_output):
            run_ghidra_yara(state, self.VALID_YARA_SCANNER, self.NO_MATCH_RULE)

        self.assertIn(self.CONSOLE_OUTPUT_NOT_MATCHED, self.console_output.getvalue())

        scan_results = get_ghidra_yara_results_from_bookmarks(currentProgram)
        self.assertEqual(0, len(scan_results))

    def test_invalid_yara_rule(self):
        with redirect_stdout(self.console_output):
            run_ghidra_yara(state, self.VALID_YARA_SCANNER, self.INVALID_RULE)

        self.assertIn(self.CONSOLE_OUTPUT_FAILED_COMPILE, self.console_output.getvalue())

        scan_results = get_ghidra_yara_results_from_bookmarks(currentProgram)
        self.assertEqual(0, len(scan_results))

    def test_non_yara_scanner(self):
        with redirect_stdout(self.console_output):
            run_ghidra_yara(state, self.NON_YARA_SCANNER, self.SINGLE_MATCH_RULE)

        self.assertIn(self.CONSOLE_OUTPUT_INVALID_SCANNER, self.console_output.getvalue())

        scan_results = get_ghidra_yara_results_from_bookmarks(currentProgram)
        self.assertEqual(0, len(scan_results))

    def test_corrupted_yara_scanner_response(self):
        with redirect_stdout(self.console_output):
            run_ghidra_yara(state, self.CORRUPTED_YARA_SCANNER, self.SINGLE_MATCH_RULE)

        self.assertIn(self.CONSOLE_OUTPUT_INVALID_RESPONSE, self.console_output.getvalue())

        scan_results = get_ghidra_yara_results_from_bookmarks(currentProgram)
        self.assertEqual(0, len(scan_results))



if __name__ == '__main__':
    print('')
    print('*'*20 + ' Ghidra Script (Python) Test ' + '*'*20)
    print('')
    unittest.main(buffer=True, verbosity=2)
