"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" tests ghidra_yara_test -import tests/test.exe -readOnly -noanalysis -scriptPath tests -preScript test_ghidra_yara.py
