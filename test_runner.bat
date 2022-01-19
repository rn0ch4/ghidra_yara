"%GHIDRA_INSTALL_DIR%/support/analyzeHeadless.bat" tests ghidra_yara_test -import tests/test.exe -readOnly -noanalysis -scriptPath tests -preScript test_ghidra_yara.py %1 2>&1 | findstr /R /C:"^OK$"
