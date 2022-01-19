import "hash"

rule RULE_ID_SINGLE_MATCH
{
    meta:
        author = "rn0ch4"
        description = "This is a YARA rule to check whether ghidra_yara work correctly"
        sha1 = "32be9afdccc76c1dba49b0fb7fd031ab3b44a9ae"

    strings:
        $this_is_a_string_id = "THIS IS A TEST"

    condition:
        // to check whether encoding/exporting/decoding work correctly
        hash.sha1(0, filesize) == "32be9afdccc76c1dba49b0fb7fd031ab3b44a9ae" and
        // to check whether scanning and rendering results work correctly
        all of them
}
