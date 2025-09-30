include "../common.yara"

rule IOSSecuritySuite : protector
{
    meta:
        description = "iOS Security Suite (open-source)"
        url = "https://github.com/securing/IOSSecuritySuite"
        author = "juliangrtz"

    strings:
        $s1 = "IOSSecuritySuite" nocase
        $s2 = "FishHookChecker.swift" ascii
        $s3 = "MSHookFunctionChecker" ascii

    condition:
        is_mach_o and ( 1 of ($s1, $s2, $s3) )
}