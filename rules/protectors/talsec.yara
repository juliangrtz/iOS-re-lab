include "../common.yara"

rule TALSEC : protector
{
    meta:
        description = "Talsec freeRASP for iOS (open-source)"
        url = "https://github.com/talsec/Free-RASP-iOS"
        author = "juliangrtz"

    strings:
        $s1 = "@rpath/TalsecRuntime.framework/TalsecRuntime" nocase
        $s2 = "TalsecRuntime" ascii
        $s3 = "TalsecConfig" ascii

    condition:
        is_mach_o and ( 1 of ($s1, $s2, $s3) )
}