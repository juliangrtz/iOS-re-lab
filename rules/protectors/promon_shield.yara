include "../common.yara"

rule PROMON_SHIELD : protector
{
    meta:
        description = "Promon SHIELD (commercial)"
        url = "https://promon.io/products/mobile"
        author = "juliangrtz"
        confidence = "100%"
        info1 = "https://www.researchgate.net/publication/325640295_Honey_I_Shrunk_Your_App_Security_The_State_of_Android_App_Hardening"
        info2 = "https://github.com/KiFilterFiberContext/promon-reversal"

    strings:
        $s1 = "no.promon.shield" nocase
        $s2 = "/release/shield/dist/" ascii
        $s3 = "PRMShieldConfig" ascii

    condition:
        is_mach_o and ( 1 of ($s*) )
}