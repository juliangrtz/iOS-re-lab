include "../common.yara"

rule PROMON_SHIELD : protector
{
    meta:
        description = "Promon SHIELD (commercial)"
        url = "https://promon.io/products/mobile"
        author = "juliangrtz"
        confidence = "100%"
        
    strings:
        $s1 = "no.promon.shield" nocase
        $s2 = "/release/shield/dist/" ascii
        $s3 = "PRMShieldConfig" ascii

    condition:
        is_mach_o and ( 1 of ($s*) )
}