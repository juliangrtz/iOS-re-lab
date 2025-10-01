include "../common.yara"

rule DIGITAL_AI : protector
{
    meta:
        description = "Digital.ai, formerly Arxan (commercial)"
        url = "https://digital.ai/products/application-security/"
        author = "Eduardo Novella"

    strings:
        $m1 = { 10 62 (6? | 75) [14] 00 }
        $m2 = { (0b | 0d) 62 d0 [15] 00 }
        $m3 = { (0e | 10) 62 30 34 3? [15] 00 }
        $m4 = { (0b | 0d) 62 30 34 3? [13] 00 }
        $m5 = { (08 | 0b | 0d | 0e ) 62 [7-13] 00 }
        $m6 = { 0a 62 (30 34 3? | d? ?? ??) [11] 00 }
        $m7 = { (0d | 0b | 11) (62 d1 8? | 6? ?? ??) [14] 00 }

    condition:
        is_mach_o and ( 2 of ($m*) )
}
