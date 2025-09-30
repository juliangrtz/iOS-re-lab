rule is_mach_o : file_type
{
  meta:
    description = "Mach-O"

  condition:
    uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe
}