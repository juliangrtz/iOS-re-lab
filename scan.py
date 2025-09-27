import sys
import os
import json
import argparse
import re
from terminal import *
from typing import List, Dict, Tuple
import lief
from lief import MachO
from capstone import *
from capstone.arm64 import *

ANTI_DEBUG_FUNCS = [
    "ptrace", "dlsym", "sysctl", "task_get_exception_ports",
    "isatty", "ioctl", "getpid", "getppid", "syscall", "exit"
]
# anti-JB: "open", "access", "stat", "stat64", "fstat", "lstat"

# increase this if syscall numbers aren't being detected correctly
DISASM_CONTEXT_WINDOW = 40

lief.disable_leak_warning()

def is_aarch64_binary(bin: MachO.Binary) -> bool:
    try:
        return bin.header.cpu_type.name.lower().find("arm64") != -1 or getattr(bin.header, "is_64", False)
    except Exception:
        return False

def get_code_sections(binary: MachO.Binary) -> set[MachO.Section]:
    res = set()
    for sect in binary.sections:
        try:
            if sect.has(MachO.Section.FLAGS.PURE_INSTRUCTIONS):
                res.add(sect)
                continue
        except Exception:
            pass

        if sect.name and sect.name in [".text", "__text"]:
            res.add(sect)
    return res

def find_suspicious_imports(binary: MachO.Binary) -> List[str]:
    found = set()

    for sym in getattr(binary, "imported_symbols", []):
        name = sym.name if hasattr(sym, "name") else str(sym)
        clean_name = name.lstrip("_")
        if clean_name in ANTI_DEBUG_FUNCS:
            found.add(clean_name)

    for sect in binary.sections:
        if sect.name in ["__la_symbol_ptr", "__nl_symbol_ptr"]:
            data = bytes(sect.content or b"")
            for func in ANTI_DEBUG_FUNCS:
                if func.encode() in data:
                    found.add(func + " (la_symbol_ptr)")

    return list(found)

def section_bytes_and_va(sect: lief.MachO.Section) -> Tuple[bytes, int]:
    content = bytes(sect.content) if hasattr(sect, "content") else bytes()
    base_va = sect.virtual_address if sect.virtual_address is not None else 0
    return content, base_va

def get_svc_number(ctx: List[Dict]) -> int | None:
    result = None
    syscall_number_regex = r"x16, #(?:0[xX][0-9a-fA-F]+|\d+)"
    
    for insn in ctx[::-1]:
        mnemonic = insn.get("mnemonic", "")
        if mnemonic == "mov":
            op_str = insn.get("op_str", "")
            m = re.search(syscall_number_regex, op_str)
            if m:
                val = m.group(0).split("#")[1]
                try:
                    result = int(val, 0)
                except ValueError:
                    result = None
                break
    return result
    
def disasm_around_svcs(sec_bytes: bytes, base_va: int, section_offset:int, syscall_map: Dict[str, str], verbose: bool) -> List[Dict]:
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    length = len(sec_bytes)
    i = 0
    results = []

    while i + 4 <= length:
        svc_insn = next(cs.disasm(sec_bytes[i:i + 4], base_va + i), None)
        if svc_insn is None or svc_insn.id != ARM64_INS_SVC:
            i += 4
            continue

        ctx = []
        for ins in cs.disasm(sec_bytes[i-DISASM_CONTEXT_WINDOW:i], 0):
            ctx.append({
                "address": ins.address,
                "mnemonic": ins.mnemonic,
                "op_str": ins.op_str,
            })

        syscall_number = get_svc_number(ctx)

        result = {
            "number": syscall_number,
            "name": syscall_map.get(str(syscall_number), "unknown"),
            "offset": hex(section_offset + i),
            "hex": f"0x{bytes(svc_insn.bytes).hex()}",
            "context": ctx
        }
        results.append(result)

        print_red(f"[{syscall_number if syscall_number is not None else '?'}] {result['name']} @ {result['offset']}")
        if verbose:
            for ins in result.get("context", [])[-12:]:
                mnemonic = str(ins['mnemonic'])
                arrow = ">>> " if mnemonic.startswith("svc") else "    "
                print(f"  {arrow}0x{ins['address']:x}  {mnemonic} {ins['op_str']}")
            print("")

        i += 4
    return results

def scan_syscalls(binary: lief.MachO.Binary, syscall_map: Dict[str, str], verbose: bool) -> List[Dict]:
    print("[*] Scanning syscalls... This might take a while, every instruction must be disassembled.")
    
    code_sections = get_code_sections(binary)
    if not code_sections:
        print_red("[!] No code sections found.")
        return []
    section_names = ", ".join(str(cs.name) for cs in code_sections)
    section_count = len(code_sections)
    print(f"[*] Found {section_count} code section{'s' if section_count > 1 else ''}: {section_names}")

    results = []
    for sect in code_sections:
        sec_bytes, base_va = section_bytes_and_va(sect)
        if not sec_bytes:
            continue

        svc_results = disasm_around_svcs(sec_bytes, base_va, sect.offset, syscall_map, verbose)
        if not svc_results:
            continue
        
        syscalls = len(svc_results)
        print(f"[*] Section {sect.name!s}: {syscalls} syscall{'s' if syscalls > 1 else ''} found")
        for entry in svc_results:
            entry["section"] = sect.name
            results.append(entry)
    
    if not results:
        print("[*] No syscalls found.")
    
    return results


def parse_binaries(path: str) -> List[lief.MachO.Binary]:
    parsed = lief.parse(path)
    if parsed is None:
        raise RuntimeError("Failed to parse: " + path)
    binaries = []
    if isinstance(parsed, lief.MachO.FatBinary):
        for i in range(len(parsed)):
            try:
                b = parsed.at(i)
                binaries.append(b)
            except Exception:
                pass
    elif isinstance(parsed, lief.MachO.Binary):
        binaries.append(parsed)
    else:
        raise RuntimeError("[!] Not a Mach-O binary: " + str(type(parsed)))
    return binaries

def scan_imports(binary: lief.MachO.Binary) -> list[str]:
    print("[*] Scanning imports...")
    imports = find_suspicious_imports(binary)
    for i in imports:
        print(f"[!] Suspicious import: {i}")
        
    if not imports:
        print("[*] No suspicious imports found. They might be resolved indirectly.")
    else:
        print("[*] Use cross-references to check if these functions are used to detect a debugger.")

    return imports

def main():
    ap = argparse.ArgumentParser(description="Mach-O AArch64 syscall scanner")
    ap.add_argument("file", help="Mach-O binary path")
    ap.add_argument("--map", help="Optional JSON mapping for syscalls. Uses syscalls.json by default.",
                    default="syscalls.json")
    ap.add_argument("--out", help="Optional results JSON output path.")
    ap.add_argument("-v", "--verbose", help="Whether to log context around the syscalls.", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print_red("File does not exist:", args.file)
        sys.exit(2)

    syscall_map = {}
    if args.map:
        try:
            with open(args.map, "r") as f:
                syscall_map = json.load(f)
        except Exception as e:
            print_red("Failed to load mapping JSON:", e)

    binaries = parse_binaries(args.file)
    all_results = []
    for b in binaries:
        print(f"[*] Analysis started: cpu={b.header.cpu_type.name}, imagebase={hex(getattr(b, 'imagebase', 0))}, pie={b.is_pie}")
        binary_info = {
            "binary": args.file,
            "cpu": b.header.cpu_type.name,
            "pie": b.is_pie,
            "imports": scan_imports(b),
            "syscalls": scan_syscalls(b, syscall_map, args.verbose)
        }
        all_results.append(binary_info)
        
    if args.out:
        try:
            with open(args.out, "w") as f:
                json.dump(all_results, f, indent=2)
            print("[*] Results written to", args.out)
        except Exception as e:
            print_red("Failed to write output JSON:", e)


if __name__ == "__main__":
    main()
