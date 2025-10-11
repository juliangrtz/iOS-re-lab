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
import yara

RULES_DIRECTORY = "rules"

# increase this if syscall numbers aren't being detected correctly
DISASM_CONTEXT_WINDOW = 40

with open("strings.json", "r") as f:
    STRINGS = json.load(f)

SUSPICIOUS_IMPORTS = STRINGS["SUSPICIOUS_IMPORTS"]
JAILBREAK_STRINGS = STRINGS["JAILBREAK_STRINGS"]

lief.disable_leak_warning()


def load_yara():
    rule_files = []
    for root, _, files in os.walk(RULES_DIRECTORY):
        for f in files:
            if f.endswith(".yara"):
                rule_files.append(os.path.join(root, f))

    if not rule_files:
        print_yellow(f"[!] No YARA rules in '{RULES_DIRECTORY}' directory!")
        return None

    file_dict = {}
    for i, path in enumerate(rule_files):
        namespace = f"ns{i}"
        file_dict[namespace] = path

    try:
        rules = yara.compile(filepaths=file_dict)
        print(f"[*] Loaded {len(rule_files)} YARA rules.")
        return rules
    except Exception as e:
        print_yellow(f"[!] Failed to compile YARA rules: {e}")
        return None


def scan_yara(rules, file_path: str):
    if not rules:
        return []

    print("[*] Scanning for protectors...")
    try:
        matches = [r for r in rules.match(file_path) if r.rule != "is_mach_o"]

        if not matches:
            print("[*] Didn't find known protectors with YARA.")
            return []

        def _parse_confidence(val):
            if val is None:
                return None
            try:
                if isinstance(val, str):
                    s = val.strip()
                    if s.endswith("%"):
                        s = s[:-1]
                    return int(float(s))
                return int(float(val))
            except Exception:
                return None

        matches_with_confidence = []
        for m in matches:
            meta = getattr(m, "meta", {}) or {}
            confidence = _parse_confidence(meta.get("confidence"))
            matches_with_confidence.append((m, confidence))

        safe_matches = [m for m, c in matches_with_confidence if c == 100]

        if safe_matches:
            kept = safe_matches
        else:
            kept = matches

        for m in kept:
            meta = getattr(m, "meta", {}) or {}
            confidence = meta.get("confidence")
            desc = meta.get("description", "<no description>")
            url = meta.get("url", "<no url>")
            info_urls = [v for k, v in meta.items() if k.startswith("info")]

            print_red("[!] YARA match")
            print_red(f"    confidence: {confidence}")
            print_red(f"    description: {desc}")
            print_red(f"    url: {url}")
            print_red(f"    info: {', '.join(info_urls)}")

        return kept

    except Exception as e:
        print_yellow(f"[!] Error during YARA scan: {e}")
        return []


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


def _build_lookup_table(suspicious: Dict[str, List[str]]) -> Dict[str, str]:
    table: Dict[str, str] = {}
    for cat, names in suspicious.items():
        for n in names:
            key = n.lstrip("_").lower()
            if key not in table:
                table[key] = cat
            orig_key = n.lower()
            if orig_key not in table:
                table[orig_key] = cat
    return table


def find_suspicious_symbols(binary: lief.MachO.Binary) -> List[str]:
    found = set()
    lookup = _build_lookup_table(SUSPICIOUS_IMPORTS)

    for sym in getattr(binary, "imported_symbols", []):
        name = sym.name if hasattr(sym, "name") else str(sym)
        clean = name.lstrip("_").lower()

        if clean in lookup:
            found.add(f"{clean} ({lookup[clean]})")
        elif name.lower() in lookup:
            found.add(f"{name} ({lookup[name.lower()]})")
        else:
            lname = name.lower()
            for jb in JAILBREAK_STRINGS:
                if jb.lower() in lname:
                    found.add(
                        f"{jb} (ANTI_JAILBREAK_STRING, import_symbol={name})")

    for sect in getattr(binary, "sections", []):
        sect_name = getattr(sect, "name", "")
        data = bytes(getattr(sect, "content", b"") or b"")

        if sect_name in ("__la_symbol_ptr", "__nl_symbol_ptr"):
            for key, cat in lookup.items():
                try:
                    kb = key.encode("utf-8")
                except Exception:
                    continue
                if kb and kb in data:
                    found.add(f"{key} ({cat}, la_symbol_ptr)")

        if data:
            lower_data = data.lower()
            for jb in JAILBREAK_STRINGS:
                jb_b = jb.encode("utf-8").lower()
                if jb_b in lower_data:
                    found.add(
                        f"{jb} (ANTI_JAILBREAK_STRING, section={sect_name})")

            for key, cat in lookup.items():
                if len(key) < 3:
                    continue
                try:
                    kb = key.encode("utf-8").lower()
                except Exception:
                    continue
                if kb in lower_data:
                    label = f"{key} ({cat}, rodata)"
                    if label not in found:
                        found.add(label)

    if hasattr(binary, "objc_classes"):
        for cls in getattr(binary, "objc_classes") or []:
            cls_name = cls.name if hasattr(cls, "name") else str(cls)
            ln = cls_name.lower()
            for jb in JAILBREAK_STRINGS:
                if jb.lower() in ln:
                    found.add(
                        f"{jb} (ANTI_JAILBREAK_STRING, objc_class={cls_name})")

    return sorted(found)


def section_bytes_and_va(sect: lief.MachO.Section) -> Tuple[bytes, int]:
    content = bytes(sect.content) if hasattr(sect, "content") else bytes()
    base_va = sect.virtual_address if sect.virtual_address is not None else 0
    return content, base_va


def get_svc_number(ctx: List[Dict]) -> int | None:
    result = None
    syscall_number_regex = r"(x|w)16, #(?:0[xX][0-9a-fA-F]+|\d+)"

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


def scan_brk_instructions(code_sections: set[MachO.Section], verbose: bool = False) -> List[Dict]:
    print("[*] Scanning for BRK instructions...")
    results = []
    if not code_sections:
        return results

    for sect in code_sections:
        sec_bytes, base_va = section_bytes_and_va(sect)
        if not sec_bytes:
            continue

        length = len(sec_bytes)
        i = 0
        while i + 4 <= length:
            if sec_bytes[i+2] == 0x20 and sec_bytes[i+3] == 0xD4:
                entry = {
                    "section": sect.name,
                    "address": hex(sect.offset + i),
                    "bytes": f"0x{sec_bytes[i:i+4].hex()}",
                }
                results.append(entry)
                print_red(
                    f"[!] BRK instruction @ {entry['address']}")
                if verbose:
                    start = max(0, i-16)
                    end = min(length, i+20)
                    snippet = sec_bytes[start:end].hex()
                    print(f"    {hex(start)}: {snippet}")
                i += 4
            else:
                i += 1
    if not results:
        print("[*] No BRK occurrences found.")
    return results


def disasm(sec_bytes: bytes, base_va: int, section_offset: int, syscall_map: Dict[str, str], verbose: bool) -> List[Dict]:
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
        start = 0
        end = i - DISASM_CONTEXT_WINDOW
        for ins in cs.disasm(sec_bytes[max(start, end):i], base_va + max(start, end)):
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

        print_red(
            f"[{syscall_number if syscall_number is not None else '?'}] {result['name']} @ {result['offset']}")
        if verbose:
            for ins in result.get("context", [])[-12:]:
                mnemonic = str(ins['mnemonic'])
                arrow = ">>> " if mnemonic.startswith("svc") else "    "
                print(
                    f"  {arrow}0x{ins['address']:x}  {mnemonic} {ins['op_str']}")
            print("")

        i += 4
    return results


def scan_syscalls(code_sections: set[MachO.Section], syscall_map: Dict[str, str], verbose: bool) -> List[Dict]:
    print("[*] Scanning syscalls... This might take a while, every instruction must be disassembled.")

    if not code_sections:
        print_red("[!] No code sections found.")
        return []
    section_names = ", ".join(str(cs.name) for cs in code_sections)
    section_count = len(code_sections)
    print(
        f"[*] Found {section_count} code section{'s' if section_count > 1 else ''}: {section_names}")

    results = []
    for sect in code_sections:
        sec_bytes, base_va = section_bytes_and_va(sect)
        if not sec_bytes:
            continue

        svc_results = disasm(
            sec_bytes, base_va, sect.offset, syscall_map, verbose)
        if not svc_results:
            continue

        syscalls = len(svc_results)
        print(
            f"[*] Section {sect.name!s}: {syscalls} syscall{'s' if syscalls > 1 else ''} found")
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
            except Exception as e:
                print(f"Failed to parse fat binary: {e}")
                pass
    elif isinstance(parsed, lief.MachO.Binary):
        binaries.append(parsed)
    else:
        raise RuntimeError("[!] Not a Mach-O binary: " + str(type(parsed)))
    return binaries


def scan_symbols(binary: lief.MachO.Binary) -> list[str]:
    print("[*] Scanning symbols...")
    print("[*] Note: Strings might be encrypted, encoded or otherwise obfuscated.")
    symbols = find_suspicious_symbols(binary)
    for i in symbols:
        print_red(f"[!] Suspicious symbol: {i}")

    if not symbols:
        print("[*] No suspicious symbols found.")
    else:
        print("[*] Use cross-references to check if these symbols are actually harmful.")

    return symbols


def main():
    ap = argparse.ArgumentParser(description="iOS-antiantire")
    ap.add_argument("file", help="Mach-O binary path")
    ap.add_argument("--map", help="Optional JSON mapping for syscalls. Uses syscalls.json by default.",
                    default="syscalls.json")
    ap.add_argument("--out", help="Optional results JSON output path.")
    ap.add_argument("-v", "--verbose",
                    help="Whether to log context around the syscalls.", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print_yellow("File does not exist:", args.file)
        sys.exit(2)

    syscall_map = {}
    if args.map:
        try:
            with open(args.map, "r") as f:
                syscall_map = json.load(f)
        except Exception as e:
            print_yellow("Failed to load mapping JSON:", e)

    binaries = parse_binaries(args.file)
    yara_rules = load_yara()
    all_results = []
    for b in binaries:
        print(
            f"[*] Analysis started: cpu={b.header.cpu_type.name}, imagebase={hex(getattr(b, 'imagebase', 0))}, pie={b.is_pie}")

        code_sections = get_code_sections(b)

        binary_info = {
            "binary": args.file,
            "cpu": b.header.cpu_type.name,
            "pie": b.is_pie,
            "yara_matches": [m.rule for m in scan_yara(yara_rules, args.file)],
            "imports": scan_symbols(b),
            # "brks": scan_brk_instructions(code_sections, args.verbose),
            "syscalls": scan_syscalls(code_sections, syscall_map, args.verbose)
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
