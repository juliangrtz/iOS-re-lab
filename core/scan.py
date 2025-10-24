from __future__ import annotations

import json
import os
import re
from typing import List, Dict, Tuple, Callable, Any

import lief
import yara
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_SVC
from lief import MachO

from .logger import *

LoggerType = Callable[[str, str, object | None], None]


class MachOScanner:
    """
    Scans a Mach-O file for interesting or suspicious artifacts.

    Example:
        scanner = MachOScanner(strings_path="data/strings.json", rules_dir="rules")
        results = scanner.analyze("/path/to/binary", syscall_map_path="syscalls.json", verbose=True)
    """
    DISASM_CONTEXT_WINDOW = 40

    def __init__(
            self,
            strings_path: Optional[str] = "data/strings.json",
            strings_dict: Optional[Dict[str, Any]] = None,
            rules_dir: str = "rules",
            disasm_context_window: Optional[int] = None,
    ):
        self.rules_dir = rules_dir
        self.yara_rules = None
        self.DISASM_CONTEXT_WINDOW = disasm_context_window or MachOScanner.DISASM_CONTEXT_WINDOW

        try:
            lief.disable_leak_warning()
        except Exception:
            warn("Failed to disable LIEF leak warnings!")
            pass

        if strings_dict is not None:
            self._load_strings_from_dict(strings_dict)
        else:
            if strings_path and os.path.exists(strings_path):
                with open(strings_path, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                        self._load_strings_from_dict(data)
                    except Exception as e:
                        warn(f"Error loading strings.json: {e}")
                        self.SUSPICIOUS_IMPORTS = {}
                        self.JAILBREAK_STRINGS = []
            else:
                warn("strings.json not found")
                self.SUSPICIOUS_IMPORTS = {}
                self.JAILBREAK_STRINGS = []

    def _load_strings_from_dict(self, data: Dict[str, Any]):
        self.STRINGS = data
        self.SUSPICIOUS_IMPORTS = data.get("SUSPICIOUS_IMPORTS", {})
        self.JAILBREAK_STRINGS = data.get("JAILBREAK_STRINGS", [])

    # ---------------------------
    # YARA
    # ---------------------------
    def load_yara(self) -> Optional[yara.Rules]:
        """
        Compiles YARA rules inside self.rules_dir and saves results into self.yara_rules.
        """
        rule_files = []
        for root, _, files in os.walk(self.rules_dir):
            for f in files:
                if f.endswith(".yara") or f.endswith(".yara.txt"):
                    rule_files.append(os.path.join(root, f))

        if not rule_files:
            warn(f"No YARA rules found in '{self.rules_dir}'.")
            self.yara_rules = None
            return None

        file_dict = {f"ns{i}": path for i, path in enumerate(rule_files)}
        try:
            rules = yara.compile(filepaths=file_dict)
            self.yara_rules = rules
            info(f"{len(rule_files)} YARA rules loaded.")
            return rules
        except Exception as e:
            error(f"Error compiling YARA rules: {e}")
            self.yara_rules = None
            return None

    def scan_yara(self, file_path: str) -> List[yara.Match]:
        """
        Scans a file with loaded YARA rules (load_yara must have been called or self.yara_rules set manually).
        Returns the list of matches.
        """
        if not self.yara_rules:
            info("No YARA rules loaded; skipping YARA scan.")
            return []

        try:
            matches = [r for r in self.yara_rules.match(
                file_path) if getattr(r, "rule", "") != "is_mach_o"]
            if not matches:
                info("No known protectors found via YARA.")
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
            kept = safe_matches if safe_matches else [
                m for m, _ in matches_with_confidence]

            for m in kept:
                meta = getattr(m, "meta", {}) or {}
                confidence = meta.get("confidence")
                desc = meta.get("description", "<no description>")
                url = meta.get("url", "<no url>")
                info_urls = [
                    v for k, v in meta.items() if k.startswith("info")]
                info(
                    f"[YARA] {m.rule} (confidence={confidence}) - {desc} {url} {info_urls}")

            return kept

        except Exception as e:
            error(f"Error during YARA scan: {e}")
            return []

    def is_aarch64_binary(self, bin: MachO.Binary) -> bool:
        try:
            return bin.header.cpu_type.name.lower().find("arm64") != -1 or getattr(bin.header, "is_64", False)
        except Exception:
            return False

    def get_code_sections(self, binary: MachO.Binary) -> set:
        res = set()
        for sect in binary.sections:
            try:
                if sect.has(MachO.Section.FLAGS.PURE_INSTRUCTIONS):
                    res.add(sect)
                    continue
            except Exception:
                pass

            if getattr(sect, "name", None) in (".text", "__text"):
                res.add(sect)
        return res

    def _build_lookup_table(self, suspicious: Dict[str, List[str]]) -> Dict[str, str]:
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

    def find_suspicious_symbols(self, binary: lief.MachO.Binary) -> List[str]:
        found = set()
        lookup = self._build_lookup_table(self.SUSPICIOUS_IMPORTS)

        for sym in getattr(binary, "imported_symbols", []):
            name = sym.name if hasattr(sym, "name") else str(sym)
            clean = name.lstrip("_").lower()

            if clean in lookup:
                found.add(f"{clean} ({lookup[clean]})")
            elif name.lower() in lookup:
                found.add(f"{name} ({lookup[name.lower()]})")
            else:
                lname = name.lower()
                for jb in self.JAILBREAK_STRINGS:
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
                for jb in self.JAILBREAK_STRINGS:
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
                for jb in self.JAILBREAK_STRINGS:
                    if jb.lower() in ln:
                        found.add(
                            f"{jb} (ANTI_JAILBREAK_STRING, objc_class={cls_name})")

        return sorted(found)

    def section_bytes_and_va(self, sect: lief.MachO.Section) -> Tuple[bytes, int]:
        content = bytes(sect.content) if hasattr(sect, "content") else bytes()
        base_va = sect.virtual_address if getattr(
            sect, "virtual_address", None) is not None else 0
        return content, base_va

    # ---------------------------
    # Syscall detection / disasm
    # ---------------------------
    def get_svc_number(self, ctx: List[Dict]) -> Optional[int]:
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

    def scan_brk_instructions(self, code_sections: set, verbose: bool = False) -> List[Dict]:
        info("Scanning for BRK instructions...")
        results: List[Dict] = []
        if not code_sections:
            return results

        for sect in code_sections:
            sec_bytes, base_va = self.section_bytes_and_va(sect)
            if not sec_bytes:
                continue
            length = len(sec_bytes)
            i = 0
            while i + 4 <= length:
                if sec_bytes[i + 2] == 0x20 and sec_bytes[i + 3] == 0xD4:
                    entry = {
                        "section": sect.name,
                        "address": hex(sect.offset + i) if hasattr(sect, "offset") else hex(base_va + i),
                        "bytes": f"0x{sec_bytes[i:i + 4].hex()}",
                    }
                    results.append(entry)
                    warn(f"BRK @ {entry['address']}")
                    if verbose:
                        start = max(0, i - 16)
                        end = min(length, i + 20)
                        snippet = sec_bytes[start:end].hex()
                        debug(f"    {hex(start)}: {snippet}")
                    i += 4
                else:
                    i += 1
        if not results:
            info("No BRK instructions found.")
        return results

    def disasm(self, sec_bytes: bytes, base_va: int, section_offset: int, syscall_map: Dict[str, str], verbose: bool) -> \
            List[Dict]:
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True
        length = len(sec_bytes)
        i = 0
        results: List[Dict] = []

        while i + 4 <= length:
            svc_insn = next(cs.disasm(sec_bytes[i:i + 4], base_va + i), None)
            if svc_insn is None or svc_insn.id != ARM64_INS_SVC:
                i += 4
                continue

            ctx = []
            start = 0
            end = i - self.DISASM_CONTEXT_WINDOW
            for ins in cs.disasm(sec_bytes[max(start, end):i], base_va + max(start, end)):
                ctx.append({
                    "address": ins.address,
                    "mnemonic": ins.mnemonic,
                    "op_str": ins.op_str,
                })

            syscall_number = self.get_svc_number(ctx)

            result = {
                "number": syscall_number,
                "name": syscall_map.get(str(syscall_number), "unknown"),
                "offset": hex(section_offset + i),
                "hex": f"0x{bytes(svc_insn.bytes).hex()}",
                "context": ctx
            }
            results.append(result)

            info(
                f"[SYSCALL] [{syscall_number if syscall_number is not None else '?'}] {result['name']} @ {result['offset']}"
            )
            if verbose:
                for ins in result.get("context", [])[-12:]:
                    mnemonic = str(ins['mnemonic'])
                    arrow = ">>> " if mnemonic.startswith("svc") else "    "
                    debug(f"  {arrow}0x{ins['address']:x}  {mnemonic} {ins['op_str']}")
                debug("")
            i += 4
        return results

    def scan_syscalls(self, code_sections: set, syscall_map: Dict[str, str], verbose: bool) -> List[Dict]:
        info("Scanning syscalls...")
        if not code_sections:
            warn("No executable sections found!")
            return []
        section_names = ", ".join(str(cs.name) for cs in code_sections)
        section_count = len(code_sections)
        info(
            f"Found code sections ({section_count}): {section_names}"
        )

        results: List[Dict] = []
        for sect in code_sections:
            sec_bytes, base_va = self.section_bytes_and_va(sect)
            if not sec_bytes:
                continue
            svc_results = self.disasm(sec_bytes, base_va, getattr(
                sect, "offset", 0), syscall_map or {}, verbose)
            if not svc_results:
                continue
            syscalls = len(svc_results)
            info(f"Section {sect.name}: {syscalls} syscall(s) found")
            for entry in svc_results:
                entry["section"] = sect.name
                results.append(entry)

        if not results:
            info("No syscalls found.")
        return results

    # ---------------------------
    # Parsing / Symbol scan
    # ---------------------------
    def parse_binaries(self, path: str) -> List[lief.MachO.Binary]:
        parsed = lief.parse(path)
        if parsed is None:
            raise RuntimeError("Parsing failed: " + path)
        binaries: List[lief.MachO.Binary] = []
        if isinstance(parsed, lief.MachO.FatBinary):
            for i in range(len(parsed)):
                try:
                    b = parsed.at(i)
                    binaries.append(b)
                except Exception as e:
                    warn(f"Error parsing fat binary: {e}")
                    pass
        elif isinstance(parsed, lief.MachO.Binary):
            binaries.append(parsed)
        else:
            raise RuntimeError("Not a Mach-O binary: " + str(type(parsed)))
        return binaries

    def scan_symbols(self, binary: lief.MachO.Binary) -> List[str]:
        info("Scanning symbols...")
        symbols = self.find_suspicious_symbols(binary)
        for s in symbols:
            warn(f"Suspicious symbol: {s}")
        if not symbols:
            info("No suspicious symbols found.")
            return []
        else:
            info("Use Xrefs to check them.")
            return symbols

    # ---------------------------
    # High-level analysis
    # ---------------------------

    def analyze(
            self,
            file_path: str,
            syscall_map_path: Optional[str] = "data/syscalls.json",
            out_path: Optional[str] = None,
            verbose: bool = False,
            run_yara: bool = True,
    ) -> List[Dict]:
        """
        Analyzes the Mach-O file and yields findings.
        Every resulting entry contains: binary, cpu, pie, yara_matches, suspicious_imports, syscalls
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        # Lade syscall map
        syscall_map: Dict[str, str] = {}
        if syscall_map_path and os.path.exists(syscall_map_path):
            try:
                with open(syscall_map_path, "r", encoding="utf-8") as f:
                    syscall_map = json.load(f)
            except Exception as e:
                warn(f"Failed to load syscall map: {e}")

        binaries = self.parse_binaries(file_path)

        if run_yara:
            self.load_yara()

        all_results: List[Dict] = []
        for b in binaries:
            cpu = getattr(b.header.cpu_type, "name", "unknown")
            imagebase = hex(getattr(b, "imagebase", 0)) if hasattr(
                b, "imagebase") else "0x0"
            pie = getattr(b, "is_pie", False)
            info(
                f"Analysis started: cpu={cpu}, imagebase={imagebase}, pie={pie}")

            code_sections = self.get_code_sections(b)

            yara_matches = []
            if self.yara_rules:
                try:
                    matches = self.scan_yara(file_path)
                    yara_matches = [m.rule for m in matches] if matches else []
                except Exception as e:
                    error(f"Error during YARA scan: {e}")

            imports = self.scan_symbols(b)
            brks = self.scan_brk_instructions(code_sections, verbose)
            syscalls = self.scan_syscalls(code_sections, syscall_map, verbose)

            binary_info = {
                "binary": file_path,
                "cpu": cpu,
                "pie": pie,
                "yara_matches": yara_matches,
                "imports": imports,
                "brks": brks,
                "syscalls": syscalls
            }
            all_results.append(binary_info)

        if out_path:
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(all_results, f, indent=2)
                info(f"Results have been written to {out_path}.")
            except Exception as e:
                error(f"Failed to write results: {e}")

        return all_results


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="MachOScanner")
    ap.add_argument("file", help="Mach-O path")
    ap.add_argument("--map", default="data/syscalls.json",
                    help="syscall map (JSON)")
    ap.add_argument("--out", help="Optional output JSON")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    args = ap.parse_args()

    scanner = MachOScanner(strings_path="data/strings.json", rules_dir="rules")
    results = scanner.analyze(
        args.file, syscall_map_path=args.map, out_path=args.out, verbose=args.verbose)
    print(json.dumps(results, indent=2))
