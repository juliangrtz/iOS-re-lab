import concurrent.futures
import mmap
import os

import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from core import logger


class CapstoneDisassembler:
    def __init__(self, file_path: str, chunk_size: int = 0x2000):
        self.file_path = file_path

        if not os.path.exists(self.file_path):
            logger.error(f"[Capstone] File not found: {self.file_path}")
            raise FileNotFoundError(self.file_path)

        self.chunk_size = chunk_size
        self.max_workers = os.cpu_count() or 4
        self.functions = {}

    def _load_functions_with_lief(self):
        binary = lief.parse(self.file_path)
        if not binary:
            raise RuntimeError("Failed to parse Mach-O binary with LIEF")

        if isinstance(binary, lief.MachO.Binary):
            func_count = 0

            for f in binary.functions:
                addr = f.address
                name = f.name or f"fn_{addr:08x}"
                self.functions[addr] = name
                func_count += 1

        logger.info(f"[LIEF] Detected {len(self.functions)} functions")

    def _disassemble_chunk(self, data: bytes, base_addr: int):
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = False
        result = []

        for insn in md.disasm(data, base_addr):
            if insn.address in self.functions:
                result.append(f"{self.functions[insn.address]}:")

            result.append(f"0x{insn.address:08x}:\t{insn.mnemonic}\t{insn.op_str}")

        return result

    def disassemble(self) -> str:
        logger.info(f"[Capstone] Loading file: {self.file_path}")
        self._load_functions_with_lief()

        results = []

        with open(self.file_path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            file_size = mm.size()
            offsets = range(0, file_size, self.chunk_size)

            logger.info(f"[Capstone] File size: {file_size:,} bytes")
            logger.info(f"[Capstone] Using {self.max_workers} threads")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self._disassemble_chunk, mm[offset:offset + self.chunk_size], offset)
                           for offset in offsets]

                for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                    try:
                        chunk_result = fut.result()
                        results.extend(chunk_result)
                        if i % 10 == 0:
                            logger.info(f"[Capstone] Completed {i}/{len(futures)} chunks...")
                    except Exception as e:
                        logger.error(f"[Capstone] Error in chunk {i}: {e}")

        logger.info(f"[Capstone] Completed disassembly")
        return "\n".join(results)
