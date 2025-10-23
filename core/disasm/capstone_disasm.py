import concurrent.futures
import mmap
import os

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

    def _disassemble_chunk(self, data: bytes, base_addr: int) -> list[str]:
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = False
        result = []

        for insn in md.disasm(data, base_addr):
            result.append(f"0x{insn.address:08x}:\t{insn.mnemonic}\t{insn.op_str}")

        return result

    def disassemble(self) -> str:
        logger.info(f"[Capstone] Loading file: {self.file_path}")

        with open(self.file_path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                file_size = mm.size()
                offsets = range(0, file_size, self.chunk_size)

                logger.info(f"[Capstone] File size: {file_size:,} bytes")
                logger.info(f"[Capstone] Using {self.max_workers} threads")

                results = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = []
                    for offset in offsets:
                        data = mm[offset:offset + self.chunk_size]
                        futures.append(executor.submit(self._disassemble_chunk, data, offset))

                    for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                        try:
                            chunk_result = fut.result()
                            results.extend(chunk_result)
                            if i % 10 == 0:
                                logger.info(f"[Capstone] Completed {i}/{len(futures)} chunks...")
                        except Exception as e:
                            logger.error(f"[Capstone] Error in chunk {i}: {e}")

        disasm_text = "\n".join(results)
        logger.info(f"[Capstone] Completed disassembly.")
        return disasm_text
