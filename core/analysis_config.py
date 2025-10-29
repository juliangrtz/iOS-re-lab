from dataclasses import dataclass


@dataclass
class AnalysisOptions:
    scan: bool = True
    yara: bool = True
    verbose: bool = False
    syscall_map: str = "data/syscalls.json"
    disasm: bool = True
    disasm_only_text: bool = True
    start_addr: str | None = None
    end_addr: str | None = None
    chunk_size: int = 0x2000


class AnalysisConfig:
    file_path: str | None = None
    options: AnalysisOptions = AnalysisOptions()


ANALYSIS_CONFIG = AnalysisConfig()
