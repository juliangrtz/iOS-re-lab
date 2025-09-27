# iOS-antiantidebug

Detects common anti-debugging techniques in 64-bit Mach-O binaries. Made possible with [LIEF](https://lief.re/) and [Capstone](http://www.capstone-engine.org/).

## Features

- Syscall-based detections (ptrace, exit...)
- Suspicious imports (open, access, stat...)
- TBD: Mach-O section anomalies (code in unusual sections, encrypted sections)
- TBD: Timing / anti-breakpoint heuristics
- TBD: Hardware debug register / ptrace register detection
- TBD: Network / IPC anti-debug checks (e.g., debugger processes via sockets)
- TBD: Runtime string scanning using emulation (Unicorn?)
- TBD: Heuristics for obfuscated or dynamically resolved syscalls

## Requirements

- Python (>= 3.12.1 recommended)
- pip

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scan.py target --out results.json
```

## Example output

```plain
[*] Analysis started: cpu=ARM64, imagebase=0x100000000, pie=True
[*] Scanning imports...
[!] Suspicious import: sysctl
[!] Suspicious import: open
[!] Suspicious import: dlsym
[!] Suspicious import: access
[*] Use cross-references to check if these functions are used to detect a debugger.
[*] Scanning syscalls... This might take a while, every instruction must be disassembled.
[*] Found 3 code sections: __text, __objc_stubs, __stubs
[1] exit @ 0x3c1a8
[1] exit @ 0x3d420
[26] ptrace @ 0x3e22c
[1] exit @ 0x3e23c
...
[*] Section __text: 4350 syscalls found
[*] Results written to out.json
````

## Roadmap

- Output IDA-friendly addresses instead of file offsets
- Offer automatic patches (NOP, RET etc.)
- Add more detections
- GUI
- Support ARM32?
- ...
