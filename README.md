# iOS-antiantidebug

Detects common anti-debugging techniques in 64-bit Mach-O binaries. Made possible with [LIEF](https://lief.re/) and [Capstone](http://www.capstone-engine.org/).

## Features

- Syscall-based detections (ptrace, exit...)
- Suspicious imports (sysctl, dlsym, getppid...)
- Timing / anti-breakpoint heuristics
- TBD: Mach-O section anomalies (code in unusual sections, encrypted sections)
- TBD: Network / IPC anti-debug checks (e.g. debugger processes via sockets)
- TBD: String scanning
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
[!] Suspicious import: dlopen
[!] Suspicious import: dlsym
[!] Suspicious import: clock_gettime
[!] Suspicious import: exit
[!] Suspicious import: gettimeofday
[!] Suspicious import: sysctl
[!] Suspicious import: getpid
[*] Use cross-references to check if these functions are used to detect a debugger.
[!] BRK instruction @ 0x3ba9c
[!] BRK instruction @ 0x3c804
[!] BRK instruction @ 0x3cc0c
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
