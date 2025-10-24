# iOS-re-lab

![iOS RE Lab](img/preview.png)

WIP reverse engineering suite for iOS applications. Detects common anti-reverse-engineering techniques and protectors in
64-bit Mach-O binaries. Made possible with [LIEF](https://lief.re/), [Capstone](http://www.capstone-engine.org/)
and [YARA](https://github.com/VirusTotal/yara). UI based on PySide6.

## Features

- Anti-Reversing detections
    - Anti-Jailbreak (open/access/stat64, URL schemes, fork, symlinks, dyld...)
    - Syscall detections (ptrace, exit...)
    - Suspicious imports (sysctl, dlsym, getppid...)
    - Timing / anti-breakpoint heuristics
    - Emulator checks
    - Integrity checks
    - Frida checks
    - Protector detection using YARA
- Basic Frida integration
- Basic disassembler
- Syscall tracing
- WIP: Obfuscation detection
- WIP: Integrated LLDB-based debugger
- WIP: Integrated decompiler
- WIP: Full framework integration (Frida, LIEF, QBDI etc.)

## Requirements

- Python (>= 3.12.1 recommended)
- pip
- git, npm (if you want to trace syscalls)

## Installation

This might take a while.

```bash
git clone --recurse-submodules https://github.com/juliangrtz/iOS-re-lab
cd iOS-re-lab
pip install -r requirements.txt
```

## Usage

```bash
python app.py
```

## Roadmap

- Handle obfuscated syscalls. Unicorn emulation might be necessary. Example:

```arm
ldr x16, [sp, #0x288]
svc 0x80
```

- Show CFGs in disassembly
- Obfuscation heuristics
- Deobfuscation
- Offer automatic patches
- Add more detections
- Support ARM32?
- Localization
- ...