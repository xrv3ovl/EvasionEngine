# EvasionEngine

> A modular C toolkit for testing and benchmarking Windows Process Injection (WPI) techniques — with independently configurable syscall flavors across every stage of the injection pipeline.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Language: C](https://img.shields.io/badge/language-C-00599C?logo=c)
![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)
![Build: CMake](https://img.shields.io/badge/build-CMake-064F8C?logo=cmake)

---

## Overview

EvasionEngine is a research-grade injection framework built around a **four-stage, flavor-driven pipeline**: Allocate → Write → Protect → Invoke. Each stage can be independently configured to use one of four execution flavors, letting you isolate and benchmark the detection surface introduced at any individual step.

**Execution Flavors**

| # | Flavor | Mechanism |
|---|---|---|
| 0 | `WIN32` | Standard Win32 API (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, …) |
| 1 | `DFR` | Dynamic Function Resolution — manual EAT walk of `kernel32` via PEB, no `GetProcAddress` |
| 2 | `DIRECT` | Direct syscalls — hand-rolled x64 ASM stubs (`SysNt*`) that jump straight to the kernel |
| 3 | `INDIRECT` | Indirect syscalls — SSN harvested from the PEB; trampoline through a legitimate `syscall` gadget in `ntdll` |

Mix and match flavors across stages to test exactly which combination triggers a given sensor.

---

## Repository Structure

```
EvasionEngine/
├── src/
│   ├── EvasionEngine.c          # Entry point — CLI parse, engine construction, execution
│   ├── engine.c                 # Core orchestrator: INJECTION_ENGINE, EngineExecute(), target init, manual map
│   ├── dispatch.c               # Flavor router — switches each stage to the right implementation
│   ├── allocate.c               # Stage 1: memory allocation (Win32 / DFR / Direct / Indirect)
│   ├── write.c                  # Stage 2: payload write (Win32 / DFR / Direct / Indirect + manual map)
│   ├── protect.c                # Stage 3: permission hardening (Win32 / DFR / Direct / Indirect)
│   ├── invoke.c                 # Stage 4: thread creation (Win32 / DFR / Direct / Indirect)
│   ├── cli.c                    # Argument parsing → CLI_OPTIONS struct
│   ├── syscall-utils.c          # SSN resolution + syscall gadget address scanner
│   ├── peb-eat-utils.c          # Manual PEB walk + EAT resolver (GPAManualByName)
│   ├── ps-utils.c               # Process targeting helpers (spawn / open / self)
│   ├── utils.c                  # General utilities
│   ├── direct-syscalls.asm      # x64 ASM: SysNt* direct syscall stubs
│   └── indirect-syscalls.asm    # x64 ASM: IndirectSysNt* trampoline stubs
├── include/
│   ├── engine.h                 # INJECTION_ENGINE / INJECTION_CONTEXT structs, EngineExecute()
│   ├── dispatch.h               # DispatchAllocate / Write / Protect / Invoke declarations
│   ├── allocate.h               # Win32Allocate / DFRAllocate / DirectAllocate / IndirectAllocate
│   ├── write.h                  # Win32Write / DFRWrite / DirectWrite / IndirectWrite
│   ├── protect.h                # Win32Protect / DFRProtect / DirectProtect / IndirectProtect
│   ├── invoke.h                 # Win32Invoke / DFRInvoke / DirectInvoke / IndirectInvoke
│   ├── cli.h                    # CLI_OPTIONS struct + parse_cli()
│   ├── resolver.h               # DFR global function pointers (g_VirtualAllocEx, g_CreateRemoteThread, …)
│   ├── syscall-utils.h          # GetSSN(), GetSyscallAddress()
│   ├── peb-eat-utils.h          # GPAManualByName()
│   ├── ps-utils.h               # InitializeTarget()
│   ├── payload.h                # Payload type definitions
│   └── utils.h                  # General utilities
├── examples/
│   └── example.json             # Sample configuration for the test harness
├── tools/
│   └── test-harness.py          # Python test harness for automated campaign execution
├── CMakeLists.txt
├── build.ps1                    # PowerShell build script
└── LICENSE
```

---

## Architecture

### The Injection Pipeline

`EngineExecute()` drives each run through four sequential stages. Every stage is a function pointer inside `INJECTION_ENGINE`, set at startup by the flavor arguments:

```
┌──────────────────────────────────────────────────┐
│                  INJECTION_ENGINE                │
│                                                  │
│  Stage 1: Allocate  ─►  Stage 2: Write           │
│               │                  │               │
│          pRemoteAddress     payload bytes        │
│                                  │               │
│  Stage 4: Invoke  ◄──  Stage 3: Protect          │
│         │                        │               │
│     hThread              PAGE_EXECUTE_READ       │
└─────────┼────────────────────────────────────────┘
          │
          └─► WaitForSingleObject / NtWaitForSingleObject
```

Each stage dispatches through `dispatch.c`, which routes the call based on the configured flavor integer:

```c
// Example — all four stages independently configurable
INJECTION_ENGINE engine = {
    .Allocate = DispatchAllocate,  
    .Write    = DispatchWrite,     
    .Protect  = DispatchProtect,   
    .Invoke   = DispatchInvoke,    
};
```

### Resolver Subsystems

Two resolver subsystems are lazily initialized at startup:

- **DFR (Dynamic Function Resolution):** Walks the PEB `InMemoryOrderModuleList` to locate `kernel32`, then manually traverses its Export Address Table to resolve `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, and `CreateRemoteThread` into global function pointers — without ever calling `GetProcAddress`.

- **Indirect Syscall Resolver:** Harvests System Service Numbers (SSNs) from `ntdll`'s EAT for `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`, `NtWaitForSingleObject`, `NtQueueApcThread`, and `NtResumeThread`. `GetSyscallAddress()` then scans `ntdll` memory for a clean `syscall; ret` gadget to use as the trampoline.

### Process Targeting

`InitializeTarget()` supports three modes:

| Mode | Flag | Description |
|---|---|---|
| Spawn | `--spawn <path>` | Creates a suspended process parented to `explorer.exe` (PPID spoofing) |
| Attach | `--pid <pid>` | Opens a handle to an existing process by PID |
| Self | *(default)* | Injects into the current process (`HANDLE -1`) |

### Execution Techniques

| Value | Technique | Description |
|---|---|---|
| `0` | `EARLY_BIRD` | APC-queue injection into a freshly spawned suspended thread |
| *(default)* | `DEFAULT` | Standard `CreateRemoteThread` / `NtCreateThreadEx` execution |

### Module Stomping

Pass `--module` + `--export` (or `--offset`) to overwrite a specific DLL export in the target rather than allocating fresh memory. The write stage performs a full PE manual map, including header and section copies plus base-relocation fixup, before handing off to the invoke stage.

---

## Building

### Prerequisites

- MSVC (Visual Studio 2019+ with C build tools)
- CMake ≥ 3.15
- NASM or MASM (for `.asm` compilation)

### Build

```powershell
# PowerShell one-liner
.\build.ps1

# Or manually with CMake
cmake -B build -S . -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The compiled binary is output to `build/Release/EvasionEngine.exe`.

---

## Usage

```
EvasionEngine.exe [target] [--alloc-flavor N] [--write-flavor N]
                  [--protect-flavor N] [--invoke-flavor N]
                  [-t TECHNIQUE] [-m MODULE] [-e EXPORT] [-o OFFSET]
```

### Flavor Values

| Value | Flavor |
|---|---|
| `0` | WIN32 *(default)* |
| `1` | DFR |
| `2` | DIRECT |
| `3` | INDIRECT |

### Examples

```powershell
# All-Win32 baseline injection into a remote PID
EvasionEngine.exe --pid 1234

# Spawn notepad.exe with PPID spoofing, full indirect syscall pipeline
EvasionEngine.exe --spawn "C:\Windows\System32\notepad.exe" `
    --alloc-flavor 4 --write-flavor 4 --protect-flavor 4 --invoke-flavor 4

# Mixed-mode: DFR alloc + direct syscall write + Win32 invoke into self
EvasionEngine.exe --alloc-flavor 2 --write-flavor 3 --invoke-flavor 1

# Early Bird APC into a spawned process, stomping a specific DLL export
EvasionEngine.exe --spawn "C:\Windows\System32\svchost.exe" `
    -t 0 -m uxtheme.dll -e OpenThemeData

# Indirect syscalls everywhere, module stomp at hex offset
EvasionEngine.exe --pid 4567 `
    --alloc-flavor 4 --write-flavor 4 --protect-flavor 4 --invoke-flavor 4 `
    -m kernel32.dll -o 0x1a20
```

---

## Test Harness

`tools/test-harness.ps1` automates campaign execution, driving the engine through a matrix of flavor combinations defined in a JSON configuration file.

```powershell
tools/test-harness.ps1 -InputFile examples/example.json
```

See `examples/example.json` for the configuration schema.

---

## License

[GNU GENERAL PUBLIC LICENSE](LICENSE)

---

## Disclaimer

This tooling is intended for **authorized security research, red team engagements, and educational purposes only**. Use against systems you do not own or have explicit written permission to test is illegal. The author assumes no liability for misuse.