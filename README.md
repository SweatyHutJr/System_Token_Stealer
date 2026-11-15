# Token Impersonation PoC

A Windows proof-of-concept demonstrating **access token duplication and impersonation**.
It takes a SYSTEM-level token from a running process, duplicates it, and launches a new
process under that token — showing how a process can run with SYSTEM integrity without
being a service.

> ⚠️ **For educational and security-research use only.** Run this only on machines you
> own or are explicitly authorized to test. Impersonating SYSTEM on a machine you don't
> control is a privilege-escalation technique and is illegal in most jurisdictions.

## What it demonstrates

Windows access tokens are the kernel object that defines a process's security context.
Any process running as SYSTEM holds a token with `SYSTEM_LUID` — if another process can
obtain a handle to that token (with `TOKEN_DUPLICATE`), it can duplicate it and start a
child process that also runs as SYSTEM. This is the mechanism behind a large class of
privilege-escalation and persistence techniques.

The PoC:

1. Enumerates processes to find one running as `NT AUTHORITY\SYSTEM`
2. `OpenProcess` with `PROCESS_QUERY_INFORMATION` to get a handle
3. `OpenProcessToken` with `TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY`
4. `DuplicateTokenEx` to create a primary token from the impersonation token
5. `CreateProcessWithTokenW` (or `CreateProcessAsUser`) to launch a target process under
   the duplicated SYSTEM token
6. The spawned process now runs with SYSTEM integrity

The "target process" in the PoC is a harmless binary (e.g. `notepad.exe` or a
purpose-built stub) — the point is to show it running as SYSTEM, not to do anything with
that privilege.

## Features

- Clean, commented implementation of the `OpenProcessToken` → `DuplicateTokenEx` →
  `CreateProcessWithTokenW` chain
- User-selectable target process to spawn under the duplicated token
- No external dependencies beyond the Windows SDK
- Ships with a Visual Studio solution (`Rootkitty.slnx`)
- Error-checked at every Win32 call, with `GetLastError()` printed on failure

## Requirements

- **Windows 10/11**
- **Visual Studio 2022** with the *Desktop development with C++* workload
- **Administrator privileges** — `OpenProcess` on a SYSTEM process and
  `CreateProcessWithTokenW` both require elevation (and `SeDebugPrivilege` /
  `SeImpersonatePrivilege` enabled)
- Target architecture must match (x64 → x64)

## Build

1. Open `Rootkitty.slnx` in Visual Studio 2022.
2. Set the configuration to **Release** and platform to **x64**.
3. Build the solution (`Ctrl+Shift+B`).
4. Output is in `build/km+intermediates\` (or your configured output dir).

## Usage

Run from an **elevated** terminal:


The PoC picks a SYSTEM process (e.g. `winlogon.exe` or `lsass.exe`), duplicates its
token, and spawns the target process under it. The spawned process should show
`NT AUTHORITY\SYSTEM` as its owner in Task Manager's Details tab (add the "User name"
column).

## Notes

- **Why the spawned process can't be killed from Task Manager:** once running as SYSTEM,
  a non-elevated Task Manager can't terminate it — that's a consequence of the integrity
  level, not an evasion technique built into the PoC. An elevated Task Manager can still
  kill it, and so can `taskkill /F /PID <pid>` from an admin shell. If you're documenting
  this, say *that*, not "unkillable process."
- **This is a noisy technique.** Opening a handle to a SYSTEM process's token and calling
  `CreateProcessWithTokenW` are both heavily monitored by EDR. Any half-decent endpoint
  product will flag it. That's expected for this class of PoC.
- **`SeDebugPrivilege` is required** to open a handle to most SYSTEM processes. The PoC
  enables it via `AdjustTokenPrivileges` before `OpenProcess`.
- **The token is duplicated, not stolen** — the source process keeps its token. The
  "stealer" naming in the repo is a misnomer for what the code does.

## License

No license is specified in this repository. All rights reserved by the author unless
stated otherwise.

---

> **Disclaimer:** This project is provided for learning about Windows access tokens, the
> `DuplicateTokenEx` / `CreateProcessWithTokenW` APIs, and how SYSTEM-level process
> creation works. The author is not responsible for any misuse. Only run it on systems
> you own or are authorized to test.
