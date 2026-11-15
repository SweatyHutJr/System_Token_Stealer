# Token Impersonation PoC

A Windows proof-of-concept demonstrating **access token duplication and impersonation**.
It takes a SYSTEM-level token from a running process, duplicates it, and launches a new
process under that token — showing how a process can run with SYSTEM integrity without
being a service.

> ⚠️ **For educational and security-research use only.** Run this only on machines you
> own or are explicitly authorized to test. Impersonating SYSTEM on a machine you don't
> control is a privilege-escalation technique and is illegal in most jurisdictions.
> **This PoC requires disabling Driver Signature Enforcement and enabling test-signing,
> which weakens kernel security on the machine you run it on. Use a disposable VM.**

## What it demonstrates

Windows access tokens are the kernel object that defines a process's security context.
Any process running as SYSTEM holds a token with `SYSTEM_LUID` — if another process can
obtain a handle to that token (with `TOKEN_DUPLICATE`), it can duplicate it and start a
child process that also runs as SYSTEM. This is the mechanism behind a large class of
privilege-escalation and persistence techniques.

The PoC:

  1. Loads its kernel-mode driver (test-signed; requires DSE disabled)
  2. The driver performs the privileged token duplication
  3. The user-mode component (`RootKittyKatKittyum.exe`) uses the driver's result to
     launch a target process under the duplicated SYSTEM token
  4. The spawned process now runs with SYSTEM integrity

The "target process" is a harmless binary (e.g. `notepad.exe` or a purpose-built stub) —
the point is to show it running as SYSTEM, not to do anything with that privilege.

## Why a driver?

The token-duplication logic is split into a kernel-mode driver. Kernel code runs at a
privilege level where token manipulation doesn't require user-mode elevation workarounds,
and the PoC becomes a complete example of the user-mode ↔ kernel-mode handoff that
rootkit and EDR-evasion research relies on.

**Because the driver is not Microsoft-signed, it cannot load on a default Windows
install.** You must disable Driver Signature Enforcement and enable test-signing first
(see Setup).

## Features

  * Clean, commented implementation of the `OpenProcessToken` → `DuplicateTokenEx` →
    `CreateProcessWithTokenW` chain, split across user-mode and a kernel driver
  * User-mode launcher: `RootKittyKatKittyum.exe`
  * Ships with a Visual Studio solution (`Rootkitty.slnx`)
  * Error-checked at every Win32 call, with `GetLastError()` printed on failure

## Requirements

### To build

  * **Windows 10/11**
  * **Visual Studio 2022** with the *Desktop development with C++* workload
  * **Windows 11 SDK** — install via the Visual Studio Installer (*Individual components*
    → *Windows 11 SDK*) or the standalone SDK installer
  * **Windows Driver Kit (WDK)** — install the version matching your Visual Studio
    (VS 2022 → WDK 10.0.22621 or newer). The WDK installer also pulls the matching SDK,
    but install both explicitly to avoid version-mismatch build errors.

### To run

  * **Administrator privileges**
  * **Secure Boot disabled** in firmware (required for test-signing)
  * **Test-signing + DSE disabled** (see Setup)
  * Target architecture must match (x64 → x64)

> The WDK and SDK are **required to build** the driver — a plain Visual Studio install
> with only the C++ workload will fail to compile the kernel project. If you only want to
> *run* the prebuilt binaries, you don't need the WDK/SDK, but you still need the Setup
> steps below.

## Build

### User-mode component

  1. Open `Rootkitty.slnx` in Visual Studio 2022.
  2. Set the configuration to **Release** and platform to **x64**.
  3. Build the solution (`Ctrl+Shift+B`).
  4. Output is `RootKittyKatKittyum.exe` in `build/km+intermediates\` (or your configured
     output dir).

### Driver

  1. Build the driver project in the same solution (requires WDK + SDK installed).
  2. **Test-sign** the driver. From an elevated *Developer Command Prompt for VS*:  makecert -r -pe -ss PrivateCertStore -n "CN=RootkittyTest" RootkittyTest.cer signtool sign /v /s PrivateCertStore /n RootkittyTest /t http://timestamp.digicert.com <driver>.sys
     
3. Install the test certificate into `Trusted Root Certification Authorities` on the
test machine (double-click the `.cer` → Install Certificate → Local Machine →
Trusted Root).

## Setup (one-time, per test machine)

Test-signing and DSE changes are persistent and weaken kernel security. **Do this in a VM
snapshot you can throw away.**

1. **Disable Secure Boot** in the VM's firmware settings (test-signing cannot be enabled
while Secure Boot is on).

2. Open an **elevated** Command Prompt and enable test-signing:
`bcdedit /set testsigning on`

3. (If your driver still fails to load with test-signing on) also disable integrity
checks:


4. **Reboot.** A "Test Mode" watermark appears in the bottom-right corner — that confirms
test-signing is active.

5. Install the test certificate (Build → Driver step 3) so Windows trusts the driver.

## Usage

Run from an **elevated** terminal, in the directory containing both the driver and the
user-mode exe: RootKittyKatKittyum.exe


The PoC loads the driver, uses it to duplicate a SYSTEM token, and spawns the target
process under it. The spawned process should show `NT AUTHORITY\SYSTEM` as its owner in
Task Manager's Details tab (add the "User name" column).

To undo the test-mode changes afterward:
bcdedit /set testsigning off
bcdedit /set nointegritychecks off


…then reboot. (Or just revert the VM snapshot — easier.)

## Notes

  * **This will not run on a stock Windows install.** The driver is test-signed, not
    Microsoft-signed, so it's rejected until DSE is disabled. Skip the Setup section and
    you'll get a driver-load failure, typically error `577` (`ERROR_INVALID_IMAGE_HASH`).
  * **WDK/SDK version mismatch is the most common build failure.** If the kernel project
    won't compile, confirm the WDK version matches your VS 2022 toolset (check
    *Project → Properties → Driver Settings → Target Platform Version*).
  * **Test-signing is a machine-wide security downgrade.** While it's on, *any*
    test-signed driver can load, not just yours. Don't leave it enabled on a machine you
    care about.
  * **Why the spawned process can't be killed from a non-elevated Task Manager:** once
    running as SYSTEM, a non-elevated Task Manager can't terminate it — that's a
    consequence of the integrity level, not an evasion technique built into the PoC. An
    elevated Task Manager can still kill it, as can `taskkill /F /PID <pid>` from an admin
    shell.
  * **This is a noisy technique.** Kernel drivers, `CreateProcessWithTokenW`, and
    test-signed binaries are all heavily monitored by EDR. Any half-decent endpoint product
    will flag this. That's expected for this class of PoC.
  * **The token is duplicated, not stolen** — the source process keeps its token. The
    historical "stealer" naming is a misnomer for what the code does.

## License

No license is specified in this repository. All rights reserved by the author unless
stated otherwise.

---

> **Disclaimer:** This project is provided for learning about Windows access tokens, the
> `DuplicateTokenEx` / `CreateProcessWithTokenW` APIs, kernel-mode driver loading, and how
> SYSTEM-level process creation works. The author is not responsible for any misuse. Only
> run it on systems you own or are authorized to test — ideally a disposable VM.
