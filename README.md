# RTCore64.sys Actual driver Security Audit 2026
(Привет всем, надеюсь вы это увидите:)
This repository contains a defensive security audit of `RTCore64.sys`, the kernel driver historically associated with MSI Afterburner / RTSS tooling.

The work focuses on whether a newer observed build still exposes unsafe Ring 0 primitives similar in class to historical vulnerable-driver issues. The repository intentionally does **not** include the driver binary, crash dumps, weaponized exploit code, or destructive reproduction steps.

## Summary

Confirmed in the tested lab environment:

- Unsafe `IRP_MJ_DEVICE_CONTROL` attack surface reachable by an elevated caller.
- Validation-after-use pattern in the `0x80002044` unmap path.
- Weak 32-bit bounds predicate in mapped read/write paths (`0x80002048` / `0x8000204C`).
- Practical kernel crash evidence associated with the vulnerable driver path.
- Scoped read/write access to display BAR / MMIO windows (`BAR14` / `BAR18`).
- Controlled framebuffer / VRAM disclosure using self-generated markers.

Not proven:

- Unrestricted arbitrary physical RAM read/write.
- Stable full RAM read/write primitive.
- Direct low-privileged user to kernel LPE.
- GPU command execution.

## Repository Layout

```text
.
├── README.md
├── REPORT.md
├── USER_NOTICE_RU.md
├── SECURITY.md
├── docs/
├── evidence/
│   ├── static/
│   ├── dynamic/
│   └── crash-analysis/
└── tools/
    ├── ghidra/
    └── windows-readonly/
```

## Safety Boundary

The public package is curated for defensive review:

- No `RTCore64.sys` binary is included.
- No minidumps or memory dumps are included.
- No exploit, shellcode, token-stealing logic, or arbitrary RAM read/write tooling is included.
- Included Windows scripts are read-only telemetry collectors.
- Dynamic evidence logs document prior controlled lab observations.

## Recommended Reading Order

1. [`REPORT.md`](REPORT.md)
2. [`docs/evidence-index.md`](docs/evidence-index.md)
3. [`docs/scope-and-limitations.md`](docs/scope-and-limitations.md)
4. [`USER_NOTICE_RU.md`](USER_NOTICE_RU.md)

## Tested Environment

The most important lab results were collected in an isolated Windows 11 VM with snapshots. Some supplemental host-side inventory was collected on the researcher workstation. See [`REPORT.md`](REPORT.md) for details.

## Investigated Driver Identity

Host-side metadata for the observed driver file:

```text
Path: C:\Program Files (x86)\MSI Afterburner\RTCore64.sys
File size: 40,688 bytes
Last write time: 2024-05-12
Signature status: Valid
Signer: MICRO-STAR INTERNATIONAL CO., LTD.
Issuer: GlobalSign GCC R45 EV CodeSigning CA 2020
Certificate validity: 2022-09-13 to 2025-10-16
SHA-256: A4F44E267698D47F6A905E96B356582B4EE9CF4049E8C792FFDA1B7356E68D35
Service state: Stopped
Service start mode: Manual
Microsoft vulnerable driver blocklist: enabled on the host
```

## Disclosure Position

This is best described as a **new-build persistence / regression validation** of unsafe RTCore64 behavior, not a claim of a new unrestricted RAM exploit.

Suggested short wording:

> The investigated build still exposes high-risk kernel primitives to an elevated caller, including validation-after-use in the unmap path, weak mapped-window bounds checks, crash evidence, framebuffer/VRAM disclosure, and scoped BAR/MMIO write capability. Unrestricted arbitrary RAM read/write was not proven.
