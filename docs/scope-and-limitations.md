# Scope and Limitations

## In Scope

- Static review of `RTCore64.sys` dispatch logic.
- Ghidra-derived callsite and IOCTL surface analysis.
- Controlled lab evidence from an isolated Windows VM.
- Read-only telemetry collectors and static analysis helpers.

## Out of Scope

- Weaponized exploitation.
- Public release of the driver binary.
- Public release of memory dumps or minidumps.
- Full RAM dumping or arbitrary RAM write tooling.
- GPU command stream construction or execution.

## Confidence Model

The report uses three confidence levels:

- Confirmed: supported by static and/or controlled dynamic evidence.
- Probable: strongly suggested by static analysis, but not dynamically exercised.
- Not proven: explicitly tested or considered but not demonstrated.

## Current Boundary

The strongest confirmed claim is:

> Elevated caller to unsafe kernel / MMIO / VRAM primitives.

The following stronger claims are not supported by current evidence:

- unrestricted arbitrary physical RAM read/write;
- direct low-privileged LPE;
- GPU command execution.

