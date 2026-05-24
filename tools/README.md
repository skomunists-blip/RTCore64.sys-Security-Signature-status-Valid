# Tools

This directory contains helper scripts used to collect static or read-only evidence.

## `tools/ghidra`

Ghidra scripts used to extract dispatch tables, callsites, imports, and decompiler-oriented audit text.

These scripts do not execute the driver.

## `tools/windows-readonly`

Windows PowerShell helpers for read-only telemetry collection:

- GPU / TDR event collection.
- GPU telemetry channel discovery.
- DxgKrnl channel status checks.

These scripts are intended for a lab VM or authorized test system.

Dangerous IOCTL probing scripts are intentionally excluded from the public package.

