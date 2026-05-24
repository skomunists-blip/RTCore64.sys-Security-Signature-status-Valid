# RTCore64.sys Security Assessment Report

Date: 2026-05-24  
Scope: Static and controlled dynamic analysis of `RTCore64.sys` in an isolated Windows VM.

## Executive Summary

The tested `RTCore64.sys` build still exposes high-risk Ring 0 behavior to an elevated user-mode caller. The strongest confirmed findings are:

- Validation-after-use in `IOCTL 0x80002044`, where `MmUnmapIoSpace` is reached before ownership validation.
- Weak mapped-window bounds logic in `IOCTL 0x80002048` / `0x8000204C`.
- Kernel crash evidence associated with the RTCore64 write/fault path.
- Scoped read/write capability over display BAR / MMIO windows.
- Controlled framebuffer / VRAM information disclosure.

The assessment did **not** prove unrestricted arbitrary physical RAM read/write or direct low-privileged LPE.

## Impact Statement

Confirmed impact:

- Elevated user-mode to unsafe kernel-driver control surface.
- Kernel DoS / memory-corruption reachability.
- Unauthorized read/write in scoped MMIO / display BAR windows.
- Graphical framebuffer / VRAM disclosure of visible rendered content.

Not claimed:

- Full arbitrary RAM read/write.
- Token stealing or privilege escalation exploit.
- GPU command stream execution.

## Environment

Primary dynamic testing:

- Windows 11 guest VM (`RTCoreLab-W11`) under VirtualBox.
- Snapshot-based lab workflow.
- Administrative test account in the VM.
- MSI Afterburner / RTCore64 present in the guest.

Important host-side note:

- The public package excludes driver binaries and crash dumps.
- Evidence logs are retained as text artifacts.

## Finding 1: Validation-After-Use in `0x80002044`

Severity: High  
Confidence: Static confirmed  
Affected logic: `FUN_00011438`, `IOCTL 0x80002044`

The handler invokes:

```c
MmUnmapIoSpace(plVar4[1], (int)plVar4[2]);
```

before validating that the supplied base/size/slot tuple belongs to the driver's mapping table (`DAT_00014370` / `DAT_00014b70`).

Security effect:

- Unsafe unmap path is reachable from caller-controlled request data after device open.
- This is a strong DoS / kernel mapping-state corruption class issue.

Evidence:

- `evidence/static/rtcore64_driver_focus_prioritized_findings_20260524.txt`
- `evidence/static/rtcore_comprehensive_audit.txt`
- `evidence/static/03_STATIC_CALLSITE_EXTRACT_RU.txt`

Recommended fix:

- Validate base, size, slot index, ownership, and range before calling `MmUnmapIoSpace`.
- Reject mismatched tuples with `STATUS_INVALID_PARAMETER`.
- Add locking around mapping-table access.

## Finding 2: Weak OOB Bounds Predicate in `0x80002048` / `0x8000204C`

Severity: High  
Confidence: Static confirmed + dynamic crash evidence  
Affected logic: mapped read/write branches

The mapped read/write paths use a predicate equivalent to:

```c
offset + width <= mapped_size
```

with 32-bit arithmetic. This is fragile because `offset + width` can wrap.

Security effect:

- Unsafe memory access path is reachable.
- BugCheck evidence supports kernel write/fault reachability.

Evidence:

- `evidence/crash-analysis/kd_052426-9937-01_analysis.log`
- `evidence/crash-analysis/kd_052426-9937-01_disasm18c4.log`
- `evidence/crash-analysis/rtcore_vm_bugcheck_collect_result.txt`

Important crash detail:

- BugCheck: `PAGE_FAULT_IN_NONPAGED_AREA (0x50)`
- Fault process: `powershell.exe`
- Module: `RTCore64.sys`
- Symbol area: `RTCore64+0x18c4`
- Disassembly shows a write-like memory access: `mov dword ptr [r9+r8], eax`

Recommended fix:

- Use overflow-safe arithmetic (`RtlULongAdd`, `RtlSizeTAdd`, or explicit checked math).
- Require `width` to be one of a strict allowlist.
- Validate `offset <= mapped_size` and `width <= mapped_size - offset`.

## Finding 3: Scoped Display BAR / MMIO Read-Write

Severity: High  
Confidence: Dynamic confirmed  
Affected paths: `0x80002000` map path and mapped view behavior

Controlled testing confirmed scoped read/write behavior over display BAR / MMIO windows:

- `DisplayBAR14_E0000000`: write observed and restored.
- `DisplayBAR18_E8400000`: write observed and restored.
- `LegacyROM_C0000`: write was attempted but not observed, consistent with ROM/shadow behavior.

Evidence:

- `evidence/dynamic/rtcore_vm_controlled_diff_write_matrix_result.txt`

Important result:

```text
Case=DisplayBAR14_E0000000
CaseWriteObserved=True
CaseRestoreObserved=True

Case=DisplayBAR18_E8400000
CaseWriteObserved=True
CaseRestoreObserved=True

Summary.CasesWithObservedWrite=2
Summary.ArbitraryRAMInjectionProven=False
```

Security effect:

- Elevated callers can modify scoped MMIO / VRAM regions through the driver.
- This can affect device integrity and availability.
- This is not proof of arbitrary system RAM modification.

Recommended fix:

- Do not expose physical mappings to user mode.
- Restrict to minimal required ranges.
- Use driver-internal operations instead of mapping raw MMIO to callers.
- Require explicit administrative policy gates and signed trusted caller checks.

## Finding 4: Framebuffer / VRAM Disclosure

Severity: Medium-High  
Confidence: Dynamic confirmed  

Controlled marker testing confirmed that self-generated visible framebuffer markers were recovered through display BAR scanning.

Evidence:

- `evidence/dynamic/rtcore_vram_marker_probe_result.txt`

Important result:

```text
Summary.MarkerFoundInDisplayBar=True
Conclusion=Controlled marker was found in the display BAR scan.
```

Additional negative controls:

- Helper-owned RAM canary markers were not found through the display BAR.
- Hidden/unrendered resources were not confirmed as disclosed.

Evidence:

- `evidence/dynamic/rtcore_canary_multitarget_probe_result.txt`
- `evidence/dynamic/rtcore_vram_gtt_negative_evidence_result.txt`

Security effect:

- Visible graphical content can be exposed outside normal process/UI isolation.
- This supports an information disclosure finding.

Recommended fix:

- Avoid exposing display BAR mappings to user mode.
- Enforce strict caller and policy checks.
- Constrain any hardware access to trusted kernel-only code paths.

## Finding 5: Weak MMIO Allow-Window Model

Severity: Medium-High  
Confidence: Static confirmed  
Affected logic: `FUN_00011044`

The driver derives broad BAR-based allow windows instead of relying on precise OS resource descriptors.

Evidence:

- `evidence/static/rtcore_pci_bar_bypass_static.txt`
- `evidence/static/rtcore64_driver_focus_prioritized_findings_20260524.txt`

Security effect:

- Broad MMIO exposure can include unintended adjacent ranges.
- It increases the blast radius of mapped read/write primitives.

Recommended fix:

- Query and enforce exact translated resource descriptors.
- Avoid fixed-size synthetic BAR windows.
- Use strict allowlists and deny all other physical ranges.

## Finding 6: HAL PCI Config Reliability Flaw

Severity: Medium  
Confidence: Dynamic observed  

The PCI config read path reports driver-level success for some invalid tuples/offsets.

Evidence:

- `evidence/dynamic/rtcore_vm_hal_count_reliability_result.txt`

Security effect:

- Reliability and validation weakness.
- Not independently a full memory corruption primitive.

Recommended fix:

- Check `HalGetBusDataByOffset` / `HalSetBusDataByOffset` returned byte count.
- Return failure unless the exact requested transfer length is completed.

## GPU Command Path Assessment

The project explored whether scoped BAR14/BAR18 write capability correlated with GPU command-processor disturbance.

Confirmed:

- BAR14/BAR18 write capability.

Not confirmed:

- TDR / DxgKrnl correlation.
- GPU command execution.

Evidence:

- `evidence/dynamic/rtcore_vm_gpu_cp_correlation_collect_result.txt`

Important result:

```text
SystemEventCount=0
DxgKrnlAdminEventCount=0
DxgKrnlOperationalEventCount=0
Summary.TdrLikeSystemEvents=0
```

Conclusion:

- Do not claim GPU command execution.
- Claim only scoped MMIO / VRAM write capability and potential control-plane risk.

## Access Control and LPE Boundary

Direct low-privileged access was not proven.

Prior testing indicated:

- Dangerous paths are reachable by an elevated caller that can open the device.
- Direct low-privileged LPE was not demonstrated.

Recommended fix:

- Use `IoCreateDeviceSecure` with restrictive SDDL.
- Enforce privilege checks in dispatch, not only at object creation.
- Consider denying all user-mode access to raw hardware primitives.

## What Is Not Proven

The following claims should **not** be made based on current evidence:

- Stable arbitrary physical RAM read.
- Stable arbitrary physical RAM write.
- Full system RAM dump capability.
- Direct low-privileged LPE.
- GPU command stream execution.

## Remediation Summary

- Remove user-accessible raw physical memory mapping.
- Validate `RequestorMode` and enforce `KernelMode` or strict trusted caller policy for dangerous IOCTLs.
- Replace broad physical address filters with strict, OS-resource-backed allowlists.
- Add overflow-safe bounds checks.
- Validate before use in all map/unmap/read/write paths.
- Synchronize global mapping tables.
- Return correct NTSTATUS values:
  - `STATUS_ACCESS_DENIED` for unauthorized callers.
  - `STATUS_INVALID_PARAMETER` for malformed requests.
  - `STATUS_BUFFER_TOO_SMALL` for insufficient buffers.
- Check HAL transfer counts.
- Audit MSR and raw I/O port exposure using strict allowlists.

## Final Position

This build remains security-relevant because it preserves unsafe kernel driver patterns and confirmed scoped hardware access primitives. The strongest defensible claim is:

> RTCore64 exposes high-risk elevated user-to-kernel primitives, including validation-after-use, weak mapped-window bounds checks, crash-backed memory corruption reachability, framebuffer/VRAM disclosure, and scoped BAR/MMIO write capability. Unrestricted arbitrary RAM read/write was not proven.

