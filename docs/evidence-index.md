# Evidence Index

## Static Evidence

- `evidence/static/rtcore64_driver_focus_prioritized_findings_20260524.txt`  
  Prioritized driver findings.

- `evidence/static/rtcore64_detailed_recheck_20260524.txt`  
  Detailed static recheck and corrections.

- `evidence/static/rtcore_comprehensive_audit.txt`  
  Comprehensive Ghidra-derived audit output.

- `evidence/static/rtcore_deep_issue_hunt.txt`  
  Deep issue hunt output with primitive inventory.

- `evidence/static/rtcore_dispatch_switch_listing.txt`  
  Dispatch switch listing.

- `evidence/static/rtcore_pci_bar_bypass_static.txt`  
  Static BAR allow-window analysis.

- `evidence/static/03_STATIC_CALLSITE_EXTRACT_RU.txt`  
  Extract of relevant raw I/O and PCI-config callsites.

## Dynamic Evidence

- `evidence/dynamic/rtcore_vm_controlled_diff_write_matrix_result.txt`  
  Controlled scoped BAR write/restore result.

- `evidence/dynamic/rtcore_vram_marker_probe_result.txt`  
  Controlled visible framebuffer marker disclosure.

- `evidence/dynamic/rtcore_vram_gtt_negative_evidence_result.txt`  
  Negative evidence for helper RAM canary through VRAM/GTT.

- `evidence/dynamic/rtcore_canary_multitarget_probe_result.txt`  
  Helper-owned RAM canary targets were not mapped/read by tested paths.

- `evidence/dynamic/rtcore_vm_gpu_cp_correlation_collect_result.txt`  
  CP/TDR correlation collection with no observed TDR/DxgKrnl events.

- `evidence/dynamic/rtcore_vm_hal_count_reliability_result.txt`  
  HAL count / invalid tuple reliability evidence.

## Crash Analysis

- `evidence/crash-analysis/rtcore_vm_bugcheck_collect_result.txt`  
  Post-crash artifact summary.

- `evidence/crash-analysis/kd_052426-9937-01_analysis.log`  
  Kernel debugger analysis log.

- `evidence/crash-analysis/kd_052426-9937-01_disasm18c4.log`  
  Disassembly around RTCore64 fault site.

The original minidump is intentionally excluded from this GitHub-ready package.

