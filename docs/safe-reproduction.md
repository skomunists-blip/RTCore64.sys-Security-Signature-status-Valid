# Safe Reproduction Notes

This repository does not provide exploit reproduction steps.

Safe validation options:

1. Review static evidence in `evidence/static/`.
2. Review controlled lab logs in `evidence/dynamic/`.
3. Run only read-only telemetry collectors from `tools/windows-readonly/`.
4. Use an isolated VM with snapshots for any driver research.

Do not run destructive tests on a host system.

## Recommended Safe Checks

- Confirm driver presence and signature.
- Confirm device ACL and caller access model.
- Review IOCTL method/access bits.
- Review `IRP_MJ_DEVICE_CONTROL` handler logic.
- Validate whether dangerous calls are behind `RequestorMode`, privilege, and range checks.

## What Not To Do

- Do not send arbitrary physical addresses to a production system.
- Do not attempt raw PCI / MSR / I/O-port writes.
- Do not unmap arbitrary kernel addresses.
- Do not run crash-triggering tests outside a disposable VM.

