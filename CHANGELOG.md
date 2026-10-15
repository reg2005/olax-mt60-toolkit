# Changelog

## [Unreleased]

## [0.1.0] - 2026-10-15

### Added
- Linux/macOS sh and Windows cmd/PowerShell entry points.
- Pinned dependency bootstrap, per-device enrollment and backup verification.
- Scoped seccfg unlock, full readback, durable attempt journal, no blind retries.
- Post-boot verification and explicit diagnostic ADB closure.
- Guarded stock boot restore and instructions for uncertain outcomes.
- Kernel-only experimental stock recovery OTA and reproducible patch source.
- Offline test matrix for Linux, Windows and macOS.

### Limitations
- Portable USB workflow and stock OTA still need hardware qualification.
- Windows timeout aborts without automatic rollback; result remains uncertain.
- Charging cycle/external charger policy is not fully validated.
