# Engineering constraints

Read docs/project-status.md, docs/ADR-0001.md and docs/validation.md first.
This is an experimental, kernel-only toolkit for one exact OLAX revision.
Never add universal unlock, force, erase, relock or automatic write retries.
Never relax hash/CID/GPT/crypto guards merely to make an unsupported unit pass.
Keep backups, raw dumps, device identifiers, credentials and private signing
keys outside this repository and its release archives. Do not operate attached
hardware without an explicit user task. Offline tests must never access USB.
Do not confuse a successful build, readback or CI with successful hardware boot.
Every release must keep the hardware qualification matrix and changelog honest.
Prefer graph source discovery; index this subtree, not a parent private archive.
