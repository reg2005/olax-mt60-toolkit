# Provenance and licenses

- Toolkit Python/Go additions and local mtkclient modifications: GPL-3.0;
  see LICENSE. No private repository history is imported.
- mtkclient: B. Kerler and contributors, GPL-3.0, commit
  `cd25cf9c1ff6d36e82697ac2c798e69e9cfb78c3`,
  https://github.com/bkerler/mtkclient . The installer downloads the upstream
  archive, verifies upstream.json, applies the two source files in patches/,
  and verifies upstream-files.json. The upstream license remains in .runtime/.
  Loader/payload/DLL files are obtained from that upstream archive, not copied
  from a user's modem. Upstream notices continue to apply to those components.
- Python dependencies: pinned in requirements.txt; their respective licenses
  apply. They are installed from PyPI, not redistributed in the toolkit ZIP.
- Android AOSP SignApk/recovery reference code: Android 8.1.0_r1, Apache-2.0
  per upstream headers. ota/vendor/sources.json records original URLs and hashes;
  fetch_vendor.py obtains them for a local build. Public AOSP testkey is a
  deliberately public development key, not a personal secret.
- The kernel OTA payload contains a modified OEM boot image with its original
  ramdisk. It is firmware for the owner's supported hardware, not an entirely
  GPL-authored replacement ROM. Original vendor/component rights remain with
  their authors. The repository publishes the exact guarded binary patch recipe,
  not a claim to provide a complete matching vendor kernel source tree or a
  new license for proprietary firmware components. Raw device backups and
  calibration partitions are never distributed.

Release SHA256 files detect corruption and bind files to the release metadata.
The legacy AOSP testkey accepted by this stock recovery does not authenticate
us as the publisher; obtain release files from the intended GitHub repository.
