// Kernel-only updater for one reviewed OLAX revision. Never unlocks or formats.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const stockSHA = "aea6db447c55a144af61ad9d28bff920b294c7e7f30605ebc8938175c8f3278d"
const patchedSHA = "02b4337e75e0b088813b83280f93ef9fb908af96adcac5d1c0358884deba1feb"
const recoverySHA = "9a82a9dcb915efc78ce02e98c36fb45c82f087307882f7cb1585d8813b63ffc1"
const bootSize int64 = 33554432
const bootPath = "/dev/block/platform/bootdevice/by-name/boot"
const recoveryPath = "/dev/block/platform/bootdevice/by-name/recovery"

var mode = "probe" // set at build time; no runtime option can enable writing
var pipe io.Writer = os.Stdout

type state struct {
	Model, Device, Locked, Verified, BootSHA, RecoverySHA string
	BootSize                                              int64
	Present, Capacity, USB                                int
}

func eligibility(s state) error {
	switch {
	case s.Model != "t60_extchg_k61" || s.Device != "t60_extchg_k61":
		return errors.New("BOARD_MISMATCH: unsupported hardware")
	case s.BootSize != bootSize:
		return errors.New("BOOT_SIZE: unsupported partition size")
	case s.BootSHA != stockSHA && s.BootSHA != patchedSHA:
		return errors.New("BOOT_MISMATCH: unsupported firmware")
	case s.RecoverySHA != recoverySHA:
		return errors.New("RECOVERY_MISMATCH: unsupported recovery")
	case s.Locked != "0" || s.Verified != "orange":
		return errors.New("BOOTLOADER_LOCKED_OR_UNKNOWN: kernel was NOT written; initial unlock is required")
	case s.Present != 1 || s.Capacity < 50 || s.Capacity > 100 || s.USB != 1:
		return errors.New("POWER_NOT_READY: battery >=50% and USB power required")
	}
	return nil
}
func bootArg(cmd, key string) string {
	prefix := "androidboot." + key + "="
	v := ""
	count := 0
	for _, part := range strings.Fields(cmd) {
		if strings.HasPrefix(part, prefix) {
			v = strings.TrimPrefix(part, prefix)
			count++
		}
	}
	if count != 1 {
		return ""
	}
	return v
}
func readText(p string) string {
	b, e := os.ReadFile(p)
	if e != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func readInt(p string) int {
	v, e := strconv.Atoi(readText(p))
	if e != nil {
		return -1
	}
	return v
}
func prop(key string) string {
	for _, exe := range []string{"/sbin/getprop", "/system/bin/getprop"} {
		if b, e := exec.Command(exe, key).Output(); e == nil {
			return strings.TrimSpace(string(b))
		}
	}
	// Recovery's own default.prop is independent of userdata and requires no mounts.
	for _, line := range strings.Split(readText("/default.prop"), "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		}
	}
	return ""
}
func inspect() state {
	cmd := readText("/proc/cmdline")
	s := state{Model: prop("ro.product.model"), Device: prop("ro.product.device"), Locked: bootArg(cmd, "flash.locked"), Verified: bootArg(cmd, "verifiedbootstate"), Present: readInt("/sys/class/power_supply/battery/present"), Capacity: readInt("/sys/class/power_supply/battery/capacity"), USB: readInt("/sys/class/power_supply/usb/online")}
	s.BootSHA, s.BootSize, _ = digest(bootPath, bootSize)
	s.RecoverySHA, _, _ = digest(recoveryPath, bootSize)
	return s
}
func say(s string) {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 127 {
			return ' '
		}
		return r
	}, s)
	fmt.Fprintf(pipe, "ui_print %s\nui_print\n", s)
}
func digest(path string, limit int64) (string, int64, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, limit+1))
	if e != nil || n != limit {
		return "", n, errors.New("unexpected image size")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func copyExact(dst string, src io.Reader, size int64) error {
	f, e := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	n, e := io.Copy(f, io.LimitReader(src, size+1))
	if e == nil && n != size {
		e = errors.New("unexpected image size")
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return e
}
func writeBoot(source string) error {
	f, e := os.Open(source)
	if e != nil {
		return e
	}
	defer f.Close()
	// No O_TRUNC, O_CREATE, erase or partition discovery on the only writable target.
	out, e := os.OpenFile(bootPath, os.O_WRONLY, 0)
	if e != nil {
		return e
	}
	n, e := io.CopyN(out, f, bootSize)
	if e == nil && n != bootSize {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e == nil {
		e = ce
	}
	return e
}
func transactionalWrite(old, next, oldHash, newHash string, write func(string) error, hash func() (string, error)) error {
	e := write(next)
	if e == nil {
		var got string
		got, e = hash()
		if e == nil && got != newHash {
			e = errors.New("readback mismatch")
		}
	}
	if e == nil {
		return nil
	}
	if restore := write(old); restore != nil {
		return errors.New("WRITE_FAILED_RESTORE_FAILED: keep power connected; service recovery required")
	}
	got, restore := hash()
	if restore != nil || got != oldHash {
		return errors.New("WRITE_FAILED_RESTORE_UNVERIFIED: keep power connected; service recovery required")
	}
	return errors.New("WRITE_FAILED_ORIGINAL_RESTORED: do not repeat; inspect recovery log")
}
func extractBoot(pkg, dst string) error {
	z, e := zip.OpenReader(pkg)
	if e != nil {
		return e
	}
	defer z.Close()
	var found *zip.File
	for _, f := range z.File {
		if f.Name == "boot.img" {
			if found != nil {
				return errors.New("duplicate boot image")
			}
			found = f
		}
	}
	if found == nil || found.UncompressedSize64 != uint64(bootSize) {
		return errors.New("missing or wrong-size payload")
	}
	r, e := found.Open()
	if e != nil {
		return e
	}
	defer r.Close()
	if e = copyExact(dst, r, bootSize); e != nil {
		return e
	}
	h, _, e := digest(dst, bootSize)
	if e != nil || h != patchedSHA {
		return errors.New("payload SHA256 mismatch")
	}
	return nil
}
func backupBoot() (string, error) {
	// Recovery normally mounts /cache; if not mounted, refuse rather than put a
	// supposedly durable backup into the recovery RAM filesystem.
	mounted := false
	for _, line := range strings.Split(readText("/proc/mounts"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[1] == "/cache" && f[2] == "ext4" && strings.HasPrefix(f[0], "/dev/block/") {
			mounted = true
		}
	}
	if !mounted {
		return "", errors.New("CACHE_NOT_MOUNTED: no durable backup available")
	}
	dir := "/cache/recovery/olax-kernel"
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("backup directory is not a real directory")
	}
	p := filepath.Join(dir, "stock-boot.img")
	if info, e := os.Lstat(p); e == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("backup is not a regular file")
		}
		h, _, e := digest(p, bootSize)
		if e != nil || h != stockSHA {
			return "", errors.New("existing backup differs; preserved")
		}
		return p, nil
	} else if !os.IsNotExist(e) {
		return "", e
	}
	src, e := os.Open(bootPath)
	if e != nil {
		return "", e
	}
	defer src.Close()
	temp, e := os.CreateTemp(dir, ".stock-boot-*")
	if e != nil {
		return "", e
	}
	tmp := temp.Name()
	if e = temp.Close(); e != nil {
		return "", e
	}
	defer os.Remove(tmp)
	if e = copyExact(tmp, src, bootSize); e != nil {
		return "", e
	}
	h, _, e := digest(tmp, bootSize)
	if e != nil || h != stockSHA {
		return "", errors.New("backup SHA256 mismatch")
	}
	if e = os.Rename(tmp, p); e != nil {
		return "", e
	}
	d, e := os.Open(dir)
	if e != nil {
		return "", e
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return "", e
	}
	return p, nil
}
func run(pkg string) error {
	say("OLAX kernel-only OTA 0.1.0 EXPERIMENTAL / " + mode)
	s := inspect()
	say("model=" + s.Model + " device=" + s.Device)
	say("flash.locked=" + s.Locked + " verifiedbootstate=" + s.Verified)
	say("boot.sha256=" + s.BootSHA)
	say("recovery.sha256=" + s.RecoverySHA)
	say(fmt.Sprintf("battery.present=%d capacity=%d usb=%d", s.Present, s.Capacity, s.USB))
	e := eligibility(s)
	if mode == "probe" {
		if e != nil {
			say("INSTALL_BLOCKED: " + e.Error())
		} else {
			say("INSTALL_ELIGIBLE: hardware installation still untested")
		}
		say("PROBE_COMPLETE: no partition writes, no unlock, no data wipe")
		return nil
	}
	if mode != "install" {
		return errors.New("invalid build mode")
	}
	if e != nil {
		return e
	}
	if s.BootSHA == patchedSHA {
		say("ALREADY_INSTALLED: no write needed")
		return nil
	}
	temp, e := os.CreateTemp("/tmp", "olax-fixed-boot-*")
	if e != nil {
		return e
	}
	target := temp.Name()
	if e = temp.Close(); e != nil {
		return e
	}
	defer os.Remove(target)
	if e = extractBoot(pkg, target); e != nil {
		return e
	}
	backup, e := backupBoot()
	if e != nil {
		return e
	}
	// Verify again immediately before touching boot, after durable backup.
	h, _, e := digest(bootPath, bootSize)
	if e != nil || h != stockSHA {
		return errors.New("boot changed during preparation")
	}
	say("Backup verified. Writing ONLY boot; keep power connected.")
	e = transactionalWrite(backup, target, stockSHA, patchedSHA, writeBoot, func() (string, error) { h, _, e := digest(bootPath, bootSize); return h, e })
	if e != nil {
		return e
	}
	say("BOOT_WRITE_VERIFIED: boot SHA256 matches. Reboot and check CPU/charging.")
	return nil
}
func main() {
	if len(os.Args) != 4 || (os.Args[1] != "3" && os.Args[1] != "2" && os.Args[1] != "1") {
		fmt.Fprintln(os.Stderr, "Only Android recovery update-binary invocation is supported")
		os.Exit(2)
	}
	fd, e := strconv.Atoi(os.Args[2])
	if e != nil || fd < 3 {
		os.Exit(2)
	}
	f := os.NewFile(uintptr(fd), "recovery-pipe")
	if f == nil {
		os.Exit(2)
	}
	pipe = f
	if os.Geteuid() != 0 {
		say("ROOT_REQUIRED")
		os.Exit(1)
	}
	if e = run(os.Args[3]); e != nil {
		say("ERROR: " + e.Error())
		os.Exit(1)
	}
}
