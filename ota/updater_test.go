package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func goodState() state {
	return state{Model: "t60_extchg_k61", Device: "t60_extchg_k61", Locked: "0", Verified: "orange", BootSHA: stockSHA, RecoverySHA: recoverySHA, BootSize: bootSize, Present: 1, Capacity: 80, USB: 1}
}
func TestGuards(t *testing.T) {
	cases := []struct {
		name   string
		change func(*state)
	}{
		{"locked", func(s *state) { s.Locked = "1" }}, {"unknown lock", func(s *state) { s.Locked = "" }},
		{"green", func(s *state) { s.Verified = "green" }}, {"other board", func(s *state) { s.Device = "other" }},
		{"other model", func(s *state) { s.Model = "other" }}, {"other boot", func(s *state) { s.BootSHA = "other" }},
		{"other recovery", func(s *state) { s.RecoverySHA = "other" }}, {"size", func(s *state) { s.BootSize = 1 }},
		{"battery absent", func(s *state) { s.Present = 0 }}, {"battery unknown", func(s *state) { s.Capacity = -1 }},
		{"low battery", func(s *state) { s.Capacity = 49 }}, {"bad battery", func(s *state) { s.Capacity = 101 }},
		{"usb absent", func(s *state) { s.USB = 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := goodState()
			c.change(&s)
			if eligibility(s) == nil {
				t.Fatal("unsafe state accepted")
			}
		})
	}
	if eligibility(goodState()) != nil {
		t.Fatal("valid state rejected")
	}
	s := goodState()
	s.BootSHA = patchedSHA
	if eligibility(s) != nil {
		t.Fatal("already installed rejected")
	}
}
func TestCommandLineDuplicateFailsClosed(t *testing.T) {
	if bootArg("androidboot.flash.locked=0 androidboot.flash.locked=1", "flash.locked") != "" {
		t.Fatal("ambiguous argument")
	}
	if bootArg("androidboot.flash.locked=0", "flash.locked") != "0" {
		t.Fatal("missing argument")
	}
}
func TestFlashReadbackAndRollback(t *testing.T) {
	current := "old"
	writes := 0
	write := func(path string) error { writes++; current = path; return nil }
	read := func() (string, error) { return current, nil }
	if transactionalWrite("old", "new", "old", "new", write, read) != nil || writes != 1 || current != "new" {
		t.Fatal("happy path")
	}
	writes = 0
	current = "old"
	bad := func(path string) error {
		writes++
		current = path
		if writes == 1 {
			current = "corrupt"
		}
		return nil
	}
	if transactionalWrite("old", "new", "old", "new", bad, read) == nil || writes != 2 || current != "old" {
		t.Fatal("readback failure must restore")
	}
	writes = 0
	fail := func(string) error { writes++; return errors.New("io") }
	if transactionalWrite("old", "new", "old", "new", fail, read) == nil || writes != 2 {
		t.Fatal("failed write must attempt restore exactly once")
	}
}

func TestProbeDoesNotNeedFlashPayload(t *testing.T) {
	oldMode, oldPipe := mode, pipe
	defer func() { mode, pipe = oldMode, oldPipe }()
	mode = "probe"
	var out bytes.Buffer
	pipe = &out
	if err := run("/missing-package-must-not-be-opened"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "PROBE_COMPLETE") || !strings.Contains(out.String(), "INSTALL_BLOCKED") {
		t.Fatal("missing diagnosis")
	}
	mode = "unknown"
	if run("/missing") == nil {
		t.Fatal("unknown mode accepted")
	}
}
func TestImageSizeAndPayloadGuards(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "image")
	os.WriteFile(f, []byte("12345"), 0600)
	if _, _, err := digest(f, 4); err == nil {
		t.Fatal("oversize accepted")
	}
	if _, _, err := digest(f, 6); err == nil {
		t.Fatal("truncated accepted")
	}
	if _, _, err := digest(f, 5); err != nil {
		t.Fatal(err)
	}
	if copyExact(filepath.Join(dir, "out"), strings.NewReader("xx"), 1) == nil {
		t.Fatal("long source accepted")
	}
	for _, names := range [][]string{{"other"}, {"boot.img"}, {"boot.img", "boot.img"}} {
		p := filepath.Join(dir, "bad.zip")
		out, _ := os.Create(p)
		z := zip.NewWriter(out)
		for _, name := range names {
			w, _ := z.Create(name)
			w.Write([]byte("bad"))
		}
		z.Close()
		out.Close()
		if extractBoot(p, filepath.Join(dir, "target")) == nil {
			t.Fatal("bad ZIP payload accepted")
		}
	}
}

func TestReviewedPayloadExtraction(t *testing.T) {
	fixture := os.Getenv("OLAX_TEST_BOOT")
	if fixture == "" {
		t.Skip("set OLAX_TEST_BOOT to locally reproduced reviewed boot; no private firmware in source")
	}
	dir := t.TempDir()
	pkg := filepath.Join(dir, "kernel.zip")
	out, e := os.Create(pkg)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(out)
	w, e := z.Create("boot.img")
	if e != nil {
		t.Fatal(e)
	}
	src, e := os.Open(fixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = io.Copy(w, src); e != nil {
		t.Fatal(e)
	}
	src.Close()
	z.Close()
	out.Close()
	target := filepath.Join(dir, "boot.img")
	if e = extractBoot(pkg, target); e != nil {
		t.Fatal(e)
	}
	h, n, e := digest(target, bootSize)
	if e != nil || h != patchedSHA || n != bootSize {
		t.Fatal("reviewed image was changed")
	}
}
