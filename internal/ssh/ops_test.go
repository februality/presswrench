package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pkg/sftp"
)

func TestClassifyMode(t *testing.T) {
	cases := []struct {
		mode uint32
		want FileType
	}{
		{0o040755, FileTypeDirectory},
		{0o100644, FileTypeFile},
		{0o120777, FileTypeSymlink},
		{0o010644, FileTypeOther}, // FIFO
		{0o020644, FileTypeOther}, // char device
	}
	for _, c := range cases {
		if got := classifyMode(c.mode); got != c.want {
			t.Errorf("classifyMode(%o) = %s, want %s", c.mode, got, c.want)
		}
	}
}

func TestCapture_KeepsHeadAndTail(t *testing.T) {
	c := newCapture(20)
	for i := 0; i < 10; i++ {
		_, _ = c.Write([]byte("0123456789"))
	}
	got := c.String()
	if !c.Truncated() || !strings.HasPrefix(got, "0123456789\n[… 80 of 100 bytes omitted …]\n") || !strings.HasSuffix(got, "\n0123456789") {
		t.Fatalf("got %q", got)
	}

	small := newCapture(20)
	_, _ = small.Write([]byte("hello "))
	_, _ = small.Write([]byte("world, twenty!"))
	if small.Truncated() || small.String() != "hello world, twenty!" {
		t.Fatalf("got %q truncated=%v", small.String(), small.Truncated())
	}

	unlimited := newCapture(0)
	_, _ = unlimited.Write(bytes.Repeat([]byte("x"), 5000))
	if unlimited.Truncated() || len(unlimited.String()) != 5000 {
		t.Fatalf("unlimited capture cut its output")
	}
}

func TestCapture_DoesNotSplitRunes(t *testing.T) {
	c := newCapture(10)
	_, _ = c.Write([]byte(strings.Repeat("é", 40))) // 2 bytes each; both cuts land mid-rune
	if got := c.String(); !utf8.ValidString(got) {
		t.Fatalf("invalid UTF-8: %q", got)
	}
}

func slice(t *testing.T, content string, opts ReadOptions) *FileSlice {
	t.Helper()
	s, err := readSlice(strings.NewReader(content), int64(len(content)), opts, scan{countAll: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReadSlice(t *testing.T) {
	five := "one\ntwo\nthree\nfour\nfive\n"

	s := slice(t, five, ReadOptions{})
	if s.Content != five || !s.Whole() || s.TotalLines != 5 || s.FirstLine != 1 || s.LastLine != 5 {
		t.Errorf("whole file: %+v", s)
	}

	s = slice(t, five, ReadOptions{Offset: 2, Limit: 2})
	if s.Content != "two\nthree\n" || s.Whole() || !s.More || s.FirstLine != 2 || s.LastLine != 3 || s.TotalLines != 5 {
		t.Errorf("range: %+v", s)
	}

	s = slice(t, "one\ntwo\nlast", ReadOptions{Offset: 3})
	if s.Content != "last" || s.More || s.TotalLines != 3 || s.Whole() {
		t.Errorf("tail without newline: %+v", s)
	}

	// The byte cap keeps whole lines.
	s = slice(t, five, ReadOptions{MaxBytes: 10})
	if s.Content != "one\ntwo\n" || !s.More || s.LineCut || s.LastLine != 2 || s.TotalLines != 5 {
		t.Errorf("byte cap: %+v", s)
	}

	// One line longer than the cap is cut, and says so.
	long := strings.Repeat("x", 200000) + "\nnext\n"
	s = slice(t, long, ReadOptions{MaxBytes: 100})
	if len(s.Content) != 100 || !s.LineCut || !s.More || s.LastLine != 1 || s.TotalLines != 2 {
		t.Errorf("long line: len %d, %+v", len(s.Content), FileSlice{LineCut: s.LineCut, More: s.More, LastLine: s.LastLine, TotalLines: s.TotalLines})
	}

	// With no cap, a line longer than the read buffer comes back whole.
	if s = slice(t, long, ReadOptions{}); s.Content != long || !s.Whole() {
		t.Errorf("uncapped long line: len %d, whole %v", len(s.Content), s.Whole())
	}

	s = slice(t, five, ReadOptions{Offset: 9})
	if s.Content != "" || s.Whole() || s.TotalLines != 5 || s.FirstLine != 0 {
		t.Errorf("offset past the end: %+v", s)
	}

	if s = slice(t, "", ReadOptions{}); s.Content != "" || !s.Whole() || s.TotalLines != 0 {
		t.Errorf("empty file: %+v", s)
	}
}

func TestReadSlice_Binary(t *testing.T) {
	_, err := readSlice(strings.NewReader("PNG\x00\x01\x02"), 6, ReadOptions{}, scan{})
	var bin *BinaryError
	if !errors.As(err, &bin) || bin.Size != 6 {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyEdit(t *testing.T) {
	src := "a = 1\nb = 2\na = 1\n"

	got, lines, err := applyEdit(src, "b = 2", "b = 3", false)
	if err != nil || got != "a = 1\nb = 3\na = 1\n" || len(lines) != 1 || lines[0] != 2 {
		t.Errorf("single: %q %v %v", got, lines, err)
	}

	if _, _, err = applyEdit(src, "a = 1", "a = 9", false); err == nil || !strings.Contains(err.Error(), "matches 2 places (lines 1, 3)") {
		t.Errorf("ambiguous: %v", err)
	}
	got, lines, err = applyEdit(src, "a = 1", "a = 9", true)
	if err != nil || got != "a = 9\nb = 2\na = 9\n" || len(lines) != 2 {
		t.Errorf("replace_all: %q %v %v", got, lines, err)
	}

	if _, _, err = applyEdit(src, "missing", "x", false); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing: %v", err)
	}
	if _, _, err = applyEdit(src, "", "x", false); err == nil {
		t.Error("empty old_string accepted")
	}
	if _, _, err = applyEdit(src, "b = 2", "b = 2", false); err == nil {
		t.Error("no-op edit accepted")
	}

	// A CRLF file matches an old_string written with LF, and keeps CRLF.
	got, _, err = applyEdit("x\r\ny\r\nz\r\n", "x\ny", "x\nY\nw", false)
	if err != nil || got != "x\r\nY\r\nw\r\nz\r\n" {
		t.Errorf("crlf: %q %v", got, err)
	}
}

// memSFTP is an SFTP client wired to pkg/sftp's in-memory server.
func memSFTP(t *testing.T) *sftp.Client {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	srv := sftp.NewRequestServer(serverConn, sftp.InMemHandler())
	go func() { _ = srv.Serve() }()
	c, err := sftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = srv.Close() })
	return c
}

func remoteContent(t *testing.T, c *sftp.Client, path string) string {
	t.Helper()
	f, err := c.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriteRemote(t *testing.T) {
	c := memSFTP(t)

	n, err := writeRemote(c, "/a.txt", "/srv/htdocs/a.txt", strings.NewReader("first"), false)
	if err != nil || n != 5 || remoteContent(t, c, "/a.txt") != "first" {
		t.Fatalf("create: n=%d err=%v", n, err)
	}
	if _, err = writeRemote(c, "/a.txt", "/srv/htdocs/a.txt", strings.NewReader("second"), false); err != nil || remoteContent(t, c, "/a.txt") != "second" {
		t.Fatalf("overwrite: %v", err)
	}

	_, err = writeRemote(c, "/new/dir/b.txt", "/srv/htdocs/new/dir/b.txt", strings.NewReader("x"), false)
	if err == nil || !strings.Contains(err.Error(), "Failed to write /srv/htdocs/new/dir/b.txt") || !strings.Contains(err.Error(), "create_dirs") {
		t.Fatalf("missing folder: %v", err)
	}
	if _, err = writeRemote(c, "/new/dir/b.txt", "/srv/htdocs/new/dir/b.txt", strings.NewReader("x"), true); err != nil || remoteContent(t, c, "/new/dir/b.txt") != "x" {
		t.Fatalf("create_dirs: %v", err)
	}

	// No temp file is left behind.
	infos, _ := c.ReadDir("/")
	for _, i := range infos {
		if strings.Contains(i.Name(), ".presswrench-") {
			t.Errorf("leftover temp file %s", i.Name())
		}
	}
}

func TestRemoteCommand(t *testing.T) {
	const watchdog = "(cat <&3; kill -0 $$ && kill -KILL 0) >/dev/null 2>&1 & } 2>/dev/null | {\n"
	if got, want := remoteCommand("ls", ExecOptions{}), "exec 3<&0\n{ "+watchdog+"ls\n} 3<&-"; got != want {
		t.Errorf("bare:\n got %q\nwant %q", got, want)
	}
	got := remoteCommand("a; b", ExecOptions{Cwd: "/srv/htdocs", Stdin: "12345", TimeoutMs: 1500})
	want := "exec 3<&0\n{ head -c 5 <&3; " + watchdog + "cd '/srv/htdocs' || exit 1\na; b\n} 3<&-"
	if got != want {
		t.Errorf("cwd + stdin:\n got %q\nwant %q", got, want)
	}
}

// fakeMover is a tiny filesystem for replaceFile.
type fakeMover struct {
	files   map[string]string
	noPosix bool
	// failRename fails a plain rename onto this name.
	failRename string
}

func (m *fakeMover) PosixRename(from, to string) error {
	if m.noPosix {
		return errors.New("SSH_FX_OP_UNSUPPORTED")
	}
	m.files[to] = m.files[from]
	delete(m.files, from)
	return nil
}

func (m *fakeMover) Rename(from, to string) error {
	if _, exists := m.files[to]; exists || to == m.failRename {
		return errors.New("SSH_FX_FAILURE")
	}
	m.files[to] = m.files[from]
	delete(m.files, from)
	return nil
}

func (m *fakeMover) Remove(path string) error { delete(m.files, path); return nil }

func (m *fakeMover) Lstat(path string) (os.FileInfo, error) {
	if _, ok := m.files[path]; !ok {
		return nil, os.ErrNotExist
	}
	return nil, nil
}

func TestReplaceFile(t *testing.T) {
	const tmp, target = "/a.php.presswrench-x.tmp", "/a.php"

	m := &fakeMover{files: map[string]string{tmp: "new", target: "old"}}
	if err := replaceFile(m, tmp, target); err != nil || m.files[target] != "new" || len(m.files) != 1 {
		t.Errorf("posix rename: %v %v", err, m.files)
	}

	// No posix-rename: the original is moved aside, replaced, then removed.
	m = &fakeMover{noPosix: true, files: map[string]string{tmp: "new", target: "old"}}
	if err := replaceFile(m, tmp, target); err != nil || m.files[target] != "new" || len(m.files) != 1 {
		t.Errorf("fallback: %v %v", err, m.files)
	}
	m = &fakeMover{noPosix: true, files: map[string]string{tmp: "new"}}
	if err := replaceFile(m, tmp, target); err != nil || m.files[target] != "new" {
		t.Errorf("fallback, new file: %v %v", err, m.files)
	}

	// The original can't be moved aside: nothing is touched.
	m = &fakeMover{noPosix: true, failRename: "/a.php.presswrench-x.orig", files: map[string]string{tmp: "new", target: "old"}}
	if err := replaceFile(m, tmp, target); err == nil || m.files[target] != "old" {
		t.Errorf("can't move aside: %v %v", err, m.files)
	}
}

// swapFails lets the original be moved aside, then refuses the new file.
type swapFails struct{ *fakeMover }

func (m swapFails) Rename(from, to string) error {
	if strings.HasSuffix(from, ".tmp") {
		return errors.New("SSH_FX_FAILURE")
	}
	return m.fakeMover.Rename(from, to)
}

// The old code deleted the original before the rename that then failed.
func TestReplaceFile_FailedSwapPutsTheOriginalBack(t *testing.T) {
	const tmp, target = "/a.php.presswrench-x.tmp", "/a.php"
	m := swapFails{&fakeMover{noPosix: true, files: map[string]string{tmp: "new", target: "old"}}}
	if err := replaceFile(m, tmp, target); err == nil {
		t.Fatal("no error")
	}
	if m.files[target] != "old" {
		t.Errorf("original lost: %v", m.files)
	}
}

// Writing to a symlink changes the file it points at and leaves the link.
func TestWriteRemote_ThroughSymlink(t *testing.T) {
	c := memSFTP(t)
	if err := c.MkdirAll("/drop-ins"); err != nil {
		t.Fatal(err)
	}
	if _, err := writeRemote(c, "/drop-ins/object-cache.php", "x", strings.NewReader("v1"), false); err != nil {
		t.Fatal(err)
	}
	if err := c.MkdirAll("/wp-content"); err != nil {
		t.Fatal(err)
	}
	if err := c.Symlink("../drop-ins/object-cache.php", "/wp-content/object-cache.php"); err != nil {
		t.Skipf("server has no symlinks: %v", err)
	}

	if _, err := writeRemote(c, "/wp-content/object-cache.php", "/srv/htdocs/wp-content/object-cache.php", strings.NewReader("v2"), false); err != nil {
		t.Fatal(err)
	}
	st, err := c.Lstat("/wp-content/object-cache.php")
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced by a regular file: %v %v", st, err)
	}
	if got := remoteContent(t, c, "/drop-ins/object-cache.php"); got != "v2" {
		t.Errorf("target = %q", got)
	}

	// An edit goes through the link too.
	if _, err := editRemote(c, "/wp-content/object-cache.php", "x", "v2", "v3", false); err != nil {
		t.Fatal(err)
	}
	if st, _ = c.Lstat("/wp-content/object-cache.php"); st.Mode()&os.ModeSymlink == 0 || remoteContent(t, c, "/drop-ins/object-cache.php") != "v3" {
		t.Errorf("edit through the link: mode %v", st.Mode())
	}

	// A link to nowhere says so instead of offering create_dirs.
	if err := c.Symlink("/gone/away.php", "/wp-content/dangling.php"); err == nil {
		_, err = writeRemote(c, "/wp-content/dangling.php", "/srv/htdocs/wp-content/dangling.php", strings.NewReader("x"), false)
		if err == nil || !strings.Contains(err.Error(), "a symlink to /gone/away.php") || strings.Contains(err.Error(), "create_dirs") {
			t.Errorf("dangling link: %v", err)
		}
	}
}

// meddler changes a remote file the first time it is read from: the write
// it feeds is the "edit", and the change is someone else's, arriving
// between the edit's read and its write.
type meddler struct {
	io.Reader
	meddle func()
	done   bool
}

func (m *meddler) Read(p []byte) (int, error) {
	if !m.done {
		m.done = true
		m.meddle()
	}
	return m.Reader.Read(p)
}

func TestEdit_RefusesWhenTheFileChangedUnderneath(t *testing.T) {
	c := memSFTP(t)
	const path, shown = "/functions.php", "/srv/htdocs/functions.php"
	put := func(content string) {
		t.Helper()
		if _, err := writeRemote(c, path, shown, strings.NewReader(content), false); err != nil {
			t.Fatal(err)
		}
	}
	put("original\n")
	before, err := c.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing else touched it: the check passes and the edit lands.
	if _, err := writeRemoteIf(c, path, shown, strings.NewReader("edited\n"), false, unchangedSince(c, path, shown, before)); err != nil {
		t.Fatalf("undisturbed edit: %v", err)
	}

	// Someone else writes it mid-edit: the edit is abandoned, their version stays.
	before, _ = c.Stat(path)
	src := &meddler{Reader: strings.NewReader("my edit\n"), meddle: func() { put("someone else's much longer change\n") }}
	_, err = writeRemoteIf(c, path, shown, src, false, unchangedSince(c, path, shown, before))
	if err == nil || !strings.Contains(err.Error(), "changed on the server") || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("err = %v", err)
	}
	if got := remoteContent(t, c, path); got != "someone else's much longer change\n" {
		t.Errorf("their change was overwritten: %q", got)
	}
	infos, _ := c.ReadDir("/")
	for _, i := range infos {
		if strings.Contains(i.Name(), ".presswrench-") {
			t.Errorf("leftover temp file %s", i.Name())
		}
	}

	// And an ordinary edit still works end to end.
	if res, err := editRemote(c, path, shown, "much longer", "short", false); err != nil || res.Replacements != 1 {
		t.Fatalf("edit: %+v %v", res, err)
	}
}

func TestReadSlice_FromAMark(t *testing.T) {
	// The reader stands at line 3 (offset 8): lines are numbered from there.
	rest := "three\nfour\nfive\n"
	s, err := readSlice(strings.NewReader(rest), 23, ReadOptions{Offset: 4, Limit: 1}, scan{startLine: 3, startOff: 8, knownTotal: 5})
	if err != nil || s.Content != "four\n" || s.FirstLine != 4 || s.TotalLines != 5 || !s.More {
		t.Fatalf("got %+v, %v", s, err)
	}
}

// lineNumbers collects the line starts a read reports.
type lineNumbers struct{ marks map[int]int64 }

func (l *lineNumbers) add(line int, off int64) { l.marks[line] = off }

func TestReadSlice_RecordsWhereThePageEnds(t *testing.T) {
	content := "one\ntwo\nthree\nfour\n"
	got := &lineNumbers{marks: map[int]int64{}}
	if _, err := readSlice(strings.NewReader(content), int64(len(content)), ReadOptions{Limit: 2}, scan{countAll: true, mark: got.add}); err != nil {
		t.Fatal(err)
	}
	if got.marks[3] != 8 {
		t.Errorf("marks = %v, want line 3 at byte 8", got.marks)
	}
}

func TestEncodings(t *testing.T) {
	// Every Windows-1252 byte survives decode + encode.
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if back, ok := encode1252(decode1252(all)); !ok || back != string(all) {
		t.Error("Windows-1252 does not round-trip")
	}
	if _, ok := encode1252("→"); ok {
		t.Error("an arrow has no Windows-1252 byte")
	}

	// A line that isn't UTF-8 is shown decoded; the rest is untouched.
	s := slice(t, "plain\nnom = 'caf\xe9 \x80 5';\n", ReadOptions{})
	if s.Content != "plain\nnom = 'café € 5';\n" || s.Encoding != EncodingWindows1252 {
		t.Errorf("legacy read: %q %q", s.Content, s.Encoding)
	}
	if s = slice(t, "déjà vu\n", ReadOptions{}); s.Content != "déjà vu\n" || s.Encoding != "" {
		t.Errorf("UTF-8 read: %q %q", s.Content, s.Encoding)
	}
}

func TestEditEncoded_Windows1252(t *testing.T) {
	file := "<?php\n$nom = 'caf\xe9';\n$ok = 1;\n"
	got, lines, err := editEncoded(file, "$nom = 'café';", "$nom = 'thé';", false)
	if err != nil || got != "<?php\n$nom = 'th\xe9';\n$ok = 1;\n" || lines[0] != 2 {
		t.Fatalf("got %q %v %v", got, lines, err)
	}
	// ASCII edits in such a file need no translation.
	if got, _, err = editEncoded(file, "$ok = 1;", "$ok = 2;", false); err != nil || got != "<?php\n$nom = 'caf\xe9';\n$ok = 2;\n" {
		t.Fatalf("ascii edit: %q %v", got, err)
	}
	if _, _, err = editEncoded(file, "café", "caf→", false); err == nil || !strings.Contains(err.Error(), "Windows-1252") {
		t.Fatalf("unencodable replacement: %v", err)
	}
	if _, _, err = editEncoded(file, "thé", "x", false); !errors.Is(err, errNoMatch) {
		t.Fatalf("missing text: %v", err)
	}
	// A UTF-8 file is edited as UTF-8.
	if got, _, err = editEncoded("x = 'café';\n", "café", "thé", false); err != nil || got != "x = 'thé';\n" {
		t.Fatalf("utf-8: %q %v", got, err)
	}
}

func TestUTF16(t *testing.T) {
	text := "first line\r\nsecond ‘quoted’ 😀\r\nthird\r\n"
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		bom := "\xff\xfe"
		if order == binary.BigEndian {
			bom = "\xfe\xff"
		}
		file := bom + encodeUTF16(text, order)

		c := memSFTP(t)
		if _, err := writeRemote(c, "/u16.txt", "/srv/htdocs/u16.txt", strings.NewReader(file), false); err != nil {
			t.Fatal(err)
		}
		s, err := readRemote(c, "/u16.txt", "/srv/htdocs/u16.txt", ReadOptions{}, nil)
		if err != nil || s.Content != text || s.Encoding != utf16Name(order) || s.TotalLines != 3 {
			t.Fatalf("%s read: %+v, %v", utf16Name(order), s, err)
		}
		if s, err = readRemote(c, "/u16.txt", "/srv/htdocs/u16.txt", ReadOptions{Offset: 2, Limit: 1}, nil); err != nil || s.Content != "second ‘quoted’ 😀\r\n" {
			t.Fatalf("%s range: %+v, %v", utf16Name(order), s, err)
		}

		// An edit written with plain newlines, spanning two lines.
		res, err := editRemote(c, "/u16.txt", "/srv/htdocs/u16.txt", "second ‘quoted’ 😀\nthird", "2nd\n3rd", false)
		if err != nil || res.Lines[0] != 2 {
			t.Fatalf("%s edit: %+v, %v", utf16Name(order), res, err)
		}
		if got := remoteContent(t, c, "/u16.txt"); got != bom+encodeUTF16("first line\r\n2nd\r\n3rd\r\n", order) {
			t.Errorf("%s after edit: % x", utf16Name(order), got)
		}
	}
}

// "AB" in UTF-16LE is 41 00 42 00; the bytes 00 42 also sit across the two
// characters. A search must not match there.
func TestReplaceIn_MatchesOnCharacterBoundaries(t *testing.T) {
	content := encodeUTF16("AB䈀", binary.LittleEndian) // 41 00 42 00 00 42
	needle := encodeUTF16("䈀", binary.LittleEndian)    // 00 42
	got, _, err := replaceIn(content, needle, encodeUTF16("!", binary.LittleEndian), false, encodeUTF16("\n", binary.LittleEndian), 2)
	if err != nil || got != encodeUTF16("AB!", binary.LittleEndian) {
		t.Fatalf("got % x, %v", got, err)
	}
}
