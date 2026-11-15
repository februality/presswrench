package ssh

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// Text files on a site are nearly always UTF-8, but old themes and plugins
// carry Windows-1252 files and the odd tool writes UTF-16. A tool result is
// JSON, which is UTF-8: bytes that aren't would reach the model as
// replacement characters, and it could then neither read those lines nor
// name them in an edit. So reads decode such files for display, and edits
// encode the search and replacement text back into the file's own encoding
// instead of transcoding the file.

// Names of the encodings reads report (FileSlice.Encoding).
const (
	EncodingUTF16LE     = "UTF-16LE"
	EncodingUTF16BE     = "UTF-16BE"
	EncodingWindows1252 = "Windows-1252"
)

// cp1252High maps bytes 0x80–0x9F, where Windows-1252 differs from
// Latin-1. Its five unassigned bytes map to the control characters of the
// same value, so every byte round-trips.
var cp1252High = [32]rune{
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
	0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
}

// decode1252 reads b as Windows-1252.
func decode1252(b []byte) string {
	out := make([]rune, len(b))
	for i, c := range b {
		switch {
		case c >= 0x80 && c <= 0x9F:
			out[i] = cp1252High[c-0x80]
		default:
			out[i] = rune(c)
		}
	}
	return string(out)
}

// encode1252 writes s as Windows-1252; ok is false when s has a character
// that encoding lacks.
func encode1252(s string) (encoded string, ok bool) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r < 0x80, r >= 0xA0 && r <= 0xFF:
			out = append(out, byte(r))
		default:
			found := false
			for i, h := range cp1252High {
				if h == r {
					out = append(out, byte(0x80+i))
					found = true
					break
				}
			}
			if !found {
				return "", false
			}
		}
	}
	return string(out), true
}

// displayText returns b as UTF-8, and the encoding it was read as when
// that isn't UTF-8.
func displayText(b []byte) (text, encoding string) {
	if utf8.Valid(b) {
		return string(b), ""
	}
	return decode1252(b), EncodingWindows1252
}

// utf16Order reports the byte order a UTF-16 byte-order mark at the start
// of b announces, or nil.
func utf16Order(b []byte) binary.ByteOrder {
	if len(b) >= 2 {
		switch {
		case b[0] == 0xFF && b[1] == 0xFE:
			return binary.LittleEndian
		case b[0] == 0xFE && b[1] == 0xFF:
			return binary.BigEndian
		}
	}
	return nil
}

func utf16Name(order binary.ByteOrder) string {
	if order == binary.BigEndian {
		return EncodingUTF16BE
	}
	return EncodingUTF16LE
}

// encodeUTF16 writes s as UTF-16 in the given byte order, without a mark.
func encodeUTF16(s string, order binary.ByteOrder) string {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		order.PutUint16(out[2*i:], u)
	}
	return string(out)
}

// utf16Reader decodes a UTF-16 stream (after its byte-order mark) to UTF-8.
type utf16Reader struct {
	src   *bufio.Reader
	order binary.ByteOrder
	out   bytes.Buffer
	err   error
}

func newUTF16Reader(r io.Reader, order binary.ByteOrder) *utf16Reader {
	return &utf16Reader{src: bufio.NewReaderSize(r, 32<<10), order: order}
}

func (u *utf16Reader) unit() (uint16, bool) {
	var b [2]byte
	if _, err := io.ReadFull(u.src, b[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			err = io.EOF // a stray last byte: drop it
		}
		u.err = err
		return 0, false
	}
	return u.order.Uint16(b[:]), true
}

func (u *utf16Reader) Read(p []byte) (int, error) {
	for u.out.Len() < len(p) && u.err == nil {
		first, ok := u.unit()
		if !ok {
			break
		}
		r := rune(first)
		if utf16.IsSurrogate(r) {
			second, ok := u.unit()
			if !ok {
				u.out.WriteRune(utf8.RuneError)
				break
			}
			r = utf16.DecodeRune(r, rune(second))
		}
		u.out.WriteRune(r)
	}
	if u.out.Len() == 0 {
		return 0, u.err
	}
	return u.out.Read(p)
}
