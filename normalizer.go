package gitserver

import (
	"bufio"
	"bytes"
	"io"
	"unicode/utf8"

	"github.com/pkg/errors"
	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/encoding/unicode/utf32"
	"golang.org/x/text/transform"
)

var (
	// UTF8BOM is the UTF-8 Byte order mark.
	UTF8BOM = []byte{0xEF, 0xBB, 0xBF}

	// UTF16LEBOM is the UTF-16 (LE) Byte order mark.
	UTF16LEBOM = []byte{0xFF, 0xFE}

	// UTF16BEBOM is the UTF-16 (BE) Byte order mark.
	UTF16BEBOM = []byte{0xFE, 0xFF}

	// UTF32LEBOM is the UTF-16 (LE) Byte order mark.
	UTF32LEBOM = []byte{0xFF, 0xFE, 0x00, 0x00}

	// UTF32BEBOM is the UTF-16 (BE) Byte order mark.
	UTF32BEBOM = []byte{0x00, 0x00, 0xFE, 0xFF}
)

func removeBOM(r io.Reader) (io.Reader, bool, error) {
	br := bufio.NewReader(r)

	bom, err := br.Peek(utf8.UTFMax)
	if err != nil && err != io.EOF {
		return nil, false, errors.Wrap(
			err,
			"failed to inspect the first few bytes",
		)
	}

	if bytes.HasPrefix(bom, UTF32LEBOM) {
		return transform.NewReader(
			br,
			utf32.UTF32(utf32.LittleEndian, utf32.UseBOM).NewDecoder(),
		), true, nil
	} else if bytes.HasPrefix(bom, UTF32BEBOM) {
		return transform.NewReader(
			br,
			utf32.UTF32(utf32.BigEndian, utf32.UseBOM).NewDecoder(),
		), true, nil
	} else if bytes.HasPrefix(bom, UTF16LEBOM) {
		return transform.NewReader(
			br,
			unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder(),
		), true, nil
	} else if bytes.HasPrefix(bom, UTF16BEBOM) {
		return transform.NewReader(
			br,
			unicode.UTF16(unicode.BigEndian, unicode.UseBOM).NewDecoder(),
		), true, nil
	} else if bytes.HasPrefix(bom, UTF8BOM) {
		if _, err := br.Discard(len(UTF8BOM)); err != nil {
			return nil, false, errors.Wrap(
				err,
				"failed to consume the UTF-8 byte order mark",
			)
		}
		return br, true, nil
	}

	return br, false, nil
}

// ConvertMarkdownToUTF8 performs a best-effort detection of the encoding of
// the supplied reader and returns a Reader that is UTF-8 encoded.
func ConvertMarkdownToUTF8(r io.Reader) (io.Reader, error) {
	br, removed, err := removeBOM(r)
	if err != nil {
		// removeBOM already wrapped the error correctly.
		return nil, err
	}
	if removed {
		return NewLineEndingNormalizer(br), nil
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, br); err != nil {
		return nil, err
	}
	bytesReader := bytes.NewReader(buf.Bytes())

	// Is it already valid UTF-8?
	if utf8.Valid(buf.Bytes()) {
		return NewLineEndingNormalizer(bytesReader), nil
	}

	// There was no BOM and it wasn't valid UTF-8, so we'll need to detect the
	// encoding in another way.
	detector := chardet.NewTextDetector()
	if result, err := detector.DetectBest(buf.Bytes()); err == nil {
		enc, err := htmlindex.Get(result.Charset)
		if err == nil {
			return NewLineEndingNormalizer(
				transform.NewReader(bytesReader, unicode.BOMOverride(enc.NewDecoder())),
			), nil
		}
	}

	return NewLineEndingNormalizer(bytesReader), nil
}

// NormalizeCase performs a best-effort conversion to UTF-8 and normalizes the
// end-of-line characters.
func NormalizeCase(r io.Reader) (io.Reader, error) {
	br, _, err := removeBOM(r)
	if err != nil {
		// removeBOM already wrapped the error correctly.
		return nil, err
	}
	return NewLineEndingNormalizer(br), nil
}

// LineEndingNormalizer is an io.Reader that trims trailing whitespace and converts line endings to \n.
type LineEndingNormalizer struct {
	buf             bytes.Buffer
	outBuf          bytes.Buffer
	r               io.RuneScanner
	empty           bool
	endsWithNewline bool
	eof             bool
}

// NewLineEndingNormalizer returns a LineEndingNormalizer from the provided io.Reader.
func NewLineEndingNormalizer(rd io.Reader) *LineEndingNormalizer {
	var br io.RuneScanner
	var ok bool
	if br, ok = rd.(io.RuneScanner); !ok {
		br = bufio.NewReader(rd)
	}
	return &LineEndingNormalizer{
		r:     br,
		empty: true,
	}
}

// Read implements io.Reader.
func (n *LineEndingNormalizer) Read(p []byte) (int, error) {
	if n.eof {
		return 0, io.EOF
	}

	for n.outBuf.Len() == 0 {
		r, _, err := n.r.ReadRune()
		if err != nil {
			if err == io.EOF {
				n.eof = true
				// Unix non-empty files always end with a newline character.
				if !n.empty && !n.endsWithNewline {
					return utf8.EncodeRune(p, '\n'), nil
				}
			}
			return 0, err
		}
		n.empty = false

		switch r {
		case '\r':
			// Treat CRLF or an unaccompanied CR as an LF
			nextR, _, err := n.r.ReadRune()
			if err == nil {
				if nextR != '\n' {
					n.r.UnreadRune()
				}
			} else if err != nil {
				if err == io.EOF {
					n.eof = true
					// Unix files always end with a newline character.
					if !n.endsWithNewline {
						return utf8.EncodeRune(p, '\n'), nil
					}
				}
				return 0, err
			}
			fallthrough

		case '\n':
			// Discard any contents in the buffer, effectively trimming trailing
			// whitespace.
			n.endsWithNewline = true
			n.buf.Reset()
			n.outBuf.WriteRune('\n')

		case ' ', '\t', '\v', '\f', 0x85, 0xA0:
			// Accumulate all whitespace characters in the buffer.
			n.endsWithNewline = false
			n.buf.WriteRune(r)

		default:
			// A printable character. Write the buffer, reset it, and then write
			// the character.
			n.endsWithNewline = false
			if n.buf.Len() > 0 {
				io.Copy(&n.outBuf, &n.buf)
				n.buf.Reset()
			}
			n.outBuf.WriteRune(r)
		}
	}

	return n.outBuf.Read(p)
}
