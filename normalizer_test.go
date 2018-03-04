package gitserver

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestConvertMarkdownToUTF8(t *testing.T) {
	cases := []struct {
		encoded []byte
		decoded string
	}{
		// UTF-8 BOM
		{[]byte{0xEF, 0xBB, 0xBF, 0xC3, 0xA9}, "é\n"},
		// UTF-16 (LE) BOM
		{[]byte{0xFF, 0xFE, 0xE9, 0x00}, "é\n"},
		// UTF-16 (BE) BOM
		{[]byte{0xFE, 0xFF, 0x00, 0xE9}, "é\n"},
		// UTF-32 (LE) BOM
		{[]byte{0xFF, 0xFE, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00}, "é\n"},
		// UTF-32 (BE) BOM
		{[]byte{0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0xE9}, "é\n"},
		// UTF-8 (no BOM)
		{[]byte{0xC3, 0xA9}, "é\n"},
		// Latin-1 (ISO-8859-1)
		{[]byte{0x50, 0x6F, 0x6B, 0xE9, 0x6D, 0x6F, 0x6E}, "Pokémon\n"},
		// Empty
		{[]byte{}, "\n"},
	}

	for _, c := range cases {
		r, err := ConvertMarkdownToUTF8(bytes.NewReader(c.encoded))
		if err != nil {
			t.Errorf(
				"error converting %q to UTF-8: %q",
				c,
				err,
			)
		} else {
			contents, err := ioutil.ReadAll(r)
			if err != nil {
				t.Errorf(
					"error reading UTF-8 contents: %q",
					err,
				)
			} else if c.decoded != string(contents) {
				t.Errorf(
					"conversion error for case %q. Expected %q, got %q",
					c,
					c.decoded,
					string(contents),
				)
			}
		}
	}
}

func TestNormalizeCase(t *testing.T) {
	cases := []struct {
		input  []byte
		output string
	}{
		// leading whitespace
		{[]byte{0x20, 0x78}, " x\n"},
		// trailing whitespace
		{[]byte{0x78, 0x20}, "x\n"},
		// CRLF
		{[]byte{0x78, 0x0D, 0x0A, 0x78}, "x\nx\n"},
		// CR
		{[]byte{0x78, 0x0D, 0x78}, "x\nx\n"},
		// LR
		{[]byte{0x78, 0x0A, 0x78}, "x\nx\n"},
		// LR
		{[]byte{0x78, 0x0A, 0x20}, "x\n\n"},
		// UTF16-LE BOM
		{[]byte{0xFF, 0xFE, 0x78, 0x00}, "x\n"},
	}

	for _, c := range cases {
		r, err := NormalizeCase(bytes.NewReader(c.input))
		if err != nil {
			t.Errorf(
				"error converting to UTF-8: %q",
				err,
			)
		} else {
			contents, err := ioutil.ReadAll(r)
			if err != nil {
				t.Errorf(
					"error normalizing: %q",
					err,
				)
			} else if c.output != string(contents) {
				t.Errorf(
					"normalizer error for case %q. Expected %q, got %q",
					c,
					c.output,
					string(contents),
				)
			}
		}
	}
}
