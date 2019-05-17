package gitservertest

import (
	"archive/zip"
	"bytes"
	"io"
)

const (
	// DefaultSettingsJSON is the JSON representation of a problem with just one
	// case called "0".
	DefaultSettingsJSON = `{
	"Cases": [
		{
			"Cases": [
				{
					"Name": "0",
					"Weight": 1
				}
			],
			"Name": "0"
		}
	],
	"Limits": {
		"ExtraWallTime": "0s",
		"MemoryLimit": 33554432,
		"OutputLimit": 10240,
		"OverallWallTimeLimit": "1m0s",
		"TimeLimit": "1s"
	},
	"Slow": false,
	"Validator": {
		"Name": "token-caseless"
	}
}
`

	// CustomValidatorSettingsJSON is the JSON representation of a problem with
	// just one case called "0" and a custom validator.
	CustomValidatorSettingsJSON = `{
	"Cases": [
		{
			"Cases": [
				{
					"Name": "0",
					"Weight": 1
				}
			],
			"Name": "0"
		}
	],
	"Limits": {
		"ExtraWallTime": "0s",
		"MemoryLimit": 33554432,
		"OutputLimit": 10240,
		"OverallWallTimeLimit": "1m0s",
		"TimeLimit": "1s"
	},
	"Slow": false,
	"Validator": {
		"Name": "custom"
	}
}
`
)

// CreateZip creates a .zip file from the given file contents.
func CreateZip(
	contents map[string]io.Reader,
) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for filename, r := range contents {
		f, err := w.Create(filename)
		if err != nil {
			return nil, err
		}
		if _, err = io.Copy(f, r); err != nil {
			return nil, err
		}
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
