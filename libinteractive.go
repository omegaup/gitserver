package gitserver

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"

	"github.com/omegaup/go-base/v3/logging"
	"github.com/omegaup/quark/common"

	"github.com/pkg/errors"
)

// InteractiveSettingsCompiler converts the .idl file contents and the module
// name + parent language pair into a common.InteractiveSettings object.
type InteractiveSettingsCompiler interface {
	// GetInteractiveSettings converts the .idl file contents and the module name
	// + parent language pair into a common.InteractiveSettings object.
	GetInteractiveSettings(
		idlFileContents io.Reader,
		moduleName string,
		parentLang string,
	) (*common.InteractiveSettings, error)
}

// LibinteractiveCompiler is an implementation of
// InteractiveSettingsCompiler that uses the real libinteractive.jar to convert
// the .idl file.
type LibinteractiveCompiler struct {
	// A way to optionally override the path of libinteractive.jar.
	LibinteractiveJarPath string
	Log                   logging.Logger
}

// GetInteractiveSettings calls libinteractive.jar to produce the
// common.InteractiveSettings.
func (c *LibinteractiveCompiler) GetInteractiveSettings(
	contents io.Reader,
	moduleName string,
	parentLang string,
) (*common.InteractiveSettings, error) {
	libinteractiveJarPath := "/usr/share/java/libinteractive.jar"
	if c.LibinteractiveJarPath != "" {
		libinteractiveJarPath = c.LibinteractiveJarPath
	}
	cmd := exec.Command(
		"/usr/bin/java",
		"-jar", libinteractiveJarPath,
		"json",
		"--module-name", moduleName,
		"--parent-lang", parentLang,
		"--omit-debug-targets",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to get stdin path",
		)
	}
	stdinErrChan := make(chan error, 1)
	go (func() {
		defer stdin.Close()
		if _, err := io.Copy(stdin, contents); err != nil {
			c.Log.Error(
				"Failed to write to libinteractive",
				map[string]interface{}{
					"cmd": cmd,
					"err": err,
				},
			)
			stdinErrChan <- err
		}
		close(stdinErrChan)
	})()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to get stdout path",
		)
	}
	settingsChan := make(chan *common.InteractiveSettings, 1)
	go (func() {
		var settings common.InteractiveSettings
		if err := json.NewDecoder(stdout).Decode(&settings); err != nil {
			c.Log.Error(
				"Failed to read from libinteractive",
				map[string]interface{}{
					"cmd": cmd,
					"err": err,
				},
			)
			settingsChan <- nil
		} else {
			settingsChan <- &settings
		}
		close(settingsChan)
	})()

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to get stderr pipe",
		)
	}
	stderrChan := make(chan *bytes.Buffer, 1)
	go (func() {
		var buffer bytes.Buffer
		if _, err := io.Copy(&buffer, stderr); err != nil {
			c.Log.Error(
				"Failed to copy libinteractive stderr",
				map[string]interface{}{
					"cmd": cmd,
					"err": err,
				},
			)
		}
		stderrChan <- &buffer
		close(stderrChan)
	})()

	if err := cmd.Run(); err != nil {
		stderrError := errors.New((<-stderrChan).String())
		c.Log.Error(
			"Failed to run command",
			map[string]interface{}{
				"cmd":    cmd,
				"err":    err,
				"stderr": stderrError,
			},
		)
		return nil, errors.Wrap(
			stderrError,
			"libinteractive compile error",
		)
	}

	if err, ok := <-stdinErrChan; ok {
		return nil, errors.Wrap(
			err,
			"failed to send input to libinteractive",
		)
	}
	return <-settingsChan, nil
}

// FakeInteractiveSettingsCompiler is an implementation of
// InteractiveSettingsCompiler that just returns pre-specified settings.
type FakeInteractiveSettingsCompiler struct {
	Settings *common.InteractiveSettings
	Err      error
}

// GetInteractiveSettings returns the pre-specified settings.
func (c *FakeInteractiveSettingsCompiler) GetInteractiveSettings(
	contents io.Reader,
	moduleName string,
	parentLang string,
) (*common.InteractiveSettings, error) {
	return c.Settings, c.Err
}
