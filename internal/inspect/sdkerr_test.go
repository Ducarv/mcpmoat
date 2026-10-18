package inspect

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
)

// TestCommandError checks that each sentinel of stdioCommand maps to the
// sentinel of the error contract of Inspector, and keeps the original one.
func TestCommandError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err  error
		want error
	}{
		{errNotStdio, ErrUnsupportedTransport},
		{errUntrusted, ErrUntrusted},
		{errEmptyCommand, ErrInvalidServer},
		{errInvalidArg, ErrInvalidServer},
		{errInvalidEnvName, ErrInvalidServer},
		{errInvalidEnvValue, ErrInvalidServer},
		{errRelativeCommand, ErrInvalidServer},
		{errCommandNotFound, ErrStart},
		{errCommandNotRunnable, ErrStart},
		{errNoWorkDir, ErrStart},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			t.Parallel()
			got := commandError(tt.err)
			if !errors.Is(got, tt.want) || !errors.Is(got, tt.err) {
				t.Errorf("commandError(%v) = %v, want errors.Is %v and %v", tt.err, got, tt.want, tt.err)
			}
		})
	}
}

// TestStartError checks that startError wraps ErrStart, keeps only the class
// of the error of cmd.Start, and never holds its path, which is untrusted
// config text.
func TestStartError(t *testing.T) {
	t.Parallel()

	const path = "/srv/\x1b[31mmcpmoat-start-marker"
	tests := []struct {
		name      string
		err       error
		wantClass error // nil means no class
	}{
		{"missing command", &os.PathError{Op: "fork/exec", Path: path, Err: syscall.ENOENT}, fs.ErrNotExist},
		{"missing work directory", &os.PathError{Op: "chdir", Path: path, Err: syscall.ENOENT}, fs.ErrNotExist},
		{"no permission", &os.PathError{Op: "fork/exec", Path: path, Err: syscall.EACCES}, fs.ErrPermission},
		{"other error", &os.PathError{Op: "fork/exec", Path: path, Err: syscall.E2BIG}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := startError(t.Context(), tt.err)
			if !errors.Is(got, ErrStart) {
				t.Errorf("startError() = %v, want errors.Is ErrStart", got)
			}
			if tt.wantClass != nil && !errors.Is(got, tt.wantClass) {
				t.Errorf("startError() = %v, want errors.Is %v", got, tt.wantClass)
			}
			if strings.Contains(got.Error(), "mcpmoat-start-marker") || strings.ContainsRune(got.Error(), 0x1b) {
				t.Errorf("startError() text %q holds the path of the start error", got)
			}
		})
	}

	t.Run("ctx done", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		got := startError(ctx, &os.PathError{Op: "fork/exec", Path: path, Err: syscall.ENOENT})
		if !errors.Is(got, ErrStart) || !errors.Is(got, context.Canceled) {
			t.Errorf("startError() = %v, want errors.Is ErrStart and context.Canceled", got)
		}
	})
}
