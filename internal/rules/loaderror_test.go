package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

var errSentinel = errors.New("sentinel")

func TestLoadErrorMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *LoadError
		want string
	}{
		{
			name: "too many errors note",
			err:  newLoadError("a.yaml", ReasonTooManyErrors).wrap(errors.New("5 more errors not shown")),
			want: "a.yaml: too many errors: 5 more errors not shown",
		},
		{
			name: "file and reason only",
			err:  newLoadError("rules/a.yaml", ReasonEmptyFile),
			want: "rules/a.yaml: file is empty",
		},
		{
			name: "line only",
			err:  newLoadError("a.yaml", ReasonInvalidYAML).at(3, 0),
			want: "a.yaml:3: invalid YAML",
		},
		{
			name: "line and column",
			err:  newLoadError("a.yaml", ReasonInvalidYAML).at(3, 7),
			want: "a.yaml:3:7: invalid YAML",
		},
		{
			name: "column without line is omitted",
			err:  newLoadError("a.yaml", ReasonInvalidYAML).at(0, 7),
			want: "a.yaml: invalid YAML",
		},
		{
			name: "field",
			err:  newLoadError("a.yaml", ReasonMissingField).inField("id"),
			want: "a.yaml: field id: missing required field",
		},
		{
			name: "position and field",
			err:  newLoadError("a.yaml", ReasonUnknownField).at(4, 2).inField("sevrity"),
			want: "a.yaml:4:2: field sevrity: unknown field",
		},
		{
			name: "position, field and wrapped error",
			err:  newLoadError("a.yaml", ReasonInvalidValue).at(5, 1).inField("severity").wrap(errSentinel),
			want: "a.yaml:5:1: field severity: invalid value: sentinel",
		},
		{
			name: "wrapped error only",
			err:  newLoadError("a.yaml", ReasonUnreadable).wrap(errSentinel),
			want: "a.yaml: cannot read file: sentinel",
		},
		{
			name: "path error drops the untrusted path",
			err: newLoadError("a.yaml", ReasonUnreadable).wrap(
				&fs.PathError{Op: "open", Path: "/x/\x1b[31mevil", Err: fs.ErrPermission}),
			want: "a.yaml: cannot read file: open: permission denied",
		},
		{
			name: "nil receiver does not panic",
			err:  nil,
			want: "<nil>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadErrorEscapesUntrustedText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *LoadError
		want string
	}{
		{
			name: "ESC in file name",
			err:  newLoadError("a\x1b[31m.yaml", ReasonEmptyFile),
			want: `"a\x1b[31m.yaml": file is empty`,
		},
		{
			name: "newline in file name",
			err:  newLoadError("a\nb.yaml", ReasonEmptyFile),
			want: `"a\nb.yaml": file is empty`,
		},
		{
			name: "ESC in field name",
			err:  newLoadError("a.yaml", ReasonUnknownField).inField("x\x1b[31my"),
			want: `a.yaml: field "x\x1b[31my": unknown field`,
		},
		{
			name: "newline in field name",
			err:  newLoadError("a.yaml", ReasonUnknownField).inField("x\ny"),
			want: `a.yaml: field "x\ny": unknown field`,
		},
		{
			name: "ESC and newline in wrapped error",
			err:  newLoadError("a.yaml", ReasonInvalidYAML).wrap(errors.New("bad\x1b[31m\nline")),
			want: `a.yaml: invalid YAML: "bad\x1b[31m\nline"`,
		},
		{
			name: "C1 and bidi runes in file, field and wrapped error",
			err: newLoadError("a\u009bb\u202ec.yaml", ReasonUnknownField).at(2, 1).inField("x\u009by\u202ez").
				wrap(errors.New("w\u009b\u202e\u200b\u2066\u2028")),
			want: `"a\u009bb\u202ec.yaml":2:1: field "x\u009by\u202ez": unknown field: "w\u009b\u202e\u200b\u2066\u2028"`,
		},
		{
			name: "long field name is cut",
			err:  newLoadError("a.yaml", ReasonValueTooLong).inField(strings.Repeat("f", 300)),
			want: "a.yaml: field " + strings.Repeat("f", maxDisplayRunes) + "...: value is too long",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
			noRawControls(t, got)
		})
	}
}

func TestLoadErrorUnwrap(t *testing.T) {
	t.Parallel()

	le := newLoadError("a.yaml", ReasonUnreadable).wrap(fmt.Errorf("read: %w", errSentinel))
	// Wrap the LoadError again, as a caller that adds context would.
	err := fmt.Errorf("load rules: %w", le)

	if !errors.Is(err, errSentinel) {
		t.Error("errors.Is(err, errSentinel) = false, want true")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Error("errors.Is(err, fs.ErrNotExist) = true, want false")
	}

	got, ok := errors.AsType[*LoadError](err)
	if !ok {
		t.Fatal("errors.AsType[*LoadError](err) = false, want true")
	}
	if got != le {
		t.Errorf("AsType returned %p, want %p", got, le)
	}
	if got.Reason != ReasonUnreadable {
		t.Errorf("Reason = %q, want %q", got.Reason, ReasonUnreadable)
	}

	if (*LoadError)(nil).Unwrap() != nil {
		t.Error("nil receiver Unwrap() != nil")
	}
	if newLoadError("a.yaml", ReasonEmptyFile).Unwrap() != nil {
		t.Error("Unwrap() of an error without Err != nil")
	}
}
