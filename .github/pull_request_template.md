## Summary

<!-- What changed and why. -->

Closes #

## PRD references

<!-- For example FR-09, NFR-05, T1. -->

## Testing

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `golangci-lint run`
- [ ] `gofmt -l .` prints nothing

## Checklist

- [ ] New rules have `should_match` and `should_not_match` cases
- [ ] No new network calls, telemetry or unneeded dependencies
- [ ] No secrets in output, logs, fixtures or test data
- [ ] Docs updated if behaviour or flags changed
