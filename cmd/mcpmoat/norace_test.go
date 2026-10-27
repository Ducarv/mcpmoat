//go:build !race

package main

// raceEnabled is false: the test binary is built without -race.
const raceEnabled = false
