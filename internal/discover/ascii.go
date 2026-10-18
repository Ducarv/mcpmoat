package discover

// isLower reports whether c is an ASCII lower-case letter.
func isLower(c byte) bool {
	return 'a' <= c && c <= 'z'
}

// isUpper reports whether c is an ASCII upper-case letter.
func isUpper(c byte) bool {
	return 'A' <= c && c <= 'Z'
}

// isLetter reports whether c is an ASCII letter, a-z or A-Z.
func isLetter(c byte) bool {
	return isLower(c) || isUpper(c)
}

// isDigit reports whether c is an ASCII digit, 0-9.
func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// isHexDigit reports whether c is 0-9, a-f or A-F.
func isHexDigit(c byte) bool {
	return isDigit(c) || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// isAlnum reports whether c is an ASCII letter or digit.
func isAlnum(c byte) bool {
	return isLetter(c) || isDigit(c)
}

// isPrintable reports whether c is printable ASCII, 0x20 (space) to 0x7e
// ("~"). Control bytes (below 0x20, and 0x7f) and non-ASCII bytes (0x80 and
// up) are not printable.
func isPrintable(c byte) bool {
	return 0x20 <= c && c <= 0x7e
}

// isASCII reports whether every byte of s is below 0x80.
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
