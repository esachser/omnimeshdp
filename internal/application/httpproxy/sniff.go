package httpproxy

import (
	"bytes"
	"strings"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// H2Preface is the 24-byte HTTP/2 prior-knowledge connection preface (RFC 9113 Section 3.4).
var H2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// classifyPrefix inspects an accumulated byte prefix and reports the detected protocol
// along with whether classification is final (decided == true) or needs more bytes.
func classifyPrefix(buf []byte, maxBytes int, eof bool) (model.HTTPProtocol, bool) {
	if len(buf) == 0 {
		if eof {
			return model.ProtocolTCP, true
		}
		return "", false
	}

	// Fast-fail TLS handshake records (0x16) and any non-uppercase-letter starting byte.
	if buf[0] == 0x16 || !isUpperAlpha(buf[0]) {
		return model.ProtocolTCP, true
	}

	// Check HTTP/2 prior-knowledge preface.
	if len(buf) < len(H2Preface) {
		if bytes.Equal(buf, H2Preface[:len(buf)]) {
			if eof {
				return model.ProtocolTCP, true
			}
			return "", false
		}
	} else if bytes.Equal(buf[:len(H2Preface)], H2Preface) {
		return model.ProtocolHTTP2, true
	}

	// Inspect HTTP/1.x request-line prefix up to the first CRLF.
	nlIdx := bytes.IndexByte(buf, '\n')
	if nlIdx == -1 {
		if !validPartialRequestLine(buf) || eof || len(buf) >= maxBytes {
			return model.ProtocolTCP, true
		}
		return "", false
	}

	if nlIdx == 0 || buf[nlIdx-1] != '\r' {
		return model.ProtocolTCP, true
	}
	line := string(buf[:nlIdx-1])
	if isValidHTTP1RequestLine(line) {
		return model.ProtocolHTTP1, true
	}
	return model.ProtocolTCP, true
}

func validPartialRequestLine(buf []byte) bool {
	spaceCount := 0
	methodLen := 0
	for i, b := range buf {
		if b == 0x00 || b == 0x7f || (b < 0x20 && b != '\r') {
			return false
		}
		if b == '\r' && i+1 < len(buf) && buf[i+1] != '\n' {
			return false
		}
		if b == ' ' {
			if spaceCount == 0 && methodLen == 0 {
				return false
			}
			spaceCount++
			if spaceCount > 2 {
				return false
			}
			continue
		}
		if spaceCount == 0 {
			methodLen++
			if methodLen > 16 || !isMethodChar(b) {
				return false
			}
		}
	}
	return true
}

func isValidHTTP1RequestLine(line string) bool {
	method, rest, ok := strings.Cut(line, " ")
	if !ok || !isValidMethod(method) {
		return false
	}
	target, version, ok := strings.Cut(rest, " ")
	if !ok || len(target) == 0 || strings.ContainsRune(target, ' ') {
		return false
	}
	for i := 0; i < len(target); i++ {
		if isUnsafeControl(target[i]) {
			return false
		}
	}
	return version == "HTTP/1.1" || version == "HTTP/1.0"
}

func isValidMethod(method string) bool {
	if len(method) == 0 || len(method) > 16 || !isUpperAlpha(method[0]) {
		return false
	}
	for i := 1; i < len(method); i++ {
		if !isMethodChar(method[i]) {
			return false
		}
	}
	return true
}

func isUpperAlpha(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

func isMethodChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

func isUnsafeControl(b byte) bool {
	return b < 0x20 || b == 0x7f
}
