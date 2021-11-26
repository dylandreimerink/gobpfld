package cstr

import "strings"

// ToString trims the string at the first null byte which is used in C to indicate the end of the string
func ToString(cstr string) string {
	nbi := strings.IndexByte(cstr, 0x00)
	if nbi != -1 {
		return cstr[:nbi]
	}
	return cstr
}

// BytesToString converts bytes to string assuming it is a C string
func BytesToString(b []byte) string {
	return ToString(string(b))
}

// StringToCStrBytes turns the string into a null terminated byte slice
func StringToCStrBytes(str string) []byte {
	return []byte(str + "\x00")
}
