package gobpfld

import "strings"

// CStrToString trims the string at the first null byte which is used in C to indicate the end of the string
func CStrToString(cstr string) string {
	nbi := strings.IndexByte(cstr, 0x00)
	if nbi != -1 {
		return cstr[:nbi]
	}
	return cstr
}

// CStrBytesToString converts bytes to string assuming it is a C string
func CStrBytesToString(b []byte) string {
	return CStrToString(string(b))
}

// StringToCStrBytes turns the string into a null terminated byte slice
func StringToCStrBytes(str string) []byte {
	return []byte(str + "\x00")
}
