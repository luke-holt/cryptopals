package main

import "bytes"

func within(x, lower, upper int) bool {
	return (x <= upper) && (x >= lower)
}

func xor_cipher(raw []byte, key []byte) []byte {
	var encrypted []byte = make([]byte, len(raw))
	for i := range encrypted {
		encrypted[i] = raw[i] ^ key[i%len(key)]
	}
	return encrypted
}

func sanitize(s []byte) []byte {
	var out bytes.Buffer
	for _, char := range s {
		if within(int(char), int('A'), int('Z')) {
			out.WriteByte(byte(char) + (byte('a') - byte('A')))
		} else if char == byte(' ') {
			out.WriteByte(char)
		} else if !within(int(char), int('a'), int('z')) {
			out.WriteByte('.')
		} else {
			out.WriteByte(char)
		}
	}
	return out.Bytes()
}

func unknown_letter_rate(s []byte) float64 {
	letter_count := make(map[byte]int)
	san := sanitize(s)
	for _, char := range san {
		letter_count[char]++
	}
	return float64(letter_count[byte('.')]) / float64(len(san))
}

func solve_single_char_xor(encrypted []byte) (byte, float64) {
	var min_err float64 = 1.0
	var min_err_key byte
	key := make([]byte, 1)
	for i := range 256 {
		key[0] = byte(i)
		decoded := xor_cipher(encrypted, key)
		err := unknown_letter_rate(decoded)
		if err <= min_err {
			min_err = err
			min_err_key = key[0]
		}
	}
	return min_err_key, min_err
}
