package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"

	openssl "github.com/golang-fips/openssl/v2"
)

const AES_BLOCKLEN int = 16

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

func sanitize(s []byte) string {
	var b bytes.Buffer
	for _, char := range s {
		if within(int(char), int(' '), int('~')) {
			b.WriteByte(char)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

func unknown_letter_rate(s []byte) float64 {
	letter_norm := func(s []byte) []byte {
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

	letter_count := make(map[byte]int)
	san := letter_norm(s)
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

func pkcs7_trim(padded []byte) []byte {
	return padded[:len(padded)-int(padded[len(padded)-1])]
}

func pkcs7_pad(src []byte, blocklen byte) []byte {
	pad := blocklen - byte(len(src)%int(blocklen))
	padded := make([]byte, len(src)+int(pad))
	copy(padded, src)
	for i := range int(pad) {
		padded[len(src)+i] = pad
	}
	return padded
}

func aes_is_ecb_mode(data []byte) bool {
	m := make(map[string]bool)
	for i := range len(data) / AES_BLOCKLEN {
		start := i * AES_BLOCKLEN
		end := (i + 1) * AES_BLOCKLEN
		block := string(data[start:end])
		if m[block] {
			return true
		}
		m[block] = true
	}
	return false
}

func aes_decrypt_ecb(encrypted []byte, key [AES_BLOCKLEN]byte) ([]byte, error) {
	unencrypted := make([]byte, len(encrypted))
	cipher, err := openssl.NewAESCipher(key[:])
	if err != nil {
		return nil, err
	}
	for i := range int(len(encrypted) / AES_BLOCKLEN) {
		start := i * AES_BLOCKLEN
		end := (i + 1) * AES_BLOCKLEN
		cipher.Decrypt(unencrypted[start:end], encrypted[start:end])
	}
	return pkcs7_trim(unencrypted), nil
}

func aes_encrypt_ecb(data []byte, key [AES_BLOCKLEN]byte) ([]byte, error) {
	unencrypted := pkcs7_pad(data, byte(AES_BLOCKLEN))
	encrypted := make([]byte, len(unencrypted))

	cipher, err := openssl.NewAESCipher(key[:])
	if err != nil {
		return nil, err
	}

	for i := range int(len(unencrypted) / AES_BLOCKLEN) {
		start := i * AES_BLOCKLEN
		end := (i + 1) * AES_BLOCKLEN
		cipher.Encrypt(encrypted[start:end], unencrypted[start:end])
	}

	return encrypted, nil
}

func aes_encrypt_cbc(data []byte, key, iv [AES_BLOCKLEN]byte) ([]byte, error) {
	unencrypted := pkcs7_pad(data, byte(AES_BLOCKLEN))
	encrypted := make([]byte, len(unencrypted))
	ciphertext := make([]byte, AES_BLOCKLEN)

	copy(ciphertext, iv[:])

	cipher, err := openssl.NewAESCipher(key[:])
	if err != nil {
		return nil, err
	}

	for i := range int(len(unencrypted) / AES_BLOCKLEN) {
		start := i * AES_BLOCKLEN
		end := (i + 1) * AES_BLOCKLEN
		cipher.Encrypt(encrypted[start:end], xor_cipher(unencrypted[start:end], ciphertext))
		copy(ciphertext, encrypted[start:end])
	}

	return encrypted, nil
}

func rand_bytes(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(rand.Int() % 256)
	}
	return b
}

func concat(strs ...[]byte) []byte {
	var size int
	for i := range strs {
		size += len(strs[i])
	}
	x := make([]byte, size)
	var offset int
	for i := range strs {
		copy(x[offset:offset+len(strs[i])], strs[i])
		offset += len(strs[i])
	}
	return x
}

func memset(data *[]byte, val byte) {
	for i := range *data {
		(*data)[i] = val
	}
}

func hexdump(data []byte, blocklen int) {
	var sb strings.Builder
	for i := range data {
		if i%blocklen == 0 && i != 0 {
			fmt.Fprintf(&sb, "\n")
		}
		if i%blocklen == 0 {
			fmt.Fprintf(&sb, "%04x    ", i)
		}
		fmt.Fprintf(&sb, "%02x ", data[i])
		if (i+1)%blocklen == 0 {
			fmt.Fprintf(&sb, "   %s", sanitize(data[i+1-blocklen:i+1]))
		}
	}
	rem := len(data) % blocklen
	if rem != 0 {
		space := make([]byte, (blocklen-rem)*3)
		memset(&space, byte(' '))
		fmt.Fprintf(&sb, "%s   %s", space, sanitize(data[len(data)-rem:]))
	}
	fmt.Println(sb.String())
}
