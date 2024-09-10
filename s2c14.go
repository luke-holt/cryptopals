package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"

	openssl "github.com/golang-fips/openssl/v2"
)

func s2c14() {

	fmt.Println("> Set 2, Challenge 14: Byte-at-a-time ECB decryption (Harder)")

	libcrypto := string("c:/users/luke/repo/openssl/libcrypto-3-x64.dll")
	err := openssl.Init(libcrypto)
	if err != nil {
		log.Fatal(err)
	}

	base64_string := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\naGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\ndXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\nYnkK")
	unknown := make([]byte, base64.StdEncoding.DecodedLen(len(base64_string)))
	_, err = base64.StdEncoding.Decode(unknown, base64_string)
	if err != nil {
		log.Fatal(err)
	}

	oracle := func(bufs ...[]byte) ([]byte, error) {
		return aes_encrypt_ecb(concat(bufs...), ([AES_BLOCKLEN]byte)(rand_bytes(AES_BLOCKLEN)))
	}
	round_up_to_blocklen := func(buf []byte) int {
		return len(buf) + AES_BLOCKLEN - (len(buf) % AES_BLOCKLEN)
	}

	random_prefix := rand_bytes(27)
	prefix_rem := make([]byte, round_up_to_blocklen(random_prefix)-len(random_prefix))
	prefix_len := len(random_prefix) + len(prefix_rem)

	known := make([]byte, round_up_to_blocklen(unknown))
	window := make([]byte, AES_BLOCKLEN)
	buffer := make([]byte, AES_BLOCKLEN)
	offset := 0

	for i := range unknown {
		buf := buffer[offset%len(window) : len(window)-1]
		for j := range 256 {
			window[len(window)-1] = byte(j)
			enc, err := oracle(random_prefix, prefix_rem, window, buf, unknown)
			if err != nil {
				log.Fatal(err)
			}

			o := prefix_len
			a := enc[o:][AES_BLOCKLEN*0 : AES_BLOCKLEN*1]
			b := enc[o:][AES_BLOCKLEN*(1+i/AES_BLOCKLEN) : AES_BLOCKLEN*(2+i/AES_BLOCKLEN)]

			if bytes.Equal(a, b) {
				// match
				known[offset] = byte(j)
				offset++

				// shift bytes left
				copy(window[:len(window)-1], window[1:])
				break
			}
		}
	}

	fmt.Println(string(known))
}
