package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"

	openssl "github.com/golang-fips/openssl/v2"
)

func oracle(mine, unknown []byte) ([]byte, error) {
	return aes_encrypt_ecb(concat(mine, unknown), ([AES_BLOCKLEN]byte)(rand_bytes(AES_BLOCKLEN)))
}

func s2c12() {

	fmt.Println("> Set 2, Challenge 12: Byte-at-a-time ECB decryption (Simple)")

	libcrypto := string("c:/users/luke/repo/openssl/libcrypto-3-x64.dll")
	err := openssl.Init(libcrypto)
	if err != nil {
		log.Fatal("Could not load openssl lib from ", libcrypto)
	}

	base64_string := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\naGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\ndXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\nYnkK")
	unknown := make([]byte, base64.StdEncoding.DecodedLen(len(base64_string)))
	_, err = base64.StdEncoding.Decode(unknown, base64_string)
	if err != nil {
		log.Fatal(err)
	}

	// find blocklen
	var blocklen int
	var prev_len int = 0
	for i := range AES_BLOCKLEN {
		mine := make([]byte, i)
		memset(&mine, byte('A'))

		enc, err := oracle(mine, unknown)
		if err != nil {
			log.Fatal(err)
		}

		if prev_len > 0 && prev_len < len(enc) {
			blocklen = len(enc) - prev_len
			break
		}
		prev_len = len(enc)
	}
	fmt.Println("Blocklen:", blocklen)

	// verify that aes cipher mode is ecb
	tmp := make([]byte, blocklen*4+1)
	ecb_mode_test_str := concat(tmp, unknown)
	encrypted, err := aes_encrypt_ecb(ecb_mode_test_str, ([AES_BLOCKLEN]byte)(rand_bytes(AES_BLOCKLEN)))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ECB mode:", aes_is_ecb_mode(encrypted))

	// find first and second character of unknown string
	var first_char byte
	var second_char byte

	buf := make([]byte, blocklen*2-1)
	for i := range 256 {
		buf[blocklen-1] = byte(i)
		enc, err := oracle(buf, unknown)
		if err != nil {
			log.Fatal(err)
		}

		if bytes.Equal(enc[:AES_BLOCKLEN], enc[AES_BLOCKLEN:AES_BLOCKLEN*2]) {
			first_char = byte(i)
			break
		}
	}

	buf = make([]byte, blocklen*2-2)
	buf[blocklen-2] = first_char
	for i := range 256 {
		buf[blocklen-1] = byte(i)
		enc, err := oracle(buf, unknown)
		if err != nil {
			log.Fatal(err)
		}

		if bytes.Equal(enc[:AES_BLOCKLEN], enc[AES_BLOCKLEN:AES_BLOCKLEN*2]) {
			second_char = byte(i)
			break
		}
	}

	fmt.Println("First character:", string(byte(first_char)))
	fmt.Println("Second character:", string(byte(second_char)))

}
