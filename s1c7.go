package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	openssl "github.com/golang-fips/openssl/v2"
)

func s1c7() {
	fmt.Println("> Set 1, Challenge 7: AES in ECB mode")

	file_buffer, err := os.ReadFile("s1c7.txt")
	if err != nil {
		log.Fatal(err)
	}

	base64_decoded_buffer := make([]byte, base64.StdEncoding.DecodedLen(len(file_buffer)))
	_, err = base64.StdEncoding.Decode(base64_decoded_buffer, file_buffer)
	if err != nil {
		log.Fatal(err)
	}

	var cipher_key []byte = []byte("YELLOW SUBMARINE")

	libcrypto := string("c:/users/luke/repo/openssl/libcrypto-3-x64.dll")
	err = openssl.Init(libcrypto)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := aes_decrypt_ecb(base64_decoded_buffer, [AES_BLOCKLEN]byte(cipher_key))
	if err != nil {
		log.Fatal()
	}

	fmt.Println(string(decrypted))
}
