package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	openssl "github.com/golang-fips/openssl/v2"
)

func s2c10() {
	fmt.Println("> Set 2, Challenge 10: Implement CBC mode")

	libcrypto := string("c:/users/luke/repo/openssl/libcrypto-3-x64.dll")
	err := openssl.Init(libcrypto)
	if err != nil {
		log.Fatal(err)
	}

	file_buffer, err := os.ReadFile("s2c10.txt")
	if err != nil {
		log.Fatal(err)
	}

	base64_decoded_buffer := make([]byte, base64.StdEncoding.DecodedLen(len(file_buffer)))
	_, err = base64.StdEncoding.Decode(base64_decoded_buffer, file_buffer)
	if err != nil {
		log.Fatal(err)
	}

	cipher_key := []byte("YELLOW SUBMARINE")

	iv := [AES_BLOCKLEN]byte{}
	decrypted, err := aes_decrypt_cbc(base64_decoded_buffer, [AES_BLOCKLEN]byte(cipher_key), iv)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(decrypted))
}
