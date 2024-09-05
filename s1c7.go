package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	openssl "github.com/golang-fips/openssl/v2"
)

func s1c7() {
	fmt.Println("Set 1, Challenge 7: AES in ECB mode")

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

	exists, _ := openssl.CheckVersion("latest")
	if !exists {
		log.Fatal("Cannot load OpenSSL version latest")
	}

	cipher, err := openssl.NewAESCipher(cipher_key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cipher)
}
