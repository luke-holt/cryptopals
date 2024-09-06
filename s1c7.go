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
		log.Fatal("Could not load openssl lib from ", libcrypto)
	}

	cipher, err := openssl.NewAESCipher(cipher_key)
	if err != nil {
		log.Fatal(err)
	}

	var decrypted []byte = make([]byte, len(base64_decoded_buffer))
	cipher.Decrypt(decrypted, base64_decoded_buffer)

	var solution []byte = make([]byte, 0)
	var zeroes int
	for _, b := range decrypted {
		if b == 0 {
			zeroes++
		} else {
			solution = append(solution, b)
		}
	}
	fmt.Printf("Solution: \"%s\", followed by %d zeroes (\"black\")\n", solution, zeroes)
}
