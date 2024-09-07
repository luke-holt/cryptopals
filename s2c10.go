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
		log.Fatal("Could not load openssl lib from ", libcrypto)
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

	cipher, err := openssl.NewAESCipher(cipher_key)
	if err != nil {
		log.Fatal(err)
	}

	decrypted := make([]byte, len(base64_decoded_buffer))

	iv := make([]byte, AES_BLOCKLEN)
	for i := range int(len(base64_decoded_buffer) / AES_BLOCKLEN) {
		start := i * AES_BLOCKLEN
		end := min((i+1)*AES_BLOCKLEN, len(base64_decoded_buffer))

		ciphertext := base64_decoded_buffer[start:end]
		block := make([]byte, len(ciphertext))

		cipher.Decrypt(block, ciphertext)

		copy(decrypted[start:end], xor_cipher(block, iv))

		copy(iv, ciphertext)
	}

	fmt.Println(string(decrypted))
}
