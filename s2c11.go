package main

import (
	"fmt"
	"log"
	"math/rand"

	openssl "github.com/golang-fips/openssl/v2"
)

func rand_bytes(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(rand.Int() % 256)
	}
	return b
}

func aes_encrypt_ecb(data []byte, key [AES_BLOCKLEN]byte) ([]byte, error) {
	unencrypted := pkcs7_padding(data, byte(AES_BLOCKLEN))
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
	unencrypted := pkcs7_padding(data, byte(AES_BLOCKLEN))
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

func encryption_oracle(raw []byte) ([]byte, error) {
	// 5-10 bytes before and after
	before := 5 + rand.Int()%6
	after := 5 + rand.Int()%6

	unencrypted := make([]byte, before+after+len(raw))

	copy(unencrypted[:before], rand_bytes(before))
	copy(unencrypted[before:before+len(raw)], raw)
	copy(unencrypted[before+len(raw):], rand_bytes(after))

	key := rand_bytes(AES_BLOCKLEN)

	if rand.Int()%2 == 1 {
		// ecb
		fmt.Print("expected(ecb)")
		return aes_encrypt_ecb(unencrypted, ([AES_BLOCKLEN]byte)(key))
	} else {
		// cbc
		fmt.Print("expected(cbc)")
		iv := rand_bytes(AES_BLOCKLEN)
		return aes_encrypt_cbc(unencrypted, ([AES_BLOCKLEN]byte)(key), ([AES_BLOCKLEN]byte)(iv))
	}
}

func s2c11() {

	fmt.Println("> Set 2, Challenge 11: An ECB/CBC detection oracle")

	libcrypto := string("c:/users/luke/repo/openssl/libcrypto-3-x64.dll")
	err := openssl.Init(libcrypto)
	if err != nil {
		log.Fatal("Could not load openssl lib from ", libcrypto)
	}

	text := []byte("OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO")

	for range 10 {
		encrypted, err := encryption_oracle(text)
		if err != nil {
			log.Fatal(err)
		}

		if aes_is_ecb_mode(encrypted) {
			// ecb
			fmt.Println(" == actual(ecb)")
		} else {
			// cbc
			fmt.Println(" == actual(cbc)")
		}
	}
}
