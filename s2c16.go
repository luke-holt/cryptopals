package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/golang-fips/openssl/v2"
)

func s2c16() {

	fmt.Println("> Set 2, Challenge 16: CBC bitflipping attacks")

	libcrypto := string("c:/users/luke/repo/openssl/libcrypto-3-x64.dll")
	err := openssl.Init(libcrypto)
	if err != nil {
		log.Fatal(err)
	}

	prefix := []byte("comment1=cooking%20MCs;userdata=")
	postfix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	userin := []byte("yikes.admin.true")
	unencrypted := concat(prefix, userin, postfix)

	key := [AES_BLOCKLEN]byte(rand_bytes(AES_BLOCKLEN))
	iv := [AES_BLOCKLEN]byte{}
	encrypted, err := aes_encrypt_cbc(unencrypted, key, iv)
	if err != nil {
		log.Fatal(err)
	}

	encrypted[0x15] ^= '.' ^ ';'
	encrypted[0x1b] ^= '.' ^ '='

	decrypted, err := aes_decrypt_cbc(encrypted, key, iv)
	if err != nil {
		log.Fatal(err)
	}

	admin := []byte(";admin=true;")
	if bytes.Contains(decrypted, admin) {
		fmt.Printf("Decrypted data contains \"%s\"\n", admin)
	}
}
