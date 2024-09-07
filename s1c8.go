package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	openssl "github.com/golang-fips/openssl/v2"
)

func s1c8() {
	fmt.Println("> Set 1, Challenge 8: Detect AES in ECB mode")

	libcrypto := string("c:/users/luke/repo/openssl/libcrypto-3-x64.dll")
	err := openssl.Init(libcrypto)
	if err != nil {
		log.Fatal("Could not load openssl lib from ", libcrypto)
	}

	file, err := os.Open("s1c8.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var line int = 1
	for scanner.Scan() {
		data, err := hex.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}
		if aes_is_ecb_mode(data) {
			fmt.Printf("Detected AES encrypted string in ECB mode on line %d\n", line)
		}
		line++
	}
}
