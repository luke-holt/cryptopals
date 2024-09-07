package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	openssl "github.com/golang-fips/openssl/v2"
)

func repeating_blocks(data []byte) int {
	const block_len int = 16
	var blocks int = len(data) / block_len
	var same int
	for i := range blocks {
		cur := data[i*block_len : (i+1)*block_len]
		for j := i + 1; j < blocks; j++ {
			other := data[j*block_len : (j+1)*block_len]
			if bytes.Equal(cur, other) {
				same++
			}
		}
	}
	return same
}

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
		n := repeating_blocks(data)
		if n > 0 {
			fmt.Printf("line %d: %d repeating blocks\n", line, n)
		}
		line++
	}
}
