package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

func repeating_xor(s []byte, key []byte) []byte {
	var out bytes.Buffer

	for i, char := range s {
		out.WriteByte(char ^ key[i%len(key)])
	}

	return out.Bytes()
}

func s1c5() {

	fmt.Println("Set 1, Challenge 5: Implement repeating-key XOR")

	var input []byte = []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	var key []byte = []byte("ICE")

	encrypted := repeating_xor(input, key)

	fmt.Printf("input:\n\"%s\"\n", string(input))
	fmt.Printf("output:\n\"%s\"\n", hex.EncodeToString(encrypted))
}
