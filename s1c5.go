package main

import (
	"encoding/hex"
	"fmt"
)

func s1c5() {

	fmt.Println("> Set 1, Challenge 5: Implement repeating-key XOR")

	var input []byte = []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	var key []byte = []byte("ICE")

	encrypted := xor_cipher(input, key)

	fmt.Printf("input:\n\"%s\"\n", string(input))
	fmt.Printf("output:\n\"%s\"\n", hex.EncodeToString(encrypted))
}
