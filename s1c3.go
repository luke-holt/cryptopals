package main

import (
	"encoding/hex"
	"fmt"
)

func s1c3() {

	fmt.Println("> Set 1, Challenge 3: Singe-byte XOR cipher")

	encrypted, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	k, _ := solve_single_char_xor(encrypted)

	fmt.Printf("encrypted: %s\n", encrypted)
	fmt.Printf("key: %d\n", k)
	key := make([]byte, 1)
	key[0] = byte(k)
	fmt.Printf("decoded: \"%s\"\n", string(xor_cipher(encrypted, key)))
}
