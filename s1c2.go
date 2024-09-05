package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

func s1c2() {

	fmt.Println("Set 1, Challenge 2: Fixed XOR")

	a, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	b, _ := hex.DecodeString("686974207468652062756c6c277320657965")

	var tmp bytes.Buffer
	for i := range len(a) {
		tmp.WriteByte(a[i] ^ b[i])
	}
	x := tmp.Bytes()

	fmt.Printf("a: %s\n", hex.EncodeToString(a))
	fmt.Printf("b: %s\n", hex.EncodeToString(b))
	fmt.Printf("a^b: %s\n", hex.EncodeToString(x))
}
