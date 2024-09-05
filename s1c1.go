package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func s1c1() {

	fmt.Println("Set 1, Challenge 1: Convert hex to base64")

	h, _ := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	b64 := base64.StdEncoding.EncodeToString(h)

	fmt.Printf("hex: %s\n", hex.EncodeToString(h))
	fmt.Printf("base64: %s\n", b64)
}
