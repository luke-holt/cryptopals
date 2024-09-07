package main

import (
	"fmt"
	"strings"
)

func s2c9() {
	fmt.Println("> Set 2, Challenge 9: Implement PKCS#7 padding")

	blocklen := 20
	text := []byte("YELLOW SUBMARINE")

	pad := byte(blocklen) - byte(len(text)%int(blocklen))
	padded := make([]byte, len(text)+int(pad))
	copy(padded, text)
	for i := range int(pad) {
		padded[len(text)+i] = pad
	}

	fmt.Printf("No pad:        \"%s\"\n", sanitize(text))
	fmt.Printf("Padded:        \"%s\"\n", sanitize(padded))
	fmt.Printf("Pad byte: 0x%02x  %s%s\n", pad, strings.Repeat("-", len(text)), strings.Repeat("x", int(pad)))
}
