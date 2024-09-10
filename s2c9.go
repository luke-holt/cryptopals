package main

import (
	"fmt"
)

func s2c9() {
	fmt.Println("> Set 2, Challenge 9: Implement PKCS#7 padding")

	blocklen := 20
	text := []byte("YELLOW SUBMARINE")

	padded := pkcs7_pad(text, byte(blocklen))

	fmt.Println("No padding:")
	hexdump(text, AES_BLOCKLEN)
	fmt.Println("PKCS#7 padding:")
	hexdump(padded, AES_BLOCKLEN)
}
