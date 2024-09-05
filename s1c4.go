package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func s1c4() {

	fmt.Println("> Set 1, Challenge 4: Detect single-character XOR")

	file, err := os.Open("s1c4.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var file_min_err float64 = 1.0
	var file_min_err_key byte
	var file_min_err_line int
	var file_min_err_decoded []byte
	var line_count int
	for scanner.Scan() {
		line, err := hex.DecodeString(scanner.Text())
		if err != nil {
			continue
		}

		min_err_key, min_err := solve_single_char_xor(line)

		if min_err < file_min_err {
			file_min_err = min_err
			file_min_err_key = min_err_key
			file_min_err_line = line_count
			file_min_err_decoded = encrypt_single_xor_cipher(line, byte(min_err_key))
		}

		line_count++
	}

	fmt.Printf("line: %d\n", file_min_err_line)
	fmt.Printf("key: %d\n", file_min_err_key)
	fmt.Printf("decoded: \"%s\"\n", sanitize(file_min_err_decoded))
}
