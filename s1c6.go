package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"os"
)

func hamming_dist(a, b []byte) int {
	byte_distance := func(a, b byte) int {
		var d int
		x := a ^ b
		for i := range 8 {
			if (x & (1 << i)) == (1 << i) {
				d++
			}
		}
		return d
	}
	var distance int
	for i := range a {
		distance += byte_distance(a[i], b[i])
	}
	return distance
}

func normalized_hamming_dist(a, b []byte) float64 {
	return float64(hamming_dist(a, b)) / float64(len(a))
}

func hamming_dist_test() int {
	var s0 []byte = []byte("this is a test")
	var s1 []byte = []byte("wokka wokka!!!")
	return hamming_dist(s0, s1)
}

func keysize_sweep(keysize_min, keysize_max, block_pairs int, buffer []byte) (int, float64) {
	var min_dist_keysize int
	var min_dist float64 = math.MaxFloat64

	for keysize := keysize_min; keysize <= keysize_max; keysize++ {
		var norm_dist_sum float64
		for i := 0; i < block_pairs; i++ {
			a := buffer[(i*2+0)*keysize : (i*2+1)*keysize]
			b := buffer[(i*2+1)*keysize : (i*2+2)*keysize]
			norm_dist_sum += normalized_hamming_dist(a, b)
		}
		dist := norm_dist_sum / float64(block_pairs)

		if dist < min_dist {
			min_dist = dist
			min_dist_keysize = keysize
		}
	}

	return min_dist_keysize, min_dist
}

func most_likely_keysize(buffer []byte) int {

	const keysize_min int = 2
	const keysize_max int = 40
	const block_pair_sweep_count int = 30

	var keysize_iter_sweep map[int]int = make(map[int]int)
	for i := 1; i <= block_pair_sweep_count; i++ {
		keysize, _ := keysize_sweep(keysize_min, keysize_max, i, buffer)
		keysize_iter_sweep[keysize]++
	}

	var highest_probability_keysize int
	var highest_probability float64
	for keysize := range keysize_iter_sweep {
		prob := float64(keysize_iter_sweep[keysize]) / float64(block_pair_sweep_count)
		if prob >= highest_probability {
			highest_probability = prob
			highest_probability_keysize = keysize
		}
	}

	return highest_probability_keysize
}

func s1c6() {

	fmt.Println("Set 1, Challenge 6: Break repeating-key XOR")

	fmt.Printf("Hamming distance test: expected(37) == actual(%d)\n", hamming_dist_test())

	file_buffer, err := os.ReadFile("s1c6.txt")
	if err != nil {
		log.Fatal(err)
	}

	base64_decoded_buffer := make([]byte, base64.StdEncoding.DecodedLen(len(file_buffer)))
	_, err = base64.StdEncoding.Decode(base64_decoded_buffer, file_buffer)
	if err != nil {
		log.Fatal(err)
	}

	keysize := most_likely_keysize(base64_decoded_buffer)
	fmt.Printf("Most probable keysize: %d\n", keysize)

	transposed_blocks := make([][]byte, keysize)
	for offset := range keysize {
		for i := offset; i < len(base64_decoded_buffer); i += keysize {
			transposed_blocks[offset] = append(transposed_blocks[offset], base64_decoded_buffer[i])
		}
	}

	var solution []byte = make([]byte, len(transposed_blocks))
	for i := range transposed_blocks {
		solution[i], _ = solve_single_char_xor(transposed_blocks[i])
	}

	fmt.Printf("Solution: %s\n", solution)

}
