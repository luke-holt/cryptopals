package main

import "fmt"

func s2c15() {

	fmt.Println("> Set 2, Challenge 15: PKCS#7 padding validation")

	validate := func(str string) {
		_, err := pkcs7_trim([]byte(str))
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Valid")
		}
	}

	validate("ICE ICE BABY\x04\x04\x04\x04")
	validate("ICE ICE BABY\x05\x05\x05\x05")
	validate("ICE ICE BABY\x01\x02\x03\x04")

}
