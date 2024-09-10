package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	openssl "github.com/golang-fips/openssl/v2"
)

func encode_structured_cookie_string(email, role, uid string) string {
	var sb strings.Builder
	sb.WriteString("email=")
	sb.WriteString(email)
	sb.WriteString("&")
	sb.WriteString("uid=")
	sb.WriteString(uid)
	sb.WriteString("&")
	sb.WriteString("role=")
	sb.WriteString(role)
	return sb.String()
}

func decode_structured_cookie_string(s []byte) map[string]string {
	m := make(map[string]string)

	key_value_re, err := regexp.Compile("([_a-zA-Z][_a-zA-Z0-9]+)=([^=&]*)(&|$)")
	if err != nil {
		log.Fatal(err)
	}

	match_list := key_value_re.FindAllStringSubmatch(string(s), -1)

	for i := range match_list {
		key := match_list[i][1]
		value := match_list[i][2]
		m[key] = value
	}

	return m
}

func s2c13() {

	fmt.Println("> Set 2, Challenge 13: ECB cut-and-paste")

	libcrypto := string("c:/users/luke/repo/openssl/libcrypto-3-x64.dll")
	err := openssl.Init(libcrypto)
	if err != nil {
		log.Fatal(err)
	}

	attack_email := []byte("luke@site.admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0Bcom")
	fmt.Println("attack email string:")
	hexdump(attack_email, AES_BLOCKLEN)

	user_profile_string := encode_structured_cookie_string(string(attack_email), "user", "10")
	fmt.Println("encoded user profile string:")
	hexdump([]byte(user_profile_string), AES_BLOCKLEN)

	key := rand_bytes(AES_BLOCKLEN)
	encrypted, err := aes_encrypt_ecb([]byte(user_profile_string), [AES_BLOCKLEN]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	attack_ciphertext := make([]byte, len(encrypted)-AES_BLOCKLEN)
	copy(attack_ciphertext[AES_BLOCKLEN*0:AES_BLOCKLEN*1], encrypted[AES_BLOCKLEN*0:AES_BLOCKLEN*1])
	copy(attack_ciphertext[AES_BLOCKLEN*1:AES_BLOCKLEN*2], encrypted[AES_BLOCKLEN*2:AES_BLOCKLEN*3])
	copy(attack_ciphertext[AES_BLOCKLEN*2:AES_BLOCKLEN*3], encrypted[AES_BLOCKLEN*1:AES_BLOCKLEN*2])

	decrypted, err := aes_decrypt_ecb(attack_ciphertext, [AES_BLOCKLEN]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("decoded user profile object:", decode_structured_cookie_string(decrypted))

}
