// aes command uses Advanced Encryption Standard (AES) for decrypting
// ciphertext or encrypting plaintext.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var (
	decrypt = flag.Bool("d", false, "true for decrypting; false for encrypting")
	keyfile = flag.String("keyfile", "default.key", "path to file containing key")
)

func do(key []byte) ([]byte, error) {
	if *decrypt {
		ciphertext, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if len(ciphertext) < aes.BlockSize {
			return nil, errors.New("ciphertext too short")
		}
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(ciphertext, ciphertext)
		return ciphertext, nil
	}
	plaintext, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

func main() {
	flag.Parse()
	key, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		log.Fatal(err)
	}
	out, err := do(key)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		log.Fatal(err)
	}
}
