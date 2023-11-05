package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/larahfelipe/crypto/pkg/crypto"
)

func main() {
	mnemonicPhrase := strings.Join(os.Args[1:], " ")

	mnemonic := &crypto.Mnemonic{
		Phrase: mnemonicPhrase,
	}

	seed, err := mnemonic.GetSeed("")
	if err != nil {
		log.Fatal(err)
	}

	masterKey, err := mnemonic.GetMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	keyPair, err := masterKey.DeriveChildKeyPair("m/44'/195'/0'/0/0")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n---")
	fmt.Println("Mnemonic:", mnemonic.Phrase)
	fmt.Println("Private Key:", strings.ToUpper(keyPair.PrivateKey))
	fmt.Println("Public Key:", strings.ToUpper(keyPair.PublicKey))
}
