package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/larahfelipe/crypto/pkg/crypto"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	var path string

	fmt.Println("\nEnter your mnemonic phrase:")
	scanner.Scan()

	fmt.Println("\nEnter your derivation path:")
	fmt.Scanln(&path)

	mnemonic := &crypto.Mnemonic{
		Phrase: scanner.Text(),
	}

	seed, err := mnemonic.GetSeed("")
	if err != nil {
		log.Fatal(err)
	}

	masterKey, err := mnemonic.GetMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	keyPair, err := masterKey.DeriveChildKeyPair(path)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n---")
	fmt.Println("Mnemonic:", mnemonic.Phrase)
	fmt.Println("Path:", path)
	fmt.Println("Private Key:", strings.ToUpper(keyPair.PrivateKey))
	fmt.Println("Public Key:", strings.ToUpper(keyPair.PublicKey))
	fmt.Println("---")
}
