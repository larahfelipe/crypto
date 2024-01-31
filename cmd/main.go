package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/larahfelipe/crypto/pkg/crypto"
)

func main() {
	var inputOp, path string

	fmt.Print("\033[H\033[2J") // Clear the terminal
	fmt.Println("Type `new` to generate a new mnemonic or `recover` to recover an existing one:")
	fmt.Scanln(&inputOp)

	mnemonic := &crypto.Mnemonic{}

	switch inputOp {
	case "new":
		var bitSize int
		fmt.Println("\nEnter the number of bits for the mnemonic (must be between 128 and 256 and a multiple of 32):")
		fmt.Scanln(&bitSize)
		newMnemonic, err := crypto.NewMnemonic(bitSize)
		if err != nil {
			panic(err)
		}
		mnemonic = newMnemonic

	case "recover":
		phraseScanner := bufio.NewScanner(os.Stdin)
		fmt.Println("\nEnter your mnemonic phrase:")
		phraseScanner.Scan()
		mnemonic.Phrase = phraseScanner.Text()
		seed, err := mnemonic.GetSeed("")
		if err != nil {
			panic(err)
		}
		mnemonic.Seed = seed

	default:
		panic("invalid operation")
	}

	masterKey, err := mnemonic.GetMasterKey(mnemonic.Seed)
	if err != nil {
		panic(err)
	}

	fmt.Println("\nEnter the child derivation path (e.g. m/44'/0'/0'/0/0):")
	fmt.Scanln(&path)

	childKeyPair, err := masterKey.DeriveChildKeyPair(path)
	if err != nil {
		panic(err)
	}

	fmt.Println("\033[H\033[2J") // Clear the terminal
	fmt.Println("WARNING: Mnemonic phrases and private keys are sensitive data and give the holder full control over your funds. Keep them safe and never share them with anyone!")
	fmt.Println("")
	fmt.Println("Mnemonic Phrase:", mnemonic.Phrase)
	fmt.Println("Child Path:", path)
	fmt.Println("Public Key:", strings.ToUpper(childKeyPair.PublicKey))
	fmt.Println("Private Key:", strings.ToUpper(childKeyPair.PrivateKey))
}
