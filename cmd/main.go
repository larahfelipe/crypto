package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/larahfelipe/crypto/internal/util"
	"github.com/larahfelipe/crypto/pkg/crypto"
)

func main() {
	inputScan := bufio.NewScanner(os.Stdin)
	mnemonic := &crypto.Mnemonic{}
	key := &crypto.Key{}

	fmt.Print("\033[H\033[2J") // Clear the terminal
	fmt.Println("Type `new` to generate a new mnemonic or `recover` to recover an existing one:")
	inputScan.Scan()

	switch inputScan.Text() {
	case "new":
		fmt.Println("\nType `128` to generate a 12-words mnemonic phrase or `256` to generate a 24-words mnemonic phrase:")
		inputScan.Scan()
		isc, err := strconv.Atoi(inputScan.Text())
		if err != nil {
			panic("failed to parse inputScan to int")
		}
		nm, err := crypto.NewMnemonic(isc)
		if err != nil {
			panic(err)
		}
		mnemonic = nm

	case "recover":
		fmt.Println("\nEnter your mnemonic phrase:")
		inputScan.Scan()
		seed, err := mnemonic.GetSeed("")
		if err != nil {
			panic(err)
		}
		mnemonic.Phrase = inputScan.Text()
		mnemonic.Seed = seed

	default:
		panic("invalid input")
	}

	masterKey, err := mnemonic.GetMasterKey(mnemonic.Seed)
	if err != nil {
		panic(err)
	}

	key = masterKey

	fmt.Println("\nDerive master key? [y/N]")
	inputScan.Scan()

	if strings.ToLower(inputScan.Text()) == "y" {
		fmt.Println("\nEnter the child derivation path (e.g. m/44'/0'/0'/0/0):")
		inputScan.Scan()

		key, err = key.Derive(inputScan.Text())
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("\033[H\033[2J") // Clear the terminal
	fmt.Println("WARNING: Mnemonic phrases and private keys are sensitive data and give the holder full control over your funds. Keep them safe and never share them with anyone!")

	fmt.Printf("\n\n* Key\n")
	util.PrintMap(map[string]interface{}{
		"Phrase":      mnemonic.Phrase,
		"Seed":        mnemonic.Seed,
		"Depth":       key.Key.Depth(),
		"Fingerprint": key.Key.ParentFingerprint(),
		"Private":     key.Key.IsPrivate(),
		"Path":        key.Path,
	})

	ecPubKey, err := key.Key.ECPubKey()
	if err != nil {
		panic(err)
	}

	ecPrivKey, err := key.Key.ECPrivKey()
	if err != nil {
		panic(err)
	}

	fmt.Println("\n* Public Key")
	util.PrintMap(map[string]interface{}{
		"Serialized": strings.ToUpper(fmt.Sprintf("%x", ecPubKey.SerializeUncompressed())),
		"X":          ecPubKey.X,
		"Y":          ecPubKey.Y,
	})

	fmt.Println("\n* Private Key")
	util.PrintMap(map[string]interface{}{
		"Serialized": strings.ToUpper(fmt.Sprintf("%x", ecPrivKey.Serialize())),
		"X":          ecPrivKey.X,
		"Y":          ecPrivKey.Y,
		"D":          ecPrivKey.D,
	})
}
