package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip39"
)

type Mnemonic struct {
	Phrase    string
	Seed      []byte
	CreatedAt time.Time
}

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

const (
	PathSeparatorChar = "/"
	HardenedKeyChar   = "'"
	RootKeyChar       = "m"
)

func getSeedFromMnemonic(mnemonicPhrase string, password string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonicPhrase) {
		return nil, errors.New("ERROR: invalid mnemonic phrase")
	}

	seed := bip39.NewSeed(mnemonicPhrase, password)

	return seed, nil
}

func getMasterKeyFromMnemonic(mnemonicPhrase string, password string) (*hdkeychain.ExtendedKey, error) {
	seed, err := getSeedFromMnemonic(mnemonicPhrase, password)
	if err != nil {
		return nil, errors.New("ERROR: failed to get seed from mnemonic" + err.Error())
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, errors.New("ERROR: failed to generate master key from seed" + err.Error())
	}

	return masterKey, nil
}

func generateNewMnemonic(bitSize int) (*Mnemonic, error) {
	if bitSize != 128 && bitSize != 256 {
		return nil, errors.New("ERROR: bit size must be 128 or 256")
	}

	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return nil, errors.New("ERROR: failed to generate entropy from bit size" + err.Error())
	}

	mnemonicPhrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, errors.New("ERROR: failed to generate mnemonic phrase from entropy" + err.Error())
	}

	seed, err := getSeedFromMnemonic(mnemonicPhrase, "")
	if err != nil {
		return nil, err
	}

	return &Mnemonic{
		Phrase:    mnemonicPhrase,
		Seed:      seed,
		CreatedAt: time.Now(),
	}, nil
}

func deriveChildKeyPairFromMasterKey(masterKey *hdkeychain.ExtendedKey, derivationPath string) (*KeyPair, error) {
	pathComponents := strings.Split(strings.Trim(derivationPath, PathSeparatorChar), PathSeparatorChar)
	if len(pathComponents) == 0 {
		return nil, errors.New("ERROR: invalid derivation path")
	}

	childKey := masterKey

	for _, c := range pathComponents {
		if c == RootKeyChar {
			continue
		}

		hardened := strings.HasSuffix(c, HardenedKeyChar)
		indexTrimmed := strings.TrimSuffix(c, HardenedKeyChar)
		index, err := strconv.ParseUint(indexTrimmed, 10, 32)
		if err != nil {
			return nil, errors.New("ERROR: failed to parse index" + err.Error())
		}

		if hardened {
			index += hdkeychain.HardenedKeyStart
		}

		childKey, err = childKey.Child(uint32(index))
		if err != nil {
			return nil, errors.New("ERROR: failed to derive master key" + err.Error())
		}
	}

	privKeyRaw, err := childKey.ECPrivKey()
	if err != nil {
		return nil, errors.New("ERROR: failed to get private key from child key" + err.Error())
	}

	pubKeyRaw, err := childKey.ECPubKey()
	if err != nil {
		return nil, errors.New("ERROR: failed to get public key from child key" + err.Error())
	}

	privKey := fmt.Sprintf("%x", privKeyRaw.Serialize())
	pubKey := fmt.Sprintf("%x", pubKeyRaw.SerializeUncompressed())

	return &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

func main() {
	// mnemonic, err := generateNewMnemonic(128)
	// if err != nil {
	// 	panic(err)
	// }
	mnemonicPhrase := strings.Join(os.Args[1:], " ")

	masterKey, err := getMasterKeyFromMnemonic(mnemonicPhrase, "")
	if err != nil {
		log.Fatal(err)
	}

	keyPair, err := deriveChildKeyPairFromMasterKey(masterKey, "m/44'/195'/0'/0/0")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n---")
	fmt.Println("Mnemonic Phrase:", mnemonicPhrase)
	fmt.Println("Private Key:", strings.ToUpper(keyPair.PrivateKey))
	fmt.Println("Public Key:", strings.ToUpper(keyPair.PublicKey))
}
