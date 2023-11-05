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
	CreatedAt time.Time
}

type HDExtendedKey struct {
	*hdkeychain.ExtendedKey
}

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

const (
	PathSeparator   = "/"
	PathHardenedKey = "'"
	PathRootKey     = "m"
)

func createMnemonic(bitSize int) (*Mnemonic, error) {
	if bitSize < 128 || bitSize > 256 || bitSize%32 != 0 {
		return nil, errors.New("ERROR: invalid bit size")
	}

	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return nil, errors.New("ERROR: failed to generate entropy from bit size" + err.Error())
	}

	mnemonicPhrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, errors.New("ERROR: failed to generate mnemonic phrase from entropy" + err.Error())
	}

	return &Mnemonic{
		Phrase:    mnemonicPhrase,
		CreatedAt: time.Now(),
	}, nil
}

func (mnemonic *Mnemonic) getSeed(password string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic.Phrase) {
		return nil, errors.New("ERROR: invalid mnemonic phrase")
	}

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic.Phrase, password)
	if err != nil {
		return nil, errors.New("ERROR: failed to generate seed from mnemonic" + err.Error())
	}

	return seed, nil
}

func (mnemonic *Mnemonic) getMasterKey(seed []byte) (*HDExtendedKey, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, errors.New("ERROR: failed to generate master key from seed" + err.Error())
	}

	return &HDExtendedKey{masterKey}, nil
}

func (masterKey *HDExtendedKey) deriveChildKeyPair(path string) (*KeyPair, error) {
	pathComponents := strings.Split(strings.Trim(path, PathSeparator), PathSeparator)
	if len(pathComponents) == 0 {
		return nil, errors.New("ERROR: invalid derivation path")
	}

	childKey := masterKey.ExtendedKey

	for _, c := range pathComponents {
		if c == PathRootKey {
			continue
		}

		hardened := strings.HasSuffix(c, PathHardenedKey)
		indexTrimmed := strings.TrimSuffix(c, PathHardenedKey)
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
	mnemonicPhrase := strings.Join(os.Args[1:], " ")

	mnemonic := &Mnemonic{
		Phrase: mnemonicPhrase,
	}

	seed, err := mnemonic.getSeed("")
	if err != nil {
		log.Fatal(err)
	}

	masterKey, err := mnemonic.getMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	keyPair, err := masterKey.deriveChildKeyPair("m/44'/195'/0'/0/0")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n---")
	fmt.Println("Mnemonic:", mnemonic.Phrase)
	fmt.Println("Private Key:", strings.ToUpper(keyPair.PrivateKey))
	fmt.Println("Public Key:", strings.ToUpper(keyPair.PublicKey))
}
