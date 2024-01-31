package crypto

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
)

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

func CreateMasterKey(seed []byte) (*HDExtendedKey, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to generate master key from seed: %s", err)
	}

	return &HDExtendedKey{masterKey}, nil
}

func (mk *HDExtendedKey) DeriveChildKeyPair(path string) (*KeyPair, error) {
	pathComponents := strings.Split(strings.Trim(path, PathSeparator), PathSeparator)
	if len(pathComponents) == 0 {
		return nil, fmt.Errorf("provided path is invalid")
	}

	childKey := mk.ExtendedKey

	for _, c := range pathComponents {
		if c == PathRootKey {
			continue
		}

		hardened := strings.HasSuffix(c, PathHardenedKey)
		indexTrimmed := strings.TrimSuffix(c, PathHardenedKey)
		index, err := strconv.ParseUint(indexTrimmed, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse index: %s", err)
		}

		if hardened {
			index += hdkeychain.HardenedKeyStart
		}

		childKey, err = childKey.Child(uint32(index))
		if err != nil {
			return nil, fmt.Errorf("failed to derive master key: %s", err)
		}
	}

	rawPrivKey, err := childKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key from child key: %s", err)
	}

	rawPubKey, err := childKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from child key: %s", err)
	}

	return &KeyPair{
		PrivateKey: fmt.Sprintf("%x", rawPrivKey.Serialize()),
		PublicKey:  fmt.Sprintf("%x", rawPubKey.SerializeUncompressed()),
	}, nil
}
