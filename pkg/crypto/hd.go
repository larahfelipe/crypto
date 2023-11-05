package crypto

import (
	"errors"
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
    return nil, errors.New("ERROR: failed to generate master key from seed" + err.Error())
  }

  return &HDExtendedKey{masterKey}, nil
}

func (masterKey *HDExtendedKey) DeriveChildKeyPair(path string) (*KeyPair, error) {
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
