package crypto

import (
	"errors"
	"time"

	"github.com/tyler-smith/go-bip39"
)

type Mnemonic struct {
	Phrase    string
	CreatedAt time.Time
}

func (mnemonic *Mnemonic) GetMasterKey(seed []byte) (*HDExtendedKey, error) {
  return CreateMasterKey(seed)
}

func (mnemonic *Mnemonic) GetSeed(password string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic.Phrase) {
		return nil, errors.New("ERROR: invalid mnemonic phrase")
	}

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic.Phrase, password)
	if err != nil {
		return nil, errors.New("ERROR: failed to generate seed from mnemonic" + err.Error())
	}

	return seed, nil
}

func CreateMnemonic(bitSize int) (*Mnemonic, error) {
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
