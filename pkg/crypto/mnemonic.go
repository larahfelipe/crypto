package crypto

import (
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

type Mnemonic struct {
	Phrase string
	Seed   []byte
}

func (m *Mnemonic) GetMasterKey(seed []byte) (*HDExtendedKey, error) {
	return CreateMasterKey(seed)
}

func (m *Mnemonic) GetSeed(password string) ([]byte, error) {
	if !bip39.IsMnemonicValid(m.Phrase) {
		return nil, fmt.Errorf("provided mnemonic phrase is invalid")
	}

	seed, err := bip39.NewSeedWithErrorChecking(m.Phrase, password)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed from mnemonic phrase: %s", err)
	}

	return seed, nil
}

func NewMnemonic(bitSize int) (*Mnemonic, error) {
	if bitSize < 128 || bitSize > 256 || bitSize%32 != 0 {
		return nil, fmt.Errorf("invalid bit size for generating mnemonic phrase: must be between 128 and 256 and a multiple of 32")
	}

	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy from bit size: %s", err)
	}

	mnemonicPhrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic phrase from entropy: %s", err)
	}

	mnemonic := &Mnemonic{
		Phrase: mnemonicPhrase,
	}

	mnemonicSeed, err := mnemonic.GetSeed("")
	if err != nil {
		return nil, err
	}

	mnemonic.Seed = mnemonicSeed

	return mnemonic, nil
}
