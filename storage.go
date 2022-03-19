package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
)

var ConfigDirectory string = os.Getenv("HOME") + "/.config/ff-pwd"
var StorageFile string = ConfigDirectory + "/data.json"

type Store struct {
	PassphraseHash string
	Data           string
	NonceSize      int
}

func (s *Store) ValidatePassphrase(passphrase string) (bool, error) {
	saltedPassphraseHash, err := base64.StdEncoding.DecodeString(s.PassphraseHash)
	if err != nil {
		return false, err
	}

	return ValidatePassword(passphrase, saltedPassphraseHash)
}

func (s *Store) GetLogins(passPhrase string) ([]*Login, error) {
	storeData, err := base64.StdEncoding.DecodeString(s.Data)
	if err != nil {
		return nil, err
	}

	storeData, err = Decrypt(passPhrase, s.NonceSize, storeData)
	if err != nil {
		return nil, err
	}

	logins := make([]*Login, 0)
	err = json.Unmarshal(storeData, &logins)

	return logins, err
}

func EnsureConfigDirectory() error {
	if _, err := os.Stat(ConfigDirectory); os.IsNotExist(err) {
		err = os.MkdirAll(ConfigDirectory, 0700)
		if err != nil {
			return err
		}

	}

	return os.Chmod(ConfigDirectory, 0700)
}

func StoreExists() bool {
	_, err := os.Stat(StorageFile)

	if os.IsNotExist(err) {
		return false
	}

	return true
}

func GetStore() (*Store, error) {
	file, err := os.Open(StorageFile)
	if err != nil {
		return nil, err
	}

	store := &Store{}
	err = json.NewDecoder(bufio.NewReader(file)).Decode(store)

	return store, err
}

func SaveLogins(logins []*Login, passPhrase string) error {
	data, err := json.Marshal(logins)
	if err != nil {
		return err
	}

	nonceSize, encryptedData, err := Encrypt(passPhrase, data)
	if err != nil {
		return err
	}

	encodedData := base64.StdEncoding.EncodeToString(encryptedData)
	hash, salt := HashPassword(passPhrase, nil)
	passPhraseHash := append(salt, hash...)

	store := &Store{
		PassphraseHash: base64.StdEncoding.EncodeToString(passPhraseHash),
		Data:           encodedData,
		NonceSize:      nonceSize,
	}

	file, err := os.Create(StorageFile)
	if err != nil {
		return err
	}

	return json.NewEncoder(bufio.NewWriter(file)).Encode(store)
}
