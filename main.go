package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/ktr0731/go-fuzzyfinder"
	"golang.org/x/term"
)

func importCSV(fileName string) error {
	err := EnsureConfigDirectory()

	file, err := os.Open(fileName)
	if err != nil {
		return err
	}

	reader := csv.NewReader(bufio.NewReader(file))
	logins := make([]*Login, 0)

	// Discard the first row, which only contains headers
	_, err = reader.Read()
	if err != nil {
		return err
	}

	for record, err := reader.Read(); err == nil; record, err = reader.Read() {
		login, err := ParseLoginRow(record)
		if err != nil {
			log.Fatal(err)
		}

		logins = append(logins, login)
	}

	if err != nil && err != io.EOF {
		return err
	}

	var store *Store
	if StoreExists() {
		store, err = GetStore()
		if err != nil {
			return err
		}
	}

	fmt.Fprint(os.Stderr, "Encryption Passphrase:")
	passPhrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	fmt.Print("\n")

	if store == nil {
		fmt.Fprint(os.Stderr, "Encryption Passphrase repeat:")
		repeatPassPhrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		fmt.Print("\n")

		if string(passPhrase) != string(repeatPassPhrase) {
			return errors.New("Repeat passphrase did not match")
		}
	} else {
		valid, err := store.ValidatePassphrase(string(passPhrase))
		if err != nil {
			return err
		}

		if !valid {
			return errors.New("Passphrase did not match existing passphrase")
		}
	}

	return SaveLogins(logins, string(passPhrase))
}

func findPassword() (string, error) {
	if !StoreExists() {
		return "", errors.New("No stored passwords found")
	}

	store, err := GetStore()
	if err != nil {
		return "", err
	}

	fmt.Fprint(os.Stderr, "Decryption Passphrase:")
	passPhrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "\n")

	valid, err := store.ValidatePassphrase(string(passPhrase))
	if err != nil {
		return "", err
	}

	if !valid {
		return "", errors.New("Passphrase did not match existing passphrase")
	}

	logins, err := store.GetLogins(string(passPhrase))
	if err != nil {
		return "", err
	}

	idx, err := fuzzyfinder.FindMulti(
		logins,
		func(i int) string {
			return logins[i].URL
		},
		fuzzyfinder.WithPreviewWindow(func(i, w, h int) string {
			if i == -1 {
				return ""
			}

			return logins[i].Format()
		}))

	if err != nil {
		log.Fatal(err)
	}

	return logins[idx[0]].Password, nil
}

func main() {
	importCmd := flag.NewFlagSet("import", flag.ExitOnError)
	importFile := importCmd.String(
		"file",
		os.Getenv("HOME")+"/Downloads/logins.csv",
		"The CSV file containing passwords, as exported from firefox.",
	)

	subcommand := "help"
	if len(os.Args) > 1 {
		subcommand = os.Args[1]
	}

	switch subcommand {
	case "import":
		importCmd.Parse(os.Args[2:])
		err := importCSV(*importFile)
		if err != nil {
			log.Fatal(err)
		}
	case "find":
		pass, err := findPassword()
		if err != nil {
			log.Fatal(err)
		}

		// use stderr to surround the password with some newlines in the console
		// without dirtying up stdout. This way the password is easier to select
		// in a terminal, but can still be used from standard output for
		// scripting purposes.
		fmt.Fprint(os.Stderr, "\n")
		fmt.Println(pass)
		fmt.Fprint(os.Stderr, "\n")
	default:
		fmt.Fprint(os.Stderr, "Expected subcommand \"import\" or \"find\".")
		fmt.Fprint(os.Stderr, "\n\nSUPPORTED SUBCOMMANDS\n\nimport: Import logins.csv from firefox.\n")
		importCmd.Usage()
		fmt.Fprint(os.Stderr, "find: Find a password string and print it to stdout.\n")
		os.Exit(1)
	}
}
