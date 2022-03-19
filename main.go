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

	fmt.Print("Encryption Passphrase:")
	passPhrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	fmt.Print("\n")

	if store == nil {
		fmt.Print("Encryption Passphrase repeat:")
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

	fmt.Print("Decryption Passphrase:")
	passPhrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Print("\n")

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

	switch os.Args[1] {
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

		fmt.Println(pass)
	default:
		fmt.Fprint(os.Stderr, "Expected subcommand \"import\" or \"find\".")
		os.Exit(1)
	}

	// idx, err := fuzzyfinder.FindMulti(
	// 	logins,
	// 	func(i int) string {
	// 		return logins[i].URL
	// 	},
	// 	fuzzyfinder.WithPreviewWindow(func(i, w, h int) string {
	// 		if i == -1 {
	// 			return ""
	// 		}

	// 		return logins[i].Format()
	// 	}))

	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println(logins[idx[0]].Password)
}

// type Track struct {
// 	Name      string
// 	AlbumName string
// 	Artist    string
// }

// var tracks = []Track{
// 	{"foo", "album1", "artist1"},
// 	{"bar", "album1", "artist1"},
// 	{"foo", "album2", "artist1"},
// 	{"baz", "album2", "artist2"},
// 	{"baz", "album3", "artist2"},
// }

// func main() {
// 	idx, err := fuzzyfinder.FindMulti(
// 		tracks,
// 		func(i int) string {
// 			return tracks[i].Name
// 		},
// 		fuzzyfinder.WithPreviewWindow(func(i, w, h int) string {
// 			if i == -1 {
// 				return ""
// 			}
// 			return fmt.Sprintf("Track: %s (%s)\nAlbum: %s",
// 				tracks[i].Name,
// 				tracks[i].Artist,
// 				tracks[i].AlbumName)
// 		}))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Printf("selected: %v\n", idx)
//}
