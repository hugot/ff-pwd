package main

import (
	"errors"
	"fmt"
)

type Login struct {
	URL                 string
	Username            string
	Password            string
	HttpRealm           string
	FormActionOrigin    string
	GUID                string
	TimeCreated         string
	TimeLastUsed        string
	TimePasswordChanged string
}

func (l *Login) Format() string {
	username := l.Username
	if username == "" {
		username = "(none)"
	}

	password := "[secret]"
	if l.Password == "" {
		password = "(none)"
	}

	return fmt.Sprintf("URL: %s\nUsername: %s\nPassword: %s\n", l.URL, username, password)
}

const LoginRowLength = 9

var ErrLoginRowWrongLength error = errors.New("Login row does not have the expected length.")

func ParseLoginRow(row []string) (*Login, error) {
	if len(row) != LoginRowLength {
		return nil, ErrLoginRowWrongLength
	}

	return &Login{
		URL:                 row[0],
		Username:            row[1],
		Password:            row[2],
		HttpRealm:           row[3],
		FormActionOrigin:    row[4],
		GUID:                row[5],
		TimeCreated:         row[6],
		TimeLastUsed:        row[7],
		TimePasswordChanged: row[8],
	}, nil
}
