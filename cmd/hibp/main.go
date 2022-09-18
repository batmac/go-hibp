// Copyright 2022 Baptiste Canton.
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/batmac/go-hibp"

	"github.com/erikgeiser/promptkit/textinput"
)

const (
	OK    = "\033[32m"
	KO    = "\033[31m"
	RESET = "\033[0m"
)

func main() {
	input := textinput.New("Enter the password to check against HIBP:")
	input.Placeholder = "password"
	input.Validate = func(s string) error {
		if len(s) == 0 {
			return errors.New("Please enter at least one character")
		}
		return nil
	}
	input.Hidden = true
	input.Template += `
	{{- if .ValidationError -}}
		{{- print "\n" (Foreground "1" .ValidationError.Error) -}}
	{{- end -}}`

	name, err := input.RunPrompt()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	startTime := time.Now()

	if r, err := hibp.HasBeenPwned(name); err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		duration := time.Since(startTime)
		if r == 0 {
			fmt.Printf(OK+"The password has not been pwned. (%v)\n"+RESET, duration)
		} else {
			fmt.Printf(KO+"The password has been pwned %d times. (%v)%s\n", r, duration, RESET)
		}
		fmt.Printf("Duration: %s\n", duration)
	}
}
