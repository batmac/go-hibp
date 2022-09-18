// Copyright 2022 Baptiste Canton.
// SPDX-License-Identifier: MIT

package hibp

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// we return this on error, so that the caller can't think the password is safe
// if the returned error is ignored
const uint64max = ^uint64(0)

func HasBeenPwned(password string) (uint64, error) {
	// get the first 5 characters of the SHA1 hash of the password
	// and check if the password is in the database
	sha := sha1.Sum([]byte(password))
	hex := hex.EncodeToString(sha[:])
	// uppercase the hex string
	hex = strings.ToUpper(hex)
	prefix, suffix := hex[:5], hex[5:]
	url := "https://api.pwnedpasswords.com/range/" + prefix
	// log.Println(url)
	resp, err := http.Get(url)
	if err != nil {
		return uint64max, err
	}
	defer func() {
		// ensure the body is exhausted
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return uint64max, fmt.Errorf("unexpected HTTP status code: %d", resp.StatusCode)
	}

	// scanner over body lines to find the suffix
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, suffix) {
			// get the number of times the password has been pwned
			countStr := line[len(suffix)+1:]
			count, err := strconv.ParseUint(countStr, 10, 0)
			if err != nil {
				return uint64max, err
			}
			return count, nil
		}
	}
	return uint64max, nil
}
