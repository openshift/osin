package osin

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ValidateUri validates that redirectUri is contained in baseUri
func ValidateUri(baseUri string, redirectUri string) error {
	if baseUri == "" || redirectUri == "" {
		return errors.New("urls cannot be blank.")
	}

	// parse base url
	base, err := url.Parse(baseUri)
	if err != nil {
		return err
	}

	// parse passed url
	redirect, err := url.Parse(redirectUri)
	if err != nil {
		return err
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return errors.New("url must not include fragment.")
	}

	// check if urls match
	if base.Scheme == redirect.Scheme && base.Host == redirect.Host && len(redirect.Path) >= len(base.Path) && strings.HasPrefix(redirect.Path, base.Path) {
		return nil
	}

	return errors.New(fmt.Sprintf("urls don't validate: %s / %s\n", baseUri, redirectUri))
}
