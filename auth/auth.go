/*
Copyright © 2019, 2020, 2022, 2023 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	types "github.com/RedHatInsights/insights-results-types"
	"github.com/rs/zerolog/log"
)

const (
	// XRHAuthTokenHeader represents the name of the header used in XRH authorization type
	// #nosec G101
	XRHAuthTokenHeader = "x-rh-identity"
	// #nosec G101
	invalidTokenMessage = "Invalid/Malformed auth token"
	// #nosec G101
	missingTokenMessage = "Missing auth token"
)

func DecodeTokenFromHeader(w http.ResponseWriter, r *http.Request, authType string) (*types.Token, error) {

	// try to read auth. header from HTTP request (if provided by client)
	token := GetAuthTokenHeader(r)
	if token == "" {
		return nil, &AuthenticationError{ErrString: missingTokenMessage}
	}

	// decode auth. token to JSON string
	decoded, err := base64.StdEncoding.DecodeString(token)

	// if token is malformed return HTTP code 403 to client
	if err != nil {
		// malformed token, returns with HTTP code 403 as usual
		log.Error().Err(err).Msg(invalidTokenMessage)
		return nil, &AuthenticationError{ErrString: invalidTokenMessage}
	}

	tk := &types.Token{}

	if authType == "xrh" {
		// auth type is xrh (x-rh-identity header)
		err = json.Unmarshal(decoded, tk)
		if err != nil {
			// malformed token, returns with HTTP code 403 as usual
			log.Error().Err(err).Msg(invalidTokenMessage)
			return nil, &AuthenticationError{ErrString: invalidTokenMessage}
		}
	} else {
		err := errors.New("unknown auth type")
		log.Error().Err(err).Send()
		return nil, err
	}
	return tk, nil
}

// GetAuthToken returns request's authentication token
func GetAuthToken(request *http.Request) (*types.Identity, error) {
	i := request.Context().Value(types.ContextKeyUser)

	if i == nil {
		return nil, &AuthenticationError{ErrString: "token is not provided"}
	}

	identity, ok := i.(types.Identity)
	if !ok {
		return nil, &AuthenticationError{ErrString: "contextKeyUser has wrong type"}
	}

	return &identity, nil
}

func GetAuthTokenHeader(r *http.Request) string {
	var tokenHeader string

	log.Debug().Msg("Retrieving x-rh-identity token")
	// Grab the token from the header
	tokenHeader = r.Header.Get(XRHAuthTokenHeader)

	log.Debug().Int("Length", len(tokenHeader)).Msg("Token retrieved")

	if tokenHeader == "" {
		log.Error().Msg(missingTokenMessage)
		return ""
	}

	return tokenHeader
}
