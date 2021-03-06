/*
 * Copyright 2017-2019 Kopano and its licensors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package clients

import (
	"crypto"
)

// Details hold detail information about clients identified by ID.
type Details struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	RedirectURI string `json:"redirect_uri"`
	Trusted     bool   `json:"trusted"`

	Registration *ClientRegistration `json:"-"`
}

// A Secured is a client records public key identified by ID.
type Secured struct {
	ID              string
	DisplayName     string
	ApplicationType string

	Kid       string
	PublicKey crypto.PublicKey

	TrustedScopes []string

	Registration *ClientRegistration
}
