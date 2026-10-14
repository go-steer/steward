// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package steward lets a go-steer service act as its caller.
//
// A steward looks after passengers' belongings on their behalf; purser
// (github.com/go-steer/purser) checks who is aboard. This module is the
// first half's complement: given a request carrying a person's Google
// access token, it decides whether the token is good for this service,
// who it belongs to, and whether that person is let in, and then hands
// the service a purser.Caller plus a token source it can use to call
// Google APIs and GKE clusters as that person.
//
// The design, the hard rules and the phase plan are in docs/DESIGN.md.
package steward
