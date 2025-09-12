/*
Copyright © 2025 Michael Fero

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

package sesh

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypes(t *testing.T) {
	t.Run("LogLevel", func(t *testing.T) {
		t.Run("string representation", func(t *testing.T) {
			testCases := []struct {
				name     string
				level    LogLevel
				expected string
			}{
				{"unknown level", LogLevelUnknown, "unknown"},
				{"debug level", LogLevelDebug, "debug"},
				{"info level", LogLevelInfo, "info"},
				{"notice level", LogLevelNotice, "notice"},
				{"warn level", LogLevelWarn, "warn"},
				{"error level", LogLevelError, "error"},
				{"alert level", LogLevelAlert, "alert"},
				{"crit level", LogLevelCritical, "crit"},
				{"invalid level returns unknown", LogLevel(999), "unknown"},
				{"negative level returns unknown", LogLevel(-1), "unknown"},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					assert.Equal(t, tc.expected, tc.level.String())
				})
			}
		})

		t.Run("parse from string", func(t *testing.T) {
			testCases := []struct {
				name     string
				input    string
				expected LogLevel
			}{
				{"debug string", "debug", LogLevelDebug},
				{"info string", "info", LogLevelInfo},
				{"notice string", "notice", LogLevelNotice},
				{"warn string", "warn", LogLevelWarn},
				{"error string", "error", LogLevelError},
				{"alert string", "alert", LogLevelAlert},
				{"crit string", "crit", LogLevelCritical},
				{"invalid string returns unknown", "invalid", LogLevelUnknown},
				{"empty string returns unknown", "", LogLevelUnknown},
				{"case sensitive - uppercase returns unknown", "INFO", LogLevelUnknown},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					result := ParseLogLevel(tc.input)
					assert.Equal(t, tc.expected, result)
				})
			}
		})

		t.Run("json marshaling", func(t *testing.T) {
			testCases := []struct {
				name     string
				level    LogLevel
				expected string
			}{
				{"info level", LogLevelInfo, `"info"`},
				{"error level", LogLevelError, `"error"`},
				{"alert level", LogLevelAlert, `"alert"`},
				{"unknown level", LogLevelUnknown, `"unknown"`},
				{"crit level", LogLevelCritical, `"crit"`},
				{"invalid level", LogLevel(999), `"unknown"`},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					data, err := tc.level.MarshalJSON()
					require.NoError(t, err)
					assert.Equal(t, tc.expected, string(data))
				})
			}
		})
	})

	t.Run("LogEntryType", func(t *testing.T) {
		t.Run("string representation", func(t *testing.T) {
			testCases := []struct {
				name      string
				entryType LogEntryType
				expected  string
			}{
				{"unknown type", LogEntryTypeUnknown, "unknown"},
				{"kong application type", LogEntryTypeKongApplication, "kong"},
				{"nginx access type", LogEntryTypeNginxAccess, "access"},
				{"nginx startup type", LogEntryTypeNginxStartup, "nginx"},
				{"invalid type returns unknown", LogEntryType(999), "unknown"},
				{"negative type returns unknown", LogEntryType(-1), "unknown"},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					assert.Equal(t, tc.expected, tc.entryType.String())
				})
			}
		})

		t.Run("json marshaling", func(t *testing.T) {
			testCases := []struct {
				name      string
				entryType LogEntryType
				expected  string
			}{
				{"kong type", LogEntryTypeKongApplication, `"kong"`},
				{"access type", LogEntryTypeNginxAccess, `"access"`},
				{"nginx type", LogEntryTypeNginxStartup, `"nginx"`},
				{"unknown type", LogEntryTypeUnknown, `"unknown"`},
				{"invalid type", LogEntryType(999), `"unknown"`},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					data, err := tc.entryType.MarshalJSON()
					require.NoError(t, err)
					assert.Equal(t, tc.expected, string(data))
				})
			}
		})
	})

	t.Run("HTTPRequestInfo json marshaling", func(t *testing.T) {
		t.Run("all fields present", func(t *testing.T) {
			httpRequest := HTTPRequestInfo{
				ClientAddress: "127.0.0.1",
				RemoteUser:    "user",
				RemoteLogname: "logname",
				Method:        "GET",
				Path:          "/api/test",
				Protocol:      "HTTP/1.1",
				StatusCode:    200,
				ResponseBytes: 1024,
				Referrer:      "http://example.com",
				UserAgent:     "curl/7.68.0",
				KongRequestID: "req-123",
				Host:          "example.com",
				Server:        "nginx/1.21",
				Upstream:      "backend:8080",
			}

			data, err := httpRequest.MarshalJSON()
			require.NoError(t, err)

			// Unmarshal to verify all fields are correctly marshaled
			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, "127.0.0.1", result["client_address"])
			assert.Equal(t, "user", result["remote_user"])
			assert.Equal(t, "logname", result["remote_logname"])
			assert.Equal(t, "GET", result["method"])
			assert.Equal(t, "/api/test", result["path"])
			assert.Equal(t, "HTTP/1.1", result["protocol"])
			assert.Equal(t, float64(200), result["status_code"])
			assert.Equal(t, float64(1024), result["response_bytes"])
			assert.Equal(t, "http://example.com", result["referrer"])
			assert.Equal(t, "curl/7.68.0", result["user_agent"])
			assert.Equal(t, "req-123", result["kong_request_id"])
			assert.Equal(t, "example.com", result["host"])
			assert.Equal(t, "nginx/1.21", result["server"])
			assert.Equal(t, "backend:8080", result["upstream"])
		})

		t.Run("dash fields omitted", func(t *testing.T) {
			httpRequest := HTTPRequestInfo{
				ClientAddress: "127.0.0.1",
				RemoteUser:    "-",
				RemoteLogname: "-",
				Method:        "GET",
				Path:          "/api/test",
				Protocol:      "HTTP/1.1",
				StatusCode:    200,
				ResponseBytes: 1024,
				Referrer:      "-",
				UserAgent:     "-",
			}

			data, err := httpRequest.MarshalJSON()
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			// Required fields should be present
			assert.Equal(t, "127.0.0.1", result["client_address"])
			assert.Equal(t, "GET", result["method"])
			assert.Equal(t, "/api/test", result["path"])
			assert.Equal(t, "HTTP/1.1", result["protocol"])
			assert.Equal(t, float64(200), result["status_code"])
			assert.Equal(t, float64(1024), result["response_bytes"])

			// Dash fields should be omitted
			_, exists := result["remote_user"]
			assert.False(t, exists)
			_, exists = result["remote_logname"]
			assert.False(t, exists)
			_, exists = result["referrer"]
			assert.False(t, exists)
			_, exists = result["user_agent"]
			assert.False(t, exists)
		})

		t.Run("empty string fields omitted", func(t *testing.T) {
			httpRequest := HTTPRequestInfo{
				ClientAddress: "127.0.0.1",
				RemoteUser:    "",
				RemoteLogname: "",
				Method:        "GET",
				Path:          "/api/test",
				Protocol:      "HTTP/1.1",
				StatusCode:    200,
				ResponseBytes: 1024,
				Referrer:      "",
				UserAgent:     "",
			}

			data, err := httpRequest.MarshalJSON()
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			// Required fields should be present
			assert.Equal(t, "127.0.0.1", result["client_address"])
			assert.Equal(t, "GET", result["method"])

			// Empty fields should be omitted
			_, exists := result["remote_user"]
			assert.False(t, exists)
			_, exists = result["remote_logname"]
			assert.False(t, exists)
			_, exists = result["referrer"]
			assert.False(t, exists)
			_, exists = result["user_agent"]
			assert.False(t, exists)
		})

		t.Run("mixed dash and valid fields", func(t *testing.T) {
			httpRequest := HTTPRequestInfo{
				ClientAddress: "127.0.0.1",
				RemoteUser:    "user",
				RemoteLogname: "-",
				Method:        "POST",
				Path:          "/api/submit",
				Protocol:      "HTTP/1.1",
				StatusCode:    201,
				ResponseBytes: 512,
				Referrer:      "http://example.com",
				UserAgent:     "-",
			}

			data, err := httpRequest.MarshalJSON()
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			// Valid fields should be present
			assert.Equal(t, "user", result["remote_user"])
			assert.Equal(t, "http://example.com", result["referrer"])

			// Dash fields should be omitted
			_, exists := result["remote_logname"]
			assert.False(t, exists)
			_, exists = result["user_agent"]
			assert.False(t, exists)
		})
	})
}
