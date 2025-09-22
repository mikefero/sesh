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
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEntryCollector is a helper for collecting entries via callback in tests
type TestEntryCollector struct {
	mu      sync.Mutex
	entries []LogEntry
}

func NewTestEntryCollector() *TestEntryCollector {
	return &TestEntryCollector{
		entries: make([]LogEntry, 0),
	}
}

func (c *TestEntryCollector) Callback(entry LogEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, entry)
}

func (c *TestEntryCollector) Entries() []LogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries
}

func (c *TestEntryCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = c.entries[:0]
}

func (c *TestEntryCollector) WaitForEntries(expectedCount int, timeout time.Duration) []LogEntry {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.entries) >= expectedCount {
			entries := c.entries
			c.mu.Unlock()
			return entries
		}
		c.mu.Unlock()
		time.Sleep(1 * time.Millisecond)
	}
	return c.Entries() // Return whatever we have
}

// statErrorFile is a wrapper around os.File that returns an error on Stat() calls
type statErrorFile struct {
	*os.File
}

// errorAfterReader simulates a reader that errors after reading some bytes
type errorAfterReader struct {
	data       string
	pos        int
	errorAfter int
}

func (r *errorAfterReader) Read(p []byte) (n int, err error) {
	if r.pos >= r.errorAfter {
		return 0, fmt.Errorf("simulated read error")
	}

	remaining := len(r.data) - r.pos
	if remaining == 0 {
		return 0, io.EOF
	}

	toCopy := min(len(p), remaining)
	if r.pos+toCopy > r.errorAfter {
		toCopy = r.errorAfter - r.pos
	}

	copy(p, r.data[r.pos:r.pos+toCopy])
	r.pos += toCopy
	return toCopy, nil
}

// slowReader simulates a slow streaming input
type slowReader struct {
	data  []string
	pos   int
	delay time.Duration
}

func (r *slowReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}

	if r.pos > 0 {
		time.Sleep(r.delay) // Simulate slow input after first read
	}

	line := r.data[r.pos] + "\n"
	toCopy := min(len(p), len(line))

	copy(p, line[:toCopy])
	r.pos++
	return toCopy, nil
}

func TestParser(t *testing.T) {
	t.Run("constructor", func(t *testing.T) {
		parser := NewParser()
		assert.NotNil(t, parser)
		assert.Equal(t, DefaultFlushTimeout, parser.flushTimeout)
		assert.Nil(t, parser.entryCallback)
	})

	t.Run("configuration", func(t *testing.T) {
		t.Run("with flush timeout", func(t *testing.T) {
			timeout := 5 * time.Second
			parser := NewParser().WithFlushTimeout(timeout)
			assert.Equal(t, timeout, parser.flushTimeout)
		})

		t.Run("with entry callback", func(t *testing.T) {
			callback := func(LogEntry) {}
			parser := NewParser().WithEntryCallback(callback)
			assert.NotNil(t, parser.entryCallback)
		})

		t.Run("with CLEF", func(t *testing.T) {
			parser := NewParser().WithCLEF(true)
			assert.True(t, parser.clef)

			parser = NewParser().WithCLEF(false)
			assert.False(t, parser.clef)
		})

		t.Run("with callback timeout", func(t *testing.T) {
			// Test default value
			parser := NewParser()
			assert.Equal(t, DefaultCallbackTimeout, parser.callbackTimeout)

			// Test custom value
			timeout := 15 * time.Second
			parser = NewParser().WithCallbackTimeout(timeout)
			assert.Equal(t, timeout, parser.callbackTimeout)
		})
	})

	t.Run("callback requirement", func(t *testing.T) {
		t.Run("missing callback returns error", func(t *testing.T) {
			parser := NewParser()
			reader := strings.NewReader("test")

			_, err := parser.ParseReader(context.Background(), reader)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "entry callback is required")
		})

		t.Run("with callback succeeds", func(t *testing.T) {
			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader("2020/07/07 12:30:45 [info] 2694#0: test message")

			_, err := parser.ParseReader(context.Background(), reader)
			assert.NoError(t, err)
		})
	})

	t.Run("kong application logs", func(t *testing.T) {
		testCases := []struct {
			name    string
			input   string
			level   LogLevel
			message string
		}{
			{
				name:    "debug level",
				input:   "2020/07/07 12:30:45 [debug] 2694#0: debug message",
				level:   LogLevelDebug,
				message: "debug message",
			},
			{
				name:    "info level",
				input:   "2020/07/07 12:30:45 [info] 2694#0: info message",
				level:   LogLevelInfo,
				message: "info message",
			},
			{
				name:    "notice level",
				input:   "2020/07/07 12:30:45 [notice] 2694#0: notice message",
				level:   LogLevelNotice,
				message: "notice message",
			},
			{
				name:    "warn level",
				input:   "2020/07/07 12:30:45 [warn] 2694#0: warning message",
				level:   LogLevelWarn,
				message: "warning message",
			},
			{
				name:    "error level",
				input:   "2020/07/07 12:30:45 [error] 2694#0: error message",
				level:   LogLevelError,
				message: "error message",
			},
			{
				name:    "crit level",
				input:   "2020/07/07 12:30:45 [crit] 2694#0: critical message",
				level:   LogLevelCritical,
				message: "critical message",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				collector := NewTestEntryCollector()
				parser := NewParser().WithEntryCallback(collector.Callback)
				reader := strings.NewReader(tc.input)

				result, err := parser.ParseReader(context.Background(), reader)
				require.NoError(t, err)

				entries := collector.WaitForEntries(1, 100*time.Millisecond)
				require.Len(t, entries, 1)

				entry := entries[0]
				assert.Equal(t, tc.level, entry.Level)
				assert.Equal(t, tc.message, entry.Message)
				assert.Equal(t, LogEntryTypeKongApplication, entry.Type)
				assert.NotNil(t, entry.Timestamp)
				assert.NotNil(t, entry.ProcessID)
				assert.NotNil(t, entry.WorkerID)
				assert.Equal(t, []string{tc.input}, entry.RawMessage)

				// Check stats
				assert.Equal(t, 1, result.Stats.TotalLines)
				assert.Equal(t, 1, result.Stats.ParsedEntries)
				assert.Equal(t, 0, result.Stats.ErrorCount)
				assert.Equal(t, 1, result.Stats.LogLevelCount[tc.level])
				assert.Equal(t, 1, result.Stats.EntryTypeCount[LogEntryTypeKongApplication])
			})
		}

		t.Run("with source info", func(t *testing.T) {
			input := `2020/07/07 12:30:45 [info] 2694#0: [lua] test.lua:42: init(): message from lua`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			_, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogLevelInfo, entry.Level)
			assert.Equal(t, LogEntryTypeKongApplication, entry.Type)
			assert.Contains(t, entry.Message, "message from lua")

			// Check source info is parsed into fields
			require.NotNil(t, entry.Fields)
			assert.Equal(t, "test.lua", entry.Fields["source_file"])
			assert.Equal(t, "42", entry.Fields["source_line"])
			assert.Equal(t, "init", entry.Fields["source_function"])
		})

		t.Run("with source info without trailing colon", func(t *testing.T) {
			input := `2020/07/07 12:30:46 [info] 5#0: *4267 [kong] data_plane.lua:376 [clustering] processing cluster event`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			_, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogLevelInfo, entry.Level)
			assert.Equal(t, LogEntryTypeKongApplication, entry.Type)
			assert.Equal(t, "clustering", entry.Namespace)
			assert.Contains(t, entry.Message, "processing cluster event")

			// Check source info is parsed into fields despite missing colon after line number
			require.NotNil(t, entry.Fields)
			assert.Equal(t, "data_plane.lua", entry.Fields["source_file"])
			assert.Equal(t, "376", entry.Fields["source_line"])
			// No source_function in this format
			_, hasSourceFunction := entry.Fields["source_function"]
			assert.False(t, hasSourceFunction)
		})

		t.Run("message cleanup with duplicate namespaces and context", func(t *testing.T) {
			input := `2020/07/07 12:30:47 [info] 100#1: *200 [kong] test_file.lua:123 [namespace] [namespace] test message content, context: worker.thread`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			_, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogLevelInfo, entry.Level)
			assert.Equal(t, LogEntryTypeKongApplication, entry.Type)
			assert.Equal(t, "namespace", entry.Namespace)

			// Message should be cleaned - no source info, no duplicate namespaces, no context
			assert.Equal(t, "test message content", entry.Message)

			// All metadata should be extracted to structured fields
			require.NotNil(t, entry.Fields)
			assert.Equal(t, "test_file.lua", entry.Fields["source_file"])
			assert.Equal(t, "123", entry.Fields["source_line"])
			assert.Equal(t, "worker.thread", entry.Fields["context"])
		})

		t.Run("multiline message", func(t *testing.T) {
			input := `2020/07/07 12:30:45 [error] 2694#0: main message
    continuation line 1
    continuation line 2`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogLevelError, entry.Level)
			assert.Equal(t, "main message", entry.Message)
			assert.Equal(t, LogEntryTypeKongApplication, entry.Type)
			assert.Equal(t, []string{"    continuation line 1", "    continuation line 2"}, entry.MultilineContent)

			// Check stats
			assert.Equal(t, 3, result.Stats.TotalLines)
			assert.Equal(t, 1, result.Stats.ParsedEntries)
			assert.Equal(t, 0, result.Stats.ErrorCount)
		})

		t.Run("invalid timestamp", func(t *testing.T) {
			input := `invalid-timestamp [info] 2694#0: message`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback).WithFlushTimeout(10 * time.Millisecond)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogEntryTypeUnknown, entry.Type)
			assert.Equal(t, LogLevelUnknown, entry.Level)
			assert.Equal(t, 1, result.Stats.ErrorCount)
		})

		t.Run("invalid process worker id", func(t *testing.T) {
			input := `2020/07/07 12:30:45 [info] abc#def: message`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback).WithFlushTimeout(10 * time.Millisecond)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			// This should parse as a Kong startup log (not application log) since abc#def: is not valid process#worker: format
			assert.Equal(t, LogEntryTypeKongApplication, entry.Type)
			assert.Equal(t, LogLevelInfo, entry.Level)
			assert.Equal(t, "abc#def: message", entry.Message)
			assert.Equal(t, 0, result.Stats.ErrorCount)
		})
	})

	t.Run("nginx access logs", func(t *testing.T) {
		t.Run("standard format", func(t *testing.T) {
			input := `127.0.0.1 - - [07/Jul/2020:12:30:45 +0000] "GET /api/health HTTP/1.1" 200 15 "-" "curl/7.68.0"`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogLevelInfo, entry.Level)
			assert.Equal(t, LogEntryTypeNginxAccess, entry.Type)
			require.NotNil(t, entry.HTTPRequest)
			assert.Equal(t, "127.0.0.1", entry.HTTPRequest.ClientAddress)
			assert.Equal(t, "GET", entry.HTTPRequest.Method)
			assert.Equal(t, "/api/health", entry.HTTPRequest.Path)
			assert.Equal(t, "HTTP/1.1", entry.HTTPRequest.Protocol)
			assert.Equal(t, 200, entry.HTTPRequest.StatusCode)
			assert.Equal(t, 15, entry.HTTPRequest.ResponseBytes)
			assert.Equal(t, "curl/7.68.0", entry.HTTPRequest.UserAgent)

			// Check stats
			assert.Equal(t, 1, result.Stats.TotalLines)
			assert.Equal(t, 1, result.Stats.ParsedEntries)
			assert.Equal(t, 0, result.Stats.ErrorCount)
		})

		t.Run("with extended fields", func(t *testing.T) {
			input := `127.0.0.1 - - [07/Jul/2020:12:30:45 +0000] "GET /api HTTP/1.1" 200 15 "http://example.com" "curl/7.68.0" host="example.com" upstream="backend:8080"`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			_, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogLevelInfo, entry.Level)
			assert.Equal(t, LogEntryTypeNginxAccess, entry.Type)
			require.NotNil(t, entry.HTTPRequest)
			assert.Equal(t, "http://example.com", entry.HTTPRequest.Referrer)

			// Extended fields are parsed into the Fields map
			require.NotNil(t, entry.Fields)
			assert.Contains(t, entry.Fields, "host=\"example.com\" upstream=\"backend")
		})

		t.Run("status code based log levels", func(t *testing.T) {
			testCases := []struct {
				name          string
				statusCode    string
				expectedLevel LogLevel
				description   string
			}{
				{
					name:          "1xx informational",
					statusCode:    "100",
					expectedLevel: LogLevelDebug,
					description:   "Continue",
				},
				{
					name:          "2xx success",
					statusCode:    "200",
					expectedLevel: LogLevelInfo,
					description:   "OK",
				},
				{
					name:          "201 created",
					statusCode:    "201",
					expectedLevel: LogLevelInfo,
					description:   "Created",
				},
				{
					name:          "3xx redirection",
					statusCode:    "301",
					expectedLevel: LogLevelInfo,
					description:   "Moved Permanently",
				},
				{
					name:          "302 found",
					statusCode:    "302",
					expectedLevel: LogLevelInfo,
					description:   "Found",
				},
				{
					name:          "4xx client error",
					statusCode:    "400",
					expectedLevel: LogLevelWarn,
					description:   "Bad Request",
				},
				{
					name:          "401 unauthorized",
					statusCode:    "401",
					expectedLevel: LogLevelWarn,
					description:   "Unauthorized",
				},
				{
					name:          "404 not found",
					statusCode:    "404",
					expectedLevel: LogLevelWarn,
					description:   "Not Found",
				},
				{
					name:          "5xx server error",
					statusCode:    "500",
					expectedLevel: LogLevelError,
					description:   "Internal Server Error",
				},
				{
					name:          "502 bad gateway",
					statusCode:    "502",
					expectedLevel: LogLevelError,
					description:   "Bad Gateway",
				},
				{
					name:          "503 service unavailable",
					statusCode:    "503",
					expectedLevel: LogLevelError,
					description:   "Service Unavailable",
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					input := fmt.Sprintf(`127.0.0.1 - - [07/Jul/2020:12:30:45 +0000] "GET /test HTTP/1.1" %s 15 "-" "curl/7.68.0"`, tc.statusCode)

					collector := NewTestEntryCollector()
					parser := NewParser().WithEntryCallback(collector.Callback)
					reader := strings.NewReader(input)

					_, err := parser.ParseReader(context.Background(), reader)
					require.NoError(t, err)

					entries := collector.WaitForEntries(1, 100*time.Millisecond)
					require.Len(t, entries, 1)

					entry := entries[0]
					assert.Equal(t, tc.expectedLevel, entry.Level, "Status code %s should map to %s level", tc.statusCode, tc.expectedLevel.String())
					assert.Equal(t, LogEntryTypeNginxAccess, entry.Type)
					require.NotNil(t, entry.HTTPRequest)

					statusCodeInt, _ := strconv.Atoi(tc.statusCode)
					assert.Equal(t, statusCodeInt, entry.HTTPRequest.StatusCode)
				})
			}
		})

		t.Run("invalid status codes", func(t *testing.T) {
			testCases := []struct {
				name       string
				statusCode string
			}{
				{
					name:       "non-numeric status code",
					statusCode: "abc",
				},
				{
					name:       "empty status code",
					statusCode: "",
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					input := fmt.Sprintf(`127.0.0.1 - - [07/Jul/2020:12:30:45 +0000] "GET /test HTTP/1.1" %s 15 "-" "curl/7.68.0"`, tc.statusCode)

					collector := NewTestEntryCollector()
					parser := NewParser().WithEntryCallback(collector.Callback)
					reader := strings.NewReader(input)

					result, err := parser.ParseReader(context.Background(), reader)
					require.NoError(t, err)

					entries := collector.WaitForEntries(1, 100*time.Millisecond)
					require.Len(t, entries, 1)

					entry := entries[0]
					assert.Equal(t, LogLevelUnknown, entry.Level, "Invalid status code should result in unknown log level")
					assert.Equal(t, LogEntryTypeUnknown, entry.Type)
					assert.Equal(t, 1, result.Stats.ErrorCount)
				})
			}
		})

		t.Run("unparseable timestamp", func(t *testing.T) {
			input := `127.0.0.1 - - [invalid-date] "GET /api HTTP/1.1" 200 15 "-" "curl/7.68.0"`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			// Still parses as access log, but timestamp is nil and raw_timestamp is preserved
			assert.Equal(t, LogEntryTypeNginxAccess, entry.Type)
			assert.Equal(t, LogLevelInfo, entry.Level)
			assert.Nil(t, entry.Timestamp)
			assert.Equal(t, "invalid-date", entry.RawTimestamp)
			assert.Equal(t, 0, result.Stats.ErrorCount)
		})

		t.Run("invalid status code", func(t *testing.T) {
			input := `127.0.0.1 - - [07/Jul/2020:12:30:45 +0000] "GET /api HTTP/1.1" abc 15 "-" "curl/7.68.0"`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogEntryTypeUnknown, entry.Type)
			assert.Equal(t, LogLevelUnknown, entry.Level)
			assert.Equal(t, 1, result.Stats.ErrorCount)
		})

		t.Run("invalid response bytes", func(t *testing.T) {
			input := `127.0.0.1 - - [07/Jul/2020:12:30:45 +0000] "GET /api HTTP/1.1" 200 abc "-" "curl/7.68.0"`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogEntryTypeUnknown, entry.Type)
			assert.Equal(t, LogLevelUnknown, entry.Level)
			assert.Equal(t, 1, result.Stats.ErrorCount)
		})

		t.Run("malformed HTTP request defaults to info level", func(t *testing.T) {
			input := `127.0.0.1 - - [07/Jul/2020:12:30:45 +0000] "INVALID" 200 15 "-" "curl/7.68.0"`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogEntryTypeNginxAccess, entry.Type)
			assert.Equal(t, LogLevelInfo, entry.Level) // Default to info when request can't be parsed
			assert.Empty(t, entry.Message) // No message set for malformed requests
			assert.Nil(t, entry.HTTPRequest) // No HTTP request object created for malformed requests
			assert.Equal(t, 0, result.Stats.ErrorCount)
		})
	})

	t.Run("nginx startup logs", func(t *testing.T) {
		t.Run("valid format", func(t *testing.T) {
			input := `nginx: [notice] nginx/1.21.6`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			assert.Equal(t, LogLevelNotice, entry.Level)
			assert.Equal(t, LogEntryTypeNginxStartup, entry.Type)
			assert.Equal(t, "nginx/1.21.6", entry.Message)

			// Check stats
			assert.Equal(t, 1, result.Stats.TotalLines)
			assert.Equal(t, 1, result.Stats.ParsedEntries)
			assert.Equal(t, 0, result.Stats.ErrorCount)
		})

		t.Run("invalid level", func(t *testing.T) {
			input := `nginx: [invalid-level] message`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			result, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			// Becomes unparseable due to invalid level
			assert.Equal(t, LogLevelUnknown, entry.Level)
			assert.Equal(t, LogEntryTypeUnknown, entry.Type)
			assert.Equal(t, 1, result.Stats.ErrorCount)
		})
	})

	t.Run("unparseable entries", func(t *testing.T) {
		testCases := []struct {
			name  string
			input string
		}{
			{
				name:  "orphaned continuation line",
				input: "    This is an orphaned continuation line",
			},
			{
				name:  "unrecognized format",
				input: "This is not a log format at all",
			},
			{
				name:  "malformed timestamp",
				input: "invalid-timestamp [info] 123#0: message",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				collector := NewTestEntryCollector()
				parser := NewParser().WithEntryCallback(collector.Callback)
				reader := strings.NewReader(tc.input)

				result, err := parser.ParseReader(context.Background(), reader)
				require.NoError(t, err)

				entries := collector.WaitForEntries(1, 100*time.Millisecond)
				require.Len(t, entries, 1)

				entry := entries[0]
				assert.Equal(t, LogEntryTypeUnknown, entry.Type)
				assert.Equal(t, LogLevelUnknown, entry.Level)
				assert.Equal(t, strings.TrimSpace(tc.input), entry.Message)
				assert.Equal(t, []string{tc.input}, entry.RawMessage)
				assert.Equal(t, 1, result.Stats.ErrorCount)
				assert.Len(t, result.Errors, 1)
			})
		}
	})

	t.Run("streaming functionality", func(t *testing.T) {
		t.Run("flush timeout", func(t *testing.T) {
			// Create a pipe for streaming test
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			defer reader.Close()
			defer writer.Close()

			collector := NewTestEntryCollector()
			parser := NewParser().
				WithFlushTimeout(100 * time.Millisecond).
				WithEntryCallback(collector.Callback)

			// Start parsing in a goroutine
			var parseErr error
			done := make(chan bool)

			go func() {
				defer close(done)
				_, parseErr = parser.ParseReader(context.Background(), reader)
			}()

			// Write incomplete entry and close
			_, err = writer.Write([]byte("2020/07/07 12:30:45 [info] 2694#0: incomplete\n    continuation"))
			require.NoError(t, err)
			writer.Close()

			// Wait for parsing to complete
			<-done
			require.NoError(t, parseErr)

			// Should have flushed the incomplete entry
			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)
			assert.Contains(t, entries[0].Message, "incomplete")
			assert.Contains(t, entries[0].MultilineContent[0], "continuation")
		})

		t.Run("is streaming detection", func(t *testing.T) {
			reader := strings.NewReader("test")
			streaming := isStreaming(reader)
			assert.False(t, streaming)
		})

		t.Run("isStreaming comprehensive tests", func(t *testing.T) {
			t.Run("returns false for non-file readers", func(t *testing.T) {
				reader := strings.NewReader("test data")
				assert.False(t, isStreaming(reader))
			})

			t.Run("returns true for stdin", func(t *testing.T) {
				assert.True(t, isStreaming(os.Stdin))
			})

			t.Run("returns true for pipes", func(t *testing.T) {
				reader, writer, err := os.Pipe()
				require.NoError(t, err)
				defer reader.Close()
				defer writer.Close()

				assert.True(t, isStreaming(reader))
			})

			t.Run("returns false for regular files", func(t *testing.T) {
				tempFile, err := os.CreateTemp("", "test-*.txt")
				require.NoError(t, err)
				defer os.Remove(tempFile.Name())
				defer tempFile.Close()

				_, err = tempFile.WriteString("test data")
				require.NoError(t, err)
				tempFile.Seek(0, 0)

				// Regular files should return false
				assert.False(t, isStreaming(tempFile))
			})

			t.Run("returns true for character devices that are not regular files", func(t *testing.T) {
				reader, writer, err := os.Pipe()
				require.NoError(t, err)
				defer reader.Close()
				defer writer.Close()

				stat, err := reader.Stat()
				require.NoError(t, err)

				// Verify this is not a character device (pipes are not character devices)
				assert.Equal(t, uint32(0), uint32(stat.Mode()&os.ModeCharDevice))
				assert.True(t, isStreaming(reader))
			})
		})
	})

	t.Run("timestamp parsing", func(t *testing.T) {
		t.Run("kong timestamp format", func(t *testing.T) {
			input := "2020/07/07 12:30:45 [info] 2694#0: test message"

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			_, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			require.NotNil(t, entry.Timestamp)
			assert.Equal(t, 2020, entry.Timestamp.Year())
			assert.Equal(t, time.July, entry.Timestamp.Month())
			assert.Equal(t, 7, entry.Timestamp.Day())
			assert.Equal(t, 12, entry.Timestamp.Hour())
			assert.Equal(t, 30, entry.Timestamp.Minute())
			assert.Equal(t, 45, entry.Timestamp.Second())
		})

		t.Run("access log timestamp format", func(t *testing.T) {
			input := `127.0.0.1 - - [07/Jul/2020:12:30:45 +0000] "GET /path HTTP/1.1" 200 15 "-" "curl/7.68.0"`

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)
			reader := strings.NewReader(input)

			_, err := parser.ParseReader(context.Background(), reader)
			require.NoError(t, err)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			require.Len(t, entries, 1)

			entry := entries[0]
			require.NotNil(t, entry.Timestamp)
			assert.Equal(t, 2020, entry.Timestamp.Year())
			assert.Equal(t, time.July, entry.Timestamp.Month())
			assert.Equal(t, 7, entry.Timestamp.Day())
			assert.Equal(t, 12, entry.Timestamp.Hour())
			assert.Equal(t, 30, entry.Timestamp.Minute())
			assert.Equal(t, 45, entry.Timestamp.Second())
		})
	})

	t.Run("comprehensive statistics", func(t *testing.T) {
		input := `2020/07/07 12:30:45 [info] 2694#0: info message
2020/07/07 12:30:46 [error] 2694#0: error message
127.0.0.1 - - [07/Jul/2020:12:30:47 +0000] "GET /api HTTP/1.1" 200 15 "-" "curl/7.68.0"
nginx: [notice] nginx/1.21.6
This is unparseable`

		collector := NewTestEntryCollector()
		parser := NewParser().WithEntryCallback(collector.Callback)
		reader := strings.NewReader(input)

		result, err := parser.ParseReader(context.Background(), reader)
		require.NoError(t, err)

		// Verify stats
		assert.Equal(t, 5, result.Stats.TotalLines)
		assert.Equal(t, 4, result.Stats.ParsedEntries) // 4 entries (unparseable attached as multiline)
		assert.Equal(t, 0, result.Stats.ErrorCount)    // No errors (unparseable is multiline content)

		// Log level counts (2 info: 1 kong + 1 access)
		assert.Equal(t, 2, result.Stats.LogLevelCount[LogLevelInfo])
		assert.Equal(t, 1, result.Stats.LogLevelCount[LogLevelError])
		assert.Equal(t, 1, result.Stats.LogLevelCount[LogLevelNotice])

		// Entry type counts
		assert.Equal(t, 2, result.Stats.EntryTypeCount[LogEntryTypeKongApplication])
		assert.Equal(t, 1, result.Stats.EntryTypeCount[LogEntryTypeNginxAccess])
		assert.Equal(t, 1, result.Stats.EntryTypeCount[LogEntryTypeNginxStartup])

		// Verify all entries were collected
		entries := collector.WaitForEntries(4, 100*time.Millisecond)
		assert.Len(t, entries, 4)
	})

	t.Run("buildSourcePattern edge cases", func(t *testing.T) {
		t.Run("insufficient matches", func(t *testing.T) {
			matches := []string{"", "", ""}
			result := buildSourcePattern(matches, "test message")
			assert.Empty(t, result)
		})

		t.Run("empty matches slice", func(t *testing.T) {
			matches := []string{}
			result := buildSourcePattern(matches, "test message")
			assert.Empty(t, result)
		})

		t.Run("nil matches", func(t *testing.T) {
			result := buildSourcePattern(nil, "test message")
			assert.Empty(t, result)
		})
	})

	t.Run("parsing errors create unknown entries", func(t *testing.T) {
		collector := NewTestEntryCollector()
		parser := NewParser()
		parser.entryCallback = collector.Callback

		// Create content that looks like a Kong log start but has invalid timestamp format
		// This should trigger isLogEntryStart but fail in parseKongLog
		invalidContent := "invalid/timestamp/format [info] 123#456: this looks like kong but has bad timestamp"
		reader := strings.NewReader(invalidContent)
		result, _ := parser.ParseReader(context.Background(), reader)

		// Should have parsing errors
		assert.Greater(t, result.Stats.ErrorCount, 0)
		assert.Len(t, result.Errors, 1)

		// Should create unknown entry with raw message
		entries := collector.WaitForEntries(1, 100*time.Millisecond)
		assert.Len(t, entries, 1)
		assert.Equal(t, LogEntryTypeUnknown, entries[0].Type)
		assert.Equal(t, LogLevelUnknown, entries[0].Level)
		assert.NotEmpty(t, entries[0].RawMessage)
	})

	t.Run("kong log parsing edge cases", func(t *testing.T) {
		collector := NewTestEntryCollector()
		parser := NewParser()
		parser.entryCallback = collector.Callback

		t.Run("invalid connection id", func(t *testing.T) {
			kongLog := `2020/07/07 12:30:45 [info] 123#456: *invalid_connection message content`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Nil(t, entries[0].RequestID)
		})

		t.Run("invalid process id", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] invalid#456: message content`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Nil(t, entries[0].ProcessID)
		})

		t.Run("invalid worker id", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#invalid: message content`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Nil(t, entries[0].WorkerID)
		})

		t.Run("empty connection id", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#456: message content`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Nil(t, entries[0].RequestID)
		})

		t.Run("source pattern with no function", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#456: [lua] file.lua:123: message without function`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Contains(t, entries[0].Fields, "source_file")
			assert.Equal(t, "file.lua", entries[0].Fields["source_file"])
			assert.Equal(t, "123", entries[0].Fields["source_line"])
			_, hasFuncField := entries[0].Fields["source_function"]
			assert.False(t, hasFuncField)
		})

		t.Run("namespace skips lua and kong", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#456: [lua] [kong] [clustering] actual message`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Equal(t, "clustering", entries[0].Namespace)
		})

		t.Run("buildSourcePattern no type prefix", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#456: file.lua:456: function_name(): message`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Contains(t, entries[0].Fields, "source_file")
			assert.Equal(t, "file.lua", entries[0].Fields["source_file"])
			assert.Equal(t, "456", entries[0].Fields["source_line"])
			assert.Equal(t, "function_name", entries[0].Fields["source_function"])
		})

		t.Run("source info without function or filename and line only", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#456: file.lua:456: message without function`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Contains(t, entries[0].Fields, "source_file")
			assert.Equal(t, "file.lua", entries[0].Fields["source_file"])
			assert.Equal(t, "456", entries[0].Fields["source_line"])
			assert.NotContains(t, entries[0].Fields, "source_function")
			assert.Equal(t, "message without function", entries[0].Message)
		})

		t.Run("kong timestamp parsing error", func(t *testing.T) {
			collector.Reset()
			kongLog := `9999/99/99 99:99:99 [info] 123#456: message with bad timestamp`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			// Should parse as Kong but with raw timestamp due to parse error
			assert.Equal(t, LogEntryTypeKongApplication, entries[0].Type)
			assert.Nil(t, entries[0].Timestamp)
			assert.Equal(t, "9999/99/99 99:99:99", entries[0].RawTimestamp)
		})

		t.Run("kong connection id parsing error", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#456: *abc message with non-numeric connection id`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			// Should parse as Kong but RequestID should be nil due to parse error
			assert.Equal(t, LogEntryTypeKongApplication, entries[0].Type)
			assert.Nil(t, entries[0].RequestID)
		})

		t.Run("kong namespace pattern removal", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#456: [custom] message with namespace pattern`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Equal(t, LogEntryTypeKongApplication, entries[0].Type)
			// Message should have namespace pattern removed
			assert.Equal(t, "message with namespace pattern", entries[0].Message)
		})

		t.Run("kong context extraction", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [info] 123#456: message with, context: request_id=abc123`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Equal(t, LogEntryTypeKongApplication, entries[0].Type)
			// Context should be extracted from message
			assert.Equal(t, "request_id=abc123", entries[0].Fields["context"])
		})

		t.Run("source info cleanup with colon after line number", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [debug] 100#0: *200 [lua] test.lua:42: [namespace] message content here`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Equal(t, LogEntryTypeKongApplication, entries[0].Type)

			// Source info should be extracted to fields
			assert.Equal(t, "test.lua", entries[0].Fields["source_file"])
			assert.Equal(t, "42", entries[0].Fields["source_line"])
			assert.Equal(t, "namespace", entries[0].Namespace)

			// Message should be cleaned - no source info prefix
			assert.Equal(t, "message content here", entries[0].Message)
			assert.NotContains(t, entries[0].Message, "[lua]")
			assert.NotContains(t, entries[0].Message, "test.lua:42:")
		})

		t.Run("source info cleanup with multiple namespace brackets", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [debug] 100#0: *200 [lua] test.lua:42: [namespace] [extra] message content here`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Equal(t, LogEntryTypeKongApplication, entries[0].Type)

			// Source info should be extracted to fields
			assert.Equal(t, "test.lua", entries[0].Fields["source_file"])
			assert.Equal(t, "42", entries[0].Fields["source_line"])
			assert.Equal(t, "namespace", entries[0].Namespace)

			// Additional tags should be captured in fields as array
			assert.Equal(t, []string{"extra"}, entries[0].Fields["tags"])

			// Message should be cleaned - no source info prefix or extra namespace brackets
			assert.Equal(t, "message content here", entries[0].Message)
			assert.NotContains(t, entries[0].Message, "[lua]")
			assert.NotContains(t, entries[0].Message, "test.lua:42:")
			assert.NotContains(t, entries[0].Message, "[extra]")
		})

		t.Run("multiple additional tags captured", func(t *testing.T) {
			collector.Reset()
			kongLog := `2020/07/07 12:30:45 [debug] 100#0: *200 [lua] test.lua:42: [messaging-utils] [counters] [stats] message content`
			reader := strings.NewReader(kongLog)
			parser.ParseReader(context.Background(), reader)

			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Equal(t, LogEntryTypeKongApplication, entries[0].Type)

			// First namespace becomes primary
			assert.Equal(t, "messaging-utils", entries[0].Namespace)

			// Additional tags should be captured in fields as array
			assert.Equal(t, []string{"counters", "stats"}, entries[0].Fields["tags"])

			// Message should be cleaned
			assert.Equal(t, "message content", entries[0].Message)
		})
	})

	t.Run("streaming reader edge cases", func(t *testing.T) {
		t.Run("scanner error handling", func(t *testing.T) {
			collector := NewTestEntryCollector()
			parser := NewParser()
			parser.entryCallback = collector.Callback

			// Create a reader that will cause scanner errors
			errorReader := &errorAfterReader{data: "2020/07/07 12:30:45 [info] 123#456: test message\n", errorAfter: 10}

			_, err := parser.ParseReader(context.Background(), errorReader)
			require.ErrorContains(t, err, "error reading input")
		})

		t.Run("flush timeout behavior", func(t *testing.T) {
			collector := NewTestEntryCollector()
			parser := NewParser()
			parser.WithFlushTimeout(1 * time.Millisecond)
			parser.entryCallback = collector.Callback

			// Create a slow reader that will trigger timeout
			slowReader := &slowReader{
				data: []string{
					"2020/07/07 12:30:45 [info] 123#456: message1",
					"  continuation line",
				},
				delay: 5 * time.Millisecond, // Longer than flush timeout
			}

			result, _ := parser.ParseReader(context.Background(), slowReader)

			// Should have processed the first entry due to timeout flush
			assert.Greater(t, result.Stats.ParsedEntries, 0)
			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Greater(t, len(entries), 0)
		})

		t.Run("streaming with actual pipe", func(t *testing.T) {
			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)

			// Create a real pipe to ensure streaming mode
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			defer reader.Close()
			defer writer.Close()

			// Start parsing in background
			done := make(chan error, 1)
			go func() {
				_, err := parser.ParseReader(context.Background(), reader)
				done <- err
			}()

			// Write test data
			testData := "2020/07/07 12:30:45 [info] 123#456: streaming test message\n"
			_, err = writer.Write([]byte(testData))
			require.NoError(t, err)
			writer.Close()

			// Wait for completion
			parseErr := <-done
			assert.NoError(t, parseErr)

			// Should have processed the entry
			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Equal(t, LogEntryTypeKongApplication, entries[0].Type)
		})

		t.Run("parseStreamingReader error from errChan", func(t *testing.T) {
			parser := NewParser().WithEntryCallback(func(LogEntry) {})
			reader := &errorAfterReader{data: "irrelevant", errorAfter: 0}
			result, err := parser.ParseReader(context.Background(), reader)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "simulated read error")
			assert.NotNil(t, result)
		})

		t.Run("parseStreamingReader flush timeout", func(t *testing.T) {
			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback).WithFlushTimeout(10 * time.Millisecond)
			reader, writer := io.Pipe()
			go func() {
				writer.Write([]byte("2020/07/07 12:30:45 [info] 2694#0: message\n"))
				time.Sleep(20 * time.Millisecond)
				writer.Close()
			}()
			result, err := parser.ParseReader(context.Background(), reader)
			assert.NoError(t, err)
			entries := collector.WaitForEntries(1, 100*time.Millisecond)
			assert.Len(t, entries, 1)
			assert.Equal(t, "message", entries[0].Message)
			assert.Equal(t, 1, result.Stats.ParsedEntries)
		})
	})

	t.Run("statusCodeToLogLevel function", func(t *testing.T) {
		testCases := []struct {
			name          string
			statusCode    int
			expectedLevel LogLevel
		}{
			// 1xx Informational
			{name: "100 Continue", statusCode: 100, expectedLevel: LogLevelDebug},
			{name: "101 Switching Protocols", statusCode: 101, expectedLevel: LogLevelDebug},
			{name: "102 Processing", statusCode: 102, expectedLevel: LogLevelDebug},
			{name: "199 boundary", statusCode: 199, expectedLevel: LogLevelDebug},

			// 2xx Success
			{name: "200 OK", statusCode: 200, expectedLevel: LogLevelInfo},
			{name: "201 Created", statusCode: 201, expectedLevel: LogLevelInfo},
			{name: "204 No Content", statusCode: 204, expectedLevel: LogLevelInfo},
			{name: "299 boundary", statusCode: 299, expectedLevel: LogLevelInfo},

			// 3xx Redirection
			{name: "300 Multiple Choices", statusCode: 300, expectedLevel: LogLevelInfo},
			{name: "301 Moved Permanently", statusCode: 301, expectedLevel: LogLevelInfo},
			{name: "302 Found", statusCode: 302, expectedLevel: LogLevelInfo},
			{name: "399 boundary", statusCode: 399, expectedLevel: LogLevelInfo},

			// 4xx Client Error
			{name: "400 Bad Request", statusCode: 400, expectedLevel: LogLevelWarn},
			{name: "401 Unauthorized", statusCode: 401, expectedLevel: LogLevelWarn},
			{name: "404 Not Found", statusCode: 404, expectedLevel: LogLevelWarn},
			{name: "499 boundary", statusCode: 499, expectedLevel: LogLevelWarn},

			// 5xx Server Error
			{name: "500 Internal Server Error", statusCode: 500, expectedLevel: LogLevelError},
			{name: "502 Bad Gateway", statusCode: 502, expectedLevel: LogLevelError},
			{name: "503 Service Unavailable", statusCode: 503, expectedLevel: LogLevelError},
			{name: "999 high boundary", statusCode: 999, expectedLevel: LogLevelError},

			// Invalid/Edge cases
			{name: "negative status code", statusCode: -1, expectedLevel: LogLevelUnknown},
			{name: "zero status code", statusCode: 0, expectedLevel: LogLevelUnknown},
			{name: "below 100", statusCode: 99, expectedLevel: LogLevelUnknown},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := statusCodeToLogLevel(tc.statusCode)
				assert.Equal(t, tc.expectedLevel, result,
					"Status code %d should map to log level %s", tc.statusCode, tc.expectedLevel.String())
			})
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		t.Run("batch mode context cancellation", func(t *testing.T) {
			// Create a large input that will take time to process
			var largeInput strings.Builder
			for i := 0; i < 1000; i++ {
				largeInput.WriteString(fmt.Sprintf("2020/07/07 12:30:45 [info] %d#0: test message %d\n", i, i))
			}

			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)

			// Create a context that will be cancelled quickly
			ctx, cancel := context.WithCancel(context.Background())

			// Cancel the context after a short delay
			go func() {
				time.Sleep(1 * time.Millisecond)
				cancel()
			}()

			reader := strings.NewReader(largeInput.String())
			result, err := parser.ParseReader(ctx, reader)

			// Context cancellation should return nil error with partial results
			assert.NoError(t, err)

			// Should have processed some entries but not all
			assert.NotNil(t, result)
			assert.Less(t, result.Stats.ParsedEntries, 1000)
		})

		t.Run("streaming mode context cancellation", func(t *testing.T) {
			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)

			// Create a pipe for streaming
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			defer reader.Close()
			defer writer.Close()

			// Create a context that will be cancelled
			ctx, cancel := context.WithCancel(context.Background())

			// Start parsing in a goroutine
			var parseErr error
			var result *ParseResult
			done := make(chan bool)

			go func() {
				defer close(done)
				result, parseErr = parser.ParseReader(ctx, reader)
			}()

			_, err = writer.Write([]byte("2020/07/07 12:30:45 [info] 1234#0: test message 1\n"))
			require.NoError(t, err)

			// Let it process the first entry
			time.Sleep(10 * time.Millisecond)
			cancel()
			<-done

			// Context cancellation should return nil error with partial results
			assert.NoError(t, parseErr)

			// Should have processed at least one entry
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Stats.ParsedEntries, 1)
		})

		t.Run("streaming mode goroutine respects context cancellation", func(t *testing.T) {
			collector := NewTestEntryCollector()
			parser := NewParser().WithEntryCallback(collector.Callback)

			// Create a pipe for streaming
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			defer reader.Close()
			defer writer.Close()

			// Create a context that will be cancelled immediately
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Cancel immediately

			// Start parsing - should return quickly due to cancelled context
			start := time.Now()
			result, parseErr := parser.ParseReader(ctx, reader)
			elapsed := time.Since(start)

			// Should return quickly (within 100ms) and with context cancelled error
			assert.Less(t, elapsed, 100*time.Millisecond)
			assert.NoError(t, parseErr)
			assert.NotNil(t, result)
		})

		t.Run("context with deadline", func(t *testing.T) {
			collector := NewTestEntryCollector()
			parser := NewParser().WithFlushTimeout(100 * time.Millisecond)
			parser = parser.WithEntryCallback(collector.Callback)

			// Create a context with a short deadline
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()

			// Create a slow reader
			slowReader := &slowReader{
				data: []string{
					"2020/07/07 12:30:45 [info] 1234#0: message1",
					"2020/07/07 12:30:46 [info] 1234#0: message2",
				},
				delay: 100 * time.Millisecond, // Longer than context deadline
			}
			result, err := parser.ParseReader(ctx, slowReader)

			// Context deadline should return nil error with partial results
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	})

	t.Run("parseAccessLogExtras edge cases", func(t *testing.T) {
		parser := NewParser()

		t.Run("kong_request_id with HTTPRequest set", func(t *testing.T) {
			entry := &LogEntry{
				Fields:      make(map[string]interface{}),
				HTTPRequest: &HTTPRequestInfo{}, // HTTPRequest is set
			}

			extras := "kong_request_id: req-123-456"
			parser.parseAccessLogExtras(entry, extras)
			assert.Equal(t, "req-123-456", entry.Fields["kong_request_id"])
			assert.Equal(t, "req-123-456", entry.HTTPRequest.KongRequestID)
		})

		t.Run("kong_request_id with HTTPRequest nil", func(t *testing.T) {
			entry := &LogEntry{
				Fields:      make(map[string]interface{}),
				HTTPRequest: nil, // HTTPRequest is nil
			}

			extras := "kong_request_id: req-789"
			parser.parseAccessLogExtras(entry, extras)
			assert.Equal(t, "req-789", entry.Fields["kong_request_id"])
		})

		t.Run("empty extras string", func(t *testing.T) {
			entry := &LogEntry{
				Fields: make(map[string]interface{}),
			}

			parser.parseAccessLogExtras(entry, "")
			parser.parseAccessLogExtras(entry, "   ")
			assert.Empty(t, entry.Fields)
		})

		t.Run("malformed key-value pairs", func(t *testing.T) {
			entry := &LogEntry{
				Fields: make(map[string]interface{}),
			}

			extras := "no_colon_here, :starts_with_colon, key: value"
			parser.parseAccessLogExtras(entry, extras)

			// Only the valid "key: value" should be parsed
			assert.Equal(t, 1, len(entry.Fields))
			assert.Equal(t, "value", entry.Fields["key"])
		})
	})
}
