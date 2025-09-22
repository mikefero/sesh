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

// Package sesh provides Kong Gateway log parsing functionality.
package sesh

import (
	"encoding/json"
	"fmt"
	"time"
)

// LogEntry represents a complete Kong Gateway log entry that may span multiple lines.
// This is the unified structure that all parsed log types will be converted into.
type LogEntry struct {
	// Timestamp is the parsed timestamp from the log entry
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// RawTimestamp preserves the original timestamp string from all log formats
	RawTimestamp string `json:"raw_timestamp,omitempty"`
	// Level represents the log level (debug, info, notice, warn, error, crit)
	Level LogLevel `json:"level"`
	// ProcessID is the nginx process ID; may be nil for access logs
	ProcessID *int `json:"process_id,omitempty"`
	// WorkerID is the nginx worker ID; may be nil for access logs
	WorkerID *int `json:"worker_id,omitempty"`
	// RequestID is the nginx request ID; may be nil for some log types
	RequestID *int `json:"request_id,omitempty"`
	// Message contains the main log message content
	Message string `json:"message"`
	// MultilineContent contains additional lines for multi-line entries; e.g. bad config, stack traces, ...etc
	MultilineContent []string `json:"multiline_content,omitempty"`
	// Type indicates the detected log entry type
	Type LogEntryType `json:"type"`
	// Namespace is the Kong namespace; e.g., plugin name, service context, or other identifier
	Namespace string `json:"namespace,omitempty"`
	// Fields contains parsed structured fields from the log entry
	Fields map[string]interface{} `json:"fields,omitempty"`
	// HTTPRequest contains HTTP request information for access logs
	HTTPRequest *HTTPRequestInfo `json:"http_request,omitempty"`
	// RawMessage contains the original log lines that formed this entry
	RawMessage []string `json:"raw_message,omitempty"`

	// clef indicates whether this entry should be rendered in CLEF format
	clef bool `json:"-"`
}

// MarshalJSON implements the json.Marshaler interface for LogEntry.
func (le LogEntry) MarshalJSON() ([]byte, error) {
	if le.clef {
		clefLevel := le.Level.String()
		switch clefLevel {
		case "debug":
			clefLevel = "Debug"
		case "info":
			//nolint:goconst
			clefLevel = "Information"
		case "notice":
			clefLevel = "Information"
		case "warn":
			clefLevel = "Warning"
		case "error":
			clefLevel = "Error"
		case "alert":
			clefLevel = "Error"
		case "crit":
			clefLevel = "Fatal"
		case "unknown":
			clefLevel = "Information"
		}

		//nolint:wrapcheck
		return json.Marshal(struct {
			Timestamp        *time.Time        `json:"@t,omitempty"`
			RawTimestamp     string            `json:"raw_timestamp,omitempty"`
			Level            string            `json:"@l"`
			ProcessID        *int              `json:"process_id,omitempty"`
			WorkerID         *int              `json:"worker_id,omitempty"`
			RequestID        *int              `json:"request_id,omitempty"`
			Message          string            `json:"@m"`
			MultilineContent []string          `json:"multiline_content,omitempty"`
			Type             LogEntryType      `json:"@i"`
			Namespace        string            `json:"namespace,omitempty"`
			Fields           map[string]interface{} `json:"fields,omitempty"`
			HTTPRequest      *HTTPRequestInfo  `json:"http_request,omitempty"`
			RawMessage       []string          `json:"raw_message,omitempty"`
		}{
			Timestamp:        le.Timestamp,
			RawTimestamp:     le.RawTimestamp,
			Level:            clefLevel,
			ProcessID:        le.ProcessID,
			WorkerID:         le.WorkerID,
			RequestID:        le.RequestID,
			Message:          le.Message,
			MultilineContent: le.MultilineContent,
			Type:             le.Type,
			Namespace:        le.Namespace,
			Fields:           le.Fields,
			HTTPRequest:      le.HTTPRequest,
			RawMessage:       le.RawMessage,
		})
	}

	type Alias LogEntry
	//nolint:wrapcheck
	return json.Marshal(Alias(le))
}

// LogLevel represents the severity level of a log entry.
type LogLevel int

const (
	// LogLevelUnknown represents an unparseable or missing log level.
	LogLevelUnknown LogLevel = iota
	// LogLevelDebug represents debug messages.
	LogLevelDebug
	// LogLevelInfo represents informational messages.
	LogLevelInfo
	// LogLevelNotice represents notice messages.
	LogLevelNotice
	// LogLevelWarn represents warning messages.
	LogLevelWarn
	// LogLevelError represents error messages.
	LogLevelError
	// LogLevelAlert represents alert messages.
	LogLevelAlert
	// LogLevelCritical represents critical messages.
	LogLevelCritical
)

// String constants for log levels.
const (
	levelUnknown  = "unknown"
	levelDebug    = "debug"
	levelInfo     = "info"
	levelNotice   = "notice"
	levelWarn     = "warn"
	levelError    = "error"
	levelAlert    = "alert"
	levelCritical = "crit"
)

// String returns the string representation of the log level.
func (ll LogLevel) String() string {
	switch ll {
	case LogLevelUnknown:
		return levelUnknown
	case LogLevelDebug:
		return levelDebug
	case LogLevelInfo:
		return levelInfo
	case LogLevelNotice:
		return levelNotice
	case LogLevelWarn:
		return levelWarn
	case LogLevelError:
		return levelError
	case LogLevelAlert:
		return levelAlert
	case LogLevelCritical:
		return levelCritical
	default:
		return levelUnknown
	}
}

// MarshalJSON implements custom JSON marshaling for LogLevel.
func (ll LogLevel) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(ll.String())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal log level: %w", err)
	}
	return data, nil
}

// ParseLogLevel converts a string to a LogLevel.
func ParseLogLevel(s string) LogLevel {
	switch s {
	case levelDebug:
		return LogLevelDebug
	case levelInfo:
		return LogLevelInfo
	case levelNotice:
		return LogLevelNotice
	case levelWarn:
		return LogLevelWarn
	case levelError:
		return LogLevelError
	case levelAlert:
		return LogLevelAlert
	case levelCritical:
		return LogLevelCritical
	default:
		return LogLevelUnknown
	}
}

// LogEntryType categorizes the type of log entry for specialized parsing.
type LogEntryType int

const (
	// LogEntryTypeUnknown represents an unrecognized log entry type.
	LogEntryTypeUnknown LogEntryType = iota
	// LogEntryTypeKongApplication represents standard Kong application logs.
	LogEntryTypeKongApplication
	// LogEntryTypeNginxAccess represents nginx access log entries.
	LogEntryTypeNginxAccess
	// LogEntryTypeNginxStartup represents nginx startup/configuration messages.
	LogEntryTypeNginxStartup
)

// String constants for log entry types.
const (
	entryTypeUnknown = "unknown"
	entryTypeKong    = "kong"
	entryTypeAccess  = "access"
	entryTypeNginx   = "nginx"
)

// String returns the string representation of the log entry type.
func (let LogEntryType) String() string {
	switch let {
	case LogEntryTypeUnknown:
		return entryTypeUnknown
	case LogEntryTypeKongApplication:
		return entryTypeKong
	case LogEntryTypeNginxAccess:
		return entryTypeAccess
	case LogEntryTypeNginxStartup:
		return entryTypeNginx
	default:
		return entryTypeUnknown
	}
}

// MarshalJSON implements custom JSON marshaling for LogEntryType.
func (let LogEntryType) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(let.String())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal log entry type: %w", err)
	}
	return data, nil
}

// HTTPRequestInfo contains HTTP request details from access logs.
type HTTPRequestInfo struct {
	// ClientAddress is the raw client address; may be hostname or IP
	ClientAddress string `json:"client_address"`
	// RemoteUser is the authenticated user; omitted if "-"
	RemoteUser string `json:"remote_user,omitempty"`
	// RemoteLogname is the remote logname from identd; omitted if "-"
	RemoteLogname string `json:"remote_logname,omitempty"`
	// Method is the HTTP method; e.g. GET, POST, ...etc
	Method string `json:"method"`
	// Path is the requested path
	Path string `json:"path"`
	// Protocol is the HTTP protocol version
	Protocol string `json:"protocol"`
	// StatusCode is the HTTP response status code
	StatusCode int `json:"status_code"`
	// ResponseBytes is the number of bytes in the response
	ResponseBytes int `json:"response_bytes"`
	// Referrer is the HTTP referrer header
	Referrer string `json:"referrer,omitempty"`
	// UserAgent is the HTTP user agent header
	UserAgent string `json:"user_agent,omitempty"`
	// KongRequestID is the Kong-specific request identifier
	KongRequestID string `json:"kong_request_id,omitempty"`
	// Host is the Host header value
	Host string `json:"host,omitempty"`
	// Server identifies the Kong server instance
	Server string `json:"server,omitempty"`
	// Upstream contains upstream server information
	Upstream string `json:"upstream,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for HTTPRequestInfo
// to omit fields when they are "-"; indicating no value in nginx logs.
func (h HTTPRequestInfo) MarshalJSON() ([]byte, error) {
	type Alias HTTPRequestInfo
	aux := &struct {
		RemoteUser    *string `json:"remote_user,omitempty"`
		RemoteLogname *string `json:"remote_logname,omitempty"`
		Referrer      *string `json:"referrer,omitempty"`
		UserAgent     *string `json:"user_agent,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(&h),
	}

	// Only include RemoteUser if it's valid
	if h.RemoteUser != "" && h.RemoteUser != "-" {
		aux.RemoteUser = &h.RemoteUser
	}

	// Only include RemoteLogname if it's valid
	if h.RemoteLogname != "" && h.RemoteLogname != "-" {
		aux.RemoteLogname = &h.RemoteLogname
	}

	// Only include Referrer if it's valid
	if h.Referrer != "" && h.Referrer != "-" {
		aux.Referrer = &h.Referrer
	}

	// Only include UserAgent if it's valid
	if h.UserAgent != "" && h.UserAgent != "-" {
		aux.UserAgent = &h.UserAgent
	}

	data, err := json.Marshal(aux)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HTTP request info: %w", err)
	}
	return data, nil
}

// ParseResult represents the result of parsing a log file or stream.
type ParseResult struct {
	// Errors contains any parsing errors encountered
	Errors []ParseError
	// Stats contains parsing statistics
	Stats ParseStats
}

// ParseError represents an error that occurred during log parsing.
type ParseError struct {
	// LineNumber is the line number where the error occurred
	LineNumber int
	// RawLine is the raw log line that caused the error
	RawLine string
	// Error is the underlying error
	Error error
}

// ParseStats contains statistics about the parsing operation.
type ParseStats struct {
	// TotalLines is the total number of lines processed
	TotalLines int
	// ParsedEntries is the number of successfully parsed log entries
	ParsedEntries int
	// ErrorCount is the number of parsing errors
	ErrorCount int
	// EntryTypeCount maps log entry types to their occurrence count
	EntryTypeCount map[LogEntryType]int
	// LogLevelCount maps log levels to their occurrence count
	LogLevelCount map[LogLevel]int
}
