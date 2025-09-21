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
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "embed"
)

// License contains the embedded license for the application/module.
//
//go:embed LICENSE
var License string

// DefaultFlushTimeout is the default timeout for flushing incomplete entries in streaming mode.
const DefaultFlushTimeout = 2 * time.Second

// Parser provides Kong Gateway log parsing functionality.
type Parser struct {
	// FlushTimeout is the timeout for flushing incomplete entries in streaming mode
	FlushTimeout time.Duration
	// EntryCallback is called for each parsed entry
	EntryCallback func(LogEntry)
	// CLEF indicates whether entries should be formatted in CLEF format
	CLEF bool
}

// NewParser creates a new Kong Gateway log parser with default settings.
func NewParser() *Parser {
	return &Parser{
		FlushTimeout: DefaultFlushTimeout,
	}
}

// WithFlushTimeout sets a custom flush timeout for streaming mode and returns the parser.
func (p *Parser) WithFlushTimeout(timeout time.Duration) *Parser {
	p.FlushTimeout = timeout
	return p
}

// WithEntryCallback sets a callback function that will be called for each parsed entry
// and returns the parser.
func (p *Parser) WithEntryCallback(callback func(LogEntry)) *Parser {
	p.EntryCallback = callback
	return p
}

// WithCLEF enables or disables CLEF formatting for parsed entries and returns the parser.
func (p *Parser) WithCLEF(enabled bool) *Parser {
	p.CLEF = enabled
	return p
}

// ParseReader parses Kong Gateway logs from an io.Reader.
// Requires a callback to be set for processing entries.
func (p *Parser) ParseReader(ctx context.Context, reader io.Reader) (*ParseResult, error) {
	if p.EntryCallback == nil {
		return nil, fmt.Errorf("entry callback is required; use WithEntryCallback() to set one")
	}

	if isStreaming(reader) {
		return p.parseStreamingReader(ctx, reader)
	}
	return p.parseFileReader(ctx, reader)
}

// Regular expressions for detecting and parsing log entries.
var (
	// Kong application log: YYYY/MM/DD HH:MM:SS [level] processId#workerId: *connectionId [optional_info] message.
	kongLogRegex = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): (\*(\d+) )?(.*)$`)
	// Kong startup log: YYYY/MM/DD HH:MM:SS [level] message (without process IDs).
	kongStartupRegex = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.*)$`)
	// Nginx access log: client - - [timestamp] "METHOD path PROTOCOL" status bytes "referrer" "user_agent" extras.
	accessLogRegex = regexp.MustCompile(
		`^([^\s]+) ([^\s]+) ([^\s]+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"(.*)$`)
	// Nginx startup: nginx: [level] message.
	nginxStartupRegex = regexp.MustCompile(`^nginx: \[(\w+)\] (.*)$`)
	// Source info: [lua] filename:line: function(): or filename:line function() or just filename:line.
	sourceInfoRegex = regexp.MustCompile(`(?:\[(\w+)\] )?([^:\s]+):(\d+):?\s*(?:([^:\s]+)\(\):?\s*)?`)
	// Namespace: [namespace].
	namespaceRegex = regexp.MustCompile(`\[([^\]]+)\]`)
	// Context: context: value.
	contextRegex = regexp.MustCompile(`, context: (.+)`)
)

// isStreaming determines if we're reading from a pipe/stream vs a regular file.
func isStreaming(reader io.Reader) bool {
	if file, ok := reader.(*os.File); ok {
		stat, err := file.Stat()
		if err != nil {
			return true // assume streaming if we can't stat
		}

		// Check if it's stdin
		if file == os.Stdin {
			return true
		}

		// Check if it's a pipe, socket, or other non-regular file that's not a character device
		mode := stat.Mode()
		if (mode&os.ModeCharDevice) == 0 && !mode.IsRegular() {
			return true
		}
	}
	return false
}

// parseCommon handles common parsing logic for both file and streaming modes.
// Both modes process lines incrementally (one at a time) to avoid loading entire files into memory.
// The difference is in flushing behavior:
// - File mode: only processes complete log entries.
// - Streaming mode: also flushes incomplete entries after timeout for real-time processing.
func (p *Parser) parseCommon(ctx context.Context, reader io.Reader,
	inputHandler func(context.Context, *bufio.Scanner) (<-chan string, <-chan error),
	useTimeout bool) (*ParseResult, error) {
	result := p.createParseResult()
	scanner := bufio.NewScanner(reader)
	lineNumber := 0
	var currentEntry []string // Accumulates lines for multi-line log entries

	// Get channels from the input handler; same goroutine pattern for both modes
	lineChan, errChan := inputHandler(ctx, scanner)

	// Set up timeout channel only for streaming mode
	// Note: nil channel blocks forever in select, effectively disabling timeout case
	var timeoutChan <-chan time.Time
	if useTimeout {
		timeoutChan = time.After(p.FlushTimeout)
	}

	for {
		select {
		// Context cancellation; process any remaining entry and exit gracefully
		case <-ctx.Done():
			if len(currentEntry) > 0 {
				p.processEntry(currentEntry, result)
			}
			return result, nil

		// New line received from input
		case line, ok := <-lineChan:
			if !ok {
				// Input channel closed; process final entry and exit
				if len(currentEntry) > 0 {
					p.processEntry(currentEntry, result)
				}
				return result, nil
			}

			lineNumber++
			// processLine handles multi-line entry detection and accumulation
			currentEntry = p.processLine(line, lineNumber, currentEntry, result)

		// Scanner error from input handler goroutine
		case err := <-errChan:
			if err != nil {
				return result, fmt.Errorf("error reading input: %w", err)
			}

		// Timeout reached (streaming mode only); flush incomplete entry for real-time processing
		case <-timeoutChan:
			if useTimeout {
				if len(currentEntry) > 0 {
					p.processEntry(currentEntry, result)
					currentEntry = nil // Clear the buffer after flushing
				}
				// Reset timeout for next flush cycle
				timeoutChan = time.After(p.FlushTimeout)
			}
		}
	}
}

// parseFileReader handles file processing.
func (p *Parser) parseFileReader(ctx context.Context, reader io.Reader) (*ParseResult, error) {
	// Input handler that reads lines from scanner in a goroutine
	inputHandler := func(ctx context.Context, scanner *bufio.Scanner) (<-chan string, <-chan error) {
		lineChan := make(chan string)
		errChan := make(chan error)

		go func() {
			defer close(lineChan)
			defer close(errChan)

			// Read lines one by one and send to channel
			for scanner.Scan() {
				select {
				case <-ctx.Done():
					return // Exit if context is canceled
				case lineChan <- scanner.Text():
				}
			}

			// Send any scanner errors to error channel
			if err := scanner.Err(); err != nil {
				select {
				case <-ctx.Done():
					return
				case errChan <- err:
				}
			}
		}()

		return lineChan, errChan
	}

	return p.parseCommon(ctx, reader, inputHandler, false)
}

// parseStreamingReader handles streaming processing for pipes/stdin.
func (p *Parser) parseStreamingReader(ctx context.Context, reader io.Reader) (*ParseResult, error) {
	// Input handler that reads lines from scanner in a goroutine
	inputHandler := func(ctx context.Context, scanner *bufio.Scanner) (<-chan string, <-chan error) {
		lineChan := make(chan string)
		errChan := make(chan error)

		go func() {
			defer close(lineChan)
			defer close(errChan)

			// Read lines one by one and send to channel
			for scanner.Scan() {
				select {
				case <-ctx.Done():
					return // Exit if context is canceled
				case lineChan <- scanner.Text():
				}
			}

			// Send any scanner errors to error channel
			if err := scanner.Err(); err != nil {
				select {
				case <-ctx.Done():
					return
				case errChan <- err:
				}
			}
		}()

		return lineChan, errChan
	}

	return p.parseCommon(ctx, reader, inputHandler, true)
}

// createParseResult creates a new ParseResult with initialized maps.
func (p *Parser) createParseResult() *ParseResult {
	return &ParseResult{
		Errors: make([]ParseError, 0),
		Stats: ParseStats{
			EntryTypeCount: make(map[LogEntryType]int),
			LogLevelCount:  make(map[LogLevel]int),
		},
	}
}

// processLine handles a single line and returns the updated currentEntry.
func (p *Parser) processLine(line string, lineNumber int, currentEntry []string, result *ParseResult) []string {
	result.Stats.TotalLines++

	// Check if this line starts a new log entry
	if p.isLogEntryStart(line) {
		// Process the previous entry if it exists
		if len(currentEntry) > 0 {
			p.processEntry(currentEntry, result)
		}
		// Start a new entry
		return []string{line}
	}

	// Add to current multi-line entry
	if len(currentEntry) > 0 {
		return append(currentEntry, line)
	}

	// Orphaned continuation line or a line that doesn't start a log entry
	// Treat it as a separate unknown entry if it's not just whitespace
	if len(strings.TrimSpace(line)) > 0 {
		orphanedEntry := &LogEntry{
			Type:       LogEntryTypeUnknown,
			Level:      LogLevelUnknown,
			Message:    strings.TrimSpace(line),
			RawMessage: []string{line},
			clef:       p.CLEF,
		}

		result.Stats.ParsedEntries++
		result.Stats.EntryTypeCount[orphanedEntry.Type]++
		result.Stats.LogLevelCount[orphanedEntry.Level]++

		// Still record the parsing error
		result.Errors = append(result.Errors, ParseError{
			LineNumber: lineNumber,
			RawLine:    line,
			Error:      fmt.Errorf("orphaned line without a starting log entry"),
		})
		result.Stats.ErrorCount++

		// Process the orphaned entry; create copy for goroutine
		go p.EntryCallback(*orphanedEntry)
	}

	return currentEntry
}

// processEntry is a helper to parse and add an entry to results.
func (p *Parser) processEntry(entryLines []string, result *ParseResult) {
	entry := p.parseLogEntry(entryLines)
	entry.clef = p.CLEF

	// Update stats and call callback
	result.Stats.ParsedEntries++
	result.Stats.EntryTypeCount[entry.Type]++
	result.Stats.LogLevelCount[entry.Level]++

	// Create a copy of the entry for the goroutine to avoid race conditions
	go p.EntryCallback(*entry)
}

// isLogEntryStart determines if a line starts a new log entry.
func (p *Parser) isLogEntryStart(line string) bool {
	return kongLogRegex.MatchString(line) ||
		kongStartupRegex.MatchString(line) ||
		accessLogRegex.MatchString(line) ||
		nginxStartupRegex.MatchString(line)
}

// parseLogEntry parses a complete log entry; potentially multi-line.
func (p *Parser) parseLogEntry(lines []string) *LogEntry {
	firstLine := lines[0]
	multilineContent := lines[1:]

	entry := &LogEntry{
		RawMessage:       lines,
		MultilineContent: multilineContent,
		Fields:           make(map[string]string),
	}

	// Try parsing as different log types
	if p.parseKongLog(entry, firstLine) {
		return entry
	}
	if p.parseKongStartupLog(entry, firstLine) {
		return entry
	}
	if p.parseAccessLog(entry, firstLine) {
		return entry
	}
	if p.parseNginxStartupLog(entry, firstLine) {
		return entry
	}

	// This should never happen since isLogEntryStart already verified
	// that one of the regexes matches; return unknown entry as fallback
	entry.Type = LogEntryTypeUnknown
	entry.Level = LogLevelUnknown
	entry.Message = firstLine
	return entry
}

// parseKongLog parses a Kong application log entry.
func (p *Parser) parseKongLog(entry *LogEntry, line string) bool {
	matches := kongLogRegex.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	entry.Type = LogEntryTypeKongApplication

	// Parse timestamp; don't fail if parsing fails, just store raw timestamp
	if timestamp, err := time.Parse("2006/01/02 15:04:05", matches[1]); err == nil {
		entry.Timestamp = &timestamp
	} else {
		entry.RawTimestamp = matches[1]
	}
	entry.Level = ParseLogLevel(matches[2])

	if processID, err := strconv.Atoi(matches[3]); err == nil {
		entry.ProcessID = &processID
	}
	if workerID, err := strconv.Atoi(matches[4]); err == nil {
		entry.WorkerID = &workerID
	}
	if matches[6] != "" {
		if connectionID, err := strconv.Atoi(matches[6]); err == nil {
			entry.RequestID = &connectionID
		}
	}

	messageContent := matches[7]

	// Extract source information
	if sourceMatches := sourceInfoRegex.FindStringSubmatch(messageContent); sourceMatches != nil {
		entry.Fields["source_file"] = sourceMatches[2]
		entry.Fields["source_line"] = sourceMatches[3]
		if sourceMatches[4] != "" {
			entry.Fields["source_function"] = sourceMatches[4]
		}
	}

	// Extract namespace; look for bracketed content that isn't source info
	namespaceMatches := namespaceRegex.FindAllStringSubmatch(messageContent, -1)
	for _, match := range namespaceMatches {
		namespace := match[1]
		// Skip source types like "lua", "kong"
		if namespace != "lua" && namespace != "kong" {
			entry.Namespace = namespace
			break
		}
	}

	// Now clean up the message by removing redundant information
	cleanedMessage := messageContent

	// Remove source file information if present; e.g., "[kong] data_plane.lua:376" or "[lua] test.lua:42: "
	if cleanupSourceMatches := sourceInfoRegex.FindStringSubmatch(cleanedMessage); cleanupSourceMatches != nil {
		if sourcePattern := buildSourcePattern(cleanupSourceMatches); sourcePattern != "" {
			if after, found := strings.CutPrefix(cleanedMessage, sourcePattern); found {
				cleanedMessage = after
			}
		}
	}

	// Remove ALL namespace brackets, including duplicates, that aren't source types
	for {
		cleanupNamespaceMatches := namespaceRegex.FindAllStringSubmatch(cleanedMessage, -1)
		removed := false
		for _, match := range cleanupNamespaceMatches {
			namespace := match[1]
			// Skip source types like "lua", "kong"
			if namespace != "lua" && namespace != "kong" {
				namespacePattern := fmt.Sprintf("[%s] ", namespace)
				if after, found := strings.CutPrefix(cleanedMessage, namespacePattern); found {
					cleanedMessage = after
					removed = true
					break
				}
			}
		}
		// Keep removing until no more namespace patterns found
		if !removed {
			break
		}
	}

	// Remove context information since it's extracted to fields
	if contextMatch := contextRegex.FindStringSubmatch(cleanedMessage); contextMatch != nil {
		contextPattern := fmt.Sprintf(", context: %s", contextMatch[1])
		cleanedMessage = strings.TrimSuffix(cleanedMessage, contextPattern)
	}

	// Remove trailing spaces and colons
	cleanedMessage = strings.TrimRight(cleanedMessage, " :")
	entry.Message = cleanedMessage

	// Extract context
	if contextMatch := contextRegex.FindStringSubmatch(messageContent); contextMatch != nil {
		entry.Fields["context"] = strings.TrimSpace(contextMatch[1])
	}

	return true
}

// parseKongStartupLog parses a Kong startup log entry; without process/worker IDs.
func (p *Parser) parseKongStartupLog(entry *LogEntry, line string) bool {
	matches := kongStartupRegex.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	entry.Type = LogEntryTypeKongApplication

	// Parse timestamp; don't fail if parsing fails, just store raw timestamp
	if timestamp, err := time.Parse("2006/01/02 15:04:05", matches[1]); err == nil {
		entry.Timestamp = &timestamp
	} else {
		entry.RawTimestamp = matches[1]
	}
	entry.Level = ParseLogLevel(matches[2])
	entry.Message = matches[3]

	return true
}

// statusCodeToLogLevel maps HTTP status codes to appropriate log levels.
func statusCodeToLogLevel(statusCode int) LogLevel {
	switch {
	case statusCode >= 100 && statusCode < 200:
		return LogLevelDebug // 1xx Informational
	case statusCode >= 200 && statusCode < 400:
		return LogLevelInfo // 2xx Success, 3xx Redirection
	case statusCode >= 400 && statusCode < 500:
		return LogLevelWarn // 4xx Client Error
	case statusCode >= 500:
		return LogLevelError // 5xx Server Error
	default:
		return LogLevelUnknown // Invalid status code
	}
}

// buildSourcePattern builds a source pattern string for cleanup based on regex matches.
func buildSourcePattern(matches []string) string {
	if len(matches) < 4 {
		return ""
	}

	if matches[1] != "" {
		// Has [type] prefix: "[kong] filename:line " or "[lua] filename:line: function(): "
		if matches[4] != "" {
			// With function: "[lua] filename:line: function(): "
			return fmt.Sprintf("[%s] %s:%s: %s(): ", matches[1], matches[2], matches[3], matches[4])
		}
		// Without function: "[kong] filename:line " (space after line number, no colon)
		return fmt.Sprintf("[%s] %s:%s ", matches[1], matches[2], matches[3])
	}

	// No [type] prefix: "filename:line: " or "filename:line: function(): "
	if matches[4] != "" {
		return fmt.Sprintf("%s:%s: %s(): ", matches[2], matches[3], matches[4])
	}
	return fmt.Sprintf("%s:%s: ", matches[2], matches[3])
}

// parseAccessLog parses an nginx access log entry.
func (p *Parser) parseAccessLog(entry *LogEntry, line string) bool {
	matches := accessLogRegex.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	entry.Type = LogEntryTypeNginxAccess

	// Parse timestamp; don't fail if parsing fails, just store raw timestamp
	if timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[4]); err == nil {
		entry.Timestamp = &timestamp
	} else {
		entry.RawTimestamp = matches[4]
	}

	// Parse HTTP request details
	requestParts := strings.Fields(matches[5])
	if len(requestParts) >= 3 {
		entry.Message = matches[5]

		entry.HTTPRequest = &HTTPRequestInfo{
			ClientAddress: matches[1],
			RemoteUser:    matches[2],
			RemoteLogname: matches[3],
			Method:        requestParts[0],
			Path:          requestParts[1],
			Protocol:      requestParts[2],
			Referrer:      matches[8],
			UserAgent:     matches[9],
		}

		// Parse status code and response bytes, then set log level based on status code
		if statusCode, err := strconv.Atoi(matches[6]); err == nil {
			entry.HTTPRequest.StatusCode = statusCode
			entry.Level = statusCodeToLogLevel(statusCode)
		} else {
			entry.Level = LogLevelUnknown // Invalid status code
		}

		if responseBytes, err := strconv.Atoi(matches[7]); err == nil {
			entry.HTTPRequest.ResponseBytes = responseBytes
		}

		// Parse extra fields like kong_request_id
		p.parseAccessLogExtras(entry, matches[10])
	} else {
		// If we can't parse the request parts, default to info level
		entry.Level = LogLevelInfo
	}

	return true
}

// parseNginxStartupLog parses an nginx startup log entry.
func (p *Parser) parseNginxStartupLog(entry *LogEntry, line string) bool {
	matches := nginxStartupRegex.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	entry.Type = LogEntryTypeNginxStartup
	entry.Level = ParseLogLevel(matches[1])
	entry.Message = matches[2]
	// Nginx startup logs don't have timestamps, use current time
	now := time.Now()
	entry.Timestamp = &now

	return true
}

// parseAccessLogExtras parses additional fields from access log entries.
func (p *Parser) parseAccessLogExtras(entry *LogEntry, extras string) {
	extras = strings.TrimSpace(extras)
	if extras == "" {
		return
	}

	// Look for key-value pairs using strings
	remaining := extras
	for remaining != "" {
		var part string
		if before, after, found := strings.Cut(remaining, ","); found {
			part = strings.TrimSpace(before)
			remaining = after
		} else {
			part = strings.TrimSpace(remaining)
			remaining = ""
		}

		if colonIdx := strings.Index(part, ":"); colonIdx > 0 {
			key := strings.TrimSpace(part[:colonIdx])
			value := strings.TrimSpace(part[colonIdx+1:])
			value = strings.Trim(value, "\"' ")

			entry.Fields[key] = value

			// Special handling for kong_request_id; store in dedicated HTTPRequest field
			// for easy access, in addition to the generic Fields map
			if key == "kong_request_id" && entry.HTTPRequest != nil {
				entry.HTTPRequest.KongRequestID = value
			}
		}
	}
}
