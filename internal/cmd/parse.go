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

// Package cmd contains the command line package.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mikefero/sesh"
	"github.com/spf13/cobra"
)

var (
	jsonOutput       bool
	prettyJSONOutput bool
	noColor          bool
	rawOutput        bool
	showResults      bool
	quiet            bool
	flushTimeout     time.Duration
)

var parseCmd = &cobra.Command{
	Use:   "parse [file]",
	Short: "Parse Kong Gateway logs",
	Long:  `Parse Kong Gateway logs and output the parsed results.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Set up signal handling
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigChan
			cancel()
		}()

		var reader *os.File
		var err error

		// Determine input source
		if len(args) == 0 || (len(args) == 1 && args[0] == "--") {
			// Read from stdin
			reader = os.Stdin
		} else {
			// Read from file
			reader, err = os.Open(args[0])
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", args[0], err)
			}
			defer func() {
				if err := reader.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
				}
			}()
		}

		// Create the parser
		parser := sesh.NewParser()
		parser = parser.WithFlushTimeout(flushTimeout)
		parser = parser.WithEntryCallback(func(entry *sesh.LogEntry) {
			if !quiet {
				outputEntry(entry, jsonOutput, prettyJSONOutput, noColor, rawOutput)
			}
		})

		// Parse the input source
		result, err := parser.ParseReader(ctx, reader)

		// Check if context was canceled
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "Parsing interrupted\n")
		} else if err != nil {
			return fmt.Errorf("failed to parse logs: %w", err)
		}

		// Output results if requested
		if showResults {
			if err := outputResults(result); err != nil {
				fmt.Fprintf(os.Stderr, "Error outputting results: %v\n", err)
			}
		}

		return nil
	},
}

// outputEntry outputs a single log entry with the specified formatting.
func outputEntry(entry *sesh.LogEntry, jsonOutput, prettyJSON, noColor, includeRaw bool) {
	if jsonOutput {
		outputJSONEntry(entry, prettyJSON, noColor, includeRaw)
		return
	}
	outputRawEntry(entry, noColor)
}

// outputJSONEntry outputs a log entry as JSON.
func outputJSONEntry(entry *sesh.LogEntry, prettyJSON, noColor, includeRaw bool) {
	// Create a copy of the entry to potentially modify
	outputEntry := *entry

	// If includeRaw is false, remove the raw_message field
	if !includeRaw {
		outputEntry.RawMessage = nil
	}

	var jsonData []byte
	var err error
	if prettyJSON {
		jsonData, err = json.MarshalIndent(&outputEntry, "", "  ")
	} else {
		jsonData, err = json.Marshal(&outputEntry)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling entry to JSON: %v\n", err)
		return
	}

	jsonString := string(jsonData)
	if !noColor {
		jsonString = colorizeByLogLevel(jsonString, entry.Level)
	}

	//nolint:forbidigo
	fmt.Println(jsonString)
}

// outputRawEntry outputs a log entry as raw text with optional coloring.
func outputRawEntry(entry *sesh.LogEntry, noColor bool) {
	rawMessage := strings.Join(entry.RawMessage, "\n")
	if noColor {
		//nolint:forbidigo
		fmt.Println(rawMessage)
		return
	}

	coloredMessage := colorizeByLogLevel(rawMessage, entry.Level)
	//nolint:forbidigo
	fmt.Println(coloredMessage)
}

// colorizeByLogLevel adds ANSI color codes based on log level.
func colorizeByLogLevel(message string, level sesh.LogLevel) string {
	const (
		colorReset     = "\033[0m"
		colorRed       = "\033[31m"   // error
		colorBrightRed = "\033[91m"   // alert
		colorBoldRed   = "\033[1;31m" // critical
		colorYellow    = "\033[33m"   // warn
		colorBlue      = "\033[34m"   // info/notice
		colorLightGray = "\033[90m"   // debug
		colorViolet    = "\033[35m"   // unknown
	)

	switch level {
	case sesh.LogLevelError:
		return colorRed + message + colorReset
	case sesh.LogLevelAlert:
		return colorBrightRed + message + colorReset
	case sesh.LogLevelCritical:
		return colorBoldRed + message + colorReset
	case sesh.LogLevelWarn:
		return colorYellow + message + colorReset
	case sesh.LogLevelInfo, sesh.LogLevelNotice:
		return colorBlue + message + colorReset
	case sesh.LogLevelDebug:
		return colorLightGray + message + colorReset
	case sesh.LogLevelUnknown:
		return colorViolet + message + colorReset
	default:
		return message // no color for unexpected levels
	}
}

// colorizeByEntryType adds ANSI color codes based on entry type.
func colorizeByEntryType(message string, entryType sesh.LogEntryType) string {
	const (
		colorReset      = "\033[0m"
		colorGreen      = "\033[32m"       // kong
		colorBrightCyan = "\033[96m"       // access
		colorPink       = "\033[38;5;165m" // nginx
		colorOrange     = "\033[38;5;208m" // unknown
	)

	switch entryType {
	case sesh.LogEntryTypeKongApplication:
		return colorGreen + message + colorReset
	case sesh.LogEntryTypeNginxAccess:
		return colorBrightCyan + message + colorReset
	case sesh.LogEntryTypeNginxStartup:
		return colorPink + message + colorReset
	case sesh.LogEntryTypeUnknown:
		return colorOrange + message + colorReset
	default:
		return message
	}
}

// outputResults outputs parsing statistics in simple text format.
func outputResults(result *sesh.ParseResult) error {
	if result == nil {
		return nil
	}

	// Basic stats
	fmt.Fprintf(os.Stderr, "Processed %d lines, parsed %d entries",
		result.Stats.TotalLines, result.Stats.ParsedEntries)
	if result.Stats.ErrorCount > 0 {
		fmt.Fprintf(os.Stderr, ", %d errors", result.Stats.ErrorCount)
	}
	fmt.Fprintln(os.Stderr)

	// Entry types breakdown
	if result.Stats.ParsedEntries > 0 {
		outputEntryTypesBreakdown(result.Stats.EntryTypeCount)
	}

	// Log levels breakdown
	if result.Stats.ParsedEntries > 0 {
		outputLogLevelsBreakdown(result.Stats.LogLevelCount)
	}

	// Unparseable lines (if any)
	if len(result.Errors) > 0 {
		header := colorizeByLogLevel("Unparseable lines:", sesh.LogLevelError)
		fmt.Fprintln(os.Stderr, header)
		for _, parseErr := range result.Errors {
			line := fmt.Sprintf("  Line %d: %s", parseErr.LineNumber, parseErr.RawLine)
			coloredLine := colorizeByLogLevel(line, sesh.LogLevelUnknown)
			fmt.Fprintln(os.Stderr, coloredLine)
		}
	}

	return nil
}

// outputEntryTypesBreakdown outputs the entry types breakdown with colors.
func outputEntryTypesBreakdown(entryTypeCount map[sesh.LogEntryType]int) {
	var parts []string
	entryTypes := []sesh.LogEntryType{
		sesh.LogEntryTypeKongApplication, sesh.LogEntryTypeNginxAccess,
		sesh.LogEntryTypeNginxStartup, sesh.LogEntryTypeUnknown,
	}

	for _, entryType := range entryTypes {
		if count, exists := entryTypeCount[entryType]; exists && count > 0 {
			typeStr := fmt.Sprintf("%s=%d", entryType.String(), count)
			typeStr = colorizeByEntryType(typeStr, entryType)
			parts = append(parts, typeStr)
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(os.Stderr, "Entry types: %s\n", strings.Join(parts, ", "))
	}
}

// outputLogLevelsBreakdown outputs the log levels breakdown with colors.
func outputLogLevelsBreakdown(logLevelCount map[sesh.LogLevel]int) {
	var parts []string
	logLevels := []sesh.LogLevel{
		sesh.LogLevelDebug, sesh.LogLevelInfo, sesh.LogLevelNotice, sesh.LogLevelWarn, sesh.LogLevelError,
		sesh.LogLevelAlert, sesh.LogLevelCritical, sesh.LogLevelUnknown,
	}

	for _, level := range logLevels {
		if count, exists := logLevelCount[level]; exists && count > 0 {
			levelStr := fmt.Sprintf("%s=%d", level.String(), count)
			levelStr = colorizeByLogLevel(levelStr, level)
			parts = append(parts, levelStr)
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(os.Stderr, "Log levels: %s\n", strings.Join(parts, ", "))
	}
}

func init() {
	rootCmd.AddCommand(parseCmd)

	// Add flags
	parseCmd.Flags().DurationVar(&flushTimeout, "flush-timeout", sesh.DefaultFlushTimeout,
		"Timeout to flush incomplete multi-line entries when streaming")
	parseCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable syntax coloring")
	parseCmd.Flags().BoolVar(&showResults, "results", false, "Show parsing statistics and errors at the end")
	parseCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output structured JSON instead of raw messages")
	parseCmd.Flags().BoolVar(&prettyJSONOutput, "pretty", false, "Pretty-print JSON output")
	parseCmd.Flags().BoolVar(&rawOutput, "raw", false, "Output raw_message field in JSON output")
	parseCmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress all parsed log output (useful with --results)")
}
