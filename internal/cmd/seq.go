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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mikefero/sesh"
	"github.com/spf13/cobra"
)

var (
	seqURL             string
	seqFlushTimeout    time.Duration
	seqCallbackTimeout time.Duration
	seqBatchSize       int
)

var seqCmd = &cobra.Command{
	Use:   "seq [file]",
	Short: "Parse Kong Gateway logs and send to Seq",
	Long:  `Parse Kong Gateway logs and send them to Seq in CLEF format.`,
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
		parseJSONOutput = true // This is used for the shared function in parse CLI command
		parser := sesh.NewParser()
		parser = parser.WithCLEF(true)
		parser = parser.WithFlushTimeout(seqFlushTimeout)
		parser = parser.WithCallbackTimeout(seqCallbackTimeout)
		parser = parser.WithEntryCallback(func(entry sesh.LogEntry) {
			addToQueue(entry)
		})

		// Create HTTP client for Seq
		httpClient := &http.Client{
			Timeout: 10 * time.Second,
		}

		// Start goroutine to process queue
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					// Process remaining entries before exit
					processQueue(httpClient)
					return
				case <-ticker.C:
					processQueue(httpClient)
				}
			}
		}()

		// Parse the input source
		result, err := parser.ParseReader(ctx, reader)

		// Process any remaining entries in the queue before exiting
		processQueue(httpClient)

		// Check if context was canceled
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "Parsing interrupted\n")
		} else if err != nil {
			return fmt.Errorf("failed to parse logs: %w", err)
		}

		// Output results
		if err := outputResults(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error outputting results: %v\n", err)
		}

		return nil
	},
}

// processQueue sends all queued entries to Seq in batches.
func processQueue(client *http.Client) {
	queueMutex.Lock()
	entries := make([]sesh.LogEntry, len(entryQueue))
	copy(entries, entryQueue)
	entryQueue = entryQueue[:0] // Clear the queue
	queueMutex.Unlock()

	for i := 0; i < len(entries); i += seqBatchSize {
		end := min(i+seqBatchSize, len(entries))
		batch := entries[i:end]

		if err := sendBatchToSeq(client, batch); err != nil {
			fmt.Fprintf(os.Stderr, "Error sending batch to Seq: %v\n", err)
		}
	}
}

// sendBatchToSeq sends multiple log entries to Seq in CLEF format as a batch.
func sendBatchToSeq(client *http.Client, entries []sesh.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	var batchData bytes.Buffer
	for _, entry := range entries {
		clefData, err := jsonEntry(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal entry: %w", err)
		}
		batchData.Write(clefData)
		batchData.WriteString("\n") // CLEF format requires newline separation
	}

	// Send HTTP POST to Seq
	resp, err := client.Post(seqURL, "application/vnd.serilog.clef", &batchData)
	if err != nil {
		return fmt.Errorf("failed to post batch to Seq: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("invalid status code returned from Seq: %v", resp)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(seqCmd)

	// Add flags
	seqCmd.Flags().DurationVar(&seqCallbackTimeout, "callback-timeout", sesh.DefaultCallbackTimeout,
		"Timeout to wait for all callback processing to finish before giving up")
	seqCmd.Flags().DurationVar(&seqFlushTimeout, "flush-timeout", sesh.DefaultFlushTimeout,
		"Timeout to flush incomplete multi-line entries when streaming")
	seqCmd.Flags().StringVar(&seqURL, "url", "http://localhost:5480/ingest/clef",
		"Seq ingestion URL")
	seqCmd.Flags().IntVar(&seqBatchSize, "batch-size", 1000,
		"Number of log entries to batch together when sending to Seq")
}
