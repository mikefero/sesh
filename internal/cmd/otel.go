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
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mikefero/sesh"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

var (
	otelEndpoint        string
	otelUseHTTP         bool
	otelUseGRPC         bool
	otelFlushTimeout    time.Duration
	otelCallbackTimeout time.Duration
	otelBatchSize       int
)

var otelCmd = &cobra.Command{
	Use:   "otel [file]",
	Short: "Parse Kong Gateway logs and send to OTLP collector",
	Long:  `Parse Kong Gateway logs and send them to an OpenTelemetry collector via OTLP.`,
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

		// Validate protocol flags
		if otelUseHTTP && otelUseGRPC {
			return fmt.Errorf("cannot specify both --http and --grpc flags")
		}

		// Determine endpoint and protocol; setting defaults if needed
		endpoint := otelEndpoint
		useGRPC := otelUseGRPC || (!otelUseHTTP && !otelUseGRPC) // gRPC is default
		if len(strings.TrimSpace(endpoint)) == 0 {
			if useGRPC {
				endpoint = "localhost:4317"
			} else {
				endpoint = "localhost:4318"
			}
		}

		// Create OTLP exporter based on protocol
		var exporter sdklog.Exporter
		if useGRPC {
			exporter, err = otlploggrpc.New(ctx,
				otlploggrpc.WithEndpoint(endpoint),
				otlploggrpc.WithInsecure(),
			)
		} else {
			exporter, err = otlploghttp.New(ctx,
				otlploghttp.WithEndpoint(endpoint),
				otlploghttp.WithInsecure(),
			)
		}
		if err != nil {
			return fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
		defer func() {
			if err := exporter.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Error shutting down exporter: %v\n", err)
			}
		}()

		// Create resource
		res, err := resource.New(ctx,
			resource.WithAttributes(
				semconv.ServiceNameKey.String(AppName),
				semconv.ServiceVersionKey.String(formatVersion()),
			),
		)
		if err != nil {
			return fmt.Errorf("failed to create resource: %w", err)
		}

		// Create batch processor
		processor := sdklog.NewBatchProcessor(exporter,
			sdklog.WithMaxQueueSize(otelBatchSize),
		)

		// Create logger provider
		loggerProvider := sdklog.NewLoggerProvider(
			sdklog.WithProcessor(processor),
			sdklog.WithResource(res),
		)
		defer func() {
			if err := loggerProvider.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Error shutting down logger provider: %v\n", err)
			}
		}()

		// Get logger
		logger := loggerProvider.Logger(AppName)

		// Create the parser
		parseJSONOutput = true // This is used for the shared function in parse CLI command
		parser := sesh.NewParser()
		parser = parser.WithFlushTimeout(otelFlushTimeout)
		parser = parser.WithCallbackTimeout(otelCallbackTimeout)
		parser = parser.WithEntryCallback(func(entry sesh.LogEntry) {
			emitOTLPLog(ctx, logger, entry)
		})

		// Parse the input source
		result, err := parser.ParseReader(ctx, reader)

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

// emitOTLPLog converts a LogEntry to an OTLP log record and emits it.
func emitOTLPLog(ctx context.Context, logger log.Logger, entry sesh.LogEntry) {
	// Convert sesh log level to OTLP severity
	var severity log.Severity
	var severityText string

	switch entry.Level {
	case sesh.LogLevelDebug:
		severity = log.SeverityDebug
		severityText = "DEBUG"
	case sesh.LogLevelInfo, sesh.LogLevelNotice:
		severity = log.SeverityInfo
		severityText = "INFO"
	case sesh.LogLevelWarn:
		severity = log.SeverityWarn
		severityText = "WARN"
	case sesh.LogLevelError:
		severity = log.SeverityError
		severityText = "ERROR"
	case sesh.LogLevelAlert:
		severity = log.SeverityError
		severityText = "ALERT"
	case sesh.LogLevelCritical:
		severity = log.SeverityFatal
		severityText = "CRITICAL"
	case sesh.LogLevelUnknown:
		severity = log.SeverityInfo
		severityText = "UNKNOWN"
	default:
		severity = log.SeverityInfo
		severityText = "INFO"
	}

	// Build record
	var record log.Record
	if entry.Timestamp != nil {
		record.SetTimestamp(*entry.Timestamp)
	}
	record.SetBody(log.StringValue(entry.Message))
	record.SetSeverity(severity)
	record.SetSeverityText(severityText)

	// Add attributes
	record.AddAttributes(
		log.String("log.type", entry.Type.String()),
	)

	if entry.ProcessID != nil {
		record.AddAttributes(log.Int("process.id", *entry.ProcessID))
	}
	if entry.WorkerID != nil {
		record.AddAttributes(log.Int("worker.id", *entry.WorkerID))
	}
	if entry.RequestID != nil {
		record.AddAttributes(log.Int("request.id", *entry.RequestID))
	}
	if entry.Namespace != "" {
		record.AddAttributes(log.String("namespace", entry.Namespace))
	}
	if len(entry.MultilineContent) > 0 {
		values := make([]log.Value, len(entry.MultilineContent))
		for i, line := range entry.MultilineContent {
			values[i] = log.StringValue(line)
		}
		record.AddAttributes(log.Slice("multiline_content", values...))
	}

	// Add custom fields from the log entry
	if len(entry.Fields) > 0 {
		addFieldsAttributes(&record, entry.Fields)
	}

	// Add HTTP request info if present
	if entry.HTTPRequest != nil {
		addHTTPAttributes(&record, entry.HTTPRequest)
	}

	// Emit the log record
	logger.Emit(ctx, record)
}

// addFieldsAttributes adds custom fields as attributes to the log record.
func addFieldsAttributes(record *log.Record, fields map[string]interface{}) {
	for key, value := range fields {
		switch v := value.(type) {
		case string:
			record.AddAttributes(log.String(fmt.Sprintf("field.%s", key), v))
		case []string:
			// Convert string slice to OTEL Value slice
			values := make([]log.Value, len(v))
			for i, s := range v {
				values[i] = log.StringValue(s)
			}
			record.AddAttributes(log.Slice(fmt.Sprintf("field.%s", key), values...))
		default:
			// Fallback for any unexpected types
			record.AddAttributes(log.String(fmt.Sprintf("field.%s", key), fmt.Sprintf("%v", v)))
		}
	}
}

// addHTTPAttributes adds HTTP request attributes to the log record.
func addHTTPAttributes(record *log.Record, httpReq *sesh.HTTPRequestInfo) {
	record.AddAttributes(
		log.String("http.method", httpReq.Method),
		log.String("http.path", httpReq.Path),
		log.String("http.protocol", httpReq.Protocol),
		log.Int("http.status_code", httpReq.StatusCode),
		log.Int("http.response_bytes", httpReq.ResponseBytes),
	)
	if httpReq.ClientAddress != "" {
		record.AddAttributes(log.String("client.address", httpReq.ClientAddress))
	}
	if httpReq.Referrer != "" && httpReq.Referrer != "-" {
		record.AddAttributes(log.String("http.referrer", httpReq.Referrer))
	}
	if httpReq.UserAgent != "" && httpReq.UserAgent != "-" {
		record.AddAttributes(log.String("http.user_agent", httpReq.UserAgent))
	}
	if httpReq.KongRequestID != "" {
		record.AddAttributes(log.String("kong.request_id", httpReq.KongRequestID))
	}
	if httpReq.Host != "" {
		record.AddAttributes(log.String("http.host", httpReq.Host))
	}
	if httpReq.Server != "" {
		record.AddAttributes(log.String("server", httpReq.Server))
	}
	if httpReq.Upstream != "" {
		record.AddAttributes(log.String("upstream", httpReq.Upstream))
	}
}

func init() {
	rootCmd.AddCommand(otelCmd)

	// Add flags
	otelCmd.Flags().DurationVar(&otelCallbackTimeout, "callback-timeout", sesh.DefaultCallbackTimeout,
		"Timeout to wait for all callback processing to finish before giving up")
	otelCmd.Flags().DurationVar(&otelFlushTimeout, "flush-timeout", sesh.DefaultFlushTimeout,
		"Timeout to flush incomplete multi-line entries when streaming")
	otelCmd.Flags().StringVar(&otelEndpoint, "endpoint", "",
		"OTLP collector endpoint (overrides default based on protocol)")
	otelCmd.Flags().BoolVar(&otelUseHTTP, "http", false,
		"Use OTLP/HTTP protocol (default endpoint: localhost:4318)")
	otelCmd.Flags().BoolVar(&otelUseGRPC, "grpc", false,
		"Use OTLP/gRPC protocol (default endpoint: localhost:4317)")
	otelCmd.Flags().IntVar(&otelBatchSize, "batch-size", 1000,
		"Maximum number of log entries to batch together when sending to OTLP collector")
}
