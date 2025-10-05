# Sesh

Sesh is a Go library for parsing Kong Gateway logs. It provides structured parsing of Kong
application logs, nginx access logs, and nginx startup logs with support for both streaming and
batch processing modes.

The library automatically detects the input source type and switches between streaming mode (for
pipes and stdin with timeout-based flushing) and batch mode (for regular files). It handles
multi-line log entries, extracts structured data, and maps HTTP status codes to appropriate log
levels for access logs.

## Installation

```bash
go get github.com/mikefero/sesh
```

## Basic Usage

This example demonstrates parsing Kong Gateway logs from a string. The parser processes each log
entry and calls the provided callback function. The callback receives a structured `LogEntry`
that contains all parsed information including timestamps, log levels, HTTP request details, and
extracted fields.

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mikefero/sesh"
)

func main() {
	logs := `2025/01/09 10:30:45 [error] 1234#0: *5678 database connection failed
172.17.0.1 - - [09/Jan/2025:10:30:45 +0000] "GET /api/health HTTP/1.1" 404 15 "-" "curl/7.68.0"`

	parser := sesh.NewParser().WithEntryCallback(func(entry sesh.LogEntry) {
		data, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Println(string(data))
	})

	result, err := parser.ParseReader(context.Background(), strings.NewReader(logs))
	if err != nil {
		panic(err)
	}

	fmt.Printf("\nParsed %d entries with %d errors\n",
		result.Stats.ParsedEntries, result.Stats.ErrorCount)
}
```

## Kong Gateway Log Types

Kong Gateway produces logs in three distinct formats. The Sesh parser automatically detects and
parses each type, extracting relevant structured data and normalizing them into a common
`LogEntry` structure.

All log types include basic fields like timestamp, log level, message content, and the original
raw log lines. Each type also provides specific fields relevant to its context.

### Kong Application Logs

Kong application logs contain detailed information about Kong's internal operations, plugin
execution, and request processing.

```
2025/01/09 10:30:45 [error] 1234#0: *5678 [lua] plugin.lua:42: execute(): failed to process request, context: ngx.timer
```

**Extracted Fields:**
- `ProcessID` and `WorkerID`: Nginx process and worker identifiers
- `RequestID`: Connection identifier for request correlation
- `Namespace`: Plugin or service context (e.g., "rate-limiting", "jwt")
- `Fields["source_file"]`, `Fields["source_line"]`, `Fields["source_function"]`: Source code location
- `Fields["context"]`: Additional context information
- `MultilineContent`: Stack traces and continuation lines

### Nginx Access Logs

Access logs record HTTP requests processed by Kong Gateway. The parser extracts HTTP details and
maps status codes to appropriate log levels.

```
172.17.0.1 - - [09/Jan/2025:10:30:45 +0000] "GET /api/health HTTP/1.1" 404 15 "-" "curl/7.68.0" kong_request_id=abc123
```

**Status Code to Log Level Mapping:**
- 1xx responses → Debug
- 2xx, 3xx responses → Info
- 4xx responses → Warn
- 5xx responses → Error
- Unparseable responses → Unknown

**HTTPRequest Fields:**
- `ClientAddress`: Client IP address
- `Method`, `Path`, `Protocol`: HTTP request details
- `StatusCode`: HTTP response status
- `ResponseBytes`: Response body size
- `UserAgent`, `Referrer`: HTTP headers
- `KongRequestID`: Kong's internal request identifier

### Nginx Startup Logs

Startup logs capture nginx service lifecycle events and configuration messages.

```
nginx: [notice] nginx/1.21.6
```

These logs contain basic information about nginx startup, configuration loading, and service
status changes.

## Streaming Mode

This example shows real-time log processing with streaming mode. When reading from stdin, pipes,
or other streaming sources, the parser automatically enables streaming mode with timeout-based
flushing for incomplete log entries.

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mikefero/sesh"
)

func main() {
	parser := sesh.NewParser().
		WithFlushTimeout(3 * time.Second).
		WithEntryCallback(func(entry sesh.LogEntry) {
			data, _ := json.MarshalIndent(entry, "", "  ")
			fmt.Println(string(data))
		})

	result, err := parser.ParseReader(context.Background(), os.Stdin)
	if err != nil {
		panic(err)
	}

	fmt.Printf("\nProcessed %d entries\n", result.Stats.ParsedEntries)
}
```

## Error Handling and Statistics

This example demonstrates comprehensive error handling and statistics collection. The parser
tracks parsing errors, entry type distribution, and log level counts. Unparseable lines are
preserved in the results for analysis.

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mikefero/sesh"
)

func main() {
	logs := `2025/01/09 10:30:45 [error] 1234#0: database connection failed
172.17.0.1 - - [09/Jan/2025:10:30:45 +0000] "GET /api/health HTTP/1.1" 500 15 "-" "curl/7.68.0"
invalid log line that cannot be parsed
nginx: [notice] nginx/1.21.6`

	parser := sesh.NewParser().WithEntryCallback(func(entry sesh.LogEntry) {
		data, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Println(string(data))
	})

	result, err := parser.ParseReader(context.Background(), strings.NewReader(logs))
	if err != nil {
		panic(err)
	}

	statsData, _ := json.MarshalIndent(result.Stats, "", "  ")
	fmt.Printf("\nParsing Statistics:\n%s\n", string(statsData))

	if len(result.Errors) > 0 {
		fmt.Println("\nParsing Errors:")
		for _, parseErr := range result.Errors {
			errorData, _ := json.MarshalIndent(parseErr, "", "  ")
			fmt.Println(string(errorData))
		}
	}
}
```

## Multi-line Log Processing

This example processes Kong Gateway logs that span multiple lines, such as Lua stack traces or
detailed error messages. The parser automatically groups continuation lines with their parent log
entry using configurable timeouts in streaming mode.

```go
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mikefero/sesh"
)

func main() {
	multilineLogs := `2025/01/09 01:22:44 [error] 1994#0: *15 [lua] tracing.lua:323: set_attribute(): invalid span attribute value type: nil
stack traceback:
	/usr/local/share/lua/5.1/kong/tracing/instrumentation.lua:295: in function 'toip'
	/usr/local/share/lua/5.1/kong/globalpatches.lua:560: in function 'connect'
	/usr/local/openresty/lualib/resty/websocket/client.lua:217: in function 'connect'
	/usr/local/share/lua/5.1/kong/clustering/telemetry.lua:218: in function </usr/local/share/lua/5.1/kong/clustering/telemetry.lua:187>
	[C]: in function 'pcall'
	/usr/local/share/lua/5.1/resty/timerng/job.lua:274: in function 'execute'
	/usr/local/share/lua/5.1/resty/timerng/thread/worker.lua:169: in function </usr/local/share/lua/5.1/resty/timerng/thread/worker.lua:153>
	[C]: in function 'pcall'
	/usr/local/share/lua/5.1/resty/timerng/thread/loop.lua:101: in function 'phase_handler_wrapper'
	/usr/local/share/lua/5.1/resty/timerng/thread/loop.lua:144: in function 'do_phase_handler'
	/usr/local/share/lua/5.1/resty/timerng/thread/loop.lua:170: in function </usr/local/share/lua/5.1/resty/timerng/thread/loop.lua:162>, context: ngx.timer`

	parser := sesh.NewParser().WithEntryCallback(func(entry sesh.LogEntry) {
		fmt.Printf("=== %s Log Entry ===\n", entry.Type.String())
		fmt.Printf("Level: %s\n", entry.Level.String())
		fmt.Printf("Message: %s\n", entry.Message)

		if len(entry.MultilineContent) > 0 {
			fmt.Println("Additional lines:")
			for i, line := range entry.MultilineContent {
				fmt.Printf("  [%d] %s\n", i+1, line)
			}
		}
		fmt.Println()
	})

	result, err := parser.ParseReader(context.Background(), strings.NewReader(multilineLogs))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Processed %d multi-line entries\n", result.Stats.ParsedEntries)
}
```

## Field Extraction

This example shows extraction of structured fields from Kong application logs. The parser
automatically extracts source code information, Kong namespaces, context data, and other
structured information into the Fields map.

```go
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mikefero/sesh"
)

func main() {
	logsWithFields := `2025/01/09 15:18:33 [debug] 2319#0: *18 [lua] init.lua:44: log(): [rate-limiting] rate-limiting strategy is 'off' or sync_rate is '-1'. Skipping instantiating strategy
2025/01/09 15:18:33 [warn] 1234#0: [clustering] failed to connect to control plane
172.17.0.1 - - [09/Jan/2025:10:30:45 +0000] "POST /api/users HTTP/1.1" 201 156 "-" "MyApp/1.0" kong_request_id=req-abc123`

	parser := sesh.NewParser().WithEntryCallback(func(entry sesh.LogEntry) {
		fmt.Printf("=== %s Entry ===\n", entry.Type.String())
		fmt.Printf("Message: %s\n", entry.Message)

		if entry.Namespace != "" {
			fmt.Printf("Namespace: %s\n", entry.Namespace)
		}

		if len(entry.Fields) > 0 {
			fmt.Println("Extracted Fields:")
			for key, value := range entry.Fields {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}

		if entry.HTTPRequest != nil && entry.HTTPRequest.KongRequestID != "" {
			fmt.Printf("Kong Request ID: %s\n", entry.HTTPRequest.KongRequestID)
		}

		fmt.Println()
	})

	result, err := parser.ParseReader(context.Background(), strings.NewReader(logsWithFields))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Processed %d entries with extracted fields\n", result.Stats.ParsedEntries)
}
```

## OpenTelemetry OTLP Export

Sesh provides native OpenTelemetry Protocol (OTLP) export for integration with modern observability
platforms. The OTLP exporter transforms parsed log entries into structured OTLP log records with
full attribute mapping and semantic conventions support.

**Protocol Support:**
- **gRPC** (default, port 4317): High-performance binary protocol
- **HTTP** (port 4318): RESTful alternative with protobuf encoding

**OTLP Attribute Mapping:**

All `LogEntry` fields are exported as OTLP log attributes except `RawMessage` and `RawTimestamp`:

- **Core Fields**:
  - Timestamp → OTLP log record timestamp
  - Level → OTLP severity number and text
  - Message → OTLP log body
  - Type → `log.type` attribute

- **Process Information**:
  - ProcessID → `process.id` (int)
  - WorkerID → `worker.id` (int)
  - RequestID → `request.id` (int)

- **Context**:
  - Namespace → `namespace` (string)
  - MultilineContent → `multiline_content` (OTLP Slice of strings)

- **Custom Fields**:
  - Fields["key"] → `field.key` attribute
  - String values preserved as-is
  - Array values exported as OTLP Slice type

- **HTTP Request** (Semantic Conventions):
  - Method → `http.method`
  - Path → `http.path`
  - Protocol → `http.protocol`
  - StatusCode → `http.status_code`
  - ResponseBytes → `http.response_bytes`
  - ClientAddress → `client.address`
  - KongRequestID → `kong.request_id`

**Kong Log Level to OTLP Severity Mapping:**
- `debug` → SeverityDebug (5)
- `info` → SeverityInfo (9)
- `notice` → SeverityInfo (9)
- `warn` → SeverityWarn (13)
- `error` → SeverityError (17)
- `alert` → SeverityError (17)
- `crit` → SeverityFatal (21)
- `unknown` → SeverityInfo (9)

**Resource Attributes:**

The OTLP exporter automatically includes resource-level metadata:
- `service.name`: Application name (sesh)
- `service.version`: Build version with commit hash

**Example Output:**

When you send logs via `./bin/sesh otel`, each log entry becomes a structured OTLP LogRecord:

```
LogRecord:
  Timestamp: 2025-09-06 13:04:34 +0000 UTC
  SeverityText: ERROR
  SeverityNumber: Error(17)
  Body: "database connection failed"
  Attributes:
    - log.type: "kong"
    - process.id: 2639
    - worker.id: 0
    - request.id: 8345
    - namespace: "rate-limiting-advanced"
    - field.source_file: "init.lua"
    - field.source_line: "70"
    - field.context: "ngx.timer"
```

This structured format enables powerful querying and filtering in observability platforms without
requiring JSON parsing or regex extraction.

## CLEF Format Support

Sesh supports outputting log entries in CLEF (Compact Log Event Format) for integration with
structured logging systems like Seq. When CLEF formatting is enabled, field names and log levels
are transformed to match Serilog standards.

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mikefero/sesh"
)

func main() {
	logs := `2025/01/09 10:30:45 [error] 1234#0: *5678 database connection failed
172.17.0.1 - - [09/Jan/2025:10:30:45 +0000] "GET /api/health HTTP/1.1" 404 15 "-" "curl/7.68.0"`

	parser := sesh.NewParser().
		WithCLEF(true).
		WithEntryCallback(func(entry sesh.LogEntry) {
			// Entry will be automatically formatted in CLEF when marshaled
			data, _ := json.MarshalIndent(entry, "", "  ")
			fmt.Println(string(data))
		})

	result, err := parser.ParseReader(context.Background(), strings.NewReader(logs))
	if err != nil {
		panic(err)
	}

	fmt.Printf("\nParsed %d entries in CLEF format\n", result.Stats.ParsedEntries)
}
```

**CLEF Field Mappings:**
- `timestamp` → `@t`
- `message` → `@m`
- `level` → `@l`
- `type` → `@i`

**Kong Log Level to Serilog Level Mapping:**
- `debug` → `Debug`
- `info` → `Information`
- `notice` → `Information`
- `warn` → `Warning`
- `error` → `Error`
- `alert` → `Error`
- `crit` → `Fatal`
- `unknown` → `Information`

## CLI Tool

Sesh includes a command-line tool for parsing log files:

```bash
# Build the CLI
make build

# Parse a log file
./bin/sesh parse /usr/local/kong/logs/access.log

# Parse with statistics and error details
./bin/sesh parse --results /usr/local/kong/logs/access.log

# Parse from stdin with JSON output
tail -f /usr/local/kong/logs/access.log \
  /usr/local/kong/logs/admin_access.log \
  /usr/local/kong/logs/debug_error.log | \
  ./bin/sesh parse --json --pretty --

# Include raw log lines in JSON output
./bin/sesh parse --json --include-raw /usr/local/kong/logs/access.log

# 5s custom flush timeout for streaming
tail -f /usr/local/kong/logs/access.log | \
  ./bin/sesh parse --flush-timeout 5s --json --pretty --

# Disable color output
./bin/sesh parse --no-color /usr/local/kong/logs/access.log

# Send logs to Seq in CLEF format
./bin/sesh seq /usr/local/kong/logs/access.log

# Send from stdin to Seq with custom batch size
tail -f /usr/local/kong/logs/access.log \
  /usr/local/kong/logs/admin_access.log \
  /usr/local/kong/logs/debug_error.log | \
  ./bin/sesh seq --batch-size 500 --

# Custom Seq server URL
./bin/sesh seq --url http://your-seq-server:5480/ingest/clef /path/to/logs

# Send logs to OpenTelemetry collector via gRPC (default)
./bin/sesh otel /usr/local/kong/logs/access.log

# Send logs to OpenTelemetry collector via HTTP
./bin/sesh otel --http /usr/local/kong/logs/access.log

# Send to custom OTLP endpoint
./bin/sesh otel --endpoint custom-collector:4317 /path/to/logs

# Stream logs to OTLP collector from stdin
tail -f /usr/local/kong/logs/access.log \
  /usr/local/kong/logs/admin_access.log \
  /usr/local/kong/logs/debug_error.log | \
  ./bin/sesh otel --
```

## OpenTelemetry Integration

The `otel` command exports logs to any OTLP-compatible observability platform (Loki, SignOz, Grafana, etc.) via the OpenTelemetry Protocol.

**Supported Protocols:**
- gRPC (default, port 4317): `./bin/sesh otel` or `./bin/sesh otel --grpc`
- HTTP (port 4318): `./bin/sesh otel --http`

**What's Exported:**
All LogEntry fields are exported as OTLP log attributes except `RawMessage`:
- Core: timestamp, level, message, type
- IDs: process.id, worker.id, request.id
- Context: namespace, multiline_content (as array)
- Custom Fields: field.* (supports strings and arrays)
- HTTP: All HTTPRequest fields with proper semantic conventions

**Example with otel-collector:**

```bash
# Start local OTLP collector with debug exporter
make otel-start

# Send logs and inspect in collector output
./bin/sesh otel /path/to/logs

# View detailed OTLP data in another terminal
make otel-logs

# Stop collector
make otel-stop
```

## Docker Operations

Start and stop observability services for log analysis:

```bash
# Seq logging server
make seq-start  # Web UI at http://localhost:5480
make seq-stop

# OpenTelemetry collector (with debug exporter)
make otel-start  # gRPC:4317, HTTP:4318, health:13133
make otel-stop
make otel-logs   # View detailed OTLP data being received
```
