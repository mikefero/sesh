package sesh

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed README.md
var readmeContent string

func TestReadmeCodeExamples(t *testing.T) {
	codeBlocks := extractGoCodeBlocks(readmeContent)
	require.NotEmpty(t, codeBlocks, "No Go code blocks found in README.md")
	for i, code := range codeBlocks {
		t.Run(fmt.Sprintf("code_block_%d", i+1), func(t *testing.T) {
			tempDir, err := os.MkdirTemp("", fmt.Sprintf("readme_test_%d_*", i+1))
			require.NoError(t, err, "Failed to create temp dir")
			defer os.RemoveAll(tempDir)

			currentDir, err := os.Getwd()
			require.NoError(t, err, "Failed to get current directory")
			goModContent := fmt.Sprintf(`module readme_test
go 1.24.6
require github.com/mikefero/sesh v0.0.0
replace github.com/mikefero/sesh => %s
`, currentDir)
			goModPath := filepath.Join(tempDir, "go.mod")
			err = os.WriteFile(goModPath, []byte(goModContent), 0644)
			require.NoError(t, err, "Failed to write go.mod")

			mainGoPath := filepath.Join(tempDir, "main.go")
			err = os.WriteFile(mainGoPath, []byte(code), 0644)
			require.NoError(t, err, "Failed to write main.go")

			cmd := exec.Command("go", "build", ".")
			cmd.Dir = tempDir
			output, err := cmd.CombinedOutput()
			assert.NoError(t, err, "Go code block %d failed to compile\nOutput:\n%s\nCode:\n%s",
				i+1, string(output), code)
		})
	}
}

func extractGoCodeBlocks(markdown string) []string {
	re := regexp.MustCompile("(?s)```go\n(.*?)\n```")
	matches := re.FindAllStringSubmatch(markdown, -1)

	var codeBlocks []string
	for _, match := range matches {
		if len(match) > 1 {
			codeBlocks = append(codeBlocks, strings.TrimSpace(match[1]))
		}
	}

	return codeBlocks
}
