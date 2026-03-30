// utils/logger.go — Logging with verbose mode, file output, colored console
// Made by Milkyway Intelligence | Author: Sharlix

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Logger handles console + file logging
type Logger struct {
	verbose bool
	file    *os.File
}

// NewLogger creates a Logger. Pass verbose=true for debug output.
func NewLogger(verbose bool) *Logger {
	l := &Logger{verbose: verbose}
	dir := LogDir()
	if err := os.MkdirAll(dir, 0700); err == nil {
		f, err := os.OpenFile(filepath.Join(dir, "m7vpn.log"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			l.file = f
		}
	}
	return l
}

func (l *Logger) write(level, msg string) {
	ts := time.Now().Format("15:04:05")
	if l.file != nil {
		fmt.Fprintf(l.file, "[%s] %-5s %s\n", ts, level, msg)
	}
}

// Debug prints only in verbose mode
func (l *Logger) Debug(msg string) {
	l.write("DEBUG", msg)
	if l.verbose {
		fmt.Printf("\033[90m  [DBG] %s\033[0m\n", msg)
	}
}

// Info prints an info line
func (l *Logger) Info(msg string) {
	l.write("INFO", msg)
	fmt.Printf("\033[36m  [*] %s\033[0m\n", msg)
}

// Warn prints a warning
func (l *Logger) Warn(msg string) {
	l.write("WARN", msg)
	fmt.Printf("\033[33m  [!] %s\033[0m\n", msg)
}

// Error prints an error
func (l *Logger) Error(msg string) {
	l.write("ERROR", msg)
	fmt.Printf("\033[31m  [✗] %s\033[0m\n", msg)
}

// Success prints a success message
func (l *Logger) Success(msg string) {
	l.write("OK", msg)
	fmt.Printf("\033[32m  [✓] %s\033[0m\n", msg)
}

// Close closes the log file
func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

// IsVerbose returns the verbose flag
func (l *Logger) IsVerbose() bool { return l.verbose }

// LogDir returns the log directory path
func LogDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/m7vpn/logs"
	}
	return filepath.Join(home, ".m7vpn", "logs")
}

// GetLogPath returns the full log file path
func GetLogPath() string {
	return filepath.Join(LogDir(), "m7vpn.log")
}

// TailLog returns the last n lines of the log file
func TailLog(n int) []string {
	data, err := os.ReadFile(GetLogPath())
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}
