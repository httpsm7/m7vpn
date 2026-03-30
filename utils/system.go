// utils/system.go — OS helpers: process, files, root check, random
// Made by Milkyway Intelligence | Author: Sharlix

package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// IsRoot returns true if running as root/sudo
func IsRoot() bool { return os.Geteuid() == 0 }

// MustBeRoot exits with a helpful message if not root
func MustBeRoot() {
	if !IsRoot() {
		fmt.Println("\n\033[31m  [✗] This command requires root privileges.\033[0m")
		fmt.Println("  Run: sudo m7vpn <command>")
		os.Exit(1)
	}
}

// RunCommand runs a command, discarding output; returns error
func RunCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// RunCommandOutput runs a command and returns trimmed combined output
func RunCommandOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ProcessExists checks if a PID is alive (signal 0)
func ProcessExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(nil) == nil
}

// WriteFileRoot writes a file as root (uses sudo tee if needed)
func WriteFileRoot(path string, data []byte, perm os.FileMode) error {
	if IsRoot() {
		return os.WriteFile(path, data, perm)
	}
	cmd := exec.Command("sudo", "tee", path)
	cmd.Stdin = strings.NewReader(string(data))
	if _, err := cmd.Output(); err != nil {
		return fmt.Errorf("sudo tee %s: %w", path, err)
	}
	return exec.Command("sudo", "chmod", fmt.Sprintf("%o", perm), path).Run()
}

// CommandExists checks if a binary is in PATH
func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RandomBase64 returns n random bytes encoded as base64
func RandomBase64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// RandomPassword returns a secure random alphanumeric+special password
func RandomPassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// ReadPIDFile reads an integer PID from a file
func ReadPIDFile(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return pid
}

// GetOSInfo returns a short OS description
func GetOSInfo() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return "unknown"
}
