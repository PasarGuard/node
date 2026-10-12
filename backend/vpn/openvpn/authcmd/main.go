// Command pg-ovpn-auth is what the OpenVPN server execve()s for
// `auth-user-pass-verify … via-file`.
//
// It is a program rather than a shell script on purpose: openvpn passes the
// client's username and password as *bytes in a file*, and this compares them
// to bytes in another file. No shell ever parses them, so a username like
// `$(reboot)` or `;rm -rf` cannot execute anything — there is nothing to
// execute it.
//
// It prints nothing, ever: a password that reaches stdout/stderr would be
// inherited by the node's log capture. Exit status is the entire contract —
// 0 accept, anything else reject.
//
// GPL note: this is PasarGuard's own code. It never links OpenVPN.
package main

import (
	"os"
	"strings"
)

const credentialsEnv = "PG_OVPN_CREDENTIALS"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv(credentialsEnv)))
}

func run(args []string, credentialsPath string) int {
	// openvpn passes exactly one argument: the temp file it wrote. Fail closed
	// on anything else rather than guessing which line is the username.
	if len(args) != 1 || credentialsPath == "" {
		return 1
	}
	attempt, ok := readPair(args[0])
	if !ok {
		return 1
	}
	roster, ok := readRoster(credentialsPath)
	if !ok {
		return 1
	}
	for _, cred := range roster {
		if cred[0] == attempt[0] && cred[1] == attempt[1] {
			return 0
		}
	}
	return 1
}

// readPair reads the two-line file openvpn wrote: username, password. Only the
// first two lines are read — a value containing a newline is not a value this
// format can carry, and the node refuses to sync one.
func readPair(path string) ([2]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return [2]string{}, false
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return [2]string{}, false
	}
	return [2]string{stripCR(lines[0]), stripCR(lines[1])}, true
}

// readRoster reads the node-written credential file: alternating username and
// password lines. An odd tail or an unreadable file fails the login rather than
// authenticating everyone.
func readRoster(path string) ([][2]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines)%2 != 0 {
		return nil, false
	}
	roster := make([][2]string, 0, len(lines)/2)
	for i := 0; i < len(lines); i += 2 {
		roster = append(roster, [2]string{lines[i], lines[i+1]})
	}
	return roster, true
}

func stripCR(s string) string { return strings.TrimSuffix(s, "\r") }
