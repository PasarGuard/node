package tunnel

import (
	"runtime"
	"strings"
	"testing"
)

// TestHostChecksNeverReportEmptyProblems: a check that fails — or cannot even
// be asked on this host — must return a Problem with a reason in Detail. An
// entry with an empty Detail is how a "ready" verdict sneaks back in.
func TestHostChecksNeverReportEmptyProblems(t *testing.T) {
	checks := map[string][]Problem{
		"root":          CheckRoot(),
		"capability":    CheckCapability("net_admin"),
		"raw_socket":    CheckRawSocket(),
		"firewall":      CheckFirewallTooling(),
		"kernel_module": CheckKernelModule("definitely_not_loaded_module_xyz"),
	}
	for name, problems := range checks {
		for _, p := range problems {
			if p.Check == "" || p.Detail == "" {
				t.Fatalf("%s returned an empty problem: %+v", name, p)
			}
		}
	}
}

// TestChecksSayWhyTheyCannotRunOnThisHost pins the host-specific-reason rule
// on the platform these tests run on: a check that is not answerable here
// reports the OS rather than claiming the host is ready.
func TestChecksSayWhyTheyCannotRunOnThisHost(t *testing.T) {
	problems := CheckKernelModule("nf_conntrack")
	if runtime.GOOS != "linux" {
		if len(problems) != 1 || !strings.Contains(problems[0].Detail, runtime.GOOS) {
			t.Fatalf("non-linux host: want one problem naming %s, got %+v", runtime.GOOS, problems)
		}
	} else if len(problems) != 1 || !strings.Contains(problems[0].Detail, "nf_conntrack") {
		// A module that is not loaded must be reported with its name and a fix.
		t.Fatalf("linux: want the missing module named, got %+v", problems)
	}

	// A loaded-module probe for a module every Linux box has answers "ready"
	// (empty) or "missing" — never an empty-detail problem.
	if runtime.GOOS == "linux" {
		for _, p := range CheckKernelModule("loop") {
			t.Fatalf("loop is built in on every kernel; got %+v", p)
		}
	}
}
