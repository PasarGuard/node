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
	}

	// A module probe answers "ready" (no problems) or names what is missing.
	// Whether a module is builtin, loaded or merely loadable differs per host —
	// `loop` is builtin on some boxes and an unloaded module on others (the
	// Linux test server this suite also runs on reports it unloaded) — so the
	// assertion is the contract, never one host's state.
	if runtime.GOOS == "linux" {
		assertModuleProblemContract(t, "nf_conntrack")
		assertModuleProblemContract(t, "loop")
	}
}

// assertModuleProblemContract: either the module is available (no problems), or
// every problem it reports names the module and offers a fix. A problem with a
// blank Fix is how "here is why this cannot run" turns into a dead end.
func assertModuleProblemContract(t *testing.T, module string) {
	t.Helper()
	for _, p := range CheckKernelModule(module) {
		if !strings.Contains(p.Detail, module) || !strings.Contains(p.Fix, module) {
			t.Fatalf("CheckKernelModule(%q): problem must name the module in Detail and Fix, got %+v", module, p)
		}
	}
}
