package api

import (
	"testing"

	"github.com/xtls/xray-core/app/stats/command"
)

func TestParseStatNameValid(t *testing.T) {
	name, link, statType, ok := parseStatName("user>>>alice@example.com>>>traffic>>>uplink")
	if !ok {
		t.Fatal("expected valid stat name")
	}
	if name != "alice@example.com" {
		t.Fatalf("unexpected name: got %q", name)
	}
	if link != "traffic" {
		t.Fatalf("unexpected link: got %q", link)
	}
	if statType != "uplink" {
		t.Fatalf("unexpected type: got %q", statType)
	}
}

func TestParseStatNameRejectsMalformed(t *testing.T) {
	tests := []string{
		"user>>>alice@example.com>>>online",  // too short
		"user>>>>>>traffic>>>uplink",         // empty name
		"user>>>alice@example.com>>>>>>uplink", // empty link
		"user>>>alice@example.com>>>traffic>>>", // empty type
	}

	for _, raw := range tests {
		if _, _, _, ok := parseStatName(raw); ok {
			t.Fatalf("expected malformed stat name to be rejected: %q", raw)
		}
	}
}

func TestBuildStatResponseSkipsMalformedAndMapsFields(t *testing.T) {
	resp := buildStatResponse([]*command.Stat{
		{Name: "user>>>alice@example.com>>>traffic>>>uplink", Value: 123},
		{Name: "user>>>alice@example.com>>>traffic>>>downlink", Value: 456},
		{Name: "user>>>alice@example.com>>>online", Value: 1},
	})

	if len(resp.GetStats()) != 2 {
		t.Fatalf("expected 2 valid stats, got %d", len(resp.GetStats()))
	}

	if resp.GetStats()[0].GetName() != "alice@example.com" || resp.GetStats()[0].GetLink() != "traffic" || resp.GetStats()[0].GetType() != "uplink" || resp.GetStats()[0].GetValue() != 123 {
		t.Fatalf("unexpected first stat mapping: %+v", resp.GetStats()[0])
	}
	if resp.GetStats()[1].GetName() != "alice@example.com" || resp.GetStats()[1].GetLink() != "traffic" || resp.GetStats()[1].GetType() != "downlink" || resp.GetStats()[1].GetValue() != 456 {
		t.Fatalf("unexpected second stat mapping: %+v", resp.GetStats()[1])
	}
}
