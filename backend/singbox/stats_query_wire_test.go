package singbox

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/common"
)

// queryStats must send sing-box's Patterns filter (field 3), not only the
// xray-style Pattern (field 1). sing-box ignores field 1: an unfiltered
// request returns AND reset-zeroes every counter in the core, which let an
// outbound-stats poll drain per-user bytes before the panel ever billed them.
func TestStatsQueryCarriesSingBoxPatterns(t *testing.T) {
	wire, err := proto.Marshal(buildStatsQuery("user>>>", true))
	if err != nil {
		t.Fatal(err)
	}

	field := func(num protowire.Number, value string) []byte {
		return protowire.AppendString(protowire.AppendTag(nil, num, protowire.BytesType), value)
	}

	if !bytes.Contains(wire, field(3, "user>>>")) {
		t.Errorf("request is missing Patterns field 3 = \"user>>>\"; wire = %x", wire)
	}
	if !bytes.Contains(wire, field(1, "user>>>")) {
		t.Errorf("request is missing Pattern field 1; wire = %x", wire)
	}
}

// An empty pattern must not pin Patterns: that is the "match everything"
// filter, and combined with reset it is the drain bug this file documents.
func TestStatsQueryEmptyPatternSendsNoPatterns(t *testing.T) {
	wire, err := proto.Marshal(buildStatsQuery("", false))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, protowire.AppendTag(nil, 3, protowire.BytesType)) {
		t.Errorf("empty pattern must not send field 3, wire = %x", wire)
	}
	if want := (&common.QueryStatsRequest{Pattern: "x", Patterns: []string{"x"}, Reset_: true}); !proto.Equal(buildStatsQuery("x", true), want) {
		t.Errorf("buildStatsQuery drifted: got %v, want %v", buildStatsQuery("x", true), want)
	}
}
