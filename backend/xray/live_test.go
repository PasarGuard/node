package xray

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	xcore "github.com/xtls/xray-core/core"
)

type fakeLiveAPI struct {
	calls  []string
	failOn string
}

func (f *fakeLiveAPI) record(call string) error {
	f.calls = append(f.calls, call)
	if call == f.failOn {
		return errors.New("refused")
	}
	return nil
}

func (f *fakeLiveAPI) AddOutbound(_ context.Context, outbound *xcore.OutboundHandlerConfig) error {
	return f.record("add " + outbound.GetTag())
}

func (f *fakeLiveAPI) RemoveOutbound(_ context.Context, tag string) error {
	return f.record("remove " + tag)
}

func (f *fakeLiveAPI) ReplaceRouting(context.Context, *serial.TypedMessage) error {
	return f.record("routing")
}

func testLiveParts(tags ...string) *liveParts {
	parts := &liveParts{
		routing:   &serial.TypedMessage{Type: routerConfigType},
		outbounds: make(map[string]*xcore.OutboundHandlerConfig),
	}
	for _, tag := range tags {
		parts.outbounds[tag] = &xcore.OutboundHandlerConfig{Tag: tag}
	}
	return parts
}

var testLiveSteps = []liveStep{planAdd("c"), planRemove("a"), planAdd("a"), planRouting(), planRemove("b")}

func TestRunLiveStepsInOrder(t *testing.T) {
	api := &fakeLiveAPI{}
	if err := runLiveSteps(context.Background(), api, testLiveSteps, testLiveParts("a", "c")); err != nil {
		t.Fatal(err)
	}
	want := []string{"add c", "remove a", "add a", "routing", "remove b"}
	if !slices.Equal(api.calls, want) {
		t.Fatalf("calls = %v, want %v", api.calls, want)
	}
}

func TestRunLiveStepsStopsAtTheFirstError(t *testing.T) {
	api := &fakeLiveAPI{failOn: "remove a"}
	err := runLiveSteps(context.Background(), api, testLiveSteps, testLiveParts("a", "c"))
	if err == nil || !strings.Contains(err.Error(), `remove outbound "a"`) {
		t.Fatalf("err = %v, want the failed step named", err)
	}
	if want := []string{"add c", "remove a"}; !slices.Equal(api.calls, want) {
		t.Fatalf("calls = %v, want %v", api.calls, want)
	}
}

func TestRunLiveStepsChecksOutboundsBeforeAnyCall(t *testing.T) {
	api := &fakeLiveAPI{}
	err := runLiveSteps(context.Background(), api, []liveStep{planRemove("a"), planAdd("missing")}, testLiveParts("a"))
	if err == nil || len(api.calls) != 0 {
		t.Fatalf("err = %v, calls = %v; want an error before any call", err, api.calls)
	}
}
