package rpc

import (
	"testing"

	"github.com/pasarguard/node/backend"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// nonRoutingBackend satisfies backend.Backend (methods promoted from the nil
// embedded interface — never called here) but NOT backend.RoutingBackend.
type nonRoutingBackend struct{ backend.Backend }

// routingFake satisfies both interfaces.
type routingFake struct {
	backend.Backend
	backend.RoutingBackend
}

func TestAsRoutingBackend(t *testing.T) {
	if _, err := asRoutingBackend(nonRoutingBackend{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("non-routing backend: code = %v, want Unimplemented", status.Code(err))
	}
	if _, err := asRoutingBackend(routingFake{}); err != nil {
		t.Fatalf("routing backend: unexpected err %v", err)
	}
}
