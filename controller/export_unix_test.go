//go:build !windows

package controller

// For the handler tests in package controller_test, which drive the rpc and
// rest services against the fake telemt.
var (
	FakeTelemtConfig    = fakeTelemtConfig
	MTProtoStartRequest = mtprotoStartRequest
)
