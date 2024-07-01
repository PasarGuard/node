package tools

import (
	"fmt"
	"math/rand"
	"net"
)

func isPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func FindFreePort() int {
	var apiPort int
	for apiPort = rand.Intn(50000) + 10000; apiPort < 65536; apiPort++ {
		if isPortFree(apiPort) {
			break
		}
	}
	return apiPort
}
