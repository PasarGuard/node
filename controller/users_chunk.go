package controller

import (
	"fmt"

	"github.com/pasarguard/node/common"
)

// BuildUsersFromChunks orders chunked user payloads by their index and returns a single slice.
func BuildUsersFromChunks(chunks map[uint64][]*common.User, lastIndex uint64, sawLast bool) ([]*common.User, error) {
	if !sawLast {
		return nil, fmt.Errorf("missing final chunk indicator")
	}

	users := make([]*common.User, 0)
	for i := uint64(0); i <= lastIndex; i++ {
		chunkUsers, ok := chunks[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk index %d", i)
		}
		users = append(users, chunkUsers...)
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("no users received")
	}

	return users, nil
}
