package mtproto

import (
	"context"
	"errors"
	"log"
	"maps"
	"slices"
)

// userChange is one user to create, patch or delete in telemt.
type userChange struct {
	username string
	user     *runtimeUser // the new state; nil deletes the user
	known    bool         // telemt is expected to have the user
}

// apiWrite is the last write of one user through telemt's user API since
// the last confirmed render: the state it set (nil for a delete), or unknown
// when the call failed and may or may not have reached telemt.
//
// telemt stages each such write as an admission override, which only a
// published config carrying the same value clears; until then the user can
// connect only if the published config agrees with the override.
type apiWrite struct {
	user    *runtimeUser
	unknown bool
}

// sendUserChangeLocked writes one change through telemt's user API and
// records it in m.apiSent. Create or patch follows change.known, and
// telemt's answer corrects that choice: a patch of a missing user creates
// it, a create of an existing user patches it, and deleting a missing user
// is done. Requires syncMu.
func (m *MTProto) sendUserChangeLocked(ctx context.Context, change userChange) error {
	var err error
	switch {
	case change.user == nil:
		err = m.deleteUser(ctx, change.username)
	case change.known:
		err = m.patchOrCreateUser(ctx, change.user)
	default:
		err = m.createOrPatchUser(ctx, change.user)
	}

	if m.apiSent == nil {
		m.apiSent = make(map[string]apiWrite)
	}
	if err != nil {
		m.apiSent[change.username] = apiWrite{unknown: true}
		return err
	}
	var sent *runtimeUser
	if change.user != nil {
		copied := *change.user
		sent = &copied
	}
	m.apiSent[change.username] = apiWrite{user: sent}
	return nil
}

// matchAPIWritesLocked makes telemt's admission overrides agree with users
// before users are rendered. A render that changed a user written through
// the API, before telemt published that write, would leave the override
// different from the published config, and the user refused. So each user
// written through the API since the last confirmed render whose rendered
// state differs from that write is written again; the render's publish then
// clears the override. A write that fails is logged and stays unknown.
// Requires syncMu.
func (m *MTProto) matchAPIWritesLocked(ctx context.Context, users map[string]*runtimeUser) {
	for _, username := range slices.Sorted(maps.Keys(m.apiSent)) {
		write := m.apiSent[username]
		wanted := users[username]
		if !write.unknown && runtimeUserEqual(write.user, wanted) {
			continue
		}
		change := userChange{username: username, user: wanted, known: write.unknown || write.user != nil}
		if err := m.sendUserChangeLocked(ctx, change); err != nil {
			log.Printf("warning: mtproto: writing user %s through the telemt API before a render failed; telemt may refuse the user until the next full apply: %v", username, err)
		}
	}
}

// forgetSettledAPIWritesLocked runs after telemt published a render that
// matchAPIWritesLocked prepared: that publish cleared every override the
// node knows of. Writes whose outcome is unknown stay, and keep the state
// unconfirmed so the next sync renders again. Requires syncMu.
func (m *MTProto) forgetSettledAPIWritesLocked() {
	maps.DeleteFunc(m.apiSent, func(_ string, write apiWrite) bool { return !write.unknown })
	if m.hasUnknownAPIWritesLocked() {
		m.needsFullApply = true
	}
}

func (m *MTProto) hasUnknownAPIWritesLocked() bool {
	for _, write := range m.apiSent {
		if write.unknown {
			return true
		}
	}
	return false
}

func (m *MTProto) patchOrCreateUser(ctx context.Context, user *runtimeUser) error {
	err := m.apiClient.PatchUser(ctx, user.Username, user)
	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.NotFound() {
		return m.apiClient.CreateUser(ctx, user)
	}
	return err
}

func (m *MTProto) createOrPatchUser(ctx context.Context, user *runtimeUser) error {
	err := m.apiClient.CreateUser(ctx, user)
	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.UserExists() {
		return m.apiClient.PatchUser(ctx, user.Username, user)
	}
	return err
}

func (m *MTProto) deleteUser(ctx context.Context, username string) error {
	err := m.apiClient.DeleteUser(ctx, username)
	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.NotFound() {
		return nil
	}
	return err
}
