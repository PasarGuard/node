package wireguard

import (
	"net"
	"testing"
)

func mustPeerStoreWithPeers(t *testing.T, peers ...*PeerInfo) *PeerStore {
	t.Helper()

	ps := NewPeerStore()
	ps.ReplaceAll(peers)

	return ps
}

func TestPeerStoreGetByEmail(t *testing.T) {
	ps := mustPeerStoreWithPeers(t,
		mustPeerInfo("user@example.com", "testkey", []string{"10.0.0.2/32"}),
	)

	peer := ps.GetByEmail("user@example.com")
	if peer == nil {
		t.Fatalf("Expected peer to be returned")
	}

	if peer.Email != "user@example.com" {
		t.Errorf("Expected email 'user@example.com', got: %s", peer.Email)
	}
}

func TestPeerStoreGetPeerByKey(t *testing.T) {
	ps := mustPeerStoreWithPeers(t,
		mustPeerInfo("user@example.com", "testkey", []string{"10.0.0.2/32"}),
	)

	peer := ps.GetByKey(dummyKey("testkey").String())
	if peer == nil {
		t.Fatal("Expected peer to be found")
	}

	if peer.Email != "user@example.com" {
		t.Errorf("Expected email 'user@example.com', got: %s", peer.Email)
	}
}

func TestPeerStoreGetPeerByKeyReturnsCopy(t *testing.T) {
	ps := mustPeerStoreWithPeers(t,
		mustPeerInfo("user@example.com", "key1", []string{"10.0.0.2/32"}),
	)

	peer := ps.GetByKey(dummyKey("key1").String())
	peer.Email = "mutated@example.com"
	_, ipn, _ := net.ParseCIDR("10.0.0.99/32")
	peer.AllowedIPs[0] = *ipn

	fresh := ps.GetByKey(dummyKey("key1").String())
	if fresh.Email != "user@example.com" {
		t.Fatalf("expected original email, got %s", fresh.Email)
	}
	if fresh.AllowedIPs[0].String() != "10.0.0.2/32" {
		t.Fatalf("expected original allowed IP, got %s", fresh.AllowedIPs[0])
	}
}

func TestPeerStoreApplyChangesAndEmailMap(t *testing.T) {
	ps := mustPeerStoreWithPeers(t,
		mustPeerInfo("user1@example.com", "key1", []string{"10.0.0.2/32"}),
		mustPeerInfo("user2@example.com", "key2", []string{"10.0.0.3/32"}),
	)

	removed := ps.ApplyChanges(
		[]string{dummyKey("key1").String()},
		[]*PeerInfo{
			mustPeerInfo("user3@example.com", "key2", []string{"10.0.0.3/32"}),
			mustPeerInfo("user4@example.com", "key4", []string{"10.0.0.4/32"}),
		},
	)

	if len(removed) != 1 || removed[0] != dummyKey("key1").String() {
		t.Fatalf("unexpected removed keys: %+v", removed)
	}

	if ps.GetByKey(dummyKey("key1").String()) != nil {
		t.Fatal("expected key1 to be removed")
	}

	emap := ps.GetEmailMap()
	if emap[dummyKey("key2").String()] != "user3@example.com" {
		t.Fatal("expected key2 owner to be updated")
	}
	if emap[dummyKey("key4").String()] != "user4@example.com" {
		t.Fatal("expected key4 to be added")
	}
}
