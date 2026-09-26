// Package usage persists non-destructive counter snapshots and replayable receipts.
package usage

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Store opens the database per operation, so locks are released on shutdown or
// process death. bbolt serializes even independent processes using the same file.
// Its default synchronous commits must never be replaced by NoSync writes.
type Store struct{ Path string }

type Snapshot func(context.Context) (epoch string, stats *common.StatResponse, err error)

type streamState struct {
	Version  int              `json:"version"`
	Epoch    string           `json:"epoch"`
	Baseline map[string]int64 `json:"baseline"`
	Pending  []byte           `json:"pending,omitempty"`
}

func streamKey(kind common.StatType) ([]byte, error) {
	switch kind {
	case common.StatType_UsersStat:
		return []byte("users"), nil
	case common.StatType_Outbounds:
		return []byte("outbounds"), nil
	default:
		return nil, status.Error(codes.InvalidArgument, "usage requires UsersStat or Outbounds")
	}
}

func (s *Store) update(fn func(*bolt.Tx) error) error {
	if s.Path == "" {
		return status.Error(codes.FailedPrecondition, "usage storage path is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return fmt.Errorf("create usage directory: %w", err)
	}
	db, err := bolt.Open(s.Path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("open usage journal: %w", err)
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		// Persist the new journal's directory entry before publishing any receipt.
		// bbolt synchronizes file contents; directory creation needs its own sync.
		// Retry a failed directory sync: existence of the file alone is not proof
		// that a previous operation reached the durable activation commit.
		if tx.Bucket([]byte("usage-v1")) == nil && runtime.GOOS != "windows" {
			for dir := filepath.Dir(s.Path); ; dir = filepath.Dir(dir) {
				f, err := os.Open(dir)
				if err != nil {
					return err
				}
				err = f.Sync()
				f.Close()
				if err != nil {
					return err
				}
				if filepath.Dir(dir) == dir {
					break
				}
			}
		}
		return fn(tx)
	})
}

func load(bucket *bolt.Bucket, key []byte) (*streamState, error) {
	state := &streamState{Version: 1, Baseline: make(map[string]int64)}
	if data := bucket.Get(key); data != nil {
		if err := json.Unmarshal(data, state); err != nil {
			return nil, fmt.Errorf("decode usage journal: %w", err)
		}
		if state.Version != 1 || state.Baseline == nil {
			return nil, status.Error(codes.FailedPrecondition, "unsupported usage journal")
		}
	}
	return state, nil
}

func save(bucket *bolt.Bucket, key []byte, state *streamState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return bucket.Put(key, data)
}

// Collect publishes a receipt only after its payload and cumulative baseline
// commit together. A failed read/write leaves counters untouched. Until ACK,
// all callers receive exactly the same receipt, including after a node restart.
func (s *Store) Collect(ctx context.Context, kind common.StatType, snapshot Snapshot) (*common.UsageReceipt, error) {
	key, err := streamKey(kind)
	if err != nil {
		return nil, err
	}
	var receipt *common.UsageReceipt
	err = s.update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket, err := tx.CreateBucketIfNotExists([]byte("usage-v1"))
		if err != nil {
			return err
		}
		state, err := load(bucket, key)
		if err != nil {
			return err
		}
		if len(state.Pending) != 0 {
			receipt = new(common.UsageReceipt)
			return proto.Unmarshal(state.Pending, receipt)
		}
		epoch, counters, err := snapshot(ctx)
		if err != nil {
			return err
		}
		if epoch == "" || counters == nil {
			return status.Error(codes.FailedPrecondition, "backend has no stable counter epoch")
		}
		if state.Epoch != epoch {
			state.Epoch = epoch
			state.Baseline = make(map[string]int64)
		}
		receipt = &common.UsageReceipt{ReceiptId: uuid.NewString(), CollectedAt: time.Now().UTC().UnixMilli()}
		// Preserve absent counters in the baseline: a temporarily omitted counter
		// must not be charged from zero if it reappears. Epochs fence core resets.
		totals := make(map[string]int64)
		rows := make(map[string]*common.Stat)
		for _, counter := range counters.GetStats() {
			if counter == nil || (counter.GetType() != "uplink" && counter.GetType() != "downlink") {
				continue
			}
			encoded, _ := json.Marshal([3]string{counter.GetName(), counter.GetType(), counter.GetLink()})
			name := string(encoded)
			value := counter.GetValue()
			if value < 0 || totals[name] > math.MaxInt64-value {
				return status.Error(codes.FailedPrecondition, "invalid cumulative usage counter")
			}
			totals[name] += value
			rows[name] = counter
		}
		for name, value := range totals {
			previous := state.Baseline[name]
			if value < previous {
				return status.Error(codes.FailedPrecondition, "usage counter decreased without a new epoch")
			}
			if value > previous {
				counter := proto.Clone(rows[name]).(*common.Stat)
				counter.Value = value - previous
				receipt.Stats = append(receipt.Stats, counter)
			}
			state.Baseline[name] = value
		}
		if len(receipt.Stats) == 0 {
			// Empty polls still persist activation/baselines but need no ACK and
			// must not create an ever-growing panel ledger of zero-usage rows.
			receipt.ReceiptId = ""
		} else {
			state.Pending, err = proto.Marshal(receipt)
			if err != nil {
				return err
			}
		}
		return save(bucket, key, state)
	})
	if err != nil {
		return nil, err
	}
	return receipt, nil
}

// Acknowledge is idempotent. An ACK for an older receipt can never remove the
// current receipt. Baselines and activation survive ACK and process restarts.
func (s *Store) Acknowledge(ctx context.Context, kind common.StatType, id string) error {
	key, err := streamKey(kind)
	if err != nil {
		return err
	}
	if _, err := uuid.Parse(id); err != nil {
		return status.Error(codes.InvalidArgument, "invalid usage receipt ID")
	}
	return s.update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := tx.Bucket([]byte("usage-v1"))
		if bucket == nil || bucket.Get(key) == nil {
			return status.Error(codes.FailedPrecondition, "usage stream not initialized")
		}
		state, err := load(bucket, key)
		if err != nil || len(state.Pending) == 0 {
			return err
		}
		receipt := new(common.UsageReceipt)
		if err := proto.Unmarshal(state.Pending, receipt); err != nil {
			return err
		}
		if receipt.GetReceiptId() != id {
			return nil
		}
		state.Pending = nil
		return save(bucket, key, state)
	})
}

// LegacyReset serializes activation with old destructive reads. Once a stream
// is activated, no old client may reset its counters, including after restart.
func (s *Store) LegacyReset(kind common.StatType, read func() (*common.StatResponse, error)) (*common.StatResponse, error) {
	key, err := streamKey(kind)
	if err != nil {
		return nil, err
	}
	var result *common.StatResponse
	err = s.update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("usage-v1"))
		if bucket != nil && bucket.Get(key) != nil {
			return status.Error(codes.FailedPrecondition, "usage receipts enabled; destructive stats reads are disabled")
		}
		var err error
		result, err = read()
		return err
	})
	return result, err
}
