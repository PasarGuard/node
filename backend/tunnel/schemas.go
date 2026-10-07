package tunnel

import (
	"sort"
	"sync"
)

// ParamField is one params key an adapter owns, as the UI needs to hear it
// (CONTRACT glue-2: the dialog generates its inputs from this reply instead
// of a hand-written form per tool).
//
// The adapter stays the authority: Render still refuses an unknown key and a
// missing required one, whatever this schema says. A wrong entry here is a
// wrong *form field*, never a wrong config — and SchemasTest registers a
// round trip per tool so the two cannot drift quietly.
type ParamField struct {
	// Key is the params key, exactly as Render reads it.
	Key string
	// RequiredFor lists "<mode>:<side>" shapes this key cannot work without
	// ("relay:a"). The panel sends ONE params map to both sides, so the UI
	// treats a field as required for a mode when any side of that mode is
	// listed. Empty = optional in every shape.
	RequiredFor []string
	// Help is the one-line hint the UI shows under the field (English; param
	// keys are protocol vocabulary and stay untranslated).
	Help string
}

// ToolSchema is one tool's complete params surface.
type ToolSchema struct {
	Tool   string
	Params []ParamField
}

var (
	schemaMu sync.RWMutex
	schemas  = map[string][]ParamField{}
)

// RegisterSchema records the params keys a tool owns. Each tool package calls
// it from init(), beside Register, with fields built next to that tool's own
// validation tables — the tables stay the single source, the schema is how
// they reach the panel.
func RegisterSchema(tool string, fields []ParamField) {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	schemas[tool] = fields
}

// Schemas returns every registered schema, ordered by tool name so the reply
// is byte-stable across runs (Render's determinism, applied to metadata).
func Schemas() []ToolSchema {
	schemaMu.RLock()
	defer schemaMu.RUnlock()
	out := make([]ToolSchema, 0, len(schemas))
	for tool, fields := range schemas {
		cp := make([]ParamField, len(fields))
		copy(cp, fields)
		out = append(out, ToolSchema{Tool: tool, Params: cp})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}
