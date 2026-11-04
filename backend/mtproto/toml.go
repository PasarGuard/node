package mtproto

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// renderTOML encodes root as TOML. root is the panel JSON (numbers as
// json.Number, null for "not set") with the node-managed values merged in.
func renderTOML(root map[string]any) (string, error) {
	value, err := tomlValue(root, "")
	if err != nil {
		return "", err
	}
	out, err := toml.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("failed to render telemt config as TOML: %w", err)
	}
	rendered := string(out)
	if err := checkNoIncludeLines(rendered); err != nil {
		return "", err
	}
	return rendered, nil
}

// tomlValue copies value for the TOML encoder. JSON numbers become int64 or
// float64, since the encoder writes a json.Number as a string. A null map
// value means "not set" and is dropped; TOML has no null, so a null array
// element is an error.
func tomlValue(value any, path string) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if item == nil {
				continue
			}
			converted, err := tomlValue(item, appendTOMLPath(path, key))
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			itemPath := fmt.Sprintf("%s[%d]", path, index)
			if item == nil {
				return nil, fmt.Errorf("mtproto config field %s is null; TOML arrays cannot hold null", itemPath)
			}
			converted, err := tomlValue(item, itemPath)
			if err != nil {
				return nil, err
			}
			out[index] = converted
		}
		return out, nil
	case json.Number:
		return tomlNumber(typed, path)
	default:
		// Any other container could hide a json.Number from the conversion
		// above, so it is refused rather than passed through.
		switch reflect.ValueOf(value).Kind() {
		case reflect.Map, reflect.Slice, reflect.Array, reflect.Struct, reflect.Pointer, reflect.Interface:
			return nil, fmt.Errorf("mtproto config field %s has unsupported type %T", path, value)
		}
		return value, nil
	}
}

// tomlNumber converts a JSON number to the TOML integer or float it spells.
// TOML integers are signed 64-bit, so a larger integer is an error rather than
// a float that telemt would reject for an integer field.
func tomlNumber(number json.Number, path string) (any, error) {
	if integer, err := number.Int64(); err == nil {
		return integer, nil
	}
	if !strings.ContainsAny(number.String(), ".eE") {
		return nil, fmt.Errorf("mtproto config field %s: integer %s is outside the TOML 64-bit range", path, number)
	}
	float, err := number.Float64()
	if err != nil {
		return nil, fmt.Errorf("mtproto config field %s: %s is not a valid TOML float", path, number)
	}
	return float, nil
}

func appendTOMLPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// checkNoIncludeLines refuses output that telemt would expand as a file
// include. Before it parses TOML, telemt reads every line that, trimmed,
// starts with "include" followed by "=" as an include of the named file, in
// any table (src/config/load/includes.rs). The encoder writes a key named
// include bare, so such a key would make telemt read other files on the node
// host. The check copies telemt's matcher rather than relying on how the
// encoder quotes keys.
func checkNoIncludeLines(rendered string) error {
	table := "the top level"
	for line := range strings.Lines(rendered) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			table = trimmed
			continue
		}
		rest, found := strings.CutPrefix(trimmed, "include")
		if found && strings.HasPrefix(strings.TrimSpace(rest), "=") {
			return fmt.Errorf("mtproto config must not use the key include (found in %s): telemt would read it as a file include", table)
		}
	}
	return nil
}
