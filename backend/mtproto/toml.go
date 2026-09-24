package mtproto

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

type tomlLiteral string

func renderTOML(root map[string]any) (string, error) {
	var builder strings.Builder
	if err := writeTOMLSection(&builder, nil, root, tomlHeaderNone); err != nil {
		return "", err
	}
	return builder.String(), nil
}

type tomlHeaderKind uint8

const (
	tomlHeaderNone tomlHeaderKind = iota
	tomlHeaderTable
	tomlHeaderArrayTable
)

func writeTOMLSection(builder *strings.Builder, path []string, section map[string]any, headerKind tomlHeaderKind) error {
	scalarKeys, tableKeys, arrayTableKeys, err := classifyTOMLSection(section)
	if err != nil {
		return err
	}

	if headerKind != tomlHeaderNone {
		writeSectionSpacing(builder)
		headerText := joinPath(path)
		switch headerKind {
		case tomlHeaderTable:
			builder.WriteString("[")
			builder.WriteString(headerText)
			builder.WriteString("]\n")
		case tomlHeaderArrayTable:
			builder.WriteString("[[")
			builder.WriteString(headerText)
			builder.WriteString("]]\n")
		}
	}

	for _, key := range scalarKeys {
		inline, err := renderInlineValue(section[key])
		if err != nil {
			return fmt.Errorf("failed to render TOML value for %s: %w", joinPath(appendPath(path, key)), err)
		}
		builder.WriteString(renderKey(key))
		builder.WriteString(" = ")
		builder.WriteString(inline)
		builder.WriteByte('\n')
	}

	for _, key := range tableKeys {
		child, _ := section[key].(map[string]any)
		if err := writeTOMLSection(builder, appendPath(path, key), child, tomlHeaderTable); err != nil {
			return err
		}
	}

	for _, key := range arrayTableKeys {
		items, _ := section[key].([]any)
		for index, rawItem := range items {
			child, ok := rawItem.(map[string]any)
			if !ok {
				return fmt.Errorf("failed to render TOML array table %s[%d]: expected object element", joinPath(appendPath(path, key)), index)
			}
			if err := writeTOMLSection(builder, appendPath(path, key), child, tomlHeaderArrayTable); err != nil {
				return err
			}
		}
	}

	return nil
}

func classifyTOMLSection(section map[string]any) ([]string, []string, []string, error) {
	keys := make([]string, 0, len(section))
	for key := range section {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	scalarKeys := make([]string, 0, len(keys))
	tableKeys := make([]string, 0, len(keys))
	arrayTableKeys := make([]string, 0)

	for _, key := range keys {
		switch value := section[key].(type) {
		case map[string]any:
			tableKeys = append(tableKeys, key)
		case []any:
			if isArrayOfObjects(value) {
				arrayTableKeys = append(arrayTableKeys, key)
				continue
			}
			scalarKeys = append(scalarKeys, key)
		default:
			scalarKeys = append(scalarKeys, key)
		}
	}

	return scalarKeys, tableKeys, arrayTableKeys, nil
}

func isArrayOfObjects(values []any) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if _, ok := value.(map[string]any); !ok {
			return false
		}
	}
	return true
}

func renderInlineValue(value any) (string, error) {
	switch typed := value.(type) {
	case nil:
		return "", fmt.Errorf("nil values are not valid in TOML")
	case tomlLiteral:
		return string(typed), nil
	case string:
		return strconv.Quote(typed), nil
	case bool:
		return strconv.FormatBool(typed), nil
	case json.Number:
		return typed.String(), nil
	case []any:
		rendered := make([]string, 0, len(typed))
		for _, item := range typed {
			inline, err := renderInlineValue(item)
			if err != nil {
				return "", err
			}
			rendered = append(rendered, inline)
		}
		return "[" + strings.Join(rendered, ", ") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		slices.Sort(keys)

		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			inline, err := renderInlineValue(typed[key])
			if err != nil {
				return "", err
			}
			parts = append(parts, fmt.Sprintf("%s = %s", renderKey(key), inline))
		}
		return "{ " + strings.Join(parts, ", ") + " }", nil
	default:
		return renderPrimitiveValue(typed)
	}
}

func renderPrimitiveValue(value any) (string, error) {
	typedValue := reflect.ValueOf(value)
	switch typedValue.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(typedValue.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(typedValue.Uint(), 10), nil
	case reflect.Float32:
		return strconv.FormatFloat(typedValue.Float(), 'f', -1, 32), nil
	case reflect.Float64:
		return strconv.FormatFloat(typedValue.Float(), 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unsupported TOML value type %T", value)
	}
}

func renderKey(key string) string {
	if isBareKey(key) {
		return key
	}
	return strconv.Quote(key)
}

func isBareKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if !(r >= 'a' && r <= 'z') &&
			!(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') &&
			r != '_' &&
			r != '-' {
			return false
		}
	}
	return true
}

func joinPath(path []string) string {
	if len(path) == 0 {
		return ""
	}
	parts := make([]string, 0, len(path))
	for _, segment := range path {
		parts = append(parts, renderKey(segment))
	}
	return strings.Join(parts, ".")
}

func appendPath(path []string, key string) []string {
	result := make([]string, 0, len(path)+1)
	result = append(result, path...)
	result = append(result, key)
	return result
}

func writeSectionSpacing(builder *strings.Builder) {
	if builder.Len() == 0 {
		return
	}
	if !strings.HasSuffix(builder.String(), "\n") {
		builder.WriteByte('\n')
	}
	builder.WriteByte('\n')
}
