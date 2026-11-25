package wireguard

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AmneziaConfig contains AmneziaWG interface settings in core JSON. The
// presence of this object selects the userspace backend, even when it is empty.
type AmneziaConfig map[string]json.RawMessage

const maxAmneziaPadding = 65507 - 9000 - 32 // UDP payload minus the largest supported MTU and transport overhead.

func (c AmneziaConfig) uapi() (string, error) {
	keys := make([]string, 0, len(c))
	for key := range c {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	var result strings.Builder
	for _, key := range keys {
		value, err := amneziaUAPIValue(key, c[key])
		if err != nil {
			return "", fmt.Errorf("amnezia.%s: %w", key, err)
		}
		fmt.Fprintf(&result, "%s=%s\n", key, value)
	}
	return result.String(), nil
}

func amneziaUAPIValue(key string, raw json.RawMessage) (string, error) {
	value := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("invalid string")
		}
	}
	// Each field must stay on one UAPI line. Its scanner limits tokens to 64 KiB.
	if strings.ContainsAny(value, "\r\n\x00") || len(value) > 32*1024 || value == "null" {
		return "", fmt.Errorf("invalid value")
	}
	switch key {
	case "header_protection_key":
		parsed, err := wgtypes.ParseKey(value)
		if err != nil {
			return "", fmt.Errorf("expected a base64-encoded 32-byte key")
		}
		return hex.EncodeToString(parsed[:]), nil
	case "random_trailers", "disable_cookies":
		switch value {
		case "on", "true":
			return "true", nil
		case "off", "false":
			return "false", nil
		default:
			return "", fmt.Errorf("expected on or off")
		}
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
		limit := uint64(65507)
		switch key {
		case "jc":
			limit = 65535
		case "s1", "s2", "s3", "s4":
			limit = maxAmneziaPadding
		}
		if n, err := strconv.ParseUint(value, 10, 16); err != nil || n > limit {
			return "", fmt.Errorf("expected an integer between 0 and %d", limit)
		}
	case "h1", "h2", "h3", "h4", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts":
		bits := 16
		if key[0] == 'h' {
			bits = 32
		}
		low, high, isRange := strings.Cut(value, "-")
		minValue, err := strconv.ParseUint(low, 10, bits)
		if err != nil {
			return "", fmt.Errorf("expected an unsigned %d-bit integer or range", bits)
		}
		if isRange {
			maxValue, err := strconv.ParseUint(high, 10, bits)
			if err != nil || maxValue < minValue {
				return "", fmt.Errorf("expected an ascending unsigned %d-bit range", bits)
			}
		}
	case "i1", "i2", "i3", "i4", "i5":
		if err := validateAmneziaSignature(value); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unknown setting")
	}
	return value, nil
}

// Validate the documented CPS tags before handing their lengths to amneziawg-go.
// The upstream parser accepts larger values which can allocate a huge packet.
func validateAmneziaSignature(spec string) error {
	size := 0
	for spec = strings.TrimSpace(spec); spec != ""; spec = strings.TrimSpace(spec) {
		tag, rest, ok := strings.Cut(spec, ">")
		if !ok || !strings.HasPrefix(tag, "<") {
			return fmt.Errorf("invalid CPS tag")
		}
		fields := strings.Fields(tag[1:])
		if len(fields) == 1 && fields[0] == "t" {
			size += 4
		} else if len(fields) != 2 {
			return fmt.Errorf("invalid CPS tag")
		} else {
			switch fields[0] {
			case "b":
				value, ok := strings.CutPrefix(fields[1], "0x")
				decoded, err := hex.DecodeString(value)
				if !ok || err != nil || len(decoded) == 0 {
					return fmt.Errorf("invalid CPS hex data")
				}
				size += len(decoded)
			case "r", "rc", "rd":
				n, err := strconv.ParseUint(fields[1], 10, 16)
				if err != nil || n > 1000 {
					return fmt.Errorf("invalid CPS random length")
				}
				size += int(n)
			default:
				return fmt.Errorf("unknown CPS tag")
			}
		}
		if size > 65507 {
			return fmt.Errorf("CPS packet exceeds the maximum UDP payload size")
		}
		spec = rest
	}
	return nil
}
