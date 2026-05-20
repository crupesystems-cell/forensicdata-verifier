// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package canonicaljson implements a deterministic JSON serializer that is
// byte-exact compatible with the CKNF Python source `cknf.ntp_trust.canonical_json`.
//
// The Python rules are:
//
//	json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
//
//	- keys sorted lexicographically (recursive)
//	- no whitespace between tokens
//	- UTF-8 preserved (no \uXXXX escaping for non-ASCII)
//	- integer-only payload (no float edge cases)
//
// Go's encoding/json differs from Python in two material ways:
//
//  1. By default it escapes < > & — disabled via Encoder.SetEscapeHTML(false).
//  2. It always escapes U+2028 and U+2029 (line/paragraph separators) as
//     /  . Python's ensure_ascii=False does NOT escape these.
//
// This package emits output that matches Python byte-for-byte for the field
// types CKNF actually uses (hex strings, ISO-8601 timestamps, integers,
// nested maps). Floats are rejected — if a future schema introduces them,
// upgrade to an RFC 8785 JCS-strict library on BOTH sides in lockstep.
package canonicaljson

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Marshal returns the canonical JSON encoding of v. The result is byte-exact
// equivalent to the CKNF Python `canonical_json(v)` for the supported value
// types: nil, bool, int (any width), int64, uint (any width), uint64, string,
// []any, map[string]any, and pointers/wrappers of those.
//
// Rejects (with error):
//   - float32, float64 — Python uses int-only and the float repr rules diverge
//   - chan, func, complex — never appear in forensic payloads
//   - non-string map keys — JSON requires string keys
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := marshalValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalString is a convenience wrapper returning the canonical JSON as
// string. The result is suitable for SHA-256 hashing.
func MarshalString(v any) (string, error) {
	b, err := Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SHA256Hex returns the lowercase hex SHA-256 digest of Marshal(v). Matches
// the CKNF `sha256_of_canonical_json(obj)` primitive.
func SHA256Hex(v any) (string, error) {
	b, err := Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func marshalValue(buf *bytes.Buffer, v any) error {
	if v == nil {
		buf.WriteString("null")
		return nil
	}
	switch x := v.(type) {
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return marshalString(buf, x)
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int8:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int16:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int32:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
		return nil
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
		return nil
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
		return nil
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
		return nil
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
		return nil
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
		return nil
	case float32, float64:
		return fmt.Errorf("canonical_json: float values are not supported (Python source uses int-only payloads; representation differs between Python and Go)")
	case []any:
		return marshalArray(buf, x)
	case map[string]any:
		return marshalObject(buf, x)
	}
	// Fall back to encoding/json's reflection path for typed structs and
	// unsupported maps. To preserve determinism we re-marshal through Go's
	// encoder then re-parse and re-emit canonically.
	return marshalViaReflection(buf, v)
}

func marshalString(buf *bytes.Buffer, s string) error {
	// Use encoding/json to handle escaping of ", \, and control chars, but
	// disable HTML escaping so < > & survive as-is (matches Python's
	// ensure_ascii=False default).
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("canonical_json: encode string: %w", err)
	}
	out := tmp.Bytes()
	// encoder appends a trailing newline — strip it.
	out = bytes.TrimRight(out, "\n")
	// Go always escapes U+2028 and U+2029 as   /  . Python's
	// ensure_ascii=False keeps them as raw UTF-8. Reverse Go's escaping
	// so output matches Python byte-for-byte.
	out = bytes.ReplaceAll(out, []byte(` `), []byte(" "))
	out = bytes.ReplaceAll(out, []byte(` `), []byte(" "))
	buf.Write(out)
	return nil
}

func marshalArray(buf *bytes.Buffer, arr []any) error {
	buf.WriteByte('[')
	for i, elem := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := marshalValue(buf, elem); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

func marshalObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := marshalString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := marshalValue(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// marshalViaReflection handles typed Go structs (and any value not covered
// by the explicit type switch above) by round-tripping through encoding/json
// into a generic any and then back through marshalAny. This guarantees that
// every value reaches the canonical serializer via the same code path
// regardless of its declared type.
func marshalViaReflection(buf *bytes.Buffer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("canonical_json: cannot encode value of type %T: %w", v, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var anyVal any
	if err := dec.Decode(&anyVal); err != nil {
		return fmt.Errorf("canonical_json: cannot re-decode value: %w", err)
	}
	return marshalAny(buf, anyVal)
}

// marshalAny is the reflection-side path: it handles values returned by a
// json.Decoder with UseNumber, which produces nil / bool / string /
// json.Number / []any / map[string]any.
func marshalAny(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return marshalString(buf, x)
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("canonical_json: float value %q is not supported", s)
		}
		buf.WriteString(s)
		return nil
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := marshalAny(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := marshalString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := marshalAny(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	}
	return fmt.Errorf("canonical_json: unsupported value type after reflection: %T", v)
}
