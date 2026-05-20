// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package bundle implements the Bundle-Spec v1.0 producer/verifier surface
// for the forensicdata-verifier CLI v0.2.0.
//
// This file (canonical.go) is a byte-exact Go mirror of the Python
// reference at:
//
//	/Volumes/FDC_MASTER/SIS/packages/forensicdata_audit/src/forensicdata_audit/canonical.py
//
// which itself mirrors the TypeScript @sis/core-crypto/canonical.ts. The
// three implementations together form Hard-Gate R9 (cross-language
// byte-exact canonical-JSON) of the Audit-Console Plan v2.
//
// Why a second canonical_json package
// ----------------------------------
// The existing internal/canonicaljson package was built for Verifier v0.1.0
// (CKNF Legal-Pack path) and mirrors Python's standard
// json.dumps(ensure_ascii=False). That implementation keeps U+2028 and
// U+2029 as raw UTF-8 bytes.
//
// Bundle-Spec v1.0 §6.1 (this file) mirrors JavaScript's JSON.stringify
// instead, which escapes U+2028 -> " " and U+2029 -> " " (ES2019
// spec-mandatory). For hex-only manifest fields the two encoders produce
// identical bytes, but Charter §4 ("forensic precision") and Plan v2 R9
// require byte-exact-by-design, not happy-path-by-content. Hence this
// separate package — the v0.1.0 Legal-Pack path is untouched and the
// v0.2.0 Bundle path gets its own forensic-grade canonical_json.
//
// Supported input types
// ---------------------
//
//	nil                       -> "null"
//	bool                      -> "true" / "false"
//	int / int8/16/32/64       -> base-10 integer literal
//	uint / uint8/16/32/64     -> base-10 integer literal
//	float32 / float64         -> finite-only; integral floats serialise as
//	                            their integer form (1.0 -> "1"). Non-integer
//	                            floats are rejected — Bundle-Spec §6.2 has
//	                            no float fields.
//	string                    -> JSON-escaped per JS JSON.stringify:
//	                            \" \\ \b \t \n \f \r, others < 0x20 as
//	                            \uXXXX, U+2028 ->  , U+2029 ->  .
//	                            All other runes pass through as raw UTF-8.
//	[]any                     -> [item,item,...]
//	map[string]any            -> {"key":value,...} keys sorted by Unicode
//	                            code point order.
//
// Rejects (with error): non-finite floats, non-integer floats, complex
// numbers, channels, functions, non-string map keys.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// CanonicalJSON returns the canonical JSON encoding of v per Bundle-Spec §6.1.
//
// The result is byte-exact equivalent to the Python
// forensicdata_audit.canonical.canonical_json(v) for every supported value
// type. Cross-language hash equality (manifest_hash, audit chain) depends
// on this guarantee.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := marshalValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalJSONString is a convenience wrapper.
func CanonicalJSONString(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SHA256Hex returns the lowercase hex SHA-256 digest of CanonicalJSON(v).
// Matches Python sha256_hex(canonical_json_bytes(v)).
func SHA256Hex(v any) (string, error) {
	b, err := CanonicalJSON(v)
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
		encodeString(buf, x)
		return nil
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
	case float32:
		return marshalFloat(buf, float64(x))
	case float64:
		return marshalFloat(buf, x)
	case []any:
		return marshalArray(buf, x)
	case map[string]any:
		return marshalObject(buf, x)
	}
	// Fall back to encoding/json's reflection path for typed structs and
	// any other supported value not covered by the explicit switch.
	return marshalViaReflection(buf, v)
}

func marshalFloat(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canonical: non-finite number %g is not JSON", f)
	}
	// Match Python: integral floats serialise as their integer form.
	if f == math.Trunc(f) {
		buf.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}
	// Non-integer floats are out of scope per Bundle-Spec §6.2 (no float
	// fields). Match the Python ref's posture: reject so a future schema
	// change forces a coordinated cross-language upgrade.
	return fmt.Errorf(
		"canonical: non-integer float %g is unsupported; Bundle-Spec §6.2 has no float fields",
		f,
	)
}

func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		case ' ':
			buf.WriteString(` `)
		case ' ':
			buf.WriteString(` `)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
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
		encodeString(buf, k)
		buf.WriteByte(':')
		if err := marshalValue(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func marshalViaReflection(buf *bytes.Buffer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("canonical: cannot encode value of type %T: %w", v, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var anyVal any
	if err := dec.Decode(&anyVal); err != nil {
		return fmt.Errorf("canonical: cannot re-decode value: %w", err)
	}
	return marshalAny(buf, anyVal)
}

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
		encodeString(buf, x)
		return nil
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return fmt.Errorf("canonical: malformed number %q: %w", s, err)
			}
			return marshalFloat(buf, f)
		}
		buf.WriteString(s)
		return nil
	case []any:
		return marshalArray(buf, x)
	case map[string]any:
		return marshalObject(buf, x)
	}
	return fmt.Errorf("canonical: unsupported value type after reflection: %T", v)
}
