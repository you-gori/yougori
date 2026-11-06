package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// decodeImageJSON accepts exactly one bounded-depth JSON value, no duplicate keys and
// no unknown typed fields. Image documents must have the same meaning on both sides of
// the VM boundary; encoding/json alone accepts duplicates and ignores a second value.
func decodeImageJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	fields := map[reflect.Type]map[string]reflect.Type{}
	var value func(int, reflect.Type) error
	value = func(depth int, schema reflect.Type) error {
		if depth > 64 {
			return fmt.Errorf("image JSON exceeds nesting bound")
		}
		for schema != nil && schema.Kind() == reflect.Pointer {
			schema = schema.Elem()
		}
		if schema == reflect.TypeOf(json.RawMessage{}) {
			schema = nil
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		var closing json.Delim
		switch delim {
		case '{':
			closing = '}'
			keys := map[string]bool{}
			// encoding/json also accepts case-insensitive aliases. The Rust boundary
			// does not; require the exact declared names for typed objects. Map keys
			// (for example xattrs) remain arbitrary and case-sensitive.
			if schema != nil && schema.Kind() == reflect.Struct && fields[schema] == nil {
				fields[schema] = map[string]reflect.Type{}
				for i := 0; i < schema.NumField(); i++ {
					field := schema.Field(i)
					name := strings.Split(field.Tag.Get("json"), ",")[0]
					if name == "" {
						name = field.Name
					}
					if name != "-" {
						fields[schema][name] = field.Type
					}
				}
			}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return fmt.Errorf("duplicate or invalid image JSON field")
				}
				keys[name] = true
				var child reflect.Type
				if schema != nil {
					switch schema.Kind() {
					case reflect.Struct:
						child = fields[schema][name]
						if child == nil {
							return fmt.Errorf("unknown image JSON field %q", name)
						}
					case reflect.Map:
						child = schema.Elem()
					}
				}
				if err := value(depth+1, child); err != nil {
					return err
				}
			}
		case '[':
			closing = ']'
			var child reflect.Type
			if schema != nil && (schema.Kind() == reflect.Slice || schema.Kind() == reflect.Array) {
				child = schema.Elem()
			}
			for decoder.More() {
				if err := value(depth+1, child); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected image JSON delimiter")
		}
		end, err := decoder.Token()
		if err != nil || end != closing {
			return fmt.Errorf("unterminated image JSON value")
		}
		return nil
	}
	if err := value(0, reflect.TypeOf(target)); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after image JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
