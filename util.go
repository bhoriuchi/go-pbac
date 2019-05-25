package pbac

import (
	"encoding/json"
	"reflect"
)

// getKind strips the pointer and interface from the kind
func getKind(value interface{}) reflect.Kind {
	rv := reflect.ValueOf(value)
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		rv = rv.Elem()
	}
	return rv.Kind()
}

// isArrayLike check if the interface is a slice or array
func isArrayLike(value interface{}) bool {
	switch kind := getKind(value); kind {
	case reflect.Slice, reflect.Array:
		return true
	default:
		return false
	}
}

// arrayify turns an interface into a map
func arrayify(src interface{}) ([]interface{}, error) {
	m := make([]interface{}, 0)

	// make array if not an array
	if !isArrayLike(src) {
		a := make([]interface{}, 0)
		src = append(a, src)
	}

	b, err := json.Marshal(src)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	if err != nil {
		return m, err
	}
	return m, nil
}
