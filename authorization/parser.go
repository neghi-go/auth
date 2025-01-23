package authorization

import (
	"errors"
	"reflect"
	"strings"
)

const tag = "attr"

func parse(obj interface{}) (map[string]interface{}, error) {
	res := make(map[string]interface{})
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Struct {
		return nil, errors.New("unsupported: expected a struct")
	}
	for i := 0; i < v.NumField(); i++ {
		key := []string{}
		field := v.Field(i)
		if attr, ok := v.Type().Field(i).Tag.Lookup(tag); ok {
			key = append(key, attr)
			if field.Kind() == reflect.Struct {
				var val interface{}
				for j := 0; j < field.NumField(); j++ {
					if k := parseField(field.Type().Field(j)); k != "" {
						switch field.Field(j).Kind() {
						case reflect.Int:
							val = int(field.Field(j).Int())
						case reflect.String:
							val = field.Field(j).String()
						default:
							val = field.Field(j).Interface()
						}
						res[strings.Join(append(key, k), ":")] = val
					}
				}

			}
		}

	}
	return res, nil
}
func parseField(val reflect.StructField) string {
	if attr, ok := val.Tag.Lookup(tag); ok {
		return attr
	}
	return ""
}
