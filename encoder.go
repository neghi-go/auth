package iam

import (
	"bytes"
	"encoding/gob"
)

func GobEncode[T any](val T) ([]byte, error) {
	var b bytes.Buffer

	if err := gob.NewEncoder(&b).Encode(val); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func GobDecode[T any](val []byte, res T) error {
	if err := gob.NewDecoder(bytes.NewBuffer(val)).Decode(res); err != nil {
		return err
	}
	return nil
}
