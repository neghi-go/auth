package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"

	"github.com/neghi-go/utilities"
)

type Encrypt struct {
}

func (e *Encrypt) Encrypt(value map[string]any) (string, error) {
	value["_pad"] = utilities.Generate(16)
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	if err := enc.Encode(&value); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b.Bytes()), nil
}

func (e *Encrypt) Decrypt(value string) (map[string]any, error) {
	res := make(map[string]any)
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	dec := gob.NewDecoder(bytes.NewBuffer(b))

	err = dec.Decode(&res)
	if err != nil {
		return nil, err
	}

	return res, nil
}
