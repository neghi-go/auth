package auth

import (
	"encoding/base64"

	"github.com/neghi-go/utilities"
)

type Encrypt struct {
}

func (e *Encrypt) Encrypt(value map[string]any) (string, error) {
	value["_pad"] = utilities.Generate(16)
	b, err := GobEncode(value)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (e *Encrypt) Decrypt(value string) (map[string]any, error) {
	res := make(map[string]any)
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	err = GobDecode(b, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}
