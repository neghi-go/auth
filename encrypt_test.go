package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var res string
var err error

func TestEncrypt_Encrypt(t *testing.T) {
	val := map[string]any{
		"email":  "jon@doe.com",
		"expiry": 1257898600,
	}
	e := &Encrypt{}

	res, err = e.Encrypt(val)
	require.NoError(t, err)
	require.NotZero(t, res)
}

func TestEncrypt_Decrypt(t *testing.T) {
	e := &Encrypt{}

	data, err := e.Decrypt(res)
	require.NoError(t, err)
	require.NotZero(t, data)
}
