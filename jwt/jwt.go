package jwt

type Options func(*JWT)

type JWT struct {
}

func (j *JWT) Sign() {}

func (j *JWT) Verify() {}
