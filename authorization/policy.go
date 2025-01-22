package authorization

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/neghi-go/database"
	"gopkg.in/yaml.v3"
)

type Effect int

const (
	Permit Effect = iota
	Deny
)

var effectMap = map[Effect]string{
	Permit: "permit",
	Deny:   "deny",
}

func (e Effect) String() string {
	return effectMap[e]
}

type Policy struct {
	ID        uuid.UUID `json:"id" yaml:"id" db:"id,unique,index"`
	Name      string    `json:"name" yaml:"name" db:"name,index,unique"`
	Condition []string  `json:"condition" yaml:"condition" db:"condition"`
	Effect    Effect    `json:"effect" yaml:"effect" db:"effect"`
}

type PDPOptions func(*PolicyDecisionPoint)

type PolicyDecisionPoint struct {
	p []*Policy
}

func NewPDP(opts ...PDPOptions) *PolicyDecisionPoint {
	cfg := &PolicyDecisionPoint{p: make([]*Policy, 0)}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

func WithPath(path string) PDPOptions {
	var res []*Policy
	return func(pdp *PolicyDecisionPoint) {
		f, err := os.OpenFile(path, os.O_RDONLY|os.O_SYNC, 0)
		if err != nil {
			panic(err)
		}

		defer f.Close()

		switch ext := strings.ToLower(filepath.Ext(path)); ext {
		case ".yaml", ".yml":
			err = parseYaml(f, &res)
		case ".json":
			err = parseJSON(f, &res)
		default:
			panic(errors.New("file format not supported"))
		}
		if err != nil {
			panic(err)
		}
		pdp.p = res
	}
}

func WithDB(model database.Model[Policy]) PDPOptions {
	return func(pdp *PolicyDecisionPoint) {
		p, err := model.Query().All()
		if err != nil {
			panic(err)
		}
		pdp.p = p
	}
}

func parseYaml(r io.Reader, val interface{}) error {
	return yaml.NewDecoder(r).Decode(val)
}

func parseJSON(r io.Reader, val interface{}) error {
	return json.NewDecoder(r).Decode(val)
}

func (pdp *PolicyDecisionPoint) Enforce(attr Attributes) Effect {
	matched := matchPolicy(pdp, attr)

	for _, m := range matched {
		if ok := enforcePolicy(m, attr); ok {
			return m.Effect
		}
	}

	return Deny
}

func matchPolicy(policies *PolicyDecisionPoint, _ Attributes) []*Policy {
	matched := make([]*Policy, 0)

	for range policies.p {
	}

	return matched
}
func enforcePolicy(_ *Policy, _ Attributes) bool {
	return true
}
