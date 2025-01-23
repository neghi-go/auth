package authorization

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/neghi-go/database"
	"gopkg.in/yaml.v3"
)

type EnforcerKeywords string

const (
	IS      EnforcerKeywords = "is"
	NOT     EnforcerKeywords = "not"
	LESS    EnforcerKeywords = "less"
	GREATER EnforcerKeywords = "greater"
)

type Effect string

const (
	Permit Effect = "permit"
	Deny   Effect = "deny"
)

func (e Effect) String() string {
	return string(e)
}

type Policy struct {
	ID       uuid.UUID `json:"id" yaml:"id" db:"id,unique,index"`
	Name     string    `json:"name" yaml:"name" db:"name,index,unique"`
	Resource []struct {
		Endpoint string   `json:"endpoint" yaml:"endpoint" db:"endpoint"`
		Method   []Method `json:"method" yaml:"method" db:"method"`
	} `json:"resource" yaml:"resource" db:"resource"` //  /resource  /resource/:id
	Condition []string `json:"condition" yaml:"condition" db:"condition"` //<attribute:field:modifier:value>
	Effect    Effect   `json:"effect" yaml:"effect" db:"effect"`
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
		a, _ := parse(attr)
		for _, c := range m.Condition {
			if ok := enforcePolicy(c, a); ok {
				return m.Effect
			}
		}
	}
	return Deny
}

func matchPolicy(policies *PolicyDecisionPoint, attr Attributes) []*Policy {
	matched := make([]*Policy, 0)

	for _, p := range policies.p {
		//check if resources and Method match
		for _, r := range p.Resource {
			if ok := strings.Contains(r.Endpoint, attr.Resource.URL); ok {
				if ok := slices.Contains(r.Method, attr.Resource.Method); ok {
					matched = append(matched, p)
				}
			}
		}
	}
	return matched
}
func enforcePolicy(condition string, a map[string]interface{}) bool {
	v := strings.Split(condition, ":")
	modifier := v[2]
	value := v[3]
	key := strings.Join([]string{v[0], v[1]}, ":")

	switch EnforcerKeywords(modifier) {
	case IS:
		return a[key] == value
	case NOT:
		return a[key] != value
	default:
		return false
	}
}
