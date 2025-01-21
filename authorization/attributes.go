package authorization

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/neghi-go/auth/store"
	"gopkg.in/yaml.v3"
)

type Options func() (*[]Attributes, error)

type Attributes struct {
	ID          uuid.UUID `json:"id" yaml:"-"`
	Subject     string    `json:"subject" yaml:"subject"`
	Actions     []string  `json:"actions" yaml:"actions"`
	Resource    string    `json:"resource" yaml:"resource"`
	Environment string    `json:"environment" yaml:"environment"`
}

func New(opt Options) (*[]Attributes, error) {
	return opt()
}

func WithPath(path string) Options {
	var res []Attributes
	return func() (*[]Attributes, error) {
		f, err := os.OpenFile(path, os.O_RDONLY|os.O_SYNC, 0)
		if err != nil {
			return nil, err
		}

		defer f.Close()

		switch ext := strings.ToLower(filepath.Ext(path)); ext {
		case ".yaml", ".yml":
			err = parseYaml(f, &res)
		case ".json":
			err = parseJSON(f, &res)
		default:
			return nil, fmt.Errorf("file format not recognized, %s", ext)
		}
		if err != nil {
			return nil, err
		}

		return &res, nil
	}
}

func WithDB(store store.Store) Options {
	return func() (*[]Attributes, error) {
		return nil, nil
	}
}

func parseYaml(r io.Reader, val interface{}) error {
	return yaml.NewDecoder(r).Decode(val)
}

func parseJSON(r io.Reader, val interface{}) error {
	return json.NewDecoder(r).Decode(val)
}
