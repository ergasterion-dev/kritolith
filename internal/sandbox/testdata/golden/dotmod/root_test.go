package lib

import (
	"example.com/lib.v2/yaml.v3"
	"testing"
)

func TestA(t *testing.T) { T{}.Boom() }
func TestB(t *testing.T) { yaml.Boom() }
