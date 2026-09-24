package dedupe

import "encoding/json"

// osvAdvisory is the subset of one OSV advisory's JSON that dedupe
// needs: which Go symbols it lists as affected, per import.
type osvAdvisory struct {
	Affected []struct {
		EcosystemSpecific struct {
			Imports []struct {
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// matchesOSVSymbol reports whether raw (one OSV advisory's stored
// JSON) lists a symbol matching a claim's (qualifier, name). OSV's Go
// ecosystem_specific.imports[].symbols lists a method as "Type.Method"
// and a plain function as its bare name. Without import resolution, a
// package qualifier and a type name are syntactically indistinguishable
// — the exact ambiguity ground.findDeclaration already accepts for the
// same reason — so both the bare and qualified forms are checked.
func matchesOSVSymbol(raw []byte, qualifier, name string) bool {
	var adv osvAdvisory
	if err := json.Unmarshal(raw, &adv); err != nil {
		return false
	}
	qualified := qualifier + "." + name
	for _, a := range adv.Affected {
		for _, im := range a.EcosystemSpecific.Imports {
			for _, sym := range im.Symbols {
				if sym == name || sym == qualified {
					return true
				}
			}
		}
	}
	return false
}
