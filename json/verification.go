package json

import (
	"strings"
)

func HasDuplicatedKey(json []byte) bool {
	replacer := strings.NewReplacer("\"", "", "{", "", "}", "", "\\", "")
	nameColonValueSet := strings.Split(replacer.Replace(string(json)), ",")

	keySet := map[string]struct{}{}

	for _, v := range nameColonValueSet {
		key := strings.Split(v, ":")[0]

		if _, exists := keySet[key]; exists {
			return true
		}

		keySet[key] = struct{}{}
	}

	return false
}
