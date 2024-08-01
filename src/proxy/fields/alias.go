package fields

import (
	"strings"

	F "github.com/yusing/go-proxy/utils/functional"
)

type Alias struct{ F.Stringable }
type Aliases struct{ *F.Slice[Alias] }

func NewAlias(s string) Alias {
	return Alias{F.NewStringable(s)}
}

func NewAliases(s string) Aliases {
	split := strings.Split(s, ",")
	a := Aliases{F.NewSliceN[Alias](len(split))}
	for i, v := range split {
		a.Set(i, NewAlias(v))
	}
	return a
}
