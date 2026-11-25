package profile

import (
	"regexp"
	"strings"
)

// MatchTemplate matches a concrete path or topic against a template with {name} segments.
func MatchTemplate(template, value, sep string) (map[string]string, bool) {
	ts := strings.Split(template, sep)
	vs := strings.Split(value, sep)
	if len(ts) != len(vs) {
		return nil, false
	}
	params := map[string]string{}
	for i, t := range ts {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") && len(t) > 2 {
			if vs[i] == "" {
				return nil, false
			}
			params[t[1:len(t)-1]] = vs[i]
			continue
		}
		if t != vs[i] {
			return nil, false
		}
	}
	return params, true
}

// FillTemplate substitutes {name} segments; ok is false when a variable is missing.
func FillTemplate(template, sep string, vars map[string]string) (string, bool) {
	ts := strings.Split(template, sep)
	for i, t := range ts {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") && len(t) > 2 {
			v, ok := vars[t[1:len(t)-1]]
			if !ok || v == "" {
				return "", false
			}
			ts[i] = v
		}
	}
	return strings.Join(ts, sep), true
}

var patternVar = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)

// PatternRegexp turns a pattern such as "thermo-{device_id}" into an anchored regexp with
// named groups.
func PatternRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	last := 0
	for _, m := range patternVar.FindAllStringSubmatchIndex(pattern, -1) {
		b.WriteString(regexp.QuoteMeta(pattern[last:m[0]]))
		b.WriteString("(?P<" + pattern[m[2]:m[3]] + ">.+?)")
		last = m[1]
	}
	b.WriteString(regexp.QuoteMeta(pattern[last:]))
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// MatchPattern applies PatternRegexp and returns the captured variables.
func MatchPattern(pattern, value string) (map[string]string, bool) {
	if pattern == "" {
		return map[string]string{}, true
	}
	re, err := PatternRegexp(pattern)
	if err != nil {
		return nil, false
	}
	m := re.FindStringSubmatch(value)
	if m == nil {
		return nil, false
	}
	out := map[string]string{}
	for i, name := range re.SubexpNames() {
		if name != "" {
			out[name] = m[i]
		}
	}
	return out, true
}
