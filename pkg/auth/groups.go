package auth

import (
	"github.com/gobwas/glob"
)

// groupsClaim is the userinfo key the filter applies to.
const groupsClaim = "groups"

// GroupsFilter narrows the `groups` claim to the groups matching any of a
// set of glob patterns before the claim is stored in the session cookie.
//
// The session cookie is encoded by gorilla/securecookie, which refuses any
// value over 4096 bytes. A user in many groups -- common with enterprise
// directories, where around a hundred is unremarkable -- pushes the stored
// userinfo past that, and every login then fails at the callback. Keeping
// only the groups that can matter to an access decision keeps the cookie
// under the limit without the identity provider having to know that list.
//
// A zero-value or empty filter keeps every group.
type GroupsFilter struct {
	patterns []glob.Glob
}

// NewGroupsFilter compiles the patterns. Empty patterns are skipped, so an
// unset setting yields a filter that keeps everything.
func NewGroupsFilter(patterns []string) (*GroupsFilter, error) {
	f := &GroupsFilter{}
	for _, p := range patterns {
		if p == "" {
			continue
		}
		g, err := glob.Compile(p)
		if err != nil {
			return nil, err
		}
		f.patterns = append(f.patterns, g)
	}
	return f, nil
}

// Apply returns userInfo with its `groups` list narrowed to matching names.
//
// Anything it cannot interpret is left untouched rather than dropped: a
// missing claim, a claim that is not a list, and non-string list entries.
// Dropping them would turn "this filter does not understand the claim" into
// "this user is in no groups", which downstream reads as a refusal.
func (f *GroupsFilter) Apply(userInfo map[string]any) map[string]any {
	if f == nil || len(f.patterns) == 0 || userInfo == nil {
		return userInfo
	}
	groups, ok := userInfo[groupsClaim].([]any)
	if !ok {
		return userInfo
	}
	kept := make([]any, 0, len(groups))
	for _, g := range groups {
		name, ok := g.(string)
		if !ok || f.match(name) {
			kept = append(kept, g)
		}
	}
	out := make(map[string]any, len(userInfo))
	for k, v := range userInfo {
		out[k] = v
	}
	out[groupsClaim] = kept
	return out
}

func (f *GroupsFilter) match(name string) bool {
	for _, p := range f.patterns {
		if p.Match(name) {
			return true
		}
	}
	return false
}
