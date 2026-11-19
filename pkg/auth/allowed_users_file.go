package auth

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/oauth2"
)

// AllowedUsersFile is an allow-list kept in a file instead of in the process
// configuration. The file is read again on every lookup, so adding or removing
// a user takes effect without a restart.
//
// Format: one user per line or comma-separated; blank lines and lines starting
// with "#" are ignored.
//
// Lookups fail closed: if the file cannot be read, nobody is allowed.
type AllowedUsersFile struct {
	path string
}

// NewAllowedUsersFile returns the allow-list stored at path. The file must be
// readable at startup; an empty list is valid and allows nobody.
func NewAllowedUsersFile(path string) (*AllowedUsersFile, error) {
	f := &AllowedUsersFile{path: path}
	if _, err := f.users(); err != nil {
		return nil, fmt.Errorf("failed to read allowed users file: %w", err)
	}
	return f, nil
}

// Path returns the location of the file.
func (f *AllowedUsersFile) Path() string {
	return f.path
}

// Contains reports whether user is currently listed in the file.
func (f *AllowedUsersFile) Contains(user string) bool {
	if user == "" {
		return false
	}
	users, err := f.users()
	if err != nil {
		return false
	}
	return slices.Contains(users, user)
}

func (f *AllowedUsersFile) users() ([]string, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, err
	}
	return parseAllowedUsers(data), nil
}

func parseAllowedUsers(data []byte) []string {
	var users []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, user := range strings.Split(line, ",") {
			if user = strings.TrimSpace(user); user != "" {
				users = append(users, user)
			}
		}
	}
	return users
}

// WithAllowedUsersFile wraps a provider so that only the users listed in file
// may sign in. The wrapped provider must be created without allow-list options
// of its own: it identifies the user and the file decides.
func WithAllowedUsersFile(provider Provider, file *AllowedUsersFile) Provider {
	return &allowedUsersFileProvider{Provider: provider, file: file}
}

type allowedUsersFileProvider struct {
	Provider
	file *AllowedUsersFile
}

func (p *allowedUsersFileProvider) Authorization(ctx context.Context, token *oauth2.Token) (bool, string, map[string]any, error) {
	ok, user, userInfo, err := p.Provider.Authorization(ctx, token)
	if err != nil || !ok {
		return ok, user, userInfo, err
	}
	return p.file.Contains(user), user, userInfo, nil
}

// AllowedUsersFiles maps a provider type (Provider.Type()) to its allow-list
// file. It is used to re-check an already issued token on every request.
type AllowedUsersFiles map[string]*AllowedUsersFile

// Allows reports whether a token issued to user through provider is still
// allowed.
//
// A provider without a file is not restricted here. Tokens issued before the
// provider was recorded in the token carry an empty provider; they are allowed
// only if some file lists the user.
func (m AllowedUsersFiles) Allows(provider, user string) bool {
	if provider != "" {
		file, ok := m[provider]
		if !ok {
			return true
		}
		return file.Contains(user)
	}
	for _, file := range m {
		if file.Contains(user) {
			return true
		}
	}
	return false
}
