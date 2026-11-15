package auth

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
)

// writeAllowedUsers replaces the file the way most tools do: write a
// temporary file and rename it over the old one.
func writeAllowedUsers(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0o600))
	require.NoError(t, os.Rename(tmp, path))
}

func newAllowedUsersFile(t *testing.T, content string) *AllowedUsersFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowed-users")
	writeAllowedUsers(t, path, content)
	file, err := NewAllowedUsersFile(path)
	require.NoError(t, err)
	return file
}

func TestParseAllowedUsers(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		want    []string
	}{
		{name: "empty", content: "", want: nil},
		{name: "one per line", content: "alice@example.com\nbob@example.com\n", want: []string{"alice@example.com", "bob@example.com"}},
		{name: "comma separated", content: "alice@example.com, bob@example.com", want: []string{"alice@example.com", "bob@example.com"}},
		{name: "comments, blank lines and CRLF", content: "# team\r\n\r\nalice@example.com\r\n  # bob@example.com\r\ncarol@example.com , \r\n", want: []string{"alice@example.com", "carol@example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, parseAllowedUsers([]byte(tt.content)))
		})
	}
}

func TestAllowedUsersFile_IsReadAgainOnEveryLookup(t *testing.T) {
	file := newAllowedUsersFile(t, "alice@example.com\nbob@example.com\n")
	require.True(t, file.Contains("alice@example.com"))
	require.True(t, file.Contains("bob@example.com"))
	require.False(t, file.Contains("carol@example.com"))
	require.False(t, file.Contains(""))
	require.False(t, file.Contains("ALICE@example.com"), "matching is exact, like the --*-allowed-users options")

	writeAllowedUsers(t, file.Path(), "bob@example.com\ncarol@example.com\n")
	require.False(t, file.Contains("alice@example.com"), "removal takes effect without a restart")
	require.True(t, file.Contains("bob@example.com"))
	require.True(t, file.Contains("carol@example.com"), "so does an addition")
}

func TestAllowedUsersFile_FailsClosed(t *testing.T) {
	t.Run("missing file is a startup error", func(t *testing.T) {
		_, err := NewAllowedUsersFile(filepath.Join(t.TempDir(), "missing"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "allowed users file")
	})

	t.Run("an empty list allows nobody", func(t *testing.T) {
		file := newAllowedUsersFile(t, "# nobody yet\n")
		require.False(t, file.Contains("alice@example.com"))
	})

	t.Run("a file that disappears allows nobody", func(t *testing.T) {
		file := newAllowedUsersFile(t, "alice@example.com\n")
		require.True(t, file.Contains("alice@example.com"))
		require.NoError(t, os.Remove(file.Path()))
		require.False(t, file.Contains("alice@example.com"))

		writeAllowedUsers(t, file.Path(), "alice@example.com\n")
		require.True(t, file.Contains("alice@example.com"), "access returns with the file")
	})
}

// Each provider identifies the user in its own way; the file decides for all
// of them in the same place.
func TestWithAllowedUsersFile_Providers(t *testing.T) {
	token := &oauth2.Token{AccessToken: "test-access-token"}

	providers := []struct {
		name   string
		user   string
		other  string
		setup  func(t *testing.T, userResp *string) Provider
		respOf func(user string) string
	}{
		{
			name:  "google",
			user:  "user1@gmail.com",
			other: "user2@gmail.com",
			setup: func(t *testing.T, userResp *string) Provider {
				p, api := setupGoogleTest([]string{}, []string{})
				api.GET("/userinfo", func(c *gin.Context) {
					c.Data(http.StatusOK, "application/json", []byte(*userResp))
				})
				return p
			},
			respOf: func(user string) string { return `{"sub": "12345", "email": "` + user + `"}` },
		},
		{
			name:  "github",
			user:  "user1",
			other: "user2",
			setup: func(t *testing.T, userResp *string) Provider {
				p, api := setupGitHubTest([]string{}, []string{})
				api.GET("/user", func(c *gin.Context) {
					c.Data(http.StatusOK, "application/json", []byte(*userResp))
				})
				return p
			},
			respOf: func(user string) string { return `{"login": "` + user + `"}` },
		},
		{
			name:  "oidc",
			user:  "user1@example.com",
			other: "user2@example.com",
			setup: func(t *testing.T, userResp *string) Provider {
				p, _, userinfo, tsConfig := setupOIDCTest([]string{}, "/email")
				t.Cleanup(tsConfig.Close)
				userinfo.GET("/userinfo", func(c *gin.Context) {
					c.Data(http.StatusOK, "application/json", []byte(*userResp))
				})
				return p
			},
			respOf: func(user string) string { return `{"sub": "12345", "email": "` + user + `"}` },
		},
	}

	for _, tt := range providers {
		t.Run(tt.name, func(t *testing.T) {
			var userResp string
			inner := tt.setup(t, &userResp)
			file := newAllowedUsersFile(t, tt.user+"\n")
			p := WithAllowedUsersFile(inner, file)

			require.Equal(t, tt.name, p.Type(), "the wrapper keeps the provider's identity")
			require.Equal(t, inner.Name(), p.Name())
			require.Equal(t, inner.RedirectURL(), p.RedirectURL())

			authorize := func(user string) (bool, string) {
				userResp = tt.respOf(user)
				ok, id, userInfo, err := p.Authorization(context.Background(), token)
				require.NoError(t, err)
				require.NotNil(t, userInfo)
				return ok, id
			}

			ok, id := authorize(tt.user)
			require.True(t, ok, "listed user signs in")
			require.Equal(t, tt.user, id)

			ok, id = authorize(tt.other)
			require.False(t, ok, "unlisted user is refused")
			require.Equal(t, tt.other, id, "the user ID is still reported for the unauthorized page")

			writeAllowedUsers(t, file.Path(), tt.other+"\n")
			ok, _ = authorize(tt.user)
			require.False(t, ok, "removed user is refused at the next sign-in")
			ok, _ = authorize(tt.other)
			require.True(t, ok, "added user signs in without a restart")

			require.NoError(t, os.Remove(file.Path()))
			ok, _ = authorize(tt.other)
			require.False(t, ok, "missing file refuses everybody")
		})
	}
}

func TestWithAllowedUsersFile_KeepsProviderDecisionsAndErrors(t *testing.T) {
	token := &oauth2.Token{AccessToken: "test-access-token"}
	file := newAllowedUsersFile(t, "alice@example.com\n")

	t.Run("provider error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		inner := NewMockProvider(ctrl)
		inner.EXPECT().Authorization(gomock.Any(), token).Return(false, "", nil, errors.New("userinfo unavailable"))
		ok, _, _, err := WithAllowedUsersFile(inner, file).Authorization(context.Background(), token)
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("provider refusal is not overruled by the file", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		inner := NewMockProvider(ctrl)
		inner.EXPECT().Authorization(gomock.Any(), token).Return(false, "alice@example.com", map[string]any{}, nil)
		ok, user, _, err := WithAllowedUsersFile(inner, file).Authorization(context.Background(), token)
		require.NoError(t, err)
		require.False(t, ok)
		require.Equal(t, "alice@example.com", user)
	})
}

func TestAllowedUsersFiles_Allows(t *testing.T) {
	google := newAllowedUsersFile(t, "alice@example.com\n")
	github := newAllowedUsersFile(t, "alice\n")
	files := AllowedUsersFiles{"google": google, "github": github}

	for _, tt := range []struct {
		name     string
		provider string
		user     string
		want     bool
	}{
		{name: "listed for its provider", provider: "google", user: "alice@example.com", want: true},
		{name: "not listed for its provider", provider: "google", user: "bob@example.com", want: false},
		{name: "listed only for another provider", provider: "google", user: "alice", want: false},
		{name: "provider without a file is not restricted", provider: "oidc", user: "anyone", want: true},
		{name: "password login is not restricted", provider: PasswordProvider, user: PasswordUserID, want: true},
		{name: "token without provider, listed somewhere", provider: "", user: "alice", want: true},
		{name: "token without provider, listed nowhere", provider: "", user: "bob", want: false},
		{name: "token without provider or user", provider: "", user: "", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, files.Allows(tt.provider, tt.user))
		})
	}

	t.Run("removal applies to the next lookup", func(t *testing.T) {
		writeAllowedUsers(t, google.Path(), "bob@example.com\n")
		require.False(t, files.Allows("google", "alice@example.com"))
		require.True(t, files.Allows("google", "bob@example.com"))
	})

	t.Run("no files configured", func(t *testing.T) {
		require.True(t, AllowedUsersFiles{}.Allows("google", "anyone"), "a provider without a file is not restricted")
		require.False(t, AllowedUsersFiles{}.Allows("", "anyone"), "never consulted in this state: the check is only installed when a file is set")
	})
}
