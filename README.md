# MCP Auth Proxy

MCP Auth Proxy is a secure OAuth 2.0 authentication proxy for Model Context Protocol (MCP) servers. MCP servers are expected to support not only standard OAuth 2.0 flows but also Dynamic Client support (e.g., dynamic client registration) and authentication-related .well-known metadata. On top of that, different MCP clients handle tokens differently, which makes implementation tricky.

MCP Auth Proxy sits in front of your MCP services and enforces sign-in with OAuth providers (such as Google or GitHub) before users can access protected MCP resources.

## Note

For a simpler approach to publish local MCP servers over OAuth, consider [MCP Warp](https://github.com/sigbit/mcp-warp), which provides an OAuth Proxy + ngrok-like service. We highly recommend considering this option as well.

## 🔧 Configuration

### Environment Variables

| Variable               | Required | Description                                      | Default                 |
| ---------------------- | -------- | ------------------------------------------------ | ----------------------- |
| `LISTEN`               | No       | Server listen address                            | `:8081`                 |
| `DATA_PATH`            | No       | Data directory path                              | `./data`                |
| `EXTERNAL_URL`         | No       | External URL for OAuth callbacks                 | `http://localhost:8081` |
| `PROXY_URL`            | No       | Target MCP server URL                            | `http://localhost:8080` |
| `GLOBAL_SECRET`        | No       | Global secret for session encryption             | `supersecret`           |
| `GOOGLE_CLIENT_ID`     | No*      | Google OAuth client ID                           | -                       |
| `GOOGLE_CLIENT_SECRET` | No*      | Google OAuth client secret                       | -                       |
| `GOOGLE_ALLOWED_USERS` | No       | Comma-separated list of allowed Google emails    | -                       |
| `GITHUB_CLIENT_ID`     | No*      | GitHub OAuth client ID                           | -                       |
| `GITHUB_CLIENT_SECRET` | No*      | GitHub OAuth client secret                       | -                       |
| `GITHUB_ALLOWED_USERS` | No       | Comma-separated list of allowed GitHub usernames | -                       |
| `MODE`                 | No       | Set to `debug` for development mode              | `production`            |

*At least one OAuth provider must be configured (Google or GitHub)

### OAuth Provider Setup

#### Google OAuth Setup
1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `{EXTERNAL_URL}/.auth/google/callback`

#### GitHub OAuth Setup
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create a new OAuth App
3. Set Authorization callback URL: `{EXTERNAL_URL}/.auth/github/callback`

## 🚀 Installation & Usage

### Method 1: Direct Binary

```bash
# Clone the repository
git clone https://github.com/sigbit/mcp-auth-proxy.git
cd mcp-auth-proxy

# Build the binary
go build -o mcp-auth-proxy .

# Run with environment variables
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GOOGLE_ALLOWED_USERS="user1@example.com,user2@example.com"
./mcp-auth-proxy
```

### Method 2: Command Line Arguments

```bash
./mcp-auth-proxy \
  --external-url "https://your-domain.com" \
  --proxy-url "http://your-mcp-server:8080" \
  --google-client-id "your-google-client-id" \
  --google-client-secret "your-google-client-secret" \
  --google-allowed-users "user1@example.com,user2@example.com"
```

### Method 3: Docker Compose (Recommended)

1. Create a `.env` file in the `example/` directory:

```env
GLOBAL_SECRET=your-super-secret-key-here
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_ALLOWED_USERS=user1@example.com,user2@example.com
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_ALLOWED_USERS=username1,username2
```

2. Run with Docker Compose:

```bash
cd example/
docker compose up -d
```

This will start:
- MCP Auth Proxy on port 8081
- Playwright MCP server on port 8931 (as an example backend)
