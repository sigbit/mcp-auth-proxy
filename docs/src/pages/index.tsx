import type { ReactNode } from "react";
import clsx from "clsx";
import Link from "@docusaurus/Link";
import Layout from "@theme/Layout";
import Heading from "@theme/Heading";

import styles from "./index.module.css";

function HomepageHeader() {
  return (
    <header className={styles.hero}>
      <div className={styles.heroBackground}>
        <div className={styles.heroPattern}></div>
      </div>
      <div className={clsx("container", styles.heroContainer)}>
        <div className={styles.heroContent}>
          <div className={styles.heroBadge}>
            <span className={styles.badgeIcon}>🔐</span>
            <span>Drop-in OAuth Gateway</span>
          </div>
          <Heading as="h1" className={styles.heroTitle}>
            Secure your{" "}
            <span className={styles.heroTitleAccent}>MCP server</span>
            <br />
            with OAuth 2.1
          </Heading>
          <p className={styles.heroSubtitle}>
            Add enterprise-grade authentication to any MCP server in minutes.
            <br />
            No code changes required — just put it in front and you're
            protected.
          </p>
          <div className={styles.heroButtons}>
            <Link
              className={clsx("button", styles.primaryButton)}
              to="/docs/intro"
            >
              <span>Get Started</span>
              <span className={styles.buttonIcon}>→</span>
            </Link>
            <Link
              className={clsx("button", styles.secondaryButton)}
              href="https://github.com/sigbit/mcp-auth-proxy"
            >
              <span className={styles.buttonIcon}>⭐</span>
              <span>View on GitHub</span>
            </Link>
          </div>
        </div>
        <div className={styles.heroVisual}>
          <div className={styles.terminalWindow}>
            <div className={styles.terminalHeader}>
              <div className={styles.terminalButtons}>
                <span className={styles.terminalButton}></span>
                <span className={styles.terminalButton}></span>
                <span className={styles.terminalButton}></span>
              </div>
              <span className={styles.terminalTitle}>Terminal</span>
            </div>
            <div className={styles.terminalContent}>
              <div className={styles.terminalLine}>
                <span className={styles.terminalComment}>
                  # Download and run MCP Auth Proxy
                </span>
              </div>
              <div className={styles.terminalLine}>
                <span className={styles.terminalPrompt}>$</span>
                <span className={styles.terminalCommand}>mcp-auth-proxy \</span>
              </div>
              <div className={styles.terminalLine}>
                <span className={styles.terminalFlag}>
                  &nbsp;&nbsp;--external-url
                </span>{" "}
                <span className={styles.terminalValue}>
                  https://your-domain.com
                </span>{" "}
                <span className={styles.terminalCommand}>\</span>
              </div>
              <div className={styles.terminalLine}>
                <span className={styles.terminalFlag}>
                  &nbsp;&nbsp;--tls-accept-tos
                </span>{" "}
                <span className={styles.terminalCommand}>\</span>
              </div>
              <div className={styles.terminalLine}>
                <span className={styles.terminalFlag}>
                  &nbsp;&nbsp;--password
                </span>{" "}
                <span className={styles.terminalValue}>changeme</span>{" "}
                <span className={styles.terminalCommand}>\</span>
              </div>
              <div className={styles.terminalLine}>
                <span className={styles.terminalCommand}>
                  &nbsp;&nbsp;-- npx -y @modelcontextprotocol/server-filesystem
                  ./
                </span>
              </div>
              <div className={styles.terminalLine}>
                <span className={styles.terminalOutput}>
                  ✅ OAuth proxy started on port 443
                </span>
              </div>
              <div className={styles.terminalLine}>
                <span className={styles.terminalOutput}>
                  🔐 Endpoint: https://your-domain.com/mcp
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

interface FeatureProps {
  title: string;
  description: ReactNode;
  icon: string;
  gradient: string;
}

function Feature({ title, description, icon, gradient }: FeatureProps) {
  return (
    <div className={styles.featureCard}>
      <div
        className={styles.featureIconWrapper}
        style={{ background: gradient }}
      >
        <span className={styles.featureIcon}>{icon}</span>
      </div>
      <div className={styles.featureContent}>
        <Heading as="h3" className={styles.featureTitle}>
          {title}
        </Heading>
        <p className={styles.featureDescription}>{description}</p>
      </div>
    </div>
  );
}

function HomepageFeatures() {
  const features: FeatureProps[] = [
    {
      title: "Drop-in OAuth Gateway",
      icon: "🔐",
      gradient: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
      description: (
        <>
          Add OAuth 2.1/OIDC authentication to any MCP server without code
          changes. Just put it in front of your existing server and you're
          protected.
        </>
      ),
    },
    {
      title: "Universal Identity Provider Support",
      icon: "🏢",
      gradient: "linear-gradient(135deg, #f093fb 0%, #f5576c 100%)",
      description: (
        <>
          Support for Google, GitHub, OIDC (Okta, Auth0, Azure AD, Keycloak,
          etc.), and password authentication. Choose your preferred identity
          provider with optional allow-lists for enhanced security.
        </>
      ),
    },
    {
      title: "All Transport Types",
      icon: "🚀",
      gradient: "linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)",
      description: (
        <>
          Works with stdio, SSE, and HTTP transports. For stdio, traffic is
          converted to <code>/mcp</code>. For SSE/HTTP, it's proxied as-is with
          authentication.
        </>
      ),
    },
  ];

  return (
    <section className={styles.features}>
      <div className="container">
        <div className={styles.featuresHeader}>
          <Heading as="h2" className={styles.sectionTitle}>
            Why Choose MCP Auth Proxy?
          </Heading>
          <p className={styles.sectionSubtitle}>
            Enterprise-grade security without the enterprise complexity
          </p>
        </div>
        <div className={styles.featuresGrid}>
          {features.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}

function QuickStart() {
  return (
    <section className={styles.quickstart}>
      <div className="container">
        <div className={styles.quickstartContent}>
          <div className={styles.quickstartText}>
            <Heading as="h2" className={styles.sectionTitle}>
              Get Started in Minutes
            </Heading>
            <p className={styles.sectionSubtitle}>
              Deploy your secure MCP server with a single command
            </p>
            <div className={styles.steps}>
              <div className={styles.step}>
                <div className={styles.stepNumber}>1</div>
                <div className={styles.stepContent}>
                  <h4>Download</h4>
                  <p>Get the latest binary from our releases page</p>
                </div>
              </div>
              <div className={styles.step}>
                <div className={styles.stepNumber}>2</div>
                <div className={styles.stepContent}>
                  <h4>Configure</h4>
                  <p>Set your domain and authentication providers</p>
                </div>
              </div>
              <div className={styles.step}>
                <div className={styles.stepNumber}>3</div>
                <div className={styles.stepContent}>
                  <h4>Deploy</h4>
                  <p>Run the command and you're live with OAuth protection</p>
                </div>
              </div>
            </div>
          </div>
          <div className={styles.quickstartCode}>
            <div className={styles.codeWindow}>
              <div className={styles.codeHeader}>
                <div className={styles.codeButtons}>
                  <span className={styles.codeButton}></span>
                  <span className={styles.codeButton}></span>
                  <span className={styles.codeButton}></span>
                </div>
                <span className={styles.codeTitle}>Quick Start</span>
              </div>
              <div className={styles.codeContent}>
                <div className={styles.codeLine}>
                  <span className={styles.codeComment}>
                    # Download and run MCP Auth Proxy
                  </span>
                </div>
                <div className={styles.codeLine}>
                  <span className={styles.codeCommand}>mcp-auth-proxy \</span>
                </div>
                <div className={styles.codeLine}>
                  <span className={styles.codeFlag}>
                    &nbsp;&nbsp;--external-url
                  </span>{" "}
                  <span className={styles.codeValue}>
                    https://your-domain.com
                  </span>{" "}
                  <span className={styles.codeCommand}>\</span>
                </div>
                <div className={styles.codeLine}>
                  <span className={styles.codeFlag}>
                    &nbsp;&nbsp;--tls-accept-tos
                  </span>{" "}
                  <span className={styles.codeCommand}>\</span>
                </div>
                <div className={styles.codeLine}>
                  <span className={styles.codeFlag}>
                    &nbsp;&nbsp;--password
                  </span>{" "}
                  <span className={styles.codeValue}>changeme</span>{" "}
                  <span className={styles.codeCommand}>\</span>
                </div>
                <div className={styles.codeLine}>
                  <span className={styles.codeCommand}>
                    &nbsp;&nbsp;-- npx -y
                    @modelcontextprotocol/server-filesystem ./
                  </span>
                </div>
              </div>
            </div>
            <div className={styles.resultBadge}>
              <span className={styles.resultIcon}>✨</span>
              <span>
                Secure endpoint at <code>https://your-domain.com/mcp</code>
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function VerifiedClients() {
  const clients = [
    { name: "Claude - Web", logo: "🤖", category: "Web" },
    { name: "Claude - Desktop", logo: "💻", category: "Desktop" },
    { name: "Claude Code", logo: "🔨", category: "IDE" },
    { name: "ChatGPT - Web", logo: "🌐", category: "Web" },
    { name: "ChatGPT - Desktop", logo: "💻", category: "Desktop" },
    { name: "GitHub Copilot", logo: "🐙", category: "IDE" },
    { name: "Cursor", logo: "⚡", category: "IDE" },
  ];

  return (
    <section className={styles.clients}>
      <div className="container">
        <div className={styles.clientsHeader}>
          <Heading as="h2" className={styles.sectionTitle}>
            Battle-Tested Compatibility
          </Heading>
          <p className={styles.sectionSubtitle}>
            Works seamlessly with all major MCP clients — no configuration
            needed
          </p>
        </div>
        <div className={styles.clientsGrid}>
          {clients.map((client, idx) => (
            <div key={idx} className={styles.clientCard}>
              <div className={styles.clientLogo}>{client.logo}</div>
              <div className={styles.clientInfo}>
                <div className={styles.clientName}>{client.name}</div>
                <div className={styles.clientCategory}>{client.category}</div>
              </div>
              <div className={styles.clientStatus}>
                <span className={styles.statusIcon}>✅</span>
                <span className={styles.statusText}>Verified</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="MCP Auth Proxy"
      description="Drop-in OAuth 2.1/OIDC gateway for MCP servers. Secure your MCP server with authentication in minutes."
    >
      <HomepageHeader />
      <main>
        <HomepageFeatures />
        <QuickStart />
        <VerifiedClients />
      </main>
    </Layout>
  );
}
