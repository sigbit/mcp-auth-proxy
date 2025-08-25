import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

const url = "https://sigbit.github.io";
const baseUrl = "/mcp-auth-proxy/";

const config: Config = {
  title: "MCP Auth Proxy",
  tagline: "Secure your MCP server with OAuth 2.1 — in a minute",
  favicon: "img/favicon.ico",

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  url,
  baseUrl,

  organizationName: "sigbit",
  projectName: "mcp-auth-proxy",

  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          editUrl: "https://github.com/sigbit/mcp-auth-proxy/tree/main/docs/",
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
        sitemap: {
          lastmod: "date",
          changefreq: "weekly",
          priority: 0.5,
          ignorePatterns: ["/tags/**"],
          filename: "sitemap.xml",
          createSitemapItems: async (params) => {
            const { defaultCreateSitemapItems, ...rest } = params;
            const items = await defaultCreateSitemapItems(rest);
            return items.map((item) => {
              if (item.url === `${url}${baseUrl}`) {
                return { ...item, priority: 1.0 };
              }
              return item;
            });
          },
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: "img/mcp-auth-proxy.svg",
    navbar: {
      title: "mcp-auth-proxy",
      items: [
        {
          type: "docSidebar",
          sidebarId: "docsSidebar",
          position: "left",
          label: "Docs",
        },
        {
          href: "https://github.com/sigbit/mcp-auth-proxy",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            {
              label: "Docs",
              to: "/docs/intro",
            },
          ],
        },
        {
          title: "Community",
          items: [
            {
              label: "Issues",
              href: "https://github.com/sigbit/mcp-auth-proxy/issues",
            },
            {
              label: "Discussions",
              href: "https://github.com/sigbit/mcp-auth-proxy/discussions",
            },
          ],
        },
        {
          title: "More",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/sigbit/mcp-auth-proxy",
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} MCP Auth Proxy. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
  headTags: [
    {
      tagName: "meta",
      attributes: {
        name: "google-site-verification",
        content: "MgNfNOkNsGVgWZiK4YsMyCqj9KFbmD3T2wdkP17juvs",
      },
    },
  ],
};

export default config;
