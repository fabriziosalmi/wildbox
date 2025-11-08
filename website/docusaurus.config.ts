import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'Wildbox',
  tagline: 'The Complete Open-Source Security Operations Suite',
  favicon: 'img/favicon.ico',

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // Set the production url of your site here
  url: 'https://wildbox.io',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'fabriziosalmi', // Usually your GitHub org/user name.
  projectName: 'wildbox', // Usually your repo name.

  onBrokenLinks: 'throw',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/fabriziosalmi/wildbox/tree/main/website/',
          docItemComponent: '@theme/ApiItem', // Derived from docusaurus-theme-openapi-docs
        },
        blog: false, // Disable blog for now
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      'docusaurus-plugin-openapi-docs',
      {
        id: 'api',
        docsPluginId: 'classic',
        config: {
          identity: {
            specPath: 'static/api-specs/identity.openapi.json',
            outputDir: 'docs/05-api-reference/identity',
            sidebarOptions: {
              groupPathsBy: 'tag',
              categoryLinkSource: 'tag',
            },
          },
          tools: {
            specPath: 'static/api-specs/tools.openapi.json',
            outputDir: 'docs/05-api-reference/tools',
            sidebarOptions: {
              groupPathsBy: 'tag',
              categoryLinkSource: 'tag',
            },
          },
          agents: {
            specPath: 'static/api-specs/agents.openapi.json',
            outputDir: 'docs/05-api-reference/agents',
            sidebarOptions: {
              groupPathsBy: 'tag',
              categoryLinkSource: 'tag',
            },
          },
          responder: {
            specPath: 'static/api-specs/responder.openapi.json',
            outputDir: 'docs/05-api-reference/responder',
            sidebarOptions: {
              groupPathsBy: 'tag',
              categoryLinkSource: 'tag',
            },
          },
          cspm: {
            specPath: 'static/api-specs/cspm.openapi.json',
            outputDir: 'docs/05-api-reference/cspm',
            sidebarOptions: {
              groupPathsBy: 'tag',
              categoryLinkSource: 'tag',
            },
          },
          data: {
            specPath: 'static/api-specs/data.openapi.json',
            outputDir: 'docs/05-api-reference/data',
            sidebarOptions: {
              groupPathsBy: 'tag',
              categoryLinkSource: 'tag',
            },
          },
        },
      },
    ],
  ],

  themes: ['docusaurus-theme-openapi-docs'],

  themeConfig: {
    // Replace with your project's social card
    image: 'img/docusaurus-social-card.jpg',
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Wildbox',
      logo: {
        alt: 'Wildbox Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'tutorialSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {
          type: 'docSidebar',
          sidebarId: 'apiSidebar',
          position: 'left',
          label: 'API Reference',
        },
        {
          href: 'https://github.com/fabriziosalmi/wildbox',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Quick Start',
              to: '/docs/getting-started/quickstart',
            },
            {
              label: 'Architecture',
              to: '/docs/architecture/overview',
            },
            {
              label: 'Components',
              to: '/docs/components/overview',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub Issues',
              href: 'https://github.com/fabriziosalmi/wildbox/issues',
            },
            {
              label: 'Discussions',
              href: 'https://github.com/fabriziosalmi/wildbox/discussions',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Security Policy',
              to: '/docs/security/policy',
            },
            {
              label: 'Contributing',
              to: '/docs/contributing/guidelines',
            },
            {
              label: 'GitHub',
              href: 'https://github.com/fabriziosalmi/wildbox',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Wildbox. Licensed under MIT. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
