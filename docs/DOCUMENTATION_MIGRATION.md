# Documentation Migration Guide

This document explains the new Wildbox documentation structure and how to use it.

## What Changed

### Before
- Documentation was fragmented across multiple locations:
  - Root markdown files (README.md, QUICKSTART.md, DEPLOYMENT.md, etc.)
  - Service-specific READMEs in each `open-security-*` directory
  - Manual HTML files in `/docs`
  - Separate API documentation files

### After
- **Centralized documentation** in `website/` directory powered by Docusaurus
- **Auto-generated API documentation** from OpenAPI specifications
- **Professional, searchable** documentation portal
- **Automated deployment** via GitHub Actions to GitHub Pages

## New Documentation Structure

```
website/
├── docs/                      # All documentation content
│   ├── 01-introduction/       # Platform overview and introduction
│   ├── 02-getting-started/    # Quick start, setup, deployment guides
│   ├── 03-architecture/       # System architecture and design
│   ├── 04-components/         # Individual component documentation
│   ├── 05-api-reference/      # Auto-generated API docs
│   ├── 06-guides/             # Tutorials and how-to guides
│   ├── 07-security/           # Security policies and audits
│   └── 08-contributing/       # Contributing guidelines
├── static/
│   ├── api-specs/             # Generated OpenAPI specifications
│   └── img/                   # Images and screenshots
└── src/                       # React components and theme customization
```

## Key Features

### 1. Auto-Generated API Documentation

API documentation is automatically generated from OpenAPI specifications exposed by each service.

**How it works:**
1. Each FastAPI service exposes `/openapi.json` endpoint
2. Script `scripts/generate-api-specs.sh` downloads all specs
3. Docusaurus plugin converts specs to interactive documentation
4. Documentation updates automatically on deployment

**Services with API docs:**
- Identity Service (`:8001`)
- Tools API (`:8000`)
- Data Lake (`:8002`)
- AI Agents (`:8006`)
- Responder (`:8018`)
- CSPM (`:8019`)

### 2. Automated Deployment

GitHub Actions automatically deploys documentation when:
- Changes are pushed to `main` branch
- Files in `website/`, `docs/`, or `*.md` are modified

**Workflow:**
1. Services start in CI environment
2. OpenAPI specs are generated
3. API docs are generated from specs
4. Docusaurus builds the site
5. Site deploys to GitHub Pages

### 3. Developer-Friendly

- **Hot reload** during development
- **TypeScript support** for type safety
- **MDX support** for embedding React components
- **Syntax highlighting** for code blocks
- **Dark mode** built-in

## How to Use

### Local Development

```bash
# Navigate to website directory
cd website

# Install dependencies
npm install

# Start development server
npm start
```

### With API Documentation

```bash
# 1. Start Wildbox services
docker-compose up -d

# 2. Generate API specs
./scripts/generate-api-specs.sh

# 3. Generate API docs
cd website
npm run gen-api-docs

# 4. Start dev server
npm start
```

### Building for Production

```bash
cd website
npm run build
npm run serve
```

## Migrating Content

### From Root Markdown Files

Old files like `QUICKSTART.md`, `DEPLOYMENT.md` have been migrated to:
- `website/docs/02-getting-started/quickstart.md`
- `website/docs/02-getting-started/deployment.md`

### From Service READMEs

Each `open-security-*/README.md` should be migrated to:
- `website/docs/04-components/[service-name].md`

### From Manual API Docs

Files like `GUARDIAN_API_ENDPOINTS.md` are replaced by auto-generated docs in:
- `website/docs/05-api-reference/`

## Updating Documentation

### Adding New Pages

1. Create `.md` file in appropriate directory
2. Add frontmatter:
   ```yaml
   ---
   sidebar_position: 1
   title: Page Title
   ---
   ```
3. Write content in Markdown
4. Commit and push

### Updating API Documentation

API docs update automatically when:
1. OpenAPI specs change in services
2. Script regenerates specs
3. Site rebuilds

**Manual update:**
```bash
./scripts/generate-api-specs.sh
cd website
npm run gen-api-docs
```

### Adding Images

1. Place image in `website/static/img/`
2. Reference in Markdown:
   ```markdown
   ![Alt text](/img/my-image.png)
   ```

## Deployment

### Automatic (GitHub Actions)

Push to `main` branch triggers automatic deployment:
```bash
git add .
git commit -m "docs: Update documentation"
git push
```

### Manual (GitHub Pages)

```bash
cd website
npm run build
npm run deploy
```

## Migration Checklist

- [x] Setup Docusaurus
- [x] Create documentation structure
- [x] Migrate introduction and quickstart
- [x] Configure OpenAPI plugin
- [x] Create API spec generation script
- [x] Setup GitHub Actions workflow
- [ ] Migrate all remaining content:
  - [ ] Architecture documentation
  - [ ] All component READMEs
  - [ ] Security documentation
  - [ ] Contributing guidelines
  - [ ] Deployment guides
- [ ] Remove old documentation files
- [ ] Update main README.md with link to new docs

## Benefits

1. **Single Source of Truth** - All documentation in one place
2. **Always Up-to-Date API Docs** - Auto-generated from code
3. **Professional Appearance** - Modern, responsive design
4. **Better Discoverability** - Search functionality
5. **Easier Maintenance** - Single documentation system
6. **Version Control** - Docs versioned with code
7. **Community Friendly** - Easy to contribute via PRs

## Resources

- **Live Documentation**: https://wildbox.io (after deployment)
- **Local Development**: http://localhost:3000
- **Docusaurus Docs**: https://docusaurus.io/docs
- **OpenAPI Plugin**: https://github.com/PaloAltoNetworks/docusaurus-openapi-docs

## Support

For documentation-related questions:
- 📖 [Docusaurus Guide](https://docusaurus.io/docs)
- 💬 [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions)
- 🐛 [Report Issues](https://github.com/fabriziosalmi/wildbox/issues)

## Next Steps

1. **Complete Migration**: Migrate remaining documentation from old locations
2. **Test Deployment**: Verify GitHub Pages deployment works
3. **Add Search**: Configure Algolia search (requires signup)
4. **Versioning**: Setup documentation versioning for releases
5. **Cleanup**: Remove old documentation files after migration complete
6. **Update Links**: Update all references to old docs locations

---

**Migration Status**: 🚧 In Progress

**Last Updated**: November 8, 2024
