# Vendored third-party libraries

Kept local so the docs make **zero third-party requests**. Each keeps its own
license.

| Path | What | Version | License |
|---|---|---|---|
| `highlight.js/` | Highlight.js core + bash/json/xml/yaml languages and the atom-one-dark style | 11.9.0 | [BSD-3-Clause](https://github.com/highlightjs/highlight.js/blob/main/LICENSE) |
| `tailwindcss/tailwind.js` | Tailwind CSS Play CDN build (browser JIT compiler) | — | [MIT](https://github.com/tailwindlabs/tailwindcss/blob/main/LICENSE) |

Self-hosted fonts are documented in `fonts/README.md`. The ReDoc bundle used by
the API reference pages is documented in `../api/vendor/redoc/README.md`.

To refresh Highlight.js, download the same version's build from
<https://highlightjs.org/download> with the same language set; to refresh
Tailwind, `curl -sL https://cdn.tailwindcss.com -o tailwindcss/tailwind.js`.
