# AI Analysis and LLM Configuration

This page used to describe running a local LLM with Ollama. **Wildbox no
longer ships or supports an Ollama container**: no Compose file defines one and
no service reads an Ollama or OpenAI-compatible endpoint. The setup that page
described does not work with the current code.

## What the Agents Service Uses

AI-assisted analysis in the agents service calls the Anthropic API (Claude).
It is optional: without a key the stack starts normally and analysis tasks
fail with an error instead of producing results.

Set these in `.env`:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | empty | Enables AI analysis when set |
| `ANTHROPIC_MODEL` | `claude-opus-4-8` | Model the agents service requests |

Then restart the agents service:

```bash
docker compose up -d agents
```

## Privacy

With `ANTHROPIC_API_KEY` set, the indicators you submit for analysis, and the
context the agents service gathers about them, are sent to Anthropic's API.
Leave the key empty if that is not acceptable for your environment; the rest
of the platform does not depend on it.

## Related

- [Service ports](ports.md)
- [Agents service API](../api/agents/endpoints.md)
