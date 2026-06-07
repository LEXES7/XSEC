# Choosing an AI provider

XSEC's AI review (`--ai`) is **opt-in** and works with several providers, so you
choose between best quality (paid) and free access. Everything else — findings,
reports, the VS Code extension — is identical regardless of provider.

## The options

| Provider | Cost | Quality | Your code is sent to… | Pick it when |
| --- | --- | --- | --- | --- |
| **anthropic** (default) | paid API | ★★★ best | Anthropic | you have Anthropic API credits and want the sharpest review |
| **groq** | **free tier** | ★★ good | Groq | you want free AI review, fast |
| **openrouter** | **free tier** | ★★ good | OpenRouter | you want free access to many models |
| **openai-compatible** | depends | varies | your endpoint | you run a local model or a private gateway |
| *(none)* | free | — | nobody (offline) | you skip `--ai`; rule-based scan still runs |

> **Note on Claude:** a Claude **Pro subscription** (the chat app) does **not**
> include API access — the API is billed separately. So if you want a free path,
> use Groq or OpenRouter.

## Quick start — free with Groq

1. Get a free API key at **https://console.groq.com** (no credit card needed).
2. Store it securely (encrypted in your OS keyring):
   ```bash
   xsec key set --provider groq          # paste the key, input is hidden
   ```
3. Scan:
   ```bash
   xsec scan . --ai --ai-provider groq
   ```

OpenRouter works the same way — get a key at https://openrouter.ai, then
`xsec key set --provider openrouter` and `--ai-provider openrouter`.

## Using the default (Anthropic / Claude)

```bash
xsec key set                # stores your Anthropic key (default provider)
xsec scan . --ai            # uses Claude
```

## Self-hosted / OpenAI-compatible endpoint

Any server exposing an OpenAI-compatible `/chat/completions` works — e.g. a
local model behind an OpenAI-compatible gateway:

```bash
xsec key set --provider openai-compatible        # if your endpoint needs a key
xsec scan . --ai \
  --ai-provider openai-compatible \
  --ai-base-url http://localhost:1234/v1 \
  --ai-model my-local-model
```

## Set it once in `.xsec.toml`

So you don't retype flags, put your choice in the project's config file:

```toml
[ai]
provider = "groq"
model = "llama-3.3-70b-versatile"     # optional; provider has a sensible default
# base_url = "http://localhost:1234/v1"   # only for openai-compatible
```

Then just:
```bash
xsec scan . --ai
```
CLI flags always override the config file.

## Honest tradeoffs

- **Free cloud providers receive your code.** Groq/OpenRouter process the files
  you scan on their servers. If that's not acceptable, use a local
  openai-compatible endpoint (code stays on your machine) or skip `--ai`
  entirely — the rule-based scan is fully offline.
- **Free tiers have rate limits.** Large repos may hit them; scan a subset, or
  use `--ai` only on the files you care about.
- **Smaller free models are less sharp** than Claude for deep logic flaws. They
  still catch a lot; just calibrate expectations.
- **Keys are stored encrypted** in your OS keyring (`xsec key set`), per
  provider — never in a plaintext file or your shell history.
