# Threat model

## Scope

Reverso parses untrusted files, serves an HTTP API and exposes MCP tools. It
never executes analyzed content. This document records the boundaries and the
controls that are actually implemented.

## Assets

- User files sent to the CLI, browser analyzer or HTTP API.
- Reports, which can contain sensitive strings and secret material.
- The hosted service and its MCP session state.

## Boundaries and controls

| Boundary | Threat | Implemented control |
| --- | --- | --- |
| File parsers | Malformed input causing crashes or memory spikes | Bounded loops, size caps, 256 MB CLI input cap, 64 MB MCP cap, 8 MB API body cap, fuzz corpus in CI |
| File content | Embedded code executing during analysis | Static parsing only; no eval, no child process on input, no rendering of documents |
| Website mirror | SSRF through user URLs | Same-origin only, every DNS answer checked against private and reserved ranges, per-hop redirect validation, streamed body caps |
| Reports | Secrets leaked when reports are shared | `--redact` masks JWTs, cloud keys, tokens and private key headers |
| HTTP API | Abuse by unauthenticated clients | Optional `REVERSO_API_KEY`, per-IP rate limit with HTTP 429 and `Retry-After`, bounded job queue |
| MCP | Unauthorized tool calls on a public server | Optional API key, session id issued on initialize and validated afterwards |
| Browser analyzer | User data leaving the browser | All analysis runs in a Web Worker; history is stored only in localStorage |
| Supply chain | Malicious or stale dependencies | Zero runtime dependencies, committed lock file, npm audit in CI, secret scan in CI, generated SBOM |

## Residual risks

- Parser bugs may still produce incorrect reports on novel formats. Fuzz
  coverage reduces but does not remove this risk.
- DNS rebinding with a TTL of zero can race the mirror's address check. All
  returned addresses are validated, but a change between check and connect
  cannot be excluded with the platform HTTP client.
- A public API instance without `REVERSO_API_KEY` accepts requests from
  anyone. Rate limits slow abuse but do not authenticate callers.
- Signed reports are not in scope; integrity of shared reports relies on the
  transport used by the operator.

## Reporting

Security issues should be reported through GitHub private vulnerability
reporting (Security tab, Report a vulnerability).
