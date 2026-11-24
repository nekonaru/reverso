# Using Reverso online

Reverso ships in three forms: the native CLI, an in-browser analyzer on the
project website, and a tiny HTTP service for a hosted API and remote MCP.

## Browser analyzer (no install, no account)

Open the project website and use the "Try Reverso online" section. Pick a file
and an analyzer, then run it. Everything happens in a Web Worker in your
browser. Files are never uploaded. There is a 64 MB per-file cap.

The browser build uses the same analysis engines as the CLI. Hashes are
computed with a pure JavaScript implementation and produce byte-identical
digests. The following tools are available in the browser: full report,
format, entropy, strings, layout, hardening, archive listing, JavaScript,
WASM, DEX, PCAP, JWT, find bytes, hex dump and two-file diff.

`reverso site` (website mirroring) and recursive directory scanning stay
CLI-only: they need filesystem and network access that a browser does not
provide.

To rebuild the browser bundles after changing an engine:

```bash
npm run build:web
```

This writes `site/analyzer.js` and `site/worker.js`. Both are committed so the
GitHub Pages deployment needs no build step.

## HTTP API

The service exposes the same tools over HTTP with a raw request body:

```bash
curl -X POST "https://YOUR-HOST/api/analyze?tool=format&label=sample.elf" \
  --data-binary @sample.elf
```

Available `tool` values: `analyze`, `format`, `entropy`, `strings`, `layout`,
`hardening`, `archive`, `js`, `wasm`, `dex`, `pcap`, `jwt`, `find-bytes`, `hex`
and `diff`. For `find-bytes`, pass the pattern in the `arg` query parameter.
For `jwt`, send the token as the request body text.

Limits: 8 MB request body by default (`REVERSO_MAX_BODY_BYTES`), 60 second
request timeout, CORS enabled for all origins. This endpoint is stateless and
parses files without executing them.

Other routes: `GET /health` for health checks and `GET /` for the static site.

## Remote MCP

`POST /mcp` speaks stateless Model Context Protocol JSON-RPC. It answers
`initialize`, `ping`, `tools/list` and `tools/call`, in JSON or as a single
`text/event-stream` message when the client asks for SSE.

Because a remote server cannot read the client's filesystem, every file tool
also accepts inline base64 content. Example:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "reverso_format",
    "arguments": { "content": "f0VMRgIBAQAAAAA" }
  }
}
```

`reverso_diff` accepts `contentA` and `contentB`. `reverso_scan` needs a local
directory and is therefore CLI-only.

Client configuration example:

```json
{
  "mcpServers": {
    "reverso-remote": {
      "type": "http",
      "url": "https://YOUR-HOST/mcp"
    }
  }
}
```

## Run locally

```bash
npm ci
npm run build
npm run build:web
npm start
```

Then open `http://localhost:3000`. Set `PORT`, `HOST` and
`REVERSO_MAX_BODY_BYTES` to override the defaults.

## Deploy for free

A `Dockerfile` and a `render.yaml` blueprint are included. On Render:

1. Create a free account and connect it to your GitHub repository.
2. Create a new Web Service from `render.yaml` (or point to the repository).
3. Render uses its own `PORT` value and runs `npm start`.
4. Check `GET /health`, then share the service URL.

Any host that runs a Node 22+ container works too. The same container can be
published to Fly.io, Railway or a home server.

## Security notes

The service has no authentication: do not put private files through a public
instance. The API is rate-limited only by the host's own limits. For private
use, run it locally or put it behind authentication at the host level.
