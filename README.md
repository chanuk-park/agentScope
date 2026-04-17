# agentscope

eBPF-based observability for AI agents. Captures SSL traffic (HTTP/1.1 & HTTP/2, plain & streaming) from agent processes using uprobes on `libssl`, classifies the traffic (Agent↔Model / Agent↔Agent / Agent↔MCP), and streams events over gRPC to a master for real-time terminal display.

No library changes, no middleware, no proxy. Works with any Python / Node / Ruby / Java agent that uses the system OpenSSL.

## How it works

```
  ┌─────────────────┐   SSL_write / SSL_read          ┌──────────────┐
  │  agent process  │ ──────────────────────────────▶ │ libssl.so.3  │
  └─────────────────┘       ┌─ uprobe ─┐              └──────┬───────┘
                            │          ▼                     │
                    ┌───────┴──────────────┐                 │
                    │ BPF ringbuf          │◀────────────────┘
                    │ (+ agent_pids filter)│
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │ agentscoped (daemon) │
                    │  - HTTP/1.1 parser   │
                    │  - HTTP/2 + HPACK    │
                    │  - SSE handler       │
                    │  - gzip/deflate      │
                    │  - classifier        │
                    └──────────┬───────────┘
                               │ gRPC stream
                               ▼
                    ┌──────────────────────┐
                    │ agentscoped (master) │
                    │  terminal printer    │
                    └──────────────────────┘
```

## Features

- **Zero-instrumentation** — attaches uprobes on `SSL_write`, `SSL_read`, `SSL_write_ex`, `SSL_read_ex` in the host `libssl.so.3`
- **HTTP/1.1** — handles split headers/body, Content-Length & Transfer-Encoding: chunked, `Connection: close`, gzip/deflate bodies
- **HTTP/2** — frame parser (HEADERS / DATA / CONTINUATION / SETTINGS / WINDOW_UPDATE / PING / GOAWAY), HPACK dynamic tables per direction, stream multiplexing, PADDED / PRIORITY flags
- **SSE streaming** — detects `Content-Type: text/event-stream`, emits on `data: [DONE]` marker (OpenAI / Anthropic) or chunked terminator (Gemini). Real LangChain `stream()` calls work out of the box.
- **Agent-only capture** — only processes identified as agents are captured (configurable via env or cmdline); system curl / shell / IDE traffic is ignored
- **Multi-daemon** — several daemons on different hosts report to one master; events tagged with `Host:`
- **Classification** — automatic `Agent↔Model` / `Agent↔Agent` / `Agent↔MCP` tagging with colored output
- **Content typing** — `TEXT` / `IMAGE` / `FILE` / `FILE_READ` inferred from request body

## Requirements

- Linux kernel 5.8+ (tested on Ubuntu 24.04, kernel 6.8)
- `libssl.so.3` (OpenSSL 3.x)
- Clang, libbpf, bpftool, protobuf-compiler
- Go 1.22+

Install everything in one shot:

```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

This installs system packages, Go, the `bpf2go` + `protoc-gen-go` tools, generates `vmlinux.h`, and builds the binary.

## Build

```bash
make          # go generate + go build
```

Produces `./agentscoped`.

## Run

### master (one instance per cluster)

```bash
./agentscoped -mode master -listen :9000 -v
```

`-v` prints the full REQ / RES body; without it bodies are truncated to 120 chars.

### daemon (one instance per agent host, root required)

```bash
sudo ./agentscoped -mode daemon -master <master-host>:9000
```

On a single host running many daemons (for demos) use `-host` to disambiguate:

```bash
sudo ./agentscoped -mode daemon -master localhost:9000 -host nodeA
sudo ./agentscoped -mode daemon -master localhost:9000 -host nodeB
```

### Telling agentscope that your process is an agent

A process is captured if **both** hold:

1. Its `comm` is `python`, `python3`, `python3.x`, `node`, `deno`, `bun`, `ruby`, or `java`.
2. **Either** (a) its environment contains an LLM API key variable —
   `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `GEMINI_API_KEY`,
   `COHERE_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY`, `XAI_API_KEY`,
   `DEEPSEEK_API_KEY`, `AZURE_OPENAI_API_KEY` — **or** the opt-in marker
   `AGENTSCOPE_AGENT=1` —
   **or** (b) its cmdline contains `langchain` / `llama_index` / `crewai` /
   `autogen` / `agentscope` / `openai` / `anthropic`.

The scanner refreshes the PID set every 200 ms.

## Example output

```
[05:16:32] Agent↔Model  → send  TEXT  generativelanguage.googleapis.com  1241ms  PID:47588  Host:agent-watcher
  REQ:
        { "body": { "contents": [ { "parts": [ { "text": "count to 10" } ], "role": "user" } ] },
          "method": "POST",
          "path": "/v1beta/models/gemini-2.5-flash:streamGenerateContent" }
  RES:
        { "body": "data: {...}\\n\\ndata: {...}\\n\\n", "status": 200 }
──────────────────────────────────────────────────────────────────────────────
```

Color legend:

| tag | meaning |
| --- | --- |
| blue  | `Agent↔Model` (known LLM endpoint) |
| yellow | `Agent↔Agent` (everything else by default) |
| green | `Agent↔MCP` (JSON-RPC 2.0 with `tools/*`, `resources/*`, `prompts/*`, `initialize` methods) |

## Tested scenarios

| # | Scenario | Transport | Notes |
| - | --- | --- | --- |
| 1 | LangChain `ChatGoogleGenerativeAI.invoke()` | HTTP/1.1 + gzip | Gemini 2.5 Flash |
| 2 | LangChain `ChatGoogleGenerativeAI.stream()` | HTTP/1.1 + SSE + chunked | real streaming, single master event with concatenated body |
| 3 | `curl https://api.anthropic.com` (default HTTP/2) | HTTP/2 | HPACK decoding, request/response paired on END_STREAM |
| 4 | Python `urllib` → Anthropic | HTTP/1.1 | split headers / body events reassembled |
| 5 | Local mock SSE server | HTTP/1.1 + SSE | `data: [DONE]` marker termination |
| 6 | Two daemons (`-host nodeA`, `-host nodeB`) to one master | HTTP/1.1 | each daemon emits the event with its own `Host:` tag |
| 7 | Agent-to-Agent over HTTP/2 (hypercorn ↔ httpx `http2=True`) | HTTP/2 | `Agent↔Agent` classification, full HPACK round-trip |
| 8 | JSON-RPC 2.0 `tools/list` to a mock MCP server | HTTP/1.1 | detected as `Agent↔MCP` via request body inspection |

## Quick start — try it yourself

```bash
# terminal 1
./agentscoped -mode master -listen :9000 -v

# terminal 2
sudo ./agentscoped -mode daemon -master localhost:9000

# terminal 3 — will be captured
python -m venv venv && source venv/bin/activate
pip install langchain-google-genai
export GOOGLE_API_KEY=...
python -c "
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage
for chunk in ChatGoogleGenerativeAI(model='gemini-2.5-flash', streaming=True).stream(
    [HumanMessage(content='count to 10')]):
    print(chunk.content, end='', flush=True)
"
```

Terminal 3's SSE stream will appear as a single event in terminal 1 once the LLM finishes.

## Project layout

```
agentscope/
├── main.go                        CLI entrypoint
├── Makefile                       make = go generate + go build
├── scripts/install.sh             one-shot host setup
├── proto/agent.proto              gRPC IDL
├── gen/agent/                     protoc-generated Go code
├── bpf/
│   ├── ssl_trace.bpf.c            uprobes + agent_pids filter
│   ├── ssl_trace.h
│   └── vmlinux.h                  bpftool-generated kernel types
└── internal/
    ├── daemon/
    │   ├── loader.go              eBPF load, uprobe attach, ringbuf loop
    │   ├── parser.go              HTTP/1.1, proto detect, classify
    │   ├── h2.go                  HTTP/2 frame + HPACK
    │   ├── scanner.go             /proc walk → agent_pids map
    │   ├── sender.go              gRPC streaming sender
    │   └── ssltrace_bpf*.{go,o}   bpf2go artefacts
    └── master/
        ├── server.go              gRPC server
        └── printer.go             terminal formatter
```

## Protocol detection

The daemon distinguishes HTTP/1.1 from HTTP/2 by inspecting the **first** SSL write on a connection:

- Data beginning with `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` (the RFC 7540 client connection preface) → HTTP/2 mode; all subsequent bytes on that `(host, pid)` pair feed the HTTP/2 parser
- Data beginning with `GET ` / `POST ` / `PUT ` / etc. → HTTP/1.1 mode

There is no need to peek at ALPN; the wire is authoritative.

## Known limitations

- `libssl.so.3` only (OpenSSL 3.x). BoringSSL, GnuTLS, and statically-linked SSL implementations are not covered.
- HTTP responses are buffered until a boundary (Content-Length, chunked terminator, or SSE `[DONE]`) is seen before emit; multi-MB streams sit in memory.
- Agent-to-Agent capture is one-sided — the client-side SSL sequence becomes the emitted event; the server-side SSL traffic for the same connection is discarded by the parser (raw events still flow, but there's no plausible request to pair with).
- No ARM64 build; the `bpf2go` directive targets `__TARGET_ARCH_x86`.
- Buffer / stream cleanup on long-lived connections is best-effort (documented in agentscope.md "남은 작업").

## Progress notes

See [`../agentscope.md`](../agentscope.md) for a running log of implementation decisions, resolved issues, and verified scenarios.
