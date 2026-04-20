# AgentScope — Implementation Result

이 문서는 이번 세션에서 한 작업 전체를 다룹니다.
세 개의 Task가 누적되며 시스템이 단계적으로 변했고, 마지막으로 파일 이름을
실제 책임에 맞게 정리했습니다.

- **Task 1** — 평문 HTTP 캡처 추가 (TLS 전용 → TLS + Plaintext)
- **Task 2** — Agent Scanner를 정적(env/cmdline) → 동적(LLM 통신 관찰) 모델로 교체
- **Task 3** — “LLM 통신자 = agent” 라는 약한 가정을 보강하기 위해 Confirmation State Machine 도입
- **Rename** — `ssl_trace` → `capture` (이젠 SSL 만 다루지 않음)

---

## 1. 아키텍처 한눈에

```
                                     ┌──────────────────────────────────┐
   process X (any)                   │            BPF programs          │
   ─────────────────                 │                                  │
   SSL_write/read[_ex]  ───►  uprobe │  is_agent? ───► full payload     │
                                     │                  (SOURCE_TLS)    │
   tcp_sendmsg          ───►  kprobe │  is_agent? ─yes► full payload    │
                                     │                  (SOURCE_PLAIN)  │
                                     │           ─no ► first 512B       │
                                     │                  (SOURCE_CANDIDATE)
   tcp_recvmsg          ───►  kprobe │  is_agent && tracked sock?       │
                                     │                  full payload    │
                                     │                  (SOURCE_PLAIN)  │
                                     └──────────────┬───────────────────┘
                                                    │ ringbuf  (capture_event)
                                                    ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                   userspace daemon (agentscoped)                 │
   │                                                                  │
   │   parseRawEvent ──► dispatch by Source                           │
   │                          │                                       │
   │     SOURCE_CANDIDATE ────┘──► detector.handle()                  │
   │       (SNI / HTTP path / Host) ──► provisional promote into      │
   │                                   agent_pids BPF map             │
   │                                                                  │
   │     SOURCE_TLS|PLAIN ────────► parser.feed() → buildEvent ──┐    │
   │                                                              │   │
   │                                detector.observeEvent() ◄────┤    │
   │                          (tools/MCP/A2A signal? → confirm    │   │
   │                           else 8 events / 60s → demote)     │    │
   │                                                              ▼    │
   │                                                       sender.gRPC │
   └─────────────────────────────────────────────────────────┬────────┘
                                                             │
                                                             ▼
                                                  master  (printer)
```

---

## 2. BPF 레이어 (`bpf/capture.bpf.c`)

### 프로그램 목록
| SEC | 역할 |
|---|---|
| `uprobe/SSL_write[_ex]` + `uretprobe` | OpenSSL 평문(write) 캡처. `is_agent`만 통과. |
| `uprobe/SSL_read[_ex]` + `uretprobe`  | OpenSSL 평문(read) 캡처. 동일. |
| `kprobe/tcp_sendmsg`                  | 두 역할 — agent면 full payload, 아니면 candidate observe |
| `kprobe/tcp_recvmsg` + `kretprobe`    | agent + HTTP-classified sock 한정 full payload |

### 맵
| 이름 | 타입 | 용도 |
|---|---|---|
| `events` | RINGBUF (64MB) | 모든 이벤트 (TLS/PLAIN/CANDIDATE) 단일 채널 |
| `agent_pids` | HASH (10K) | userspace가 promote한 PID — `is_agent()` 게이트 |
| `tcp_flows` | LRU_HASH (8K) | per-sock state: `1`=HTTP-confirmed, `2`=TLS-skip (이중 캡처 방지) |
| `candidate_emitted` | LRU_HASH (16K) | 비-agent sock당 candidate 이벤트 1회 dedup |
| `write_args`, `ex_args`, `tcp_recv_args` | HASH | uprobe / kprobe entry-exit 파라미터 stash |

### 핵심 분기 (`kprobe_tcp_sendmsg`)

```c
if (bpf_map_lookup_elem(&agent_pids, &pid)) {
    // agent path
    if (state == 2)           return 0;          // TLS sock → SSL_* uprobes 담당
    if (head[0] == 0x16)      mark TLS, return;  // ClientHello 첫 감지 시 마킹
    if (!is_http_method(head)) return 0;
    push_event(DIR_WRITE, SOURCE_PLAIN, full payload, sk);
} else {
    // discovery path
    if (candidate_emitted[sk]) return 0;
    if (family != AF_INET)     return 0;
    if (loopback)              return 0;
    if (head[0] != 0x16 && !is_http_method(head)) return 0;
    push_event(.., SOURCE_CANDIDATE, first 512B + dst_ip:port, sk);
    mark candidate_emitted[sk];
}
```

### 이중 캡처 방지 메커니즘
TLS 트래픽이 SSL_write(평문)와 tcp_sendmsg(암호문) 양쪽에서 잡히면 안 됨.
- TLS sock의 첫 send (ClientHello, byte0=0x16)를 보면 `tcp_flows[sk]=2`로 마킹
- 이후 같은 sock의 모든 send/recv는 `state==2`에서 즉시 return
- LRU evict 후 재학습되어도 후속 record byte (0x14–0x17)가 HTTP method 검사를 못 통과해 emit 안 됨

---

## 3. Userspace 레이어 (`internal/daemon/`)

### 파일 구성
| 파일 | 책임 |
|---|---|
| `loader.go` | BPF 로드, 모든 uprobe/kprobe attach, ringbuf reader 루프, raw byte → `RawEvent` |
| `detector.go` | 후보 평가 + promotion + 4-state lifecycle + janitor |
| `parser.go` | HTTP/1 파싱, MCP-over-SSE 페어링, SSE 머지, comm-type classification (`Agent↔Model/MCP/Agent`) |
| `h2.go` | HTTP/2 프레임 디코더, HEADERS/DATA → req/res 페어 |
| `sender.go` | gRPC 스트림으로 master에 AgentEvent 전송, loopback peer rewrite |
| `config.go` | YAML config (peers + LLM allowlist) |
| `capture_bpfel.go` / `capture_bpfeb.go` | bpf2go 자동 생성 (수정 금지) |

### `RawEvent` (loader.go)
```go
type RawEvent struct {
    PID, TID    uint32
    TimestampNs uint64
    Conn        uint64  // SSL* or struct sock*  ─ Source와 함께 키
    DstIP       uint32  // BE IPv4   (CANDIDATE에만 의미)
    DstPort     uint16  // BE port   (CANDIDATE에만 의미)
    Dir         uint8   // DIR_WRITE/DIR_READ — CANDIDATE는 protocol hint(1=HTTP, 2=TLS)
    Source      uint8   // 0=TLS, 1=PLAIN, 2=CANDIDATE
    Data        []byte
}
```

### Wire layout (`bpf/capture.h` ↔ `parseRawEvent`)
```
offset 0  : pid       (4)
offset 4  : tid       (4)
offset 8  : timestamp (8)
offset 16 : conn      (8)
offset 24 : dst_ip    (4)
offset 28 : dst_port  (2)
offset 30 : dir       (1)
offset 31 : source    (1)
offset 32 : data_len  (4)
offset 36 : data      (≤16384)
```
바이트 오프셋이 **load-bearing**. struct 변경하면 양쪽 동시 수정 필요.

---

## 4. PID Lifecycle (detector.go)

```
   pending  ──── endpoint match ────► confirming ──── agent signal ────► confirmed
      │                                  │                                 │
      │ TTL 5분                          │ 60s OR 8 events 무신호           │ 영구
      ▼                                  ▼                                 ▼
   (forgotten)                       demoted ◄─── 재promote 차단 ────────  (—)
                                        │
                                        ▼
                                   PID 종료 → janitor 정리
```

### Promotion 신호 (provisional → confirming)
| 종류 | 출처 | 매치 |
|---|---|---|
| TLS SNI | ClientHello extension(type=0) | `llm_hostnames` exact 또는 `llm_hostname_patterns` glob |
| HTTP Host | 첫 sendmsg 첫 줄 + `Host:` 헤더 | 동일 |
| HTTP method+path | 첫 sendmsg 요청 라인 | `llm_http_paths` (`POST /v1/chat/completions` 등) |

기본 allowlist (config로 확장 가능):
- 호스트: `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api.mistral.ai`, `api.cohere.ai`, `api.groq.com`
- 패턴: `*.openai.azure.com`, `bedrock-runtime.*.amazonaws.com`
- 경로: `POST /v1/chat/completions`, `POST /v1/messages`, `POST /v1/completions`, `POST /api/generate`, `POST /api/chat`

### Confirmation 신호 (confirming → confirmed)
하나라도 보이면 confirm:
| 신호 | 잡히는 agent 패턴 |
|---|---|
| `parser.CommType == "Agent↔MCP"` | MCP 클라이언트 (initialize 핸드셰이크 또는 `tools/*`/`resources/*`/`prompts/*`) |
| `parser.CommType == "Agent↔Agent"` | A2A orchestrator / master agent (`tasks/*`, `message/*`, `/.well-known/agent.json`) |
| 요청 body에 `"tools":` / `"functions":` | OpenAI/Anthropic tool-calling agent |
| 응답 body에 `"tool_calls"` / `"tool_use"` | 위와 동일 (반대쪽 입증) |

### Demote 트리거 (confirming → demoted)
- 60초 timeout (janitor) **OR**
- 8 이벤트 동안 위 신호 0개

Demote 시: `agent_pids` 삭제 → parser 버퍼 evict → `demoted` set에 PID 등록(살아있는 동안 재promote 금지) → `likely WebUI/one-shot script` 로 로깅.

### Janitor (30s tick)
- `pending` TTL 만료 (5분)
- `confirming` window 초과 → demote
- `confirming/confirmed`의 dead PID → `agent_pids` 삭제 + parser evict
- `demoted`의 dead PID → 메모리 정리

---

## 5. Parser & Classifier (`parser.go`)

비-CANDIDATE 이벤트(SOURCE_TLS / SOURCE_PLAIN)는 parser로 흘러갑니다. 핵심 책임:

1. **Protocol detection** — 첫 write 24바이트가 HTTP/2 preface면 `h2.go`로 위임, 아니면 HTTP/1.
2. **Request/response 완성 검사** — `Content-Length`, `Transfer-Encoding: chunked`, SSE의 `data: [DONE]` 마커.
3. **MCP-over-SSE pairing** — `POST /messages/`의 JSON-RPC 요청을 PID+id로 버퍼링, 별도 GET `/sse` 스트림에서 응답이 푸시되면 페어링해 단일 이벤트로 emit (`buildMCPPairedEvent`).
4. **SSE merge** — OpenAI/Anthropic/Gemini delta 형식을 인식해 chunk text를 하나로 합치고 `usageMetadata` 등 메타 보존.
5. **Comm-type classification** (`classifyComm`) — 우선순위:
   1. user-declared peer override (config)
   2. baked-in hostname allowlist
   3. 이미 등록된 `llmEndpoints` / `mcpEndpoints` peer
   4. `isLLMResponse` shape 검사 (OpenAI `chat.completion*`, Anthropic `message_start`, Ollama `done+model`, Gemini `candidates+modelVersion`)
   5. `isInitializeHandshake` (MCP `initialize` + `protocolVersion`)
   6. MCP method namespace fallback
   7. `isA2AProtocol` (`/.well-known/agent.json`, `tasks/*`, `message/*`)
   8. `isLangGraphProtocol` (`/threads`, `/runs/*`)
   9. `Unknown`

### 부수 발견 + 수정
SSE 분기에서 `maybeEmitSSEFrames`가 항상 `return nil`로 흐름을 끊어 LLM 스트리밍 응답이 stream 종료 시점에 `buildEvent`까지 못 가던 기존 버그가 있었음. `parser.go:262` — 단순 호출만 남기고 normal-completion path로 fall through. MCP는 어차피 `responseComplete=false`라 영향 없음.

---

## 6. 설정 (`agentscope.yaml`)

샘플 — `agentscope.yaml.sample` 참고. 기본값 위에 **add**되는 구조 (replace 아님):

```yaml
peers:
  "10.0.0.2:8080": "Agent↔Agent"

llm_hostnames:
  - my-internal-llm.corp

llm_hostname_patterns:
  - "*.bedrock.example.com"

llm_http_paths:
  - "POST /custom/llm/chat"
```

CLI:
- `-config <path>` (기본 `./agentscope.yaml`, 없어도 OK)
- `-peer 'host:port=Agent↔Model'` (반복 가능, config보다 우선)
- `-cmdline-filter <substring>` (테스트/멀티-host 격리: 매치되는 cmdline의 PID만 promote 대상)

---

## 7. 파일 맵 — 변경 전/후

| Before | After | 이유 |
|---|---|---|
| `bpf/ssl_trace.bpf.c` | `bpf/capture.bpf.c` | 이젠 SSL만 다루지 않음 (TCP kprobe + discovery 포함) |
| `bpf/ssl_trace.h` | `bpf/capture.h` | 동일 |
| `internal/daemon/ssltrace_bpfel.go` | `internal/daemon/capture_bpfel.go` | bpf2go 자동 |
| `internal/daemon/ssltrace_bpfeb.go` | `internal/daemon/capture_bpfeb.go` | 자동 |
| `bpf2go target SslTrace` | `Capture` | go:generate 갱신 |
| `struct ssl_event` | `struct capture_event` | 의미 명확화 |
| `enum ssl_event_type {SSL_WRITE/READ}` | `enum capture_dir {DIR_WRITE/READ}` | SSL 한정 인상 제거 |
| `RawEvent.SSL` | `RawEvent.Conn` | 실제로는 SSL* OR sock*, 이름이 거짓말이었음 |
| `RawEvent.Type` | `RawEvent.Dir` | 동일 |
| `connKey.SSL` | `connKey.Conn` | 동일 |
| `internal/daemon/scanner.go` | **삭제** | 정적 promotion 폐기 → detector가 인계 |

`enum capture_source {SOURCE_TLS/PLAIN/CANDIDATE}`는 이름이 이미 정확해서 유지.

---

## 8. 테스트 결과 요약

세션 전체에서 검증한 시나리오:

| # | 시나리오 | 기대 동작 | 결과 |
|---|---|---|---|
| T1 | HTTPS to api.openai.com (curl) | SNI 매치 → provisional promote | ✓ `promoted pid=N (TLS SNI=api.openai.com, dst=162.159.140.245:443)` |
| T2 | HTTP POST to LiteLLM `/v1/chat/completions` | path 매치 → provisional promote | ✓ `promoted pid=N (HTTP path POST /v1/chat/completions)` |
| T3 | HTTPS to example.com | 미매치 | ✓ promotion 없음 |
| T4 | promoted PID의 후속 plaintext 호출 | full payload 캡처 | ✓ master에 body + classification (`Agent↔Model`) |
| T5 | promoted PID의 후속 HTTPS 호출 | TLS uprobe로 full 캡처 | ✓ master에 OpenAI 401 응답 본문 |
| T6 | LLM streaming (SSE) 응답 | chunks 머지 → 단일 이벤트 | ✓ `(9 chunks)`, body=`"1, 2, 3!"` (이 과정에서 SSE 버그 발견·수정) |
| T7 | WebUI 시뮬 (10× 평문 chat, no tools) | 8 이벤트 후 demote | ✓ `demoted pid=N (no agent signal in 8 events) — likely WebUI/one-shot script` |
| T8 | Tool-using agent (1 plain + 1 with `tools:`) | 첫 full event에서 confirm | ✓ `confirmed pid=N (tools/functions in request body)` |
| T9 | 이름 변경 후 회귀 (T8 재실행) | 동일 동작 | ✓ provisional → confirmed 동일 |

이중 캡처 방지 검증: T1의 HTTPS 호출에서 master.log에 정확히 1개 row만 (TLS uprobe 발) 보임. kprobe 발 ciphertext row는 0개.

---

## 9. 알려진 한계

| 영역 | 한계 | 비고 |
|---|---|---|
| Discovery 경로 | IPv4 only | `kprobe_tcp_sendmsg`에서 `family != AF_INET` skip. IPv6-mapped는 `AF_INET6`로 들어와 놓침. promote 후엔 SSL_* uprobes가 IPv6도 잡음. |
| ClientHello 파싱 | 첫 512B 안에 SNI 안 들어가면 missed | 일반적 cipher list 기준 충분하나, ECH/Encrypted ClientHello는 미지원 |
| Demote 정책 | False negative 가능 | tool 안 쓰는 순수 LLM-loop agent (drama-style RAG 등)는 webui로 오인되어 demote — semantic analysis 없이는 한계 |
| Demote 후 promotion 차단 | PID 살아있는 한 영구 | 사용자가 mid-session에 tool-mode를 켜도 다음 PID부터 적용. 의도된 보수성. |
| `tcp_flows` LRU eviction | 매우 장수명 sock에서 재학습 비용 | 잘못 emit하지는 않음 (TLS record byte ≠ HTTP method) |
| HTTP/2 평문 over kprobe | `kprobe_tcp_sendmsg`의 HTTP method 검사 통과 못 함 | h2c는 candidate emit 안 됨; HTTP/2 over TLS는 TLS uprobe 경로로 정상 |

---

## 10. 다음에 손볼 만한 것

- **Demote 결정에 누적 이벤트 수 + duration 둘 다 봐야** burst-then-quiet 패턴 webui도 잘 잡힘.
- Confirm 후에도 일정 주기로 “여전히 agent 패턴이 보이는지” 재확인하는 watchdog (long-lived chatbot이 어느 순간 webui 모드로 바뀌는 경우 대비).
- `agentscope.yaml`에 confirm window / max events / TTL을 노출 (현재는 코드 상수).
- `agent_pids` BPF map 상태를 `bpftool` 외에 daemon이 주기적으로 dump해서 master로 전송 → master UI에서 “현재 트래킹 중인 agent 목록” 표시.
- IPv6 candidate 경로 (`AF_INET6` + `skc_v6_daddr` 16바이트 → event 구조에 v6 슬롯 추가).
