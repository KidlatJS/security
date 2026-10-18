# Kidlat Security Tests

Reproducible security tests for [Kidlat](https://github.com/kidlatjs/kidlat): parser fuzzing, request-smuggling probes, a soak test and a TLS scan. Every run records the exact environment, inputs and raw results in [`results/`](results/).

The results below, each suite README and [SECURITY.md](SECURITY.md) are updated automatically by [`.github/workflows/security.yml`](.github/workflows/security.yml) on every push, every Monday, and on manual runs.

## Latest results

<!-- results:start -->
Last run: **2026-10-18** · Kidlat **2.4.0** · Node v22.23.3 · Linux 6.17.0-1022-azure x64 · [workflow run](https://github.com/KidlatJS/security/actions/runs/39135109109)

| Suite | Result | Key numbers |
|---|---|---|
| [Fuzzing](fuzz/README.md#latest-run) | ✅ pass | 120 min, 34,065,089 cases (seed `39135109109`), 0 failures |
| [Smuggling (direct)](request-smuggling/README.md#latest-run) | ✅ pass | 39/39 probes safe |
| [Smuggling (via nginx)](request-smuggling/README.md#latest-run) | ✅ pass | 39/39 probes safe |
| [Soak](soak/README.md#latest-run) | ✅ pass | 0.5 min, 316,010 req (10,534/s), 0 errors, RSS +0 MB |
| [TLS (testssl.sh)](tls/README.md#latest-run) | ✅ pass | grade A+ (min A), 0 HIGH/CRITICAL, 0 MEDIUM |
<!-- results:end -->

## Reproduce

Requires Node.js 20+. Smuggling via nginx and the TLS scan also need Docker and `openssl`.

```bash
npm ci
npm test           # fuzz, direct smuggling, soak
npm run readme     # refresh the table above from results/
```

Each suite writes `results/<suite>.json` and exits non-zero on failure. To test another Kidlat version: `npm install kidlat@<version>`.

Fuzz and soak use [`lib/server.mjs`](lib/server.mjs) (`GET /`, `POST /echo`, `GET /users/:id`) in a child process so crashes and memory are observable.

## Suites

### Fuzzing — [`fuzz/`](fuzz/)

Black-box mutation fuzzing of the HTTP/1.1 parser over raw TCP. Valid requests (plain, chunked, trailers, HTTP/1.0) are mutated with bit flips, byte inserts/deletes, framing tokens (`\r\n`, `:`, `\0`, `chunked`, oversized values) and pipelined requests.

- **Pass:** the server never crashes, every response starts with `HTTP/1.1 `, and it still answers `GET /` at the end.
- **Duration:** 120 minutes (`FUZZ_MINUTES`).
- **Reproduce a run:** `FUZZ_SEED=<seed> FUZZ_ITERATIONS=<n> npm run fuzz`, with both values from `results/fuzz.json`.
- Failing inputs are saved to `fuzz/regressions/` and replayed first on every run.

### Request smuggling — [`request-smuggling/`](request-smuggling/)

39 probes, each hiding `GET /smuggled` inside a request body: CL.TE and TE.CL across 13 `Transfer-Encoding` variants (obfuscated, duplicated, tab/space, obs-fold, quoted, bare LF, leading space), plus conflicting/signed/listed/hex `Content-Length`, bare CR, NUL, HTTP/1.0 + chunked and malformed chunks. After each probe a victim `GET /victim` is sent on a fresh connection.

The probes run twice: direct to Kidlat, and through nginx with upstream keep-alive ([`nginx.conf`](request-smuggling/nginx.conf)), so a desync would poison a reused connection.

- **Pass:** Kidlat never executes `/smuggled`, and the victim gets its own `200`.
- **Through nginx:**
  ```bash
  docker run -d --name nginx --network host -v "$PWD/request-smuggling/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:1.27-alpine
  npm run smuggling:nginx
  ```

### Soak — [`soak/`](soak/)

Keep-alive load across a mix of JSON `GET`, 1 KB JSON `POST` and `404` routes. Server RSS and heap are sampled every 5 s.

- **Pass:** zero errors or unexpected statuses, and RSS and heap grow less than 64 MB after a 20% warmup.
- **Settings:** `SOAK_SECONDS` (default 3600, one hour), `SOAK_CONNECTIONS` (default 50).

### TLS — [`tls/`](tls/)

[testssl.sh](https://testssl.sh) 3.2 scans Kidlat serving a fresh RSA root → intermediate → leaf chain for `127.0.0.1`. testssl trusts the throwaway root (`--add-ca`), so the grade reflects Kidlat's TLS configuration, not an unknown CA.

- **Pass:** overall grade A or better and no HIGH/CRITICAL findings. Findings about the test certificates themselves (`cert_*`, OCSP, CAA) are ignored.
- **Run:**
  ```bash
  mkdir -p build/testssl && npm run tls:server &
  docker run --rm --network host -v "$PWD/build/testssl:/out" drwetter/testssl.sh:3.2 --quiet --color 0 --warnings off --add-ca /out/root.pem --jsonfile /out/result.json https://127.0.0.1:8443
  npm run tls:check
  ```

## Limitations

- Fuzzing is black-box, not coverage-guided; it uses the published prebuilt binary, so there is no sanitizer or coverage instrumentation. Kidlat's own repo runs coverage-guided fuzzing with ASan/UBSan.
- The TLS scan uses a test PKI, so certificate issuance, OCSP stapling and CAA are not graded.
- Smuggling is tested behind nginx only; other proxies (HAProxy, Envoy, CDNs) may frame requests differently.
- Soak numbers come from a shared CI runner with the load generator on the same machine. Compare runs with each other, not with other benchmarks.

## Full report

[SECURITY.md](SECURITY.md) has every suite's latest log in one place.
