# web dashboard — Host allowlist + same-origin guard for state-changing requests (CSRF)

| Field | Value |
| --- | --- |
| Date | 2026-08-20 |
| Branch | `web-csrf-origin-check` |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` §16.4 (local web dashboard) |
| Slice | Two paired hardening gaps only. **No auth, no TLS** — those are a separate slice. |

## 1. Problem

`inspectorctl/web/__init__.py` records the v1 posture as *"Bound to 127.0.0.1 only; no auth,
no CSRF, no TLS in v1."* Loopback binding stops a *remote* attacker, but it does not stop a
*cross-site* one: any page the user visits can render

```html
<form method="post" action="http://127.0.0.1:8765/alerts/<id>/suppress"><script>…submit()</script>
```

A simple form POST is a CORS-*simple* request — no preflight — so the browser delivers it and
the daemon executes it. The attacker cannot read the 303 response, but the side effect already
happened. In a security monitor the ranked damage is:

1. `POST /alerts/{id}/suppress` — silently stop the console from reporting the attacker.
2. `POST /cases/{id}/close` — close the investigation.
3. `POST /{services,persistence}/capture-baseline` — bless a tampered state as "known good",
   so every subsequent diff shows clean.
4. `POST /alerts/{id}/{ack,resolve,open-case,attach-case}`, `POST /cases/{id}/notes` — noise
   and evidence tampering.

`POST /cases/{id}/export` and `POST /cases/{id}/evidence/{sha}` return bytes the attacker
still cannot read, so they are low-severity here, but they are guarded all the same.

## 2. What gets built

Two ASGI middlewares in `inspectorctl/web/csrf.py`, installed in `create_app()`. Nothing
per-route.

`AllowedHostMiddleware` runs **outermost** and constrains what `Host` values the app answers
to at all; `SameOriginMiddleware` runs inside it and compares `Origin` against `Host`. The
order is the point — see §2.5.

### 2.1 Which methods

Guarded: **everything except `GET`, `HEAD`, `OPTIONS`.** The safe set is an explicit allowlist,
not a "guard POST/PUT/PATCH/DELETE" denylist — so a route added later with any other method
(`TRACE`, a WebDAV verb, anything) is guarded by default rather than silently exempt.

`/hunt` is entirely `GET`, every page render is `GET`, and `/static` is `GET` — the whole
read side of the dashboard is untouched.

### 2.2 Missing `Origin` — decision: **fail closed**

If `Origin` is absent we fall back to `Referer`. If *both* are absent the request is
**rejected**.

Why fail closed:

- Every browser we care about sends `Origin` on `POST` — including same-origin `POST` — since
  ~2020 (Fetch spec: `Origin` is set for any request whose method is not a CORS-safelisted
  one). The old Firefox behaviour of omitting `Origin` on same-origin form posts is gone. So
  the dashboard itself never hits this branch.
- Fail-open would make the entire guard opt-out: anything that can reach the socket while
  omitting two headers walks straight through. Since there is no CSRF token to fall back on
  (and adding one is the auth slice), "no headers" must not mean "trusted".
- The cost falls on non-browser clients (curl, scripts, tests), which must now send
  `-H 'Origin: http://127.0.0.1:8765'`. That is a documented, one-flag cost, and those clients
  already have the far more direct `inspectorctl` CLI over the IPC socket.

Consequence if this judgement is wrong: a browser that omits `Origin` on a same-origin POST
would get `403` on every action button. That failure is **loud, immediate and total** — the
first click on Ack fails and it is obvious in the log — and the fix is one entry in the
allowed-origin logic. The opposite mistake (fail open) is silent and leaves the exact hole
this change exists to close. Prefer the loud failure.

`Origin: null` (sandboxed iframe, `data:` document, some cross-scheme redirects) is an opaque
origin and is **not** the dashboard: rejected.

### 2.3 What counts as "the dashboard itself"

The app learns its own origin **from the request's `Host` header**, not from configuration.
`--host`/`--port` are user-set, and the user may reach the app by a name the bind address
never mentions (`--host ::` reached as `http://localhost:8765`), so config is the wrong source.
`Host` is set by the browser from the URL the *user* navigated to and cannot be forged by an
attacker's page — a cross-site form post to `http://127.0.0.1:8765/…` carries
`Host: 127.0.0.1:8765` with `Origin: https://evil.example`. Comparing the two is exactly the
check we want, and it is port- and host-agnostic for free.

An origin matches when the (scheme, host, port) triples are equal after normalisation:

- scheme lowercased; port defaulted from scheme (`http`→80, `https`→443) when absent;
- host lowercased, IPv6 brackets stripped (`[::1]` → `::1`);
- **loopback aliasing**: `localhost`, `*.localhost`, any `127.0.0.0/8` address and `::1` all
  canonicalise to one sentinel host. So a user on `http://localhost:8765` is not blocked
  because the bind address is `127.0.0.1`, and `http://[::1]:8765` works too. This is safe
  because every one of those names resolves to *this same process* — they are not distinct
  security origins in any way that matters on a single-user box.

This is necessary but **not sufficient on its own**, which is what §2.5 adds.

### 2.4 The rejection

`403 Forbidden`, `text/plain`:

```
Forbidden: cross-origin request blocked.
This dashboard only accepts state-changing requests issued from the dashboard itself.
```

The offending `Origin` is **not** echoed into the body (no reflected content) and no route
detail is disclosed. One `WARNING` on `inspectorctl.web.csrf` records method, path, and the
rejected origin/referer, each truncated and stripped of control characters so an attacker
cannot forge log lines.

### 2.5 The `Host` allowlist — closing DNS rebinding

Deriving the app's own origin from `Host` defeats an ordinary cross-site POST, because an
attacker's page cannot forge `Host`. It does **not** defeat DNS rebinding. `evil.example` is
served with a short TTL, resolving first to the attacker's server and then to `127.0.0.1`. The
user's browser, still on the attacker's page, POSTs to
`http://evil.example:8765/alerts/{id}/suppress` and sends `Host: evil.example` with
`Origin: http://evil.example`. **Both sides of the comparison are now attacker-controlled**,
they match, and the request is genuinely same-origin — so the origin check cannot see it. Alert
suppression is the single most valuable action an attacker with a foothold could take here, and
it leaves no trace in the UI afterwards.

Measured against the origin check alone:

```
Host: 127.0.0.1:8765  Origin: http://127.0.0.1:8765   -> PASSED guard   (correct)
Host: 127.0.0.1:8765  Origin: https://evil.example    -> BLOCKED 403    (correct)
Host: evil.example    Origin: http://evil.example     -> PASSED guard   (bypass)
```

`AllowedHostMiddleware` rejects any request whose `Host` is not a name this app answers to.
The third row becomes `400`, and the origin comparison downstream is only ever handed a `Host`
that has already been vouched for.

**Default: loopback only.** `localhost`, `*.localhost`, `127.0.0.0/8`, `::1` and their
bracketed/port-bearing spellings — the same canonicalisation §2.3 already uses, so there is one
notion of "loopback" in the module, not two. That covers the entire normal use of this
dashboard.

**How the app learns the rest.** `create_app()` gains one keyword-only argument,
`allowed_hosts: Iterable[str] | None = None`, defaulting to `None` (loopback only) so every
existing caller is unchanged. `inspectorctl-web` passes `[--host, *--allowed-host]`:

- `--host 192.168.1.5` — a concrete bind address *is* the name the user will type, so it is
  allowed with no extra flag.
- `--host 0.0.0.0` / `--host ::` — a wildcard bind names no host a browser can be pointed at,
  so LAN access needs the new repeatable `--allowed-host 192.168.1.5` (or `--allowed-host
  nuc.lan`). Refused until it is given; that is deliberate, since guessing the box's addresses
  would silently widen the allowlist the operator never asked to widen.

Values are canonicalised through the same helper as the header, and the **port is discarded**:
the allowlist is about names, the listening socket already decides which port we answer on, and
the origin check still compares `Origin`'s port against `Host`'s.

**Applies to every method, not just the unsafe ones.** A rebinding attacker restricted to `GET`
cannot suppress an alert, but can still *read* `/alerts`, `/events`, process trees and watched
file paths off a box whose whole purpose is to know incriminating things. That is a disclosure,
not a nuisance, so confidentiality gets the same gate as integrity. `/static` is included:
those assets are what make a rebound page render at all.

**The rejection.** `400 Bad Request`, `text/plain` — the request is addressed to a server we
are not, which is a malformed request rather than a permissions decision, and it does not
invite a retry. The offending `Host` is **not** echoed into the body. One `WARNING` on
`inspectorctl.web.csrf` records method, path and the rejected `Host`, through the same
truncating, control-character-stripping sanitiser as the origin guard.

Two hardening details: two `Host` headers are ambiguous (and a request-smuggling shape), so
that is rejected outright; a request with *no* `Host` (HTTP/1.0) falls back to the local socket
address from the ASGI scope, which is not attacker-controlled.

Starlette ships `TrustedHostMiddleware`, which was not reused: it splits the port off with
`host.split(":")[0]` — wrong for `[::1]:8765` — has no loopback aliasing, and would give the
module two different definitions of the same host.

### 2.6 Protected by default

Because the check is ASGI middleware wrapping the whole app, it runs *before* routing — a
route added tomorrow is covered without the author doing anything. This is proved by a test
that **enumerates `app.routes` at runtime** for any route whose methods are not a subset of
the safe set, fills in path params, and asserts each one rejects a cross-origin POST. A new
unguarded POST route cannot be added without that test covering it. The test also asserts the
enumeration found at least the 11 known mutating routes, so it cannot pass vacuously.

## 3. Tests (`tests/web/test_csrf.py`)

| Test | Asserts |
| --- | --- |
| same-origin POST passes | `Origin: http://testserver` reaches the route (303) |
| loopback alias passes | app on `Host: 127.0.0.1:8765` accepts `Origin: http://localhost:8765` and `http://[::1]:8765` |
| cross-origin POST rejected | `Origin: https://evil.example` → 403, body has no origin echo, IPC never called |
| `Origin: null` rejected | 403 |
| port mismatch rejected | `http://testserver:9999` → 403 |
| scheme mismatch rejected | `https://testserver` → 403 |
| no `Origin`, good `Referer` | passes |
| no `Origin`, foreign `Referer` | 403 |
| **neither header** | 403 (the documented fail-closed decision) |
| GET/HEAD/OPTIONS with hostile `Origin` | untouched (200/redirect, never 403) |
| every mutating route enumerated from `app.routes` | 403 on cross-origin POST; count ≥ 11 |
| a route added at runtime | covered without touching the middleware |
| log line emitted | `caplog` sees one WARNING naming method, path and the rejected origin |
| log values sanitised | control characters folded, value truncated at 200 chars |
| malformed `Origin` (`http://[::1`) | 403, not a `ValueError` out of `urlsplit` |
| **the three `Host`/`Origin` rows above** | dashboard 303, cross-site 403, rebinding 400; side effect only on the first |
| every loopback `Host` spelling | served by default, including `[::1]` and no-port |
| unknown / malformed `Host` | 400 — `evil.example`, a LAN IP, `127.0.0.1.evil.example`, userinfo, bad port |
| `GET`/`HEAD`/`OPTIONS` with alien `Host` | 400 — the disclosure case, `/static` included |
| duplicate `Host` headers | 400 |
| ordering | alien `Host` + alien `Origin` → 400, not 403 (Host layer is outermost) |
| `--host 0.0.0.0` alone, LAN `Host` | 400 |
| `--host 0.0.0.0 --allowed-host 192.168.1.5`, LAN `Host` | served, and the mutating POST completes |
| `--host 192.168.1.5`, LAN `Host` | served with no extra flag |
| a configured host still gets the origin check | LAN `Host` + `evil.example` `Origin` → 403 |
| configuring one host opens only that one | loopback still served, `evil.example` still 400 |
| `build_allowed_hosts` | ports stripped, brackets stripped, lower-cased, junk dropped, default is loopback alone |
| `Host` rejection body / log | no echo of the host; value truncated |

## 4. Existing tests

14 existing `client.post(...)` call sites in `tests/web/{test_alerts,test_cases,test_services,
test_persistence}.py` need an `Origin` header. Adding it at each call site (rather than
defaulting it on the `ipc_factory` fixture) keeps the fixture honest — a bare `TestClient` stays
a non-browser client — and makes each existing test state what it is simulating: a browser on
the dashboard clicking a button. It does not weaken those tests: each still asserts the same
status, redirect target and IPC payload; the header only supplies the browser context the test
always implicitly assumed.

`TestClient`'s default base URL is `http://testserver`, so it sends `Host: testserver` — which
the loopback-only default correctly refuses, and which would otherwise `400` the entire web
suite. The fix is **not** to allowlist `testserver`: that would put a name nobody browses to
into the shipped default, and the suite would then never exercise the default at all. Instead
`tests/web/__init__.py` gains `BASE_URL = "http://127.0.0.1:8765"`, `SAME_ORIGIN` and a
`web_client(app, **kw)` helper, and every client in the package is built through it. The suite
then runs against exactly the allowlist the product ships, and a future test that builds a bare
`TestClient(app)` fails loudly with `400` rather than quietly opting out of the guard. Only the
handful of tests that are *about* a configured extra host pass `allowed_hosts=`.

## 5. Doc

`inspectorctl/web/__init__.py` posture comment: `no CSRF` becomes a description of both
guards, with `no auth, no TLS` left standing. `inspectorctl/web/csrf.py`'s module docstring
carries the reasoning, including why the `Host` layer must be outermost.

## 6. Non-goals

No CSRF tokens, no session, no auth, no TLS, no new third-party dependency (stdlib
`urllib.parse` + `ipaddress` only). The `Host` allowlist is not a substitute for auth: it says
*which names* reach the app, never *who* is asking.
