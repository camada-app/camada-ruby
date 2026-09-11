# camada

camada for Ruby: enforces the tenant snapshot inline (your ordered custom rules, then allow,
block, challenge), serves a first-party proof-of-work challenge page and beacon, records the
outcomes your handlers know (`Camada.track`), and ships wire events in batches off the request
path. One gem with a Rack middleware that any Rack app mounts (Sinatra, Hanami, plain Rack) and
a Railtie that mounts it for Rails — the `sentry-ruby` model. Fails open by design: a camada
outage or bug never 5xxes your app.

Not yet on RubyGems — install it from a sibling checkout: `gem "camada", path: "../camada-ruby"`
in your Gemfile (as [`camada-ruby-example`](../camada-ruby-example) does); publishing is one
decision with the npm packages (SDK-G01). Ruby 3.1 or newer, no runtime dependencies (stdlib
only: `net/http`, `openssl`, `digest`, `json`, `securerandom`, `zlib`, `stringio`).

## Quickstart

```ruby
# config.ru — Sinatra, Hanami, or any Rack app
require "camada"
use Camada::Rack      # first, so camada answers before routing
run App

# Rails — nothing to add: the Railtie inserts Camada::Rack at the top of the middleware stack
```

Env (printed by camada onboarding / `npm run seed` in dev):

```
CAMADA_KEY=<ingest_token>.<snap_token>
CAMADA_INGEST_URL=http://localhost:8787        # dev only; defaults to production ingest
```

The middleware shares one lazy engine built from the environment on the first request. That
build starts the snapshot poll on a thread and never blocks, so the request that triggered it is
answered cold: it passes (fail open), and so does anything else that arrives before that first
poll lands (a few hundred milliseconds against a local analyst; snapshot-size and network bound).
To enforce from request 1, warm the engine at boot (an initializer, or `config.ru` before `run`)
by waiting for the boot poll — `snap.refresh` alone is not it, the boot poll already holds the
single-in-flight lock:

```ruby
engine = Camada.default          # builds the engine; the boot poll is already running on its thread
if engine.snap                   # nil when CAMADA_KEY is unset or CAMADA_DISABLED=1
  probe = Camada::Snapshot::MatchInput.new(ip: "0.0.0.0")
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
  while engine.snap.verdict(probe).reason == "cold" && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    sleep 0.01                   # bounded: an unreachable analyst leaves it cold, and the app still fails open
  end
end
```

`snap.refresh` is not the warm-up: the boot poll holds the single-in-flight lock, so a
synchronous `refresh` called right after `Camada.default` returns at once and the engine is
still cold.

Without `CAMADA_KEY` the engine is inert (one log line, no requests, no enforcement). An app that
reads its own config builds the engine itself and hands it in:

```ruby
engine = Camada::Engine.new(env: { "CAMADA_KEY" => my_key, "CAMADA_INGEST_URL" => my_ingest })
use Camada::Rack, engine
```

## What it does per request

1. Keeps the snapshot fresh. A Ruby server is a long-lived process, so the default is a poll
   thread at the cadence your tenant config sets (`poll_seconds`), with ETag/304 and gzip on the
   wire. `CAMADA_SERVERLESS=1` switches to a per-request staleness check with no thread. Every
   poll and event batch carries `x-camada-sdk: @camada/ruby/<version>`, and polls ask for
   snapshot v5 (`x-camada-snapshot: 5`) — the container that carries your ordered custom rules.
2. Resolves the client from the socket peer (`REMOTE_ADDR`), combined with `X-Forwarded-For`
   only under your tenant's trusted-proxy config (or `CAMADA_TRUSTED_PROXY` locally). A forwarded
   header on its own is never the ip: any caller can set it. **Never `request.ip`**:
   `Rack::Request#ip` trusts `X-Forwarded-For` from anyone, which is exactly the spoof camada
   refuses; the middleware reads `env["REMOTE_ADDR"]` and applies your trusted-proxy rules itself.
3. Enforces before anything else, beacon endpoints included: your ordered custom rules first (first
   match wins; they read ip, path, user-agent and request headers), then allow → block → challenge.
   A block answers `403 Forbidden` with `x-block-reason`, `x-block-version` and, when a rule
   decided, `x-block-rule`; its event ships with `blk` (and `rl`). A `warn` rule passes and stamps
   `wrn`; a `skip` rule passes with nothing stamped. Cold (no snapshot yet) passes: fail open.
4. Challenge: a `challenge` verdict gets the self-contained proof-of-work page (or 403 JSON for a
   non-HTML request); `POST /__camada/challenge` verifies the solution, sets `_cch` (bound to the
   ip, one hour) and 302s back. A request whose ip cannot be resolved is never challenged.
5. Serves the beacon: `GET /_cam/b.js` (the `@camada/browser` build, vendored) and `POST /_cam/fp`
   (≤ 32 KB, relayed onto the event batch as a `sig: 1` row with the ip camada resolved). Both
   fall through to your app when the tenant switched the beacon off.
6. Runs your app with `x-rid` and the `_sfp` session cookie on its response, and when the server
   closes the response body ships one redacted event: method, host, path, scrubbed query, status,
   latency, header names/sizes/order, the auth scheme (never the credential), cookie count (never
   values), the matched route pattern when the framework names it (`sinatra.route`, Rails'
   `route_uri_pattern`). An exception in your app ships as `st: 500` and propagates unchanged.

## Options

`Camada::Engine.new(...)` keyword arguments (also accepted by `Camada.default(...)` and
`Camada::Rack.new(app, nil, ...)`); everything credential-shaped comes from the environment.

| option | default | meaning |
|---|---|---|
| `env` | `ENV` | where `CAMADA_*` are read from (a Hash works too) |
| `transport` | `Net::HTTP` | anything responding to `#call(HttpRequest) -> HttpResponse` (tests inject a fake) |
| `refresh_s` | server-steered | poll cadence; set, it is pinned |
| `challenge` | `true` | serve the proof-of-work page for challenge verdicts (`CAMADA_CHALLENGE=0` too) |
| `challenge_path` | `/__camada/challenge` | where the page posts its solution |
| `snapshot_version` | `5` | 4 drops your custom rules; 3 the allow/challenge sides too |
| `script_path` / `fp_path` | `/_cam/b.js` / `/_cam/fp` | the beacon endpoints; keep them in one directory |

Env: `CAMADA_KEY` (or `CAMADA_TOKEN` + `CAMADA_SNAPSHOT_TOKEN`), `CAMADA_INGEST_URL`,
`CAMADA_SNAPSHOT_URL`, `CAMADA_TRUSTED_PROXY` (`none | vercel | hops:N | cidrs:a,b`),
`CAMADA_SERVERLESS=1`, `CAMADA_CHALLENGE=0`, and the kill switch `CAMADA_DISABLED=1` (checked per
request; set at boot, no threads start at all).

## The first-party beacon

```ruby
# Sinatra: `env` is the Rack env; Rails: request.env
"<html><head>#{Camada.script_tag(env)}</head>…"
```

The tag is `<script src="/_cam/b.js?r=<rid>" async>`, so the beacon joins the page view that
served it. Move both paths with `script_path` / `fp_path` when `/_cam/` is not yours; the script
derives the post path from its own URL, so the two must share a directory.

## App-context events

```ruby
Camada.track(env, "login_failed", user: email)
```

The identifier is HMAC-hashed in-process with your ingest token; the raw value never reaches the
queue. `Camada.track` never raises and is a no-op on a request the middleware did not run for. The
event name is free-form; the analyst's app-context rules read this vocabulary:

| event | when |
|---|---|
| `login_failed` / `login_succeeded` | a login attempt settled; pass `user:` so attempts per account can be counted |
| `signup` | an account was created |
| `password_reset` | a reset was requested |
| `mfa_failed` | a second factor was rejected |
| `payment_failed` / `payment_succeeded` | a payment authorisation settled |
| `coupon_failed` | a promo/voucher code was rejected |

A route you gate yourself: `Camada.serve_challenge(env)` returns a Rack triple
`[status, headers, [body]]` to answer with (Sinatra: `halt(*answer)`) until the browser holds a
valid `_cch`, then `nil`.

## What this tap can see

`sdk-ruby` is an in-app tap: status, latency, session, the beacon's browser signals and your
outcomes. The Rack env carries no wire header order (`hord` is the env's order), so the analyst
reads no HEADER_ORDER signal from this tap, and it never scores the absence of header order, ASN,
country or a TLS fingerprint against a request; ASN and country it resolves itself. Enforcement
at this position covers ip, path, user-agent and header conditions — ASN, country and TLS entries
fail open in-app. `matches` patterns are JS regexes read by Ruby's Onigmo: named groups are
native, `[^]` and `\cX` are translated, `^`/`$` become `\A`/`\z` (Ruby's are line anchors,
JS's are not), `\d`/`\w`/`\b` are ASCII as in JS; a spelling Ruby still rejects never matches
here (and never raises), while it does at the edge.

## Deploying it

- Every worker process polls its own snapshot (about 5 MB resident, read a word at a time — never
  expanded into Ruby Integers) and flushes its own batches; the tenant's `poll_seconds` keeps the
  cadence honest across a fleet.
- Threads do not survive a fork. Ruby has no fork hook, so the SDK compares `Process.pid` on every
  call and starts over in a forked worker: new locks, an empty queue, its poll and flush threads
  restarted. Puma cluster mode with `preload_app!`, Unicorn and Passenger need nothing added.
- Pending events drain at interpreter exit within half a second (`at_exit`). No signal handlers
  are installed — an app owns its own shutdown — so a worker killed by SIGKILL, or by SIGTERM
  without a handler, may drop its last batch.
- Serverless: `CAMADA_SERVERLESS=1`. A cold invocation fails open and catches up on the next one.
- Under Rack 3 the middleware emits lower-case header names and appends `set-cookie` as an Array;
  under Rack 2 it joins cookies with `"\n"`. It never requires `rack` itself.

## Fail open

Every entry point runs inside the fail-open envelope: a dead ingest drops telemetry (logged at
most once a minute, one line, no backtrace), a corrupt snapshot keeps the previous one, a bug in
the gem costs the request its join, never its response. `CAMADA_DISABLED=1` bypasses everything.

## Development

```
bundle install && bundle exec rubocop && bundle exec rspec
```

No type checker: the gem has no runtime dependencies and a Sorbet or Steep setup would add a
toolchain (and RBS signatures for every stdlib seam) for a 2.5k-line port whose behaviour is
pinned by the golden fixtures instead; it is deferred, not refused. A Rails example app is
deferred the same way — the Railtie ships in the gem, the example repo is Sinatra.

The suite reads the golden snapshot fixtures from the `camada-core` sibling checkout and pins the
vendored beacon to `camada-browser/dist/auto.global.js` (`npm run build` there first, then
`ruby scripts/sync_beacon.rb` after a beacon release). Both fail by name when the checkout is
missing rather than skipping (`CAMADA_FIXTURES_DIR`, `CAMADA_BROWSER_DIST` override the paths).

[`camada-ruby-example`](../camada-ruby-example) is the hand-test bench (Sinatra under Puma on
:3004), and `node scripts/e2e-sdk-ruby.mjs` in `camada/edge-analyst` drives it against a seeded
local analyst over real HTTP, cold first request included.
