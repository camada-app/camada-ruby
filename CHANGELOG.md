# Changelog

## Unreleased

- fix: a Greek iota-subscript char (ᾀ and 62 others) now matches only itself under IGNORECASE, as JS `/i` does. Onigmo never matched it before a lookaround (`ᾀ(?=x)` missed "ᾀx"). (camada-all-zn38)

## 0.2.1 - 2026-10-26

- fix: inside a lookbehind, a char whose case fold is several chars (ß, ﬀ, İ and 101 others) now matches only itself under IGNORECASE, as JS `/i` does. Onigmo read such a char there as its fold alone (`(?<=ß)x` matched "ssx" but never "ßx"), and Ruby 3.3.13 and 3.4.12 extended that to ﬀ and İ, so `(?<=ﬀ)x` stopped matching "ﬀx" and `(?<!ﬀ)x` let it through. A rule now behaves the same on every supported Ruby. (camada-all-ozix)

## 0.2.0 - 2026-10-26

- fix (security): snapshot meta `pathsRegex` entries are now tested like a path `matches` rule condition, and inside the request's regex budget shared with the rule walk. They are case-insensitive, a pattern this SDK refuses never matches, and a path over 2048 chars, an engine failure or a spent budget answers block. Previously they ran outside the budget, and a failure was a miss. `Snapshot#paths_regex` is now a list of predicates. (camada-all-rvuh)
- feat: the first-party beacon relay (/_cam/fp) stamps `rts`, the relay's clock in epoch ms, on the sig:1 row (overwriting any browser-supplied `rts`), so the analyst can place the beacon on the same clock as the request rows. (camada-all-wd3b)
- fix: a signalled response (`x-camada-challenge: 1`) now also sets `cdn-cache-control`, `surrogate-control`, `cloudflare-cdn-cache-control`, `vercel-cdn-cache-control` and `netlify-cdn-cache-control` to `no-store`, overriding the app's. CDNs read those ahead of `cache-control`, so an app-set one could still let a shared cache keep the per-client copy. (camada-all-1zlg)
- feat: a non-HTML request under a challenge row passes to the app instead of a 403 JSON `challenge_required`: its response carries `x-camada-challenge: 1` and `cache-control: no-store` (replacing the app's), and its event ships `chs: 1` whatever `sample` and `exclude` say. `serve_challenge` does the same for a non-page request and returns `nil`. (camada-all-7cgs)
- fix (security): the first-party beacon relay (/_cam/fp) drops SDK-attested keys (tlsx, ja4, asn, cc, sid, ns, st, dur, rt, blk, rl, wrn, chs, ch, et, uid) from the visitor's body before queuing the sig:1 row, so a visitor cannot forge them; the analyst joins those from the request row. (camada-all-q617)
- fix: a path condition tests each distinct spelling of the request path once, so an already-canonical path no longer runs (and spends the request's regex budget on) the same regex up to three times. (camada-all-p3zg)

## 0.1.5 - 2026-10-19

- fix (security): a custom-rule `matches` regex never runs on a ua, header or path value over 2048 chars (UTF-16 units): over-cap fails closed, a hit for block/challenge/warn and a miss for skip/allow, never truncated (truncation would fail a deny rule open). (camada-all-q980)
- fix (security): control characters never reach the matcher alone: a ua/header value carrying `[\x00-\x1f\x7f]` is tested raw and stripped for deny rules (a pattern that targets `\t` or `\x00` still fires), and never matches a skip/allow rule, so stripping cannot widen an exemption such as `^partner-[a-z]+$` on `partner-acme\n`. The raw path form %-encodes the same characters. (camada-all-q980, camada-all-wh9m)
- fix (security): a regex error on a value Onigmo cannot read (invalid bytes from a custom adapter that skips the scrub) fails closed: a hit for deny rules and a miss for skip/allow, instead of `false`. A binary-tagged (ASCII-8BIT) Rack value whose bytes are valid UTF-8 is matched as UTF-8, so a non-ASCII pattern no longer takes that error path. (camada-all-cwb4)
- test: the shared blk5 conformance vectors (RC01-RC47, contract regex-cap-sdk v3) run against `../camada-core/test/fixtures`.

## 0.1.4 - 2026-10-12

- fix: a challenge page's CSP is replaced in place (Rack::Headers keeps its class).
- fix (security): under trusted proxy `cidrs`, `X-Forwarded-For` is no longer believed from a socket peer that is not a trusted proxy: such a peer is the client. Before this, anyone reaching the origin directly could pick their own client ip, slip past an ip block or get another ip blocked. A loopback peer counts as a trusted hop; with no peer the walk is unchanged. (camada-all-yfc6)
- fix: `X-Forwarded-For` entries with a port (`203.0.113.66:51234`, `[2001:db8::66]:51234`) resolve to the address in every mode. (camada-all-0vho)
- fix: `ref` no longer ships the Referer verbatim: its query and fragment go through the query scrub. (camada-all-ijsa)
- fix: the challenge page sends its own `Content-Security-Policy` (inline solver by hash, no `form-action`) and replaces a policy already on the response, so a strict app CSP no longer blocks the solver or the post-solve redirect; the solver reads the nonce from the form. (camada-all-y38o)
- fix: a block 403 sends `Cache-Control: no-store` and replaces a `Cache-Control` set upstream, so a shared cache or CDN no longer keeps one visitor's block for others. (camada-all-8lp6)
- fix (security): the resolved ip is always a valid address or none (C6 v3): a non-ip peer never walks `X-Forwarded-For`, entries are trimmed of SP/HTAB only, `::ffff:a.b.c.d` is unmapped, malformed IPv6 is rejected. The query scrub percent-decodes bytewise (up to 4 passes, no `+`) before testing and tests bare and nested parts.
- chore: beacon re-synced to `@camada/browser` 0.3.2.
