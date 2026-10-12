# Changelog

## 0.1.4 - 2026-10-12

- fix: a challenge page's CSP is replaced in place (Rack::Headers keeps its class).
- fix (security): under trusted proxy `cidrs`, `X-Forwarded-For` is no longer believed from a socket peer that is not a trusted proxy: such a peer is the client. Before this, anyone reaching the origin directly could pick their own client ip, slip past an ip block or get another ip blocked. A loopback peer counts as a trusted hop; with no peer the walk is unchanged. (camada-all-yfc6)
- fix: `X-Forwarded-For` entries with a port (`203.0.113.66:51234`, `[2001:db8::66]:51234`) resolve to the address in every mode. (camada-all-0vho)
- fix: `ref` no longer ships the Referer verbatim: its query and fragment go through the query scrub. (camada-all-ijsa)
- fix: the challenge page sends its own `Content-Security-Policy` (inline solver by hash, no `form-action`) and replaces a policy already on the response, so a strict app CSP no longer blocks the solver or the post-solve redirect; the solver reads the nonce from the form. (camada-all-y38o)
- fix: a block 403 sends `Cache-Control: no-store` and replaces a `Cache-Control` set upstream, so a shared cache or CDN no longer keeps one visitor's block for others. (camada-all-8lp6)
- fix (security): the resolved ip is always a valid address or none (C6 v3): a non-ip peer never walks `X-Forwarded-For`, entries are trimmed of SP/HTAB only, `::ffff:a.b.c.d` is unmapped, malformed IPv6 is rejected. The query scrub percent-decodes bytewise (up to 4 passes, no `+`) before testing and tests bare and nested parts.
- chore: beacon re-synced to `@camada/browser` 0.3.2.
