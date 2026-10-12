# frozen_string_literal: true

require "json"
require "openssl"

module Camada
  # Redaction, non-configurable-off. The SDK never ships: Authorization/Cookie values (scheme
  # only, events/build.rb), body field values (shape only), query params that look like
  # credentials, or raw user identifiers (HMAC-hashed here, inside the SDK, before anything
  # reaches the queue). Ported from @camada/core src/redact.ts.
  module Redact
    # Exact patterns of C6 v3, matched bytewise on a binary copy (decoding yields any byte; every pattern is ASCII,
    # so a byte >= 0x80 never matches). Whole-string anchors are \A...\z (Ruby's ^/$ are line anchors). Ruby's /i
    # folds Unicode (U+212A Kelvin K matches k), so the name test is the lowercase-A-Z-then-substring form and hex
    # spells out [a-fA-F0-9].
    NAME_WORDS = %w[pass tok secret key auth sess sig code jwt bearer credential].freeze
    JWT_RE = /\AeyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/n # prefix match: anything may follow
    HEX_RE = /\A[a-fA-F0-9]{32,}\z/n
    B64_RE = %r{\A[A-Za-z0-9+/_-]{40,}={0,2}\z}n
    ESC_RE = /%([0-9a-fA-F]{2})/n

    REDACT_ALLOWLIST = %w[plan role locale ab_variant].freeze # additions only, never narrowing

    def self.suspect_value?(v)
      v = v.b
      JWT_RE.match?(v) || HEX_RE.match?(v) || B64_RE.match?(v)
    end

    # core's NAME_RE (`pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|
    # credential`, unanchored, case-insensitive) in its ASCII-only form.
    def self.name_hit?(n)
      lower = n.b.tr("A-Z", "a-z")
      NAME_WORDS.any? { |w| lower.include?(w) }
    end

    # Percent-decoding that never raises: bytewise, each `%HH` (ASCII hex) becomes that byte, any other `%` stays,
    # `+` stays. Up to 4 passes, so double (or triple) encoding cannot hide a name or a nested query; text that still
    # holds a `%HH` after 4 passes returns nil, which the caller scrubs. The cap keeps a crafted `%252525...` linear.
    # Only ever used to TEST a part; the output keeps the raw text.
    def self.decode(s)
      s = s.b
      4.times do
        break unless ESC_RE.match?(s)

        s = s.gsub(ESC_RE) { ::Regexp.last_match(1).hex.chr }
      end
      ESC_RE.match?(s) ? nil : s
    end

    # One `name=value` or bare segment of a decoded nested value (no further decoding, no recursion).
    def self.cred_segment?(seg)
      eq = seg.index("=")
      eq.nil? ? suspect_value?(seg) : name_hit?(seg[0, eq]) || suspect_value?(seg[(eq + 1)..])
    end

    # A decoded value that carries a nested query (`?`, `&` or `=`) is a credential when any of its `[?&]`-separated
    # segments is one (C6 v3). `q=a=b` or `q=1' or '1'='1` is not; `next=/r?token=x` is.
    def self.nested_cred?(d)
      /[?&=]/n.match?(d) && d.split(/[?&]/n, -1).any? { |seg| cred_segment?(seg) }
    end

    # Replaces credential-looking query parts with ~r, preserving structure and order (C6 v3). The string is split on
    # `&`, never URL-parsed. Each part's name and value are percent-decoded (decode) before testing; the output keeps
    # the raw text. `name=value` -> `name=~r` when the name looks like a credential, the value looks like one, or the
    # value holds a nested query with a credential segment (replaced whole, so payloads like `q=1' or '1'='1` stay
    # visible to the scorer). A bare part -> `~r` when it looks like a credential value or holds a credential
    # segment. Either half still encoded after 4 decode passes counts as a credential.
    def self.scrub_query(query)
      return query || "" if query.nil? || query.length <= 1

      lead = query.start_with?("?") ? "?" : ""
      out = (lead.empty? ? query : query[1..]).split("&", -1).map do |p|
        eq = p.index("=")
        if eq.nil?
          d = decode(p)
          next d.nil? || suspect_value?(d) || nested_cred?(d) ? "~r" : p
        end

        name = p[0, eq]
        dn = decode(name)
        dv = decode(p[(eq + 1)..])
        dn.nil? || dv.nil? || name_hit?(dn) || suspect_value?(dv) || nested_cred?(dv) ? "#{name}=~r" : p
      end
      lead + out.join("&")
    end

    # A URL (a Referer) with its query and fragment run through scrub_query (camada-all-ijsa); the scheme, host and
    # path are kept as they are. The path is left alone on purpose: it gets the same treatment as the request's own
    # path `p` (none). A same-origin Referer's path already shipped as `p` on that page's own event, and a
    # cross-origin one carries only the origin under the browsers' default Referrer-Policy.
    def self.scrub_url(url)
      return nil if url.nil?

      head, hash, frag = url.partition("#")
      path, q, query = head.partition("?")
      scrubbed = q.empty? ? head : path + scrub_query(q + query)
      hash.empty? ? scrubbed : "#{scrubbed}##{scrub_query(frag)}"
    end

    # Body shape only: field names and byte sizes, never values. One level deep.
    def self.body_shape(obj)
      return nil unless obj.is_a?(Hash)

      obj.to_h do |k, v|
        size = case v
               when String then v.length
               when nil then 0
               else
                 begin
                   JSON.generate(v).length
                 rescue StandardError
                   0
                 end
               end
        [k.to_s, size]
      end
    end

    # Stable per-tenant pseudonym: HMAC-SHA256 keyed by the ingest token, labelled so the hash
    # can never double as anything else, truncated to 32 hex chars. The raw identifier never leaves.
    def self.hash_user_id(user_id, ingest_token)
      OpenSSL::HMAC.hexdigest("SHA256", ingest_token, "uid:#{user_id}")[0, 32]
    end
  end
end
