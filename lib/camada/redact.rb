# frozen_string_literal: true

require "json"
require "openssl"

module Camada
  # Redaction, non-configurable-off. The SDK never ships: Authorization/Cookie values (scheme
  # only, events/build.rb), body field values (shape only), query params that look like
  # credentials, or raw user identifiers (HMAC-hashed here, inside the SDK, before anything
  # reaches the queue). Ported from @camada/core src/redact.ts.
  module Redact
    NAME_RE = /(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)/i
    JWT_RE = /\AeyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/
    HEX_RE = /\A[a-f0-9]{32,}\z/i
    B64_RE = %r{\A[A-Za-z0-9+/_-]{40,}={0,2}\z}

    REDACT_ALLOWLIST = %w[plan role locale ab_variant].freeze # additions only, never narrowing

    def self.suspect_value?(v)
      JWT_RE.match?(v) || HEX_RE.match?(v) || B64_RE.match?(v)
    end

    # Replaces credential-looking query values with ~r, preserving structure and order.
    def self.scrub_query(query)
      return query || "" if query.nil? || query.length <= 1

      lead = query.start_with?("?") ? "?" : ""
      out = (lead.empty? ? query : query[1..]).split("&", -1).map do |p|
        eq = p.index("=")
        next p if eq.nil?

        name = p[0, eq]
        value = p[(eq + 1)..]
        NAME_RE.match?(name) || suspect_value?(value) ? "#{name}=~r" : p
      end
      lead + out.join("&")
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
