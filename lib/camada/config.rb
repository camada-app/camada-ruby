# frozen_string_literal: true

module Camada
  # Configuration shapes shared by the client and the engine. `parse_key` splits CAMADA_KEY. The
  # remote config GET /snapshot hands back in x-camada-config (whitelisted server-side) is a
  # plain Hash: { tenant, beacon, sample, exclude, trusted_proxy, poll_seconds } with string keys,
  # as JSON delivers them. A trusted-proxy config mirrors the server-validated tenant config
  # (edge-analyst src/tenant-config.js): {mode: none} | {mode: hops, hops: N} | {mode: cidrs, cidrs: [...]} | {mode: vercel}.
  module Config
    def self.token_hash_enabled?(option, env_value)
      option.nil? ? env_value == "1" : option == true
    end

    # Returns [header name, invalid setting?] so the caller can warn without logging the input.
    def self.resolve_token_header(option, env_value)
      selected = option.nil? || option == "" ? env_value : option
      return [nil, false] if selected.nil? || selected == ""
      return [nil, true] unless selected.is_a?(String)

      name = selected.b.downcase(:ascii)
      return [nil, true] unless /\A[a-z0-9-]{1,64}\z/.match?(name)
      return [nil, true] if %w[authorization cookie set-cookie].include?(name)

      [name, false]
    end

    # CAMADA_KEY is `<ingest_token>.<snap_token>` (printed by reconcile instructions and seed).
    def self.parse_key(key)
      return nil if key.nil? || key.empty?

      dot = key.index(".")
      return nil if dot.nil? || dot <= 0 || dot == key.length - 1

      [key[0, dot], key[(dot + 1)..]]
    end

    # CAMADA_TRUSTED_PROXY: none | vercel | hops:N | cidrs:a,b. Unset or malformed returns nil,
    # which callers treat as "defer to the server-delivered tenant config", never as trust.
    def self.parse_trusted_proxy_env(v)
      return nil if v.nil? || v.empty?
      return { "mode" => "none" } if v == "none"
      return { "mode" => "vercel" } if v == "vercel"

      if v.start_with?("hops:")
        hops = Integer(v[5..], 10, exception: false)
        return hops && hops >= 1 ? { "mode" => "hops", "hops" => hops } : nil
      end
      if v.start_with?("cidrs:")
        cidrs = v[6..].split(",").map(&:strip).reject(&:empty?)
        return cidrs.empty? ? nil : { "mode" => "cidrs", "cidrs" => cidrs }
      end
      nil
    end
  end
end
