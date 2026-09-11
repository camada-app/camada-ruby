# frozen_string_literal: true

require "json"
require "openssl"

module Camada
  # Wire constants and pure helpers for the SDK-served challenge (contracts §D2), ported from
  # @camada/core src/challenge/format.ts. Nothing here does crypto; verify.rb supplies HMAC and
  # SHA-256 from the stdlib, so the format has exactly one definition across the family.
  module Challenge
    CHALLENGE_COOKIE = "_cch"
    CHALLENGE_TTL_MS = 3_600_000 # 1 h (contract)
    POW_BITS = 16                # leading zero bits of SHA-256("<nonce>.<solution>")
    NONCE_HEX = 32               # the nonce is the first 32 hex chars of the HMAC
    DAY_MS = 86_400_000
    MAX_RETURN_TO = 2048
    MAX_SOLUTION = 32

    def self.utc_day(now_ms) = now_ms / DAY_MS

    # Domain-separated messages: a nonce HMAC can never be replayed as a cookie HMAC.
    def self.nonce_message(ip, day) = "camada-challenge-nonce|#{ip}|#{day}"
    def self.token_message(ip, exp) = "camada-challenge-token|#{ip}|#{exp}"

    def self.split_token(value)
      return nil if value.nil? || value.empty?

      dot = value.index(".")
      return nil if dot.nil? || dot <= 0

      exp = Integer(value[0, dot], 10, exception: false)
      return nil if exp.nil?

      mac = value[(dot + 1)..]
      mac.empty? ? nil : [exp, mac]
    end

    # Constant-time for equal-length strings; length itself is not a secret here.
    def self.safe_equal?(a, b)
      a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)
    end

    # True when the hex digest starts with `bits` zero bits.
    def self.pow_ok?(hex_digest, bits = POW_BITS)
      nibbles = bits >> 2
      rest = bits & 3
      return false if hex_digest.length < nibbles + (rest == 0 ? 0 : 1)
      return false if nibbles.times.any? { |i| hex_digest[i] != "0" }
      return true if rest == 0

      v = Integer(hex_digest[nibbles], 16, exception: false)
      return false if v.nil?

      (v >> (4 - rest)) == 0
    end

    def self.solution_shape_ok?(solution)
      !solution.nil? && !solution.empty? && solution.length <= MAX_SOLUTION
    end

    def self.challenge_cookie(value, secure)
      "#{CHALLENGE_COOKIE}=#{value}; Path=/; Max-Age=#{CHALLENGE_TTL_MS / 1000}; HttpOnly; SameSite=Lax#{"; Secure" if secure}"
    end

    # Only a printable-ASCII same-site absolute path survives: never an absolute URL, a
    # protocol-relative '//host' redirect, a control character, or something absurdly long.
    def self.safe_return_to(raw)
      return "/" if raw.nil? || raw.empty? || raw.length > MAX_RETURN_TO
      return "/" if raw[0] != "/" || (raw.length > 1 && "/\\".include?(raw[1]))
      return "/" unless raw.match?(/\A[\x21-\x7e]+\z/)

      raw
    end

    # A challenge page is only worth serving to a top-level HTML navigation (contract §D2).
    def self.wants_html?(accept, sec_fetch_dest)
      return false if accept.nil? || !accept.include?("text/html")

      sec_fetch_dest.nil? || sec_fetch_dest.empty? || sec_fetch_dest == "document"
    end

    def self.escape_attr(s)
      s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;").gsub('"', "&quot;").gsub("'", "&#39;")
    end

    # Safe to drop inside an inline <script>: `<` is escaped so no value can close the element early.
    def self.escape_script(s) = JSON.generate(s).gsub("<", "\\u003c")

    # application/x-www-form-urlencoded, last value wins. Never raises on junk: an invalid
    # %-escape is kept as is, invalid UTF-8 is replaced.
    def self.parse_form_body(body)
      out = {}
      body.split("&").each do |pair|
        next if pair.empty?

        eq = pair.index("=")
        k = eq.nil? ? pair : pair[0, eq]
        v = eq.nil? ? "" : pair[(eq + 1)..]
        out[unquote(k)] = unquote(v)
      end
      out
    end

    def self.unquote(s)
      s.tr("+", " ").b.gsub(/%[0-9a-fA-F]{2}/) { |m| [m[1, 2].hex].pack("C") }.force_encoding("UTF-8").scrub
    end
  end
end
