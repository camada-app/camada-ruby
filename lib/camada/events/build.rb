# frozen_string_literal: true

require_relative "../redact"

module Camada
  # Wire-event builder: reproduces the collector's record() (edge-analyst
  # workers/collector/edge-collector.js) from a normalized request, so events are comparable
  # across taps. HDRS bit order is pinned by the shared fixture (hdrs.json) — never reorder.
  module Events
    HDRS = %w[
      accept accept-language accept-encoding sec-fetch-site sec-fetch-mode sec-fetch-dest
      sec-fetch-user sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests dnt
      cache-control pragma referer origin cookie authorization x-requested-with content-type
      via x-forwarded-for priority sec-purpose save-data te if-modified-since if-none-match
    ].freeze
    HDR_BIT = HDRS.each_with_index.to_h { |name, i| [name, 1 << i] }.freeze

    RequestInfo = Struct.new(
      :method, :host, :path,
      :query,        # includes the leading '?', or empty
      :headers,      # [[name, value], ...] in the order the host gives them (the env's order under Rack)
      :ip,           # already resolved via trusted-proxy config
      :http_version, # e.g. '1.1'
      keyword_init: true
    )
    TokenConfig = Struct.new(:header, :hasher, keyword_init: true)

    def self.auth_scheme(value) = Redact.auth_scheme(value)

    def self.now_ms = Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)

    # The mutable wire event (string keys, ready for JSON); the caller fills st/dur on
    # response-finish before enqueueing.
    def self.build_wire_event(r, tap:, rid:, sid: nil, new_session: false, ja4: nil, token_config: nil)
      mask = hn = hb = 0
      cookie = +""
      names = []
      first = {}
      (r.headers || []).each do |name, value|
        k = name.downcase
        hn += 1
        hb += name.bytesize + value.bytesize # bytes on the wire, as the collector and the WSGI (latin-1) port count them
        names << k
        first[k] = value unless first.key?(k)
        mask |= HDR_BIT.fetch(k, 0)
        cookie << (cookie.empty? ? value : "; #{value}") if k == "cookie"
      end
      query = r.query || ""
      qn = query.length > 1 ? query[1..].split("&").count { |p| !p.empty? } : 0
      tk = token_hash(first, token_config) if token_config
      ev = {
        "tap" => tap, "rid" => rid, "sid" => sid, "ns" => new_session ? 1 : 0, "ts" => now_ms,
        "ip" => r.ip,
        "proto" => r.http_version ? "HTTP/#{r.http_version}" : nil,
        "m" => r.method, "h" => r.host,
        "p" => r.path, "q" => Redact.scrub_query(query)[0, 512], "qn" => qn,
        "ct" => first["content-type"], "cl" => first["content-length"],
        "ua" => first["user-agent"], "chua" => first["sec-ch-ua"],
        "chmob" => first["sec-ch-ua-mobile"], "chplat" => first["sec-ch-ua-platform"],
        "acc" => first["accept"], "lang" => first["accept-language"],
        "fs" => first["sec-fetch-site"], "fm" => first["sec-fetch-mode"],
        "fd" => first["sec-fetch-dest"], "fu" => first["sec-fetch-user"],
        "ref" => Redact.scrub_url(first["referer"]), "org" => first["origin"], # ref: scrubbed like q (camada-all-ijsa)
        "xrw" => first["x-requested-with"], "auth" => auth_scheme(first["authorization"]), # scheme only, never the credential
        "hm" => mask, "hn" => hn, "hb" => hb, "ck" => cookie.empty? ? 0 : cookie.split(";", -1).length,
        "hord" => names.join(",")[0, 2048] # header order as this host reports it (the env's order under Rack)
      }
      ev["ja4"] = ja4 if ja4
      ev["tk"] = tk if tk
      ev["st"] = nil
      ev["dur"] = nil # 'dur': the collector wire already claims 'lat' for latitude
      ev
    end

    def self.token_hash(first, token_config)
      credential = Redact.select_credential(first, token_config.header)
      token_config.hasher.call(credential) if credential
    rescue StandardError, NotImplementedError
      nil # Keep the row and enforcement decision even if hashing fails.
    end
    private_class_method :token_hash
  end
end
