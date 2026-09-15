# frozen_string_literal: true

require_relative "config"
require_relative "constants"

module Camada
  # Environment wiring. The two-line quickstart depends on this doing the right thing:
  #   CAMADA_KEY=<ingest_token>.<snap_token>   (printed by `reconcile instructions` and seed)
  #   CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL  (dev: http://localhost:8787[/snapshot])
  #   CAMADA_DISABLED=1                        kill switch, checked at boot and per request
  #   CAMADA_SERVERLESS=1                      lazy snapshot mode (no poll thread)
  #   CAMADA_TRUSTED_PROXY                     local override: none | vercel | hops:N | cidrs:a,b
  #   CAMADA_CHALLENGE=0                       do not enforce challenge verdicts
  Env = Struct.new(
    :ingest_token, :snap_token,
    :secret,          # HMAC key for the challenge nonce/cookie — never leaves the process
    :ingest_url, :snapshot_url,
    :serverless,
    :trusted_proxy,   # nil = defer to server-delivered config
    keyword_init: true
  )

  class Env
    # PLACEHOLDER default, the same one @camada/node and camada-python carry — confirm the
    # production ingest domain before any RubyGems publish.
    DEFAULT_INGEST_URL = "https://in.camada.app"

    # nil (SDK stays inert, one log line) rather than raising on bad config. `env` is anything
    # answering #[] with strings: ENV, or a Hash.
    def self.resolve(env)
      key = Config.parse_key(env["CAMADA_KEY"])
      ingest_token = key ? key[0] : env["CAMADA_TOKEN"]
      snap_token = key ? key[1] : env["CAMADA_SNAPSHOT_TOKEN"]
      return nil if Camada.present(ingest_token).nil? || Camada.present(snap_token).nil?

      ingest_url = (Camada.present(env["CAMADA_INGEST_URL"]) || DEFAULT_INGEST_URL).sub(%r{/+\z}, "")
      new(
        ingest_token: ingest_token, snap_token: snap_token,
        secret: Camada.present(env["CAMADA_KEY"]) || "#{ingest_token}.#{snap_token}",
        ingest_url: ingest_url,
        snapshot_url: Camada.present(env["CAMADA_SNAPSHOT_URL"]) || "#{ingest_url}/snapshot",
        serverless: env["CAMADA_SERVERLESS"] == "1",
        trusted_proxy: Config.parse_trusted_proxy_env(env["CAMADA_TRUSTED_PROXY"])
      )
    end
  end
end
