# frozen_string_literal: true

require "json"

module Camada
  # Tap identifier this SDK claims on the wire. The server validates against its own enum and
  # decides itself what each tap can see: an SDK can never grant
  # itself more than that, only name its position — and an unknown name is silently read as a
  # proxy, so this literal is load-bearing.
  TAP = "sdk-ruby"

  DEFAULT_REFRESH_S = 30.0
  # 5 carries the tenant's ordered custom rules (§D3); a tenant without one is answered with the next container down.
  DEFAULT_SNAPSHOT_VERSION = 5
  KILL_SWITCH_ENV = "CAMADA_DISABLED"

  SCRIPT_PATH = "/_cam/b.js"
  FP_PATH = "/_cam/fp"
  FP_MAX = 32 * 1024                # matches the server's /fp cap: never accept what ingest will 413
  CHALLENGE_PATH = "/__camada/challenge"
  BODY_MAX = 4 * 1024               # the verify form is ~120 bytes; anything larger is not ours
  # Row keys only the SDK can attest (TLS/network facts, outcome, session, track()). A beacon body is the
  # visitor's, so these never ride a sig:1 row; the analyst joins them from the beacon's request row.
  REQUEST_ROW_KEYS = %w[tlsx ja4 asn cc sid ns st dur rt blk rl wrn chs ch et uid].freeze

  SESSION_COOKIE = "_sfp"           # same cookie as the edge collector: sid/ns comparable across taps
  SESSION_MAX_AGE = 2_592_000       # 30 days

  # nil for nil or "", else the string: the one nil-or-empty helper every module reads through.
  def self.present(s) = s.nil? || s.empty? ? nil : s

  # JSON.parse that answers nil for anything that is not JSON (a config header, a beacon body).
  def self.parse_json(s)
    JSON.parse(s)
  rescue JSON::ParserError
    nil
  end
end
