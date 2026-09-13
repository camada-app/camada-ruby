# frozen_string_literal: true

require "digest"
require "openssl"
require_relative "format"

module Camada
  module Challenge
    # The challenge kit over OpenSSL's HMAC-SHA256 and Digest's SHA-256, ported from
    # @camada/core src/challenge/verify.ts. Synchronous, so the engine's handle stays a plain method.
    class Kit
      def initialize(secret)
        @secret = secret
      end

      # Stateless per-(ip, UTC day) nonce; the verify endpoint recomputes it, nothing is stored.
      def nonce(ip, now_ms) = at(ip, Challenge.utc_day(now_ms))

      # Yesterday still passes: a solve started before midnight UTC must not be thrown away.
      # So one solved (nonce, solution) pair is replayable from its own IP for up to ~48 h,
      # minting a fresh 1 h cookie each time. That is the price of a stateless nonce (§D2) and
      # it is deliberate — do not "fix" it into something that needs shared server state.
      def nonce_valid?(ip, now_ms, nonce)
        return false if ip.nil? || ip.empty? || nonce.nil? || nonce.length != NONCE_HEX

        day = Challenge.utc_day(now_ms)
        Challenge.safe_equal?(nonce, at(ip, day)) || Challenge.safe_equal?(nonce, at(ip, day - 1))
      end

      def issue(ip, now_ms)
        exp = now_ms + CHALLENGE_TTL_MS
        "#{exp}.#{hmac(Challenge.token_message(ip, exp))}"
      end

      # A nil ip is refused outright: without one the token is bound to nothing, so a single
      # solve would mint a cookie every other unidentified client could present. Adapters must
      # fail open (serve no challenge) rather than challenge a client they cannot identify.
      def token_valid?(ip, now_ms, cookie_value)
        return false if ip.nil? || ip.empty?

        t = Challenge.split_token(cookie_value)
        return false if t.nil?

        exp, mac = t
        return false if exp <= now_ms || exp > now_ms + CHALLENGE_TTL_MS

        Challenge.safe_equal?(mac, hmac(Challenge.token_message(ip, exp)))
      end

      # Proof of work ONLY. Never call it without a passing nonce_valid? for the same nonce.
      def solution_ok?(nonce, solution)
        Challenge.solution_shape_ok?(solution) && Challenge.pow_ok?(Digest::SHA256.hexdigest("#{nonce}.#{solution}"))
      end

      # The whole submission: the nonce is ours and unexpired, and the work is done.
      def verify?(ip, now_ms, nonce, solution)
        nonce_valid?(ip, now_ms, nonce) && solution_ok?(nonce, solution)
      end

      private

      def hmac(msg) = OpenSSL::HMAC.hexdigest("SHA256", @secret, msg)
      def at(ip, day) = hmac(Challenge.nonce_message(ip, day))[0, NONCE_HEX]
    end

    def self.create_challenge(secret) = Kit.new(secret)
  end
end
