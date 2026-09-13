# frozen_string_literal: true

require "json"
require_relative "../config"
require_relative "../constants"
require_relative "../guarded"
require_relative "../transport"
require_relative "match"
require_relative "parse"

module Camada
  module Snapshot
    # Client: the single-tenant port of the edge collector's snapshot lifecycle over the
    # GET /snapshot contract (ported from @camada/core src/snapshot/client.ts):
    #   200  [u32 LE meta-length][meta JSON][BLK container] + etag + x-camada-config
    #   304  nothing changed; config header repeated (config refreshes every poll for free)
    #   204  authenticated, no snapshot published -> enforce nothing, fail open
    # Semantics ported exactly: single-in-flight load; loaded_at stamped even on 204 (retry per
    # poll cadence, not per request); any error keeps the previous snapshot; cold = fail open.
    # Timers are threads here: timer mode runs one thread per client sleeping on a condition
    # variable; lazy mode kicks a one-shot thread from ensure_fresh so the request path never
    # waits on the network. Ruby has no register_at_fork, so every entry point compares
    # Process.pid with the pid that built the client and starts over in a forked worker.
    COLD = MatchResult.new(reason: "cold") # never loaded yet: fail open, mirrors the collector
    NONE = MatchResult.new

    class Client
      attr_accessor :transport
      attr_reader :url, :token, :matcher, :config, :refresh_s, :mode, :sdk, :snapshot_version, :timeout_s, :poll_thread

      def initialize(url, token, refresh_s: nil, timeout_s: 3.0, mode: :timer, transport: nil, sdk: nil,
                     snapshot_version: DEFAULT_SNAPSHOT_VERSION)
        # refresh_s: leave unset and the server's poll_seconds steers it; set it and it is pinned.
        # sdk: '<package>/<version>', sent as x-camada-sdk on every poll (SDK-03).
        # snapshot_version: 5 asks for the custom rules too; 4 the sides only; 3 opts out of both.
        @url = url
        @token = token
        @timeout_s = timeout_s
        @mode = mode
        @sdk = sdk
        @snapshot_version = snapshot_version
        @transport = transport || Transport::DEFAULT
        @matcher = nil
        @config = nil
        @refresh_s = refresh_s.nil? ? DEFAULT_REFRESH_S : refresh_s.to_f
        @pinned = !refresh_s.nil?
        @etag = nil
        @loaded_at = nil
        fresh_state!
      end

      # Threads do not survive fork (Puma cluster preload_app!, Unicorn, Passenger): forget the
      # parent's, then re-arm the timer so the child polls on its own (lazy mode refreshes from
      # the request path anyway).
      def after_fork!
        fresh_state!
        start if @mode == :timer
      end

      def start
        ensure_fresh
        return if @mode != :timer || !@poll_thread.nil?

        @stopped = false
        @poll_thread = Thread.new { run }
        @poll_thread.name = "camada-snapshot"
        @poll_thread.report_on_exception = false
      end

      def stop
        @stop_m.synchronize do
          @stopped = true
          @stop_cv.broadcast
        end
        @poll_thread = nil
      end

      # 0.9 x refresh so a timer tick arriving at ~refresh-ε still refreshes; a full-interval
      # comparison makes every other tick a no-op (effective cadence 2x).
      def stale?
        @loaded_at.nil? || monotonic - @loaded_at > @refresh_s * 0.9
      end

      # Kicks a refresh when stale; never blocks the request path, never raises.
      def ensure_fresh
        check_fork!
        return if !stale? || @loading.locked?

        t = Thread.new { refresh }
        t.name = "camada-snapshot-load"
        t.report_on_exception = false
        nil
      end

      # One synchronous poll (single in-flight): what the threads call, and what tests and warm-ups call directly.
      def refresh
        check_fork!
        lock = @loading # bound once: after_fork! swaps the attribute
        return unless lock.try_lock

        begin
          load_once
        rescue StandardError => e # a poll that can never succeed must not be silent, nor fatal
          Guarded.log_rate_limited(e)
        ensure
          lock.unlock
        end
      end

      # Cold (never loaded) and no-snapshot both fail open, mirroring the edge collector.
      def verdict(i)
        return COLD if @loaded_at.nil?

        m = @matcher
        m ? m.match(i) : NONE
      end

      private

      def fresh_state!
        @pid = Process.pid
        @loading = Mutex.new
        @stop_m = Mutex.new
        @stop_cv = ConditionVariable.new
        @stopped = false
        @poll_thread = nil
      end

      def check_fork!
        after_fork! if Process.pid != @pid
      end

      def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      # Sleeps one cadence; true when stop was called meanwhile.
      def wait_stop(seconds)
        @stop_m.synchronize do
          @stop_cv.wait(@stop_m, seconds) unless @stopped
          @stopped
        end
      end

      def run
        ensure_fresh until wait_stop(@refresh_s)
      end

      def load_once
        headers = { "authorization" => "Bearer #{@token}", "accept-encoding" => "gzip" }
        headers["if-none-match"] = @etag if @etag
        headers["x-camada-sdk"] = @sdk if @sdk
        # a tenant without that container is answered with the next one down
        headers["x-camada-snapshot"] = @snapshot_version.to_s if @snapshot_version > 3
        res = @transport.call(HttpRequest.new(method: "GET", url: @url, headers: headers, body: nil, timeout_s: @timeout_s))
        return unless [200, 204, 304].include?(res.status) # 401/5xx/network: keep what we have

        @loaded_at = monotonic
        read_config(res.headers["x-camada-config"])
        return if res.status == 304

        if res.status == 204 # no snapshot published: enforce nothing
          @matcher = nil
          @etag = nil
          return
        end
        body = res.body
        raise ArgumentError, "camada: truncated snapshot frame" if body.bytesize < 4

        meta_len = body.unpack1("V")
        raise ArgumentError, "camada: truncated snapshot frame" if 4 + meta_len > body.bytesize

        meta = JSON.parse(body.byteslice(4, meta_len))
        raise ArgumentError, "camada: snapshot meta is not an object" unless meta.is_a?(Hash)

        # The server ships the v3, v4 and v5 bodies of one publish under the SAME meta.version and
        # different etags, so version alone cannot say "nothing changed".
        etag = res.headers["etag"]
        return if @matcher && meta["version"].to_s == @matcher.snap.version && !etag.nil? && etag == @etag

        # parse_snapshot raises on corrupt data -> caught by refresh, previous kept
        @matcher = Matcher.new(Snapshot.parse_snapshot(Words.new(body, 4 + meta_len), meta))
        @etag = etag
      end

      def read_config(raw)
        return if raw.nil? || raw.empty?

        cfg = Camada.parse_json(raw)
        return unless cfg.is_a?(Hash) # not an object, or not JSON: keep the previous config

        @config = cfg
        # the server steers the poll cadence per tenant (its cost lever) unless the client pinned one
        secs = Float(cfg["poll_seconds"] || 0, exception: false)
        return if @pinned || secs.nil? || !secs.finite? || secs < 5 || secs == @refresh_s # JSON admits 1e999

        @refresh_s = secs
      end
    end
  end
end
