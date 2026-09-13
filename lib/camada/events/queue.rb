# frozen_string_literal: true

require "json"
require_relative "../guarded"
require_relative "../transport"

module Camada
  module Events
    # Queue: fire-and-forget batched shipping to POST /e (ported from @camada/core
    # src/events/queue.ts). The collector ships one event per request; an in-process SDK batches,
    # flushes on size or interval, and drains at exit — but the same law holds: NOTHING here may
    # ever raise into the customer's request path, and a dead ingest must cost nothing but dropped
    # telemetry. Defaults (15 s / 500): every flush is one request and one R2 put at the analyst,
    # so the bill scales with instance count x flush cadence — not with traffic.
    class Queue
      attr_accessor :transport
      attr_reader :url, :token, :max_batch, :max_queue, :flush_s, :timeout_s, :sdk, :dropped, :lock, :flush_thread

      def initialize(url, token, max_batch: 500, max_queue: 2000, flush_s: 15.0, timeout_s: 2.0, transport: nil, sdk: nil)
        # url: ingest base, e.g. https://analyst.example.com; token: ingest token (x-tenant header);
        # max_batch: flush when the queue reaches this many (server caps at 1000); max_queue: drop-oldest beyond this;
        # sdk: '<package>/<version>', sent as x-camada-sdk on every batch (SDK-03).
        @url = url.sub(%r{/+\z}, "")
        @token = token
        @max_batch = max_batch
        @max_queue = max_queue
        @flush_s = flush_s
        @timeout_s = timeout_s
        @sdk = sdk
        @transport = transport || Transport::DEFAULT
        @dropped = 0 # debug counter, not an API promise
        @exit_installed = false
        fresh_state!
      end

      # A forked worker inherits the queue but not its thread: start fresh on the next push. The
      # parent keeps its pending events (and may have held the lock mid-flush), so the child starts empty.
      def after_fork!
        fresh_state!
        @exit_installed = false
      end

      def size = @q.length
      def inflight? = @inflight.locked?

      # Synchronous, never raises. Starts the flush thread lazily on first push; a stopped queue
      # stays stopped (configure replaces the engine rather than reviving one).
      def push(event)
        check_fork!
        n = 0
        @lock.synchronize do
          if @q.length >= @max_queue
            @q.shift
            @dropped += 1
          end
          @q << event
          n = @q.length
          if @flush_thread.nil? && !@stopped
            @flush_thread = Thread.new { run }
            @flush_thread.name = "camada-events"
            @flush_thread.report_on_exception = false
          end
        end
        wake if n >= @max_batch
      rescue StandardError => e # never into the request path
        Guarded.log_rate_limited(e)
      end

      # Drains the queue, <=1000 events per POST (the server slices there); single-in-flight;
      # never raises. `wait` queues behind a flush already in flight instead of yielding to it —
      # the exit drain needs the full queue gone, not just the batch someone else is posting.
      def flush(wait: false)
        check_fork!
        inflight = @inflight # bound once: after_fork! swaps the attribute
        return unless wait ? inflight.lock : inflight.try_lock

        begin
          headers = { "x-tenant" => @token, "content-type" => "application/json" }
          headers["x-camada-sdk"] = @sdk if @sdk
          loop do
            batch = @lock.synchronize { @q.shift([1000, @q.length].min) }
            return if batch.empty?

            begin
              body = encode(batch)
              next if body.nil?

              res = @transport.call(HttpRequest.new(method: "POST", url: "#{@url}/e", headers: headers, body: body, timeout_s: @timeout_s))
              raise "ingest unreachable" if res.status == 0
            rescue StandardError => e
              @dropped += batch.length
              # Dropping telemetry is by design, doing it silently is not: a mount that can never
              # reach ingest looks identical to a healthy one otherwise.
              Guarded.log_rate_limited(e)
            end
          end
        ensure
          inflight.unlock
        end
      rescue StandardError => e
        Guarded.log_rate_limited(e)
      end

      def stop
        @wake_m.synchronize do
          @stopped = true
          @woken = true
          @wake_cv.broadcast
        end
        @flush_thread = nil
      end

      # Opt-in: drain at interpreter exit within a small budget. No signal handlers — an app owns
      # its own shutdown; SIGTERM without a handler skips at_exit, which the README says out loud.
      def install_exit_flush(budget_s = 0.5)
        return if @exit_installed

        @exit_installed = true
        at_exit { drain(budget_s) }
      end

      # A full drain (behind any flush in flight) on its own thread, abandoned once the budget is spent.
      def drain(budget_s = 0.5)
        t = Thread.new { flush(wait: true) }
        t.name = "camada-exit-flush"
        t.report_on_exception = false
        t.join(budget_s)
        nil
      end

      private

      def fresh_state!
        @pid = Process.pid
        @q = []
        @lock = Mutex.new
        @inflight = Mutex.new
        @wake_m = Mutex.new
        @wake_cv = ConditionVariable.new
        @woken = false
        @stopped = false
        @flush_thread = nil
      end

      def check_fork!
        after_fork! if Process.pid != @pid
      end

      # The batch as JSON, or nil when nothing in it can be serialised. The adapters scrub what
      # they ship, but a row that still carries an invalid byte must cost that row alone, never
      # the batch: blocked rows always ship, or blocks oscillate.
      def encode(batch)
        JSON.generate(batch)
      rescue JSON::GeneratorError, EncodingError
        rows = batch.filter_map do |ev|
          JSON.generate(ev)
        rescue JSON::GeneratorError, EncodingError
          nil
        end
        @dropped += batch.length - rows.length
        rows.empty? ? nil : "[#{rows.join(",")}]"
      end

      def wake
        @wake_m.synchronize do
          @woken = true
          @wake_cv.signal
        end
      end

      def run
        until @stopped
          @wake_m.synchronize do
            @wake_cv.wait(@wake_m, @flush_s) unless @woken
            @woken = false
          end
          return if @stopped

          flush
        end
      end
    end
  end
end
