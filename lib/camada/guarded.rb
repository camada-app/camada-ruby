# frozen_string_literal: true

module Camada
  # The fail-open envelope: a camada bug must never 5xx the customer. Every public entry point of
  # the SDK catches, falls back, and reports through log_rate_limited: at most one line a minute.
  module Guarded
    @last_log = nil # monotonic seconds of the last line; nil until the first one
    @last_warn = nil
    @warn_lock = Mutex.new
    @logger = nil

    class << self
      # Where the one line a minute goes: anything responding to #call(String). Default: $stderr.
      attr_accessor :logger

      def log_rate_limited(err)
        # CLOCK_MONOTONIC counts from boot, so a numeric "never" sentinel like 0.0 would
        # swallow the first line on a host younger than a minute (fresh CI runners are).
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        return if @last_log && now - @last_log < 60

        @last_log = now
        write_line("[camada] suppressed error (SDK fails open): #{describe(err)}")
      rescue StandardError
        nil # even logging must not raise
      end

      def warn_rate_limited(msg)
        @warn_lock.synchronize do
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          return if @last_warn && now - @last_warn < 60

          @last_warn = now
        end
        write_line("[camada] config warning: #{msg}")
      rescue StandardError
        nil # even logging must not raise
      end

      private

      def write_line(line)
        (@logger || ->(s) { warn(s) }).call(line)
      end

      # Exceptions print as "Class: message" on one line — never a backtrace, and never the
      # "(ClassName)" spelling an uncaught Ruby exception uses, so a crash grep stays quiet.
      def describe(err)
        err.is_a?(Exception) ? "#{err.class.name}: #{err.message}".tr("\n", " ") : err.to_s
      end
    end
  end
end
