# frozen_string_literal: true

module Camada
  # The fail-open envelope: a camada bug must never 5xx the customer. Every public entry point of
  # the SDK catches, falls back, and reports through log_rate_limited: at most one line a minute.
  module Guarded
    @last_log = 0.0
    @logger = nil

    class << self
      # Where the one line a minute goes: anything responding to #call(String). Default: $stderr.
      attr_accessor :logger

      def log_rate_limited(err)
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        return if now - @last_log < 60

        @last_log = now
        line = "[camada] suppressed error (SDK fails open): #{describe(err)}"
        (@logger || ->(s) { warn(s) }).call(line)
      rescue StandardError
        nil # even logging must not raise
      end

      private

      # Exceptions print as "Class: message" on one line — never a backtrace, and never the
      # "(ClassName)" spelling an uncaught Ruby exception uses, so a crash grep stays quiet.
      def describe(err)
        err.is_a?(Exception) ? "#{err.class.name}: #{err.message}".tr("\n", " ") : err.to_s
      end
    end
  end
end
