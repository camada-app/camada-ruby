# frozen_string_literal: true

# camada for Ruby: inline enforcement of your tenant snapshot (ordered custom rules, then
# allow, block, challenge), a first-party proof-of-work challenge and beacon, app-context events,
# and batched wire events shipped off the request path. Fails open by design.
#
# Quickstart (env: CAMADA_KEY, plus CAMADA_INGEST_URL in dev):
#
#     # config.ru — any Rack app (Sinatra, Hanami, plain Rack)
#     use Camada::Rack
#     run App
#
#     # Rails: nothing to add — the Railtie inserts Camada::Rack first
#
#     # in a route
#     Camada.script_tag(env)                              # the beacon tag for your HTML
#     Camada.track(env, "login_failed", user: email)      # an outcome your handler knows
#     halt(*Camada.serve_challenge(env)) if ...           # gate a route yourself
require_relative "camada/version"
require_relative "camada/constants"
require_relative "camada/config"
require_relative "camada/env"
require_relative "camada/redact"
require_relative "camada/ipparse"
require_relative "camada/ip"
require_relative "camada/guarded"
require_relative "camada/transport"
require_relative "camada/snapshot/parse"
require_relative "camada/snapshot/match"
require_relative "camada/snapshot/client"
require_relative "camada/events/build"
require_relative "camada/events/queue"
require_relative "camada/challenge/format"
require_relative "camada/challenge/verify"
require_relative "camada/challenge/page"
require_relative "camada/beacon_js"
require_relative "camada/engine"
require_relative "camada/body_proxy"
require_relative "camada/rack"
require_relative "camada/railtie"

module Camada
  @default = nil
  @default_lock = Mutex.new

  class << self
    # The lazy singleton wired from the environment on first use (what the middleware shares).
    def default(**opts)
      @default_lock.synchronize { @default ||= create_engine(**opts) }
    end

    # Replaces the default engine (stopping the old one) — for tests and explicit wiring.
    def configure(**opts)
      @default_lock.synchronize do
        @default&.stop
        @default = create_engine(**opts)
      end
    end

    # Stops and forgets the default engine; the next request builds a new one (tests).
    def reset!
      @default_lock.synchronize do
        @default&.stop
        @default = nil
      end
    end

    # The engine that produced a request context, else the default: what the helpers resolve through.
    def engine_for(ctx)
      engine_of(ctx) || default
    end

    # The helpers take the Rack env (Sinatra's `env`, Rails' `request.env`); the middleware left
    # the request context in env["camada"]. Each stands down silently when the middleware did not run.
    def script_tag(env)
      ctx = ctx_of(env)
      engine_for(ctx).script_tag(ctx)
    end

    def track(env, event, user: nil)
      ctx = ctx_of(env)
      engine_for(ctx).track(ctx, event, user: user)
    end

    # A Rack triple [status, headers, [body]] to answer with (Sinatra: `halt(*answer)`) until the
    # browser holds a valid _cch, then nil.
    def serve_challenge(env)
      ctx = ctx_of(env)
      engine_for(ctx).serve_challenge(ctx)&.to_rack
    end

    private

    def ctx_of(env)
      ctx = env.is_a?(Hash) ? env["camada"] : nil
      ctx.is_a?(Hash) ? ctx : nil
    end
  end
end
