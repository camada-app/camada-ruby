# frozen_string_literal: true

module Camada
  # Wraps the app's Rack body so the block runs exactly once, when the server closes the body
  # (after the last byte, PEP 3333's close() in Rack terms). Nothing here requires "rack": the
  # gem stays dependency-free, so this mirrors Rack::BodyProxy's shape instead: everything but
  # close is delegated, and the proxy responds to a body method only when the inner body does.
  # That last part is load-bearing — a Body that answers `each` is an Enumerable Body to every
  # server (Rack SPEC), so a proxy with its own `each` would turn a Rack 3 streaming body
  # (call-only) into a NoMethodError at the socket.
  class BodyProxy
    def initialize(body, &block)
      @body = body
      @block = block
      @closed = false
    end

    def close
      return if @closed

      @closed = true
      begin
        @body.close if @body.respond_to?(:close)
      ensure
        @block.call
      end
    end

    def closed? = @closed

    def respond_to_missing?(name, include_all = false)
      name != :to_str && @body.respond_to?(name, include_all)
    end

    # each, call (a streaming body), to_path (a file the server may sendfile) and to_ary pass
    # through. A body consumed via to_ary must close itself (SPEC), so the proxy does it there.
    def method_missing(name, ...)
      return super if name == :to_str
      return @body.__send__(name, ...) unless name == :to_ary

      begin
        @body.__send__(name, ...)
      ensure
        close
      end
    end
  end
end
