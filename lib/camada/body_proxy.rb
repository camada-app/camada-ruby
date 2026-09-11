# frozen_string_literal: true

module Camada
  # Wraps the app's Rack body so the block runs exactly once, when the server closes the body
  # (after the last byte, PEP 3333's close() in Rack terms). Nothing here requires "rack": the
  # gem stays dependency-free. Passes through each, close, and — only when the inner body has
  # them — to_path (a file the server may sendfile) and call (a Rack 3 streaming body).
  class BodyProxy
    def initialize(body, &block)
      @body = body
      @block = block
      @closed = false
    end

    def each(&blk)
      return enum_for(:each) unless blk

      @body.each(&blk)
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

    def to_path = @body.to_path
    def call(stream) = @body.call(stream)

    def respond_to_missing?(name, include_all = false)
      name == :to_path || name == :call ? @body.respond_to?(name, include_all) : super
    end

    def respond_to?(name, include_all = false)
      return @body.respond_to?(name, include_all) if name == :to_path || name == :call

      super
    end
  end
end
