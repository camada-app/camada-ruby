# frozen_string_literal: true

require "stringio"
require_relative "body_proxy"
require_relative "engine"
require_relative "guarded"

module Camada
  # Rack middleware: `use Camada::Rack` in config.ru (or the Railtie for Rails). camada answers
  # before routing (block, challenge, beacon), else runs the app and stamps x-rid and the _sfp
  # cookie on its response, shipping the event when the server closes the body. The env keeps no
  # wire header order, so the analyst reads no HEADER_ORDER signal from this tap. Nothing here
  # requires "rack": the host already loaded it, and the gem stays dependency-free.
  class Rack
    # The peer is REMOTE_ADDR — never Rack::Request#ip, which trusts X-Forwarded-For. Every value
    # the engine will match or ship goes through `utf8`: Puma tags env strings ASCII-8BIT, and a
    # binary string with a high byte raises against a UTF-8 rule needle and again in
    # JSON.generate at flush time (the whole batch, blocked rows included). WSGI hands Python
    # str, so the reference has no such seam.
    def self.req_from_env(env)
      headers = []
      env.each do |k, v|
        if k.start_with?("HTTP_")
          headers << [k[5..].downcase.tr("_", "-"), utf8(v)]
        elsif (k == "CONTENT_TYPE" || k == "CONTENT_LENGTH") && v && !v.to_s.empty?
          headers << [k.downcase.tr("_", "-"), utf8(v)]
        end
      end
      query = utf8(env["QUERY_STRING"])
      proto = env["SERVER_PROTOCOL"].to_s
      Req.new(
        method: (env["REQUEST_METHOD"] || "GET").to_s,
        path: Camada.present(utf8(env["PATH_INFO"])) || "/",
        query: query.empty? ? "" : "?#{query}",
        host: Camada.present(utf8(env["HTTP_HOST"])) || utf8(env["SERVER_NAME"]),
        http_version: proto.start_with?("HTTP/") ? proto[5..] : nil,
        peer: Camada.present(utf8(env["REMOTE_ADDR"])),
        https: env["rack.url_scheme"] == "https",
        headers: headers
      )
    end

    # A valid UTF-8 String for any env value: nil -> "", a binary or malformed string is read as
    # UTF-8 with each invalid byte replaced by U+FFFD (never raises, never mutates the env's own).
    def self.utf8(v)
      s = v.to_s
      return s if s.encoding == Encoding::UTF_8 && s.valid_encoding?

      s.dup.force_encoding(Encoding::UTF_8).scrub
    end

    # At most `limit` bytes, or nil when the declared or actual size exceeds it. Whatever was
    # read is put back so an app the request falls through to still sees its whole body (Rack 3
    # inputs need not be rewindable, so the env gets a fresh input either way).
    def self.read_body(env, limit)
      declared = env["CONTENT_LENGTH"].to_i
      return nil if declared > limit

      input = env["rack.input"]
      data = input&.read(limit + 1) || "".b
      if data.bytesize > limit
        env["rack.input"] = ChainedInput.new(data, input) # over the cap: the prefix, then the unread rest — lazily
        return nil
      end
      env["rack.input"] = StringIO.new(data)
      data
    end

    # The bytes camada already read, then whatever is left in the stream the app was owed (the
    # port of wsgi.py's _Chained). Nothing past the cap is read until the app asks: a chunked
    # POST of any size costs the process 32 KB, not the body. A Rack 3 input: gets, each, read,
    # close — plus rewind for Rack 2 hosts, which restores the position camada left the stream at.
    class ChainedInput
      def initialize(head, rest)
        @head = StringIO.new(head)
        @rest = rest
      end

      def read(length = nil, buf = nil)
        out = @head.read(length) || "".b
        if length.nil?
          out << (@rest.read || "".b)
        elsif out.bytesize < length
          more = @rest.read(length - out.bytesize)
          out << more if more
        end
        return nil if length && length > 0 && out.empty? # IO#read: nil at EOF for a positive length

        buf.nil? ? out : buf.replace(out)
      end

      def gets
        line = @head.gets
        return @rest.gets if line.nil?
        return line if line.end_with?("\n")

        line + (@rest.gets || "") # a line that straddles the seam
      end

      def each
        return enum_for(:each) unless block_given?

        while (line = gets)
          yield line
        end
      end

      def close
        @rest.close if @rest.respond_to?(:close)
      end

      def rewind
        @head.rewind
        return unless @rest.respond_to?(:rewind)

        @rest.rewind
        @rest.read(@head.string.bytesize) # back to where camada left it: the head already holds these bytes
      end
    end

    # The matched route pattern, read at finish: Sinatra's "VERB /pattern", Rails' route_uri_pattern.
    def self.route_of(env)
      rails = env["action_dispatch.route_uri_pattern"]
      return rails.to_s if rails

      sinatra = env["sinatra.route"]
      sinatra&.to_s&.sub(/\A[A-Z]+ /, "")
    end

    # `Camada::Rack.new(app)` wires the lazy default from the environment on the first request;
    # `Camada::Rack.new(app, engine)` uses the one you built.
    def initialize(app, engine = nil, **opts)
      @app = app
      @engine = engine
      @opts = opts
    end

    def engine
      @engine ||= Camada.default(**@opts)
    end

    def call(env)
      eng = engine
      begin
        req = Rack.req_from_env(env)
        limit = eng.wants_body(req.method, req.path)
        body = limit.nil? ? nil : Rack.read_body(env, limit)
      rescue StandardError => e
        Guarded.log_rate_limited(e)
        return @app.call(env)
      end
      result = eng.handle(req, body)
      return result.to_rack if result.is_a?(Answer)

      run(env, req, result)
    end

    private

    def run(env, req, passed)
      env["camada"] = passed.ctx unless passed.ctx.nil?
      begin
        status, headers, body = @app.call(env)
      rescue Exception # rubocop:disable Lint/RescueException -- the server answers 500 for anything that escapes the app
        passed.on_finish&.call(500)
        raise
      end
      headers = stamp(headers, passed)
      finish = passed.on_finish
      return [status, headers, body] if finish.nil?

      proxy = BodyProxy.new(body) do
        req.route ||= Rack.route_of(env)
        finish.call(status.to_i)
      end
      [status, headers, proxy]
    end

    # x-rid and the session cookie on the app's response. Rack 3 spells header names in lower
    # case and carries several set-cookie values as an Array; Rack 2 joins them with "\n".
    def stamp(headers, passed)
      return headers if passed.rid.nil? && passed.set_cookie.nil?

      headers = headers.to_h
      headers["x-rid"] = passed.rid if passed.rid
      if passed.set_cookie
        key = headers.keys.find { |k| k.to_s.downcase == "set-cookie" } || "set-cookie"
        headers[key] = join_cookies(headers[key], passed.set_cookie)
      end
      headers
    rescue StandardError => e
      Guarded.log_rate_limited(e)
      headers
    end

    def join_cookies(existing, cookie)
      return cookie if existing.nil? || (existing.respond_to?(:empty?) && existing.empty?)

      arrays = defined?(::Rack::RELEASE) && ::Rack::RELEASE.to_s >= "3"
      return [*existing, cookie] if existing.is_a?(Array) || arrays

      "#{existing}\n#{cookie}"
    end
  end
end
