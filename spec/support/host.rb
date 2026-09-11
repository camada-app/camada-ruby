# frozen_string_literal: true

require "rack"
require "stringio"

# Drives the SDK through the Rack middleware without a server: a Rack env built by
# Rack::MockRequest.env_for, the middleware called directly, the body iterated and closed the
# way a server does. The Ruby twin of camada-python's tests/hosts.py (one host here: Rack).
module Host
  ENV_BASE = { "CAMADA_KEY" => "tok-test.snap-test", "CAMADA_INGEST_URL" => "https://analyst.test" }.freeze
  PEER = "172.16.0.9" # a peer no golden container lists (10.0.0.0/8 is blocked in all of them)
  HELLO = ->(_env) { [200, { "content-type" => "text/plain" }, ["hello"]] }
  HTML = [["accept", "text/html,*/*"], ["sec-fetch-dest", "document"]].freeze

  Reply = Struct.new(:status, :headers, :body) do
    def header(name)
      v = headers.find { |k, _| k.downcase == name }&.last
      v.is_a?(Array) ? v.first : v
    end

    def headers_named(name)
      v = headers.find { |k, _| k.downcase == name }&.last
      v.nil? ? [] : Array(v)
    end

    def text = body
  end

  Call = Struct.new(:method, :path, :headers, :body, :peer, :https, :content_length, keyword_init: true)

  def self.engine_with(a, env = nil, **opts)
    Camada::Engine.new(env: ENV_BASE.merge(env || {}), transport: a, **opts)
  end

  def self.loaded(engine)
    raise "no snapshot client" if engine.snap.nil?

    400.times do
      return if engine.snap.verdict(Camada::Snapshot::MatchInput.new(ip: "0.0.0.0")).reason != "cold"

      sleep 0.005
    end
    raise "snapshot never loaded"
  end

  class RackDriver
    attr_reader :seen, :app

    def initialize(engine, handler = HELLO)
      @seen = []
      inner = lambda do |env|
        @seen << env
        handler.call(env)
      end
      @app = Camada::Rack.new(inner, engine)
    end

    def call(c)
      path, query = c.path.split("?", 2)
      body = (c.body || "").b
      env = ::Rack::MockRequest.env_for(path, method: c.method, input: body, "QUERY_STRING" => query || "",
                                              "rack.url_scheme" => c.https ? "https" : "http", "HTTPS" => c.https ? "on" : "off",
                                              "SERVER_NAME" => "x.test", "SERVER_PORT" => "80", "HTTP_HOST" => "x.test")
      env["REMOTE_ADDR"] = c.peer unless c.peer.nil?
      if %w[POST PUT].include?(c.method) || !body.empty?
        env["CONTENT_LENGTH"] = (c.content_length || body.bytesize).to_s
      else
        env.delete("CONTENT_LENGTH")
      end
      (c.headers || []).each do |k, v|
        key = k.upcase.tr("-", "_")
        key = "HTTP_#{key}" unless %w[CONTENT_TYPE CONTENT_LENGTH].include?(key)
        env[key] = env.key?(key) ? "#{env[key]}, #{v}" : v
      end
      status, headers, res_body = @app.call(env)
      out = +""
      begin
        res_body.each { |part| out << part }
      ensure
        res_body.close if res_body.respond_to?(:close)
      end
      Reply.new(status, headers, out)
    end
  end

  # One engine + one host per test, loaded unless asked otherwise.
  class Site
    attr_reader :engine, :drv, :a

    def initialize(a, engines, env = nil, handler: HELLO, load: true, **opts)
      @a = a
      @engine = Host.engine_with(a, env, **opts)
      engines << @engine
      @drv = RackDriver.new(@engine, handler)
      Host.loaded(@engine) if load && !@engine.snap.nil?
    end

    def call(method, path, headers: [], body: "", peer: PEER, https: false, content_length: nil)
      @drv.call(Call.new(method: method, path: path, headers: headers, body: body, peer: peer, https: https, content_length: content_length))
    end

    def events
      @engine.queue.flush
      @a.all_events
    end

    def seen = @drv.seen
  end
end
