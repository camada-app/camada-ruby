# frozen_string_literal: true

require "rack"
require "stringio"

# What only the Rack host can show: the env mapping, a body camada read being put back, the
# body proxy firing exactly once, and the lazy default engine.
RSpec.describe Camada::Rack do
  let(:a) { FakeAnalyst.new }
  let(:engine) { Host.engine_with(a).tap { |e| Host.loaded(e) } }

  after { engine.stop }

  it "maps the env to a Req" do
    req = described_class.req_from_env({
                                         "REQUEST_METHOD" => "PUT", "PATH_INFO" => "/a", "QUERY_STRING" => "x=1", "SERVER_PROTOCOL" => "HTTP/1.0",
                                         "rack.url_scheme" => "https", "REMOTE_ADDR" => "::ffff:1.2.3.4", "HTTP_HOST" => "h",
                                         "HTTP_X_FORWARDED_FOR" => "5.6.7.8", "CONTENT_TYPE" => "text/plain", "CONTENT_LENGTH" => "3"
                                       })
    expect([req.method, req.path, req.query, req.host, req.http_version, req.peer, req.https]).to eq(["PUT", "/a", "?x=1", "h", "1.0", "::ffff:1.2.3.4", true])
    expect(req.headers).to include(["x-forwarded-for", "5.6.7.8"], ["content-type", "text/plain"], %w[content-length 3])
    expect(req.header("x-forwarded-for")).to eq("5.6.7.8")
    expect(req.header("nope")).to be_nil
    bare = described_class.req_from_env({})
    expect([bare.method, bare.path, bare.query, bare.host, bare.http_version, bare.peer, bare.https]).to eq(["GET", "/", "", "", nil, nil, false])
  end

  it "joins repeated headers the way node:http does" do
    req = Camada::Req.new(method: "GET", path: "/", headers: [["cookie", "a=1"], ["cookie", "_sfp=abc"], ["accept", "a"], ["accept", "b"]])
    expect(req.header("cookie")).to eq("a=1; _sfp=abc")
    expect(req.header("accept")).to eq("a, b")
  end

  it "puts a body camada read back for the app" do
    a.config["beacon"] = false
    engine.snap.refresh
    got = []
    app = lambda do |env|
      got << env["rack.input"].read
      [200, {}, ["ok"]]
    end
    env = { "REQUEST_METHOD" => "POST", "PATH_INFO" => "/_cam/fp", "CONTENT_LENGTH" => "2", "rack.input" => StringIO.new("{}"), "REMOTE_ADDR" => "172.16.0.9" }
    _, _, body = described_class.new(app, engine).call(env)
    expect(body.to_enum(:each).to_a.join).to eq("ok")
    expect(got).to eq(["{}"])
  end

  it "hands a body over the cap to the app whole" do
    # no ip -> camada never answers the verify endpoint, so the app gets the request with its full body
    big = "x" * 70_000
    got = []
    app = lambda do |env|
      got << env["rack.input"].read
      [200, {}, ["ok"]]
    end
    env = { "REQUEST_METHOD" => "POST", "PATH_INFO" => "/__camada/challenge", "rack.input" => StringIO.new(big) }
    _, _, body = described_class.new(app, engine).call(env)
    expect(body.to_enum(:each).to_a.join).to eq("ok")
    expect(got).to eq([big])
    env2 = { "REQUEST_METHOD" => "POST", "PATH_INFO" => "/__camada/challenge" } # Rack 3.1: rack.input may be absent
    expect(described_class.new(app, engine).call(env2)[0]).to eq(200)
  end

  it "closes the app body exactly once and fires on_finish once" do
    closes = []
    body_class = Class.new do
      define_method(:each) { |&blk| blk.call("ok") }
      define_method(:close) { closes << 1 }
    end
    app = ->(_env) { [200, {}, body_class.new] }
    status, headers, body = described_class.new(app, engine).call({ "REQUEST_METHOD" => "GET", "PATH_INFO" => "/", "REMOTE_ADDR" => "172.16.0.9" })
    expect(status).to eq(200)
    expect(headers["x-rid"]).to be_a(String)
    expect(body.to_enum(:each).to_a).to eq(["ok"])
    body.close # what a server does after iterating
    body.close
    expect(closes).to eq([1])
    engine.queue.flush
    expect(a.all_events.length).to eq(1)
    expect(a.all_events[0]["st"]).to eq(200)
  end

  it "passes to_path and call through the body proxy" do
    fired = []
    file_body = Class.new do
      define_method(:each) { |&blk| blk.call("f") }
      define_method(:to_path) { "/tmp/x" }
    end.new
    p1 = Camada::BodyProxy.new(file_body) { fired << :a }
    expect(p1.respond_to?(:to_path)).to be(true)
    expect(p1.to_path).to eq("/tmp/x")
    expect(p1.respond_to?(:call)).to be(false)
    streamed = []
    stream_body = ->(stream) { streamed << stream }
    p2 = Camada::BodyProxy.new(stream_body) { fired << :b }
    expect(p2.respond_to?(:call)).to be(true)
    p2.call(:stream)
    expect(streamed).to eq([:stream])
    p2.close
    expect(fired).to eq([:b])
    expect(p2.closed?).to be(true)
    plain = Camada::BodyProxy.new(%w[a b]) { fired << :c }
    expect(plain.respond_to?(:to_path)).to be(false)
    expect(plain.each.to_a).to eq(%w[a b])
  end

  it "fires on_finish with 500 and re-raises when the app raises" do
    app = ->(_env) { raise "boom" }
    expect { described_class.new(app, engine).call({ "REQUEST_METHOD" => "GET", "PATH_INFO" => "/x", "REMOTE_ADDR" => "172.16.0.9" }) }.to raise_error("boom")
    engine.queue.flush
    expect(a.all_events[0].values_at("p", "st")).to eq(["/x", 500])
  end

  it "runs the app untouched when its own request mapping raises" do
    weird = Object.new
    def weird.each = raise("env is not a hash")
    app = ->(_env) { [200, {}, ["app"]] }
    res = described_class.new(app, engine).call(weird)
    expect(res[0]).to eq(200)
    expect(res[2]).to eq(["app"])
  end

  it "wraps the default engine lazily" do
    Camada.reset!
    ENV["CAMADA_DISABLED"] = "1"
    ENV["CAMADA_KEY"] = "a.b"
    begin
      res = described_class.new(->(_env) { [200, {}, ["x"]] }).call({ "REQUEST_METHOD" => "GET", "PATH_INFO" => "/" })
      expect(res[2].to_enum(:each).to_a).to eq(["x"])
      expect(Camada.default.disabled?).to be(true)
    ensure
      ENV.delete("CAMADA_DISABLED")
      ENV.delete("CAMADA_KEY")
      Camada.reset!
    end
  end
end
