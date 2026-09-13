# frozen_string_literal: true

require "socket"

# SnapshotClient: the single-tenant port of the edge collector's snapshot lifecycle over the
# GET /snapshot contract (200 frame + etag + x-camada-config; 304 unchanged; 204 nothing
# published -> enforce nothing). Cold = fail open; any error keeps the previous snapshot.
RSpec.describe Camada::Snapshot::Client do
  url = "https://analyst.test/snapshot"
  blocked = FakeAnalyst::BLOCKED_IP

  def client(a, **kw)
    described_class.new("https://analyst.test/snapshot", "snap-test", transport: a, sdk: "@camada/ruby/0.0.0", mode: :lazy, **kw)
  end

  def input(ip) = Camada::Snapshot::MatchInput.new(ip: ip)

  it "fails open while cold" do
    v = client(FakeAnalyst.new).verdict(input(blocked))
    expect(v.reason).to eq("cold")
    expect([v.block, v.challenge, v.allowed]).to eq([false, false, false])
  end

  it "loads and enforces with the contract headers" do
    a = FakeAnalyst.new
    c = client(a)
    c.refresh
    expect(c.verdict(input(blocked)).block).to be(true)
    req = a.snapshot_requests[0]
    expect(req.method).to eq("GET")
    expect(req.url).to eq(url)
    expect(req.headers["authorization"]).to eq("Bearer snap-test")
    expect(req.headers["x-camada-sdk"]).to eq("@camada/ruby/0.0.0")
    expect(req.headers["x-camada-snapshot"]).to eq("5")
    expect(req.headers).not_to have_key("if-none-match")
    expect(c.config).to eq(a.config)
  end

  it "repeats the config on 304 and keeps the snapshot" do
    a = FakeAnalyst.new
    c = client(a)
    c.refresh
    a.config = a.config.merge("beacon" => false)
    c.refresh
    expect(a.snapshot_requests[1].headers["if-none-match"]).to eq(a.etag)
    expect(c.verdict(input(blocked)).block).to be(true)
    expect(c.config["beacon"]).to be(false)
  end

  it "reads 204 as nothing published, not cold" do
    a = FakeAnalyst.new
    a.snapshot_status = 204
    c = client(a)
    c.refresh
    v = c.verdict(input(blocked))
    expect(v.reason).to be_nil
    expect(v.block).to be(false)
  end

  it "keeps what it has on errors" do
    a = FakeAnalyst.new
    c = client(a)
    c.refresh
    [401, 500].each do |status|
      a.snapshot_status = status
      c.refresh
      expect(c.verdict(input(blocked)).block).to be(true)
    end
    a.snapshot_status = nil
    a.snapshot_down = true
    c.refresh
    expect(c.verdict(input(blocked)).block).to be(true)
  end

  it "keeps the previous snapshot on a corrupt body" do
    a = FakeAnalyst.new
    c = client(a)
    c.refresh
    corrupt = lambda do |req|
      r = a.call(req)
      Camada::HttpResponse.new(status: 200, headers: r.headers.merge("etag" => '"other"'), body: "\x05\x00\x00\x00junk!#{"\x00" * 10}".b)
    end
    c.transport = corrupt
    c.refresh
    expect(c.verdict(input(blocked)).block).to be(true)
    c.transport = ->(_req) { Camada::HttpResponse.new(status: 200, headers: { "etag" => '"t"' }, body: "\x01".b) } # truncated frame
    c.refresh
    expect(c.verdict(input(blocked)).block).to be(true)
  end

  it "re-parses the same version under a new etag" do
    # the server ships v3/v4/v5 bodies of one publish under the same meta.version and different etags
    a = FakeAnalyst.new
    c = client(a)
    c.refresh
    expect(c.verdict(input("192.0.2.20")).challenge).to be(false) # v3 has no challenge side
    a.container = "v4"
    c.refresh
    expect(c.verdict(input("192.0.2.20")).challenge).to be(true)
  end

  it "sends the snapshot version the option names" do
    a = FakeAnalyst.new
    client(a, snapshot_version: 4).refresh
    client(a, snapshot_version: 3).refresh
    expect(a.snapshot_versions).to eq(["4", ""])
  end

  it "lets the server steer the cadence unless pinned" do
    a = FakeAnalyst.new
    a.config = a.config.merge("poll_seconds" => 7)
    c = client(a)
    c.refresh
    expect(c.refresh_s).to eq(7)
    a.config = a.config.merge("poll_seconds" => 1) # below the 5 s floor: ignored
    c.refresh
    expect(c.refresh_s).to eq(7)
    a.config = a.config.merge("poll_seconds" => "x")
    c.refresh
    expect(c.refresh_s).to eq(7)
    pinned = client(a, refresh_s: 11)
    pinned.refresh
    expect(pinned.refresh_s).to eq(11)
  end

  it "ignores a malformed config header and keeps the previous one" do
    a = FakeAnalyst.new
    c = client(a)
    c.refresh
    good = a.call(Camada::HttpRequest.new(method: "GET", url: url, headers: {}, body: nil, timeout_s: 1))
    c.transport = ->(_req) { Camada::HttpResponse.new(status: 304, headers: { "x-camada-config" => "{not json" }, body: "".b) }
    c.refresh
    expect(c.config).to eq(a.config)
    c.transport = ->(_req) { Camada::HttpResponse.new(status: 304, headers: { "x-camada-config" => "[1]" }, body: "".b) }
    c.refresh
    expect(c.config).to eq(a.config)
    expect(good.status).to eq(200)
  end

  it "refreshes off the request path, single in flight" do
    a = FakeAnalyst.new
    c = client(a)
    c.ensure_fresh
    c.ensure_fresh
    Host.wait_until { c.verdict(input("0.0.0.0")).reason != "cold" }
    expect(c.verdict(input(blocked)).block).to be(true)
    expect(a.snapshot_requests.length).to eq(1)
    c.ensure_fresh # fresh: no new poll
    sleep 0.02
    expect(a.snapshot_requests.length).to eq(1)
  end

  it "polls on its own in timer mode and stops" do
    a = FakeAnalyst.new
    c = described_class.new(url, "snap-test", transport: a, mode: :timer, refresh_s: 0.02)
    c.start
    begin
      Host.wait_until { a.snapshot_requests.length >= 3 }
    ensure
      c.stop
    end
    n = a.snapshot_requests.length
    sleep 0.05
    expect(a.snapshot_requests.length).to eq(n)
  end

  it "re-arms the timer after a fork" do
    a = FakeAnalyst.new
    c = described_class.new(url, "snap-test", transport: a, mode: :timer, refresh_s: 0.02)
    c.start
    c.stop
    n = a.snapshot_requests.length
    c.after_fork! # the child's copy: no thread, then a fresh one polling on its own
    begin
      Host.wait_until { a.snapshot_requests.length >= n + 2 }
    ensure
      c.stop
    end
  end

  it "ignores a non-finite poll_seconds" do
    a = FakeAnalyst.new
    c = client(a)
    before = c.refresh_s
    c.transport = ->(_req) { Camada::HttpResponse.new(status: 304, headers: { "x-camada-config" => '{"poll_seconds": 1e999}' }, body: "".b) }
    c.refresh
    expect(c.refresh_s).to eq(before)
  end

  it "asks for gzip and reads a frame the analyst compressed" do
    a = FakeAnalyst.new
    a.gzip = true
    c = client(a)
    c.refresh
    expect(a.snapshot_requests[0].headers["accept-encoding"]).to eq("gzip")
    expect(c.verdict(input(blocked)).block).to be(true)
  end

  describe "the Net::HTTP transport" do
    # A one-shot HTTP/1.1 server on a loopback port: answers every request with `body` gzipped.
    def serve_once(body, gz: true)
      srv = TCPServer.new("127.0.0.1", 0)
      port = srv.addr[1]
      seen = +""
      t = Thread.new do
        sock = srv.accept
        seen << sock.readpartial(65_536) # the request head (and small body)
        payload = gz ? FakeAnalyst.gzip_bytes(body) : body
        encoding = gz ? "content-encoding: gzip\r\n" : ""
        head = "HTTP/1.1 200 OK\r\ncontent-length: #{payload.bytesize}\r\netag: \"z\"\r\n#{encoding}connection: close\r\n\r\n"
        sock.write(head + payload)
        sock.close
      end
      [port, seen, t, srv]
    end

    it "gunzips and never raises" do
      payload = FakeAnalyst.frame({ "version" => "z" }, "BLK".b)
      port, seen, t, srv = serve_once(payload)
      begin
        r = Camada::Transport.net_http(Camada::HttpRequest.new(method: "GET", url: "http://127.0.0.1:#{port}/snapshot", headers: { "accept-encoding" => "gzip", "x-camada-sdk" => "s" }, body: nil, timeout_s: 2.0))
        t.join(2)
      ensure
        srv.close
      end
      expect(r.status).to eq(200)
      expect(r.body).to eq(payload)
      expect(r.headers["etag"]).to eq('"z"')
      expect(r.headers).not_to have_key("content-encoding")
      expect(seen).to match(/^x-camada-sdk: s\r$/i)
      expect(seen).to match(/^accept-encoding: .*gzip/i)
      dead = Camada::Transport.net_http(Camada::HttpRequest.new(method: "GET", url: "http://127.0.0.1:1/snapshot", headers: {}, body: nil, timeout_s: 0.2))
      expect(dead.status).to eq(0)
      junk = Camada::Transport.net_http(Camada::HttpRequest.new(method: "GET", url: "not a url", headers: {}, body: nil, timeout_s: 0.2))
      expect(junk.status).to eq(0)
    end

    it "posts a body and reads a plain answer" do
      port, seen, t, srv = serve_once("ok".b, gz: false)
      begin
        r = Camada::Transport.net_http(Camada::HttpRequest.new(method: "POST", url: "http://127.0.0.1:#{port}/e", headers: { "content-type" => "application/json" }, body: "[1]", timeout_s: 2.0))
        t.join(2)
      ensure
        srv.close
      end
      expect(r.status).to eq(200)
      expect(r.body).to eq("ok")
      expect(seen).to start_with("POST /e HTTP/1.1")
      expect(seen).to end_with("[1]")
    end
  end
end
