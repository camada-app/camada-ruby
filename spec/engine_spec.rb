# frozen_string_literal: true

require "json"
require "openssl"

# The engine through the Rack host: inline enforcement, ordered custom rules, the challenge,
# the first-party beacon, request capture, app-context events, and the fail-open envelope. The
# case list mirrors camada-python's test_engine.py (and through it camada-node's engine, rules
# and challenge suites).
RSpec.describe Camada::Engine do
  include ChallengeHelpers

  let(:a) { FakeAnalyst.new }
  let(:engines) { [] }

  after { engines.each(&:stop) }

  def site(*args, **kw) = Host::Site.new(a, engines, *args, **kw)
  def xff(addr) = { headers: [["x-forwarded-for", addr]] }
  def hops1 = a.config["trusted_proxy"] = { "mode" => "hops", "hops" => 1 }
  def nonce_of(page) = page.split('name="nonce" value="')[1].split('"')[0]

  describe "inline blocking" do
    it "answers 403 before the app and still ships the event" do
      h = site({ "CAMADA_TRUSTED_PROXY" => "hops:1" })
      r = h.call("GET", "/admin?x=1", **xff(FakeAnalyst::BLOCKED_IP))
      expect(r.status).to eq(403)
      expect(r.body).to eq("Forbidden")
      expect(r.header("x-block-reason")).to eq("ip4")
      expect(r.header("x-block-version")).to eq(a.meta["version"])
      expect(r.header("content-type")).to eq("text/plain")
      expect(r.header("x-block-rule")).to be_nil
      expect(r.header("content-length")).to eq("9")
      expect(h.seen).to eq([])
      ev, = h.events
      expect(ev.values_at("st", "blk", "ip", "p", "tap")).to eq([403, "ip4", FakeAnalyst::BLOCKED_IP, "/admin", "sdk-ruby"])
      expect(ev).not_to have_key("rl")
    end

    it "ignores a spoofed xff without trusted-proxy config" do
      h = site
      expect(h.call("GET", "/", **xff(FakeAnalyst::BLOCKED_IP)).status).to eq(200)
      expect(h.call("GET", "/", peer: FakeAnalyst::BLOCKED_IP).status).to eq(403)
    end

    it "applies the server-delivered trusted proxy when there is no local override" do
      hops1
      h = site
      expect(h.call("GET", "/", **xff(FakeAnalyst::BLOCKED_IP)).status).to eq(403)
    end

    it "fails open while cold" do
      a.snapshot_down = true
      h = site(load: false)
      expect(h.call("GET", "/", peer: FakeAnalyst::BLOCKED_IP).status).to eq(200)
      expect(h.seen[0]).to be_a(Hash)
    end

    it "honours the allow side over a wider block" do
      a.container = "v4"
      h = site
      expect(h.call("GET", "/", peer: "10.0.0.9").status).to eq(403)
      expect(h.call("GET", "/", peer: FakeAnalyst::ALLOWED_IP).status).to eq(200)
    end
  end

  describe "sdk identity" do
    it "sends x-camada-sdk on polls and batches" do
      h = site
      h.call("GET", "/")
      h.events
      expect(a.sdk_headers.uniq).to eq([Camada::SDK_ID])
      expect(a.sdk_headers.length).to be >= 2
    end

    it "asks for v5 by default and opts out at 3" do
      site
      site(snapshot_version: 3)
      expect(a.snapshot_versions[0, 2]).to eq(["5", ""])
    end
  end

  describe "capture" do
    it "captures on finish with status, latency, session and rid" do
      h = site(handler: ->(_env) { [201, { "x-app" => "1" }, ["made"]] })
      r = h.call("POST", "/things?q=1&token=secret", headers: [["user-agent", "UA/1"], ["accept", "*/*"]], body: "{}")
      expect(r.status).to eq(201)
      expect(r.body).to eq("made")
      expect(r.header("x-app")).to eq("1")
      rid = r.header("x-rid")
      expect(rid&.length).to eq(36)
      cookie = r.header("set-cookie")
      expect(cookie).to start_with("_sfp=")
      expect(cookie).to include("HttpOnly").and include("SameSite=Lax")
      expect(cookie).not_to include("Secure")
      ev, = h.events
      expect(ev["rid"]).to eq(rid)
      expect(ev["sid"]).to eq(cookie[5..].split(";")[0])
      expect(ev["ns"]).to eq(1)
      expect(ev["st"]).to eq(201)
      expect(ev["dur"]).to be_a(Integer).and be >= 0
      expect(ev.values_at("m", "p", "q", "ua")).to eq(["POST", "/things", "?q=1&token=~r", "UA/1"])
      expect(ev.values_at("ip", "proto", "h")).to eq([Host::PEER, "HTTP/1.1", "x.test"])
      expect(ev).not_to have_key("blk")
      expect(ev).not_to have_key("wrn")
    end

    it "reads Puma's binary env strings as UTF-8, so a stray byte neither escapes a rule nor costs the batch" do
      h = site
      binary = [["user-agent", "x\xff".b], ["accept", "*/*"]]
      expect(h.call("GET", "/", headers: binary, peer: FakeAnalyst::BLOCKED_IP).status).to eq(403)
      expect(h.call("GET", "/", headers: binary).status).to eq(200)
      evs = h.events
      expect(evs.map { |e| e.values_at("st", "ua") }).to eq([[403, "x\uFFFD"], [200, "x\uFFFD"]]) # both rows shipped, nothing dropped
      expect(h.engine.queue.dropped).to eq(0)
      info = Camada::Events::RequestInfo.new(method: "GET", host: "h", path: "/", query: "", headers: [["user-agent", "x\uFFFD"]])
      expect(Camada::Events.build_wire_event(info, tap: "t", rid: "r")["hb"]).to eq(10 + 4) # hb counts wire bytes (U+FFFD is three), as the collector does
    end

    it "reuses the session cookie and marks https secure" do
      h = site
      r = h.call("GET", "/", headers: [["cookie", "a=1; _sfp=sess-1; b=2"]], https: true)
      expect(r.header("set-cookie")).to be_nil
      r2 = h.call("GET", "/", https: true)
      expect(r2.header("set-cookie")).to include("; Secure")
      r3 = h.call("GET", "/", headers: [%w[x-forwarded-proto https]])
      expect(r3.header("set-cookie")).to include("; Secure")
      ev = h.events[0]
      expect([ev["sid"], ev["ns"]]).to eq(["sess-1", 0])
    end

    it "keeps the app's own cookies" do
      h = site(handler: ->(_env) { [200, { "set-cookie" => ["app=1; Path=/", "b=2"] }, [""]] })
      cookies = h.call("GET", "/").headers_named("set-cookie")
      expect(cookies.length).to eq(3)
      expect(cookies).to include("app=1; Path=/", "b=2")
      expect(cookies.any? { |c| c.start_with?("_sfp=") }).to be(true)
      h2 = site(handler: ->(_env) { [200, { "Set-Cookie" => "app=1" }, [""]] }) # a Rack 2 spelling: one key, joined
      cookies2 = h2.call("GET", "/").headers_named("set-cookie")
      expect(cookies2.length).to eq(2)
      expect(cookies2).to include("app=1")
    end

    it "honours exclude and sample and never captures credentials" do
      a.config["exclude"] = ["/health"]
      h = site
      h.call("GET", "/health/live")
      h.call("GET", "/api", headers: [["authorization", "Bearer very-secret"], ["cookie", "s=1; t=2"]])
      ev, = h.events
      expect(ev.values_at("p", "auth", "ck")).to eq(["/api", "Bearer", 2])
      expect(JSON.generate(ev)).not_to include("very-secret", "s=1")
      a.config["sample"] = 0
      h.engine.snap.refresh
      h.call("GET", "/api")
      expect(h.events.length).to eq(1)
    end

    it "exposes rid, sid and ip to the app" do
      h = site
      r = h.call("GET", "/")
      ctx = h.seen[0]["camada"]
      expect(ctx["rid"]).to eq(r.header("x-rid"))
      expect(ctx["ip"]).to eq(Host::PEER)
      expect(ctx["sid"]).to be_a(String)
    end

    it "ships st 500 and propagates when the app raises" do
      h = site(handler: ->(_env) { raise "app bug" })
      expect { h.call("GET", "/crash") }.to raise_error(RuntimeError, "app bug")
      ev, = h.events
      expect([ev["p"], ev["st"]]).to eq(["/crash", 500])
    end

    it "ships the route pattern the host names at finish" do
      h = site(handler: lambda { |env|
        env["sinatra.route"] = "GET /items/:id"
        [200, {}, ["x"]]
      })
      h.call("GET", "/items/7")
      expect(h.events[0]["rt"]).to eq("/items/:id")
    end
  end

  describe "track" do
    it "ships an app-context event with a hashed uid" do
      h = nil
      login = lambda do |env|
        h.engine.track(env["camada"], "login_failed", user: "alice@example.com")
        [401, {}, [""]]
      end
      h = site(handler: login)
      r = h.call("POST", "/login", body: "x=1")
      evs = h.events
      tracked = evs.find { |e| e["et"] }
      expect(tracked.values_at("et", "tap", "rid")).to eq(["login_failed", "sdk-ruby", r.header("x-rid")])
      expect(tracked["uid"]).to eq(OpenSSL::HMAC.hexdigest("SHA256", "tok-test", "uid:alice@example.com")[0, 32])
      expect(JSON.generate(evs)).not_to include("alice")
      expect(tracked["ip"]).to eq(Host::PEER)
      expect(tracked).not_to have_key("p")
    end

    it "tracks without a user and without context" do
      h = site
      h.engine.track(nil, "signup")
      ev, = h.events
      expect(ev.values_at("et", "uid", "rid")).to eq(["signup", nil, nil])
    end
  end

  describe "beacon" do
    it "serves the script and batches fp as a sig row with the resolved ip" do
      hops1
      h = site
      js = h.call("GET", "/_cam/b.js")
      expect(js.status).to eq(200)
      expect(js.header("content-type")).to eq("application/javascript")
      expect(js.header("cache-control")).to eq("public, max-age=3600")
      expect(js.body).to include("@camada/browser")
      body = JSON.generate({ "sdk" => "@camada/browser/0.2.0", "rid" => "r-1", "ip" => "9.9.9.9", "tap" => "proxy", "scr" => "1x1" })
      fp = h.call("POST", "/_cam/fp", headers: [["x-forwarded-for", "198.18.0.5"], ["content-type", "application/json"]], body: body)
      expect(fp.status).to eq(204)
      expect(fp.header("cache-control")).to eq("no-store")
      expect(h.seen).to eq([])
      row, = h.events
      expect(row.values_at("sig", "ip", "tap", "scr", "rid")).to eq([1, "198.18.0.5", "sdk-ruby", "1x1", "r-1"])
    end

    it "drops junk bodies instead of shipping them" do
      h = site
      ["not json", "[1,2]", "42", ""].each { |junk| expect(h.call("POST", "/_cam/fp", body: junk).status).to eq(204) }
      expect(h.events).to eq([])
    end

    it "rejects oversized posts, declared or actual" do
      h = site
      expect(h.call("POST", "/_cam/fp", body: "{}", content_length: 40_000).status).to eq(413)
      expect(h.call("POST", "/_cam/fp", body: "{#{" " * 33_000}}").status).to eq(413)
      expect(h.events).to eq([])
    end

    it "falls through to the app when the tenant disabled the beacon" do
      a.config["beacon"] = false
      h = site
      expect(h.call("GET", "/_cam/b.js").body).to eq("hello")
      expect(h.call("POST", "/_cam/fp", body: "{}").body).to eq("hello")
      expect(h.engine.script_tag(h.seen[0]["camada"])).to eq("")
    end

    it "carries the rid in the script tag" do
      h = site
      r = h.call("GET", "/")
      expect(h.engine.script_tag(h.seen[0]["camada"])).to eq(%(<script src="/_cam/b.js?r=#{r.header("x-rid")}" async></script>))
      expect(h.engine.script_tag(nil)).to eq('<script src="/_cam/b.js" async></script>')
    end

    it "enforces before the beacon endpoints" do
      h = site
      expect(h.call("GET", "/_cam/b.js", peer: FakeAnalyst::BLOCKED_IP).status).to eq(403)
    end

    it "moves with script_path and fp_path" do
      h = site(script_path: "/static/c.js", fp_path: "/static/fp")
      expect(h.call("GET", "/static/c.js").header("content-type")).to eq("application/javascript")
      expect(h.call("GET", "/_cam/b.js").body).to eq("hello")
      expect(h.call("POST", "/static/fp", body: "{}").status).to eq(204)
      expect(h.engine.script_tag(nil)).to eq('<script src="/static/c.js" async></script>')
    end
  end

  describe "rules" do
    before do
      a.container = "v5"
      hops1
    end

    it "lets a skip rule beat the wider block" do
      h = site
      expect(h.call("GET", FakeAnalyst::SKIP_PATH, **xff(FakeAnalyst::BLOCKED_IP)).status).to eq(200)
      ev, = h.events
      expect(ev).not_to have_key("blk")
      expect(ev).not_to have_key("wrn")
    end

    it "blocks by rule with x-block-rule and ships rl" do
      h = site
      r = h.call("GET", "/", **xff(FakeAnalyst::RULE_BLOCKED_IP))
      expect(r.status).to eq(403)
      expect(r.header("x-block-reason")).to eq("rule")
      expect(r.header("x-block-rule")).to eq("builtin:block")
      ev, = h.events
      expect(ev.values_at("blk", "rl")).to eq(["rule", "builtin:block"])
    end

    it "blocks by path, ua and header rules" do
      h = site
      expect(h.call("GET", FakeAnalyst::RULE_BLOCKED_PATH).header("x-block-rule")).to eq("cr_00000000000c")
      expect(h.call("GET", "/", headers: [["user-agent", FakeAnalyst::BLOCKED_UA]]).status).to eq(403)
      expect(h.call("GET", "/", headers: [[FakeAnalyst::BLOCKED_HEADER.upcase, FakeAnalyst::BLOCKED_HEADER_VALUE]]).status).to eq(403) # any spelling
      expect(h.call("GET", "/", headers: [[FakeAnalyst::BLOCKED_HEADER, "other"]]).status).to eq(200)
      expect(h.call("GET", "/").status).to eq(200)
    end

    it "passes on warn and stamps wrn" do
      h = site
      expect(h.call("GET", "/", headers: [["user-agent", FakeAnalyst::WARN_UA]]).status).to eq(200)
      ev, = h.events
      expect(ev.values_at("wrn", "st")).to eq(["cr_00000000000e", 200])
    end

    it "still enforces against an analyst that only publishes v3" do
      a.container = "v3"
      h = site
      expect(h.call("GET", "/", **xff(FakeAnalyst::BLOCKED_IP)).status).to eq(403)
      expect(h.call("GET", "/", headers: [["user-agent", FakeAnalyst::BLOCKED_UA]]).status).to eq(200) # a rule-only signal: v3 carries no rules
    end
  end

  describe "challenge" do
    let(:challenged) { FakeAnalyst::CHALLENGED_IP }

    before { a.container = "v4" }

    it "serves the page for an html navigation and ships blk challenge" do
      h = site
      r = h.call("GET", "/account?tab=1", headers: Host::HTML, peer: challenged)
      expect(r.status).to eq(403)
      expect(r.header("content-type")).to eq("text/html; charset=utf-8")
      expect(r.header("x-camada-challenge")).to eq("1")
      expect(r.header("cache-control")).to eq("no-store")
      expect(r.body).to include('action="/__camada/challenge"', 'name="to" value="/account?tab=1"')
      expect(h.seen).to eq([])
      ev, = h.events
      expect(ev.values_at("st", "blk", "p")).to eq([403, "challenge", "/account"])
    end

    it "answers json for a non-html request" do
      h = site
      r = h.call("GET", "/api", headers: [["accept", "application/json"]], peer: challenged)
      expect(r.status).to eq(403)
      expect(r.header("content-type")).to eq("application/json")
      expect(JSON.parse(r.body)).to eq({ "error" => "challenge_required" })
      r2 = h.call("GET", "/api", headers: [["accept", "text/html"], ["sec-fetch-dest", "empty"]], peer: challenged)
      expect(r2.header("content-type")).to eq("application/json")
    end

    it "blocks outright rather than challenging a blocked ip" do
      h = site
      r = h.call("GET", "/", headers: Host::HTML, peer: FakeAnalyst::BLOCKED_IP)
      expect(r.status).to eq(403)
      expect(r.header("x-camada-challenge")).to be_nil
    end

    it "verifies, sets _cch, redirects back and ships ch 1" do
      h = site
      nonce = nonce_of(h.call("GET", "/back?x=1", headers: Host::HTML, peer: challenged).body)
      form = "nonce=#{nonce}&solution=#{solve(nonce)}&to=%2Fback%3Fx%3D1"
      r = h.call("POST", "/__camada/challenge", headers: [["content-type", "application/x-www-form-urlencoded"]], body: form, peer: challenged)
      expect(r.status).to eq(302)
      expect(r.header("location")).to eq("/back?x=1")
      expect(r.header("cache-control")).to eq("no-store")
      cookie = r.header("set-cookie") || ""
      expect(cookie).to start_with("_cch=")
      expect(cookie).to include("HttpOnly")
      evs = h.events
      expect(evs[-1].values_at("st", "ch", "p")).to eq([200, 1, "/__camada/challenge"])
      # the holder of a valid _cch passes; a cookie minted for another ip does not
      pair = cookie.split(";")[0]
      expect(h.call("GET", "/back", headers: [*Host::HTML, ["cookie", pair]], peer: challenged).status).to eq(200)
      expect(h.call("GET", "/back", headers: [*Host::HTML, ["cookie", pair]], peer: "192.0.2.21").status).to eq(200) # not challenged at all
      forged = "_cch=#{pair[5..].sub("0", "1")}"
      expect(h.call("GET", "/back", headers: [*Host::HTML, ["cookie", forged]], peer: challenged).status).to eq(403)
    end

    it "re-serves the page on a wrong solution or a forged nonce" do
      h = site
      nonce = nonce_of(h.call("GET", "/", headers: Host::HTML, peer: challenged).body)
      r = h.call("POST", "/__camada/challenge", body: "nonce=#{nonce}&solution=1&to=%2F", peer: challenged)
      expect(r.status).to eq(403)
      expect(r.header("set-cookie")).to be_nil
      expect(r.body).to include("camada-f")
      forged = "f" * 32
      r = h.call("POST", "/__camada/challenge", body: "nonce=#{forged}&solution=#{solve(forged)}&to=%2F", peer: challenged)
      expect(r.status).to eq(403)
      expect(r.header("set-cookie")).to be_nil
    end

    it "never redirects off site" do
      h = site
      nonce = h.engine.kit.nonce(challenged, h.engine.now_ms)
      r = h.call("POST", "/__camada/challenge", body: "nonce=#{nonce}&solution=#{solve(nonce)}&to=https%3A%2F%2Fevil", peer: challenged)
      expect(r.status).to eq(302)
      expect(r.header("location")).to eq("/")
    end

    it "refuses an oversized verify body" do
      h = site
      expect(h.call("POST", "/__camada/challenge", body: "a=#{"b" * 5000}", peer: challenged).status).to eq(413)
    end

    it "serves no challenge without an ip" do
      h = site
      expect(h.call("GET", "/", headers: Host::HTML, peer: nil).status).to eq(200)
    end

    it "is switched off by env or option" do
      expect(site({ "CAMADA_CHALLENGE" => "0" }).call("GET", "/", headers: Host::HTML, peer: challenged).status).to eq(200)
      expect(site(challenge: false).call("GET", "/", headers: Host::HTML, peer: challenged).status).to eq(200)
    end

    it "serves the challenge on demand" do
      h = nil
      gated = lambda do |env|
        answer = h.engine.serve_challenge(env["camada"])
        answer ? [answer.status, answer.headers, [answer.body]] : [200, {}, ["secret page"]]
      end
      h = site(handler: gated)
      r = h.call("GET", "/challenge-me", headers: Host::HTML)
      expect(r.status).to eq(403)
      expect(r.body).to include("camada-f")
      evs = h.events
      expect(evs.length).to eq(1)
      expect(evs[0]["blk"]).to eq("challenge") # one request, one event
      nonce = nonce_of(r.body)
      ok = h.call("POST", "/__camada/challenge", body: "nonce=#{nonce}&solution=#{solve(nonce)}&to=%2Fchallenge-me")
      cookie = (ok.header("set-cookie") || "").split(";")[0]
      expect(h.call("GET", "/challenge-me", headers: [*Host::HTML, ["cookie", cookie]]).body).to eq("secret page")
    end

    it "moves with challenge_path" do
      h = site(challenge_path: "/verify")
      r = h.call("GET", "/", headers: Host::HTML, peer: challenged)
      expect(r.body).to include('action="/verify"')
      nonce = nonce_of(r.body)
      expect(h.call("POST", "/verify", body: "nonce=#{nonce}&solution=#{solve(nonce)}&to=%2F", peer: challenged).status).to eq(302)
      expect(h.call("POST", "/__camada/challenge", body: "x=1", peer: challenged).status).to eq(403) # the old path is just a challenged request now
    end
  end

  describe "fail open" do
    it "keeps serving when ingest is down" do
      a.ingest_down = true
      h = site
      expect(h.call("GET", "/").status).to eq(200)
      expect(h.events).to eq([])
      expect(h.engine.queue.dropped).to eq(1)
    end

    it "bypasses the SDK entirely when disabled" do
      h = site({ "CAMADA_DISABLED" => "1" }, load: false)
      expect(h.engine.snap).to be_nil
      expect(h.engine.disabled?).to be(true)
      r = h.call("GET", "/", peer: FakeAnalyst::BLOCKED_IP)
      expect(r.status).to eq(200)
      expect(r.header("x-rid")).to be_nil
      expect(a.snapshot_requests).to eq([])
    end

    it "honours the kill switch per request" do
      env = Host::ENV_BASE.dup
      h = site
      h.engine.instance_variable_set(:@env_source, env) # the live ENV in production
      expect(h.call("GET", "/", peer: FakeAnalyst::BLOCKED_IP).status).to eq(403)
      env["CAMADA_DISABLED"] = "1"
      r = h.call("GET", "/", peer: FakeAnalyst::BLOCKED_IP)
      expect(r.status).to eq(200)
      expect(r.header("x-rid")).to be_nil
      expect(h.engine.wants_body("POST", "/_cam/fp")).to be_nil
    end

    it "stays inert without credentials" do
      h = site({ "CAMADA_KEY" => "" }, load: false)
      expect(h.engine.env).to be_nil
      expect(h.call("GET", "/", peer: FakeAnalyst::BLOCKED_IP).status).to eq(200)
      expect(h.engine.script_tag(nil)).to eq("")
      expect(h.engine.serve_challenge(nil)).to be_nil
      expect { h.engine.track(nil, "x") }.not_to raise_error
    end

    it "costs a camada bug the join, not the request" do
      h = site
      h.engine.define_singleton_method(:decide) { |*_a| raise "sdk bug" }
      r = h.call("GET", "/", peer: FakeAnalyst::BLOCKED_IP)
      expect(r.status).to eq(200)
      expect(r.body).to eq("hello")
    end

    it "logs at most one line a minute" do
      lines = []
      Camada::Guarded.logger = ->(s) { lines << s }
      Camada::Guarded.instance_variable_set(:@last_log, nil)
      begin
        Camada::Guarded.log_rate_limited(RuntimeError.new("one\ntwo"))
        Camada::Guarded.log_rate_limited("two")
      ensure
        Camada::Guarded.logger = nil
      end
      expect(lines).to eq(["[camada] suppressed error (SDK fails open): RuntimeError: one two"])
      expect(lines[0]).not_to match(/\n\s+from .*:\d+:in |\((?:[A-Z]\w*Error|\w+Exception)\)/)
    end
  end

  describe "wants_body" do
    it "names the cap for the endpoints camada may answer" do
      h = site
      expect(h.engine.wants_body("POST", "/_cam/fp")).to eq(Camada::FP_MAX)
      expect(h.engine.wants_body("POST", "/__camada/challenge")).to eq(Camada::BODY_MAX)
      expect(h.engine.wants_body("GET", "/_cam/fp")).to be_nil
      expect(h.engine.wants_body("POST", "/login")).to be_nil
      expect(site(challenge: false).engine.wants_body("POST", "/__camada/challenge")).to be_nil
    end
  end

  it "warms up the way the README says: wait on verdict until it is not cold" do
    Camada.reset!
    engine = Camada.default(env: Host::ENV_BASE, transport: a)
    begin
      expect(engine.snap).not_to be_nil
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
      probe = Camada::Snapshot::MatchInput.new(ip: "0.0.0.0")
      sleep 0.01 while engine.snap.verdict(probe).reason == "cold" && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      expect(engine.snap.verdict(Camada::Snapshot::MatchInput.new(ip: FakeAnalyst::BLOCKED_IP)).block).to be(true)
    ensure
      Camada.reset!
    end
  end
end
