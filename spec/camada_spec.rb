# frozen_string_literal: true

# The module-level helpers apps call from a route: script_tag(env), track(env, ...),
# serve_challenge(env), and the lazy default engine the middleware shares.
RSpec.describe Camada do
  let(:a) { FakeAnalyst.new }

  after { described_class.reset! }

  it "builds one default engine from the environment and replaces it on configure" do
    described_class.reset!
    e1 = described_class.default(env: Host::ENV_BASE, transport: a)
    expect(described_class.default).to be(e1)
    e2 = described_class.configure(env: Host::ENV_BASE.merge("CAMADA_DISABLED" => "1"), transport: a)
    expect(e2).not_to be(e1)
    expect(described_class.default).to be(e2)
    expect(e2.disabled?).to be(true)
  end

  it "logs once when the key is missing and stays inert" do
    lines = []
    Camada::Guarded.logger = ->(s) { lines << s }
    Camada::Guarded.instance_variable_set(:@last_log, nil)
    begin
      e = described_class.configure(env: {}, transport: a)
      expect(e.env).to be_nil
      expect(lines.length).to eq(1)
      expect(lines[0]).to include("CAMADA_KEY")
    ensure
      Camada::Guarded.logger = nil
    end
  end

  it "resolves the helpers through the engine that produced the context" do
    engine = described_class.configure(env: Host::ENV_BASE, transport: a)
    Host.loaded(engine)
    drv = Host::RackDriver.new(engine)
    r = drv.call(Host::Call.new(method: "GET", path: "/", headers: [], body: "", peer: Host::PEER))
    env = drv.seen[0]
    expect(described_class.engine_for(env["camada"])).to be(engine)
    expect(described_class.engine_for(nil)).to be(engine)
    expect(described_class.script_tag(env)).to eq(%(<script src="/_cam/b.js?r=#{r.header("x-rid")}" async></script>))
    described_class.track(env, "login_failed", user: "bob")
    expect(described_class.serve_challenge(env)[0]).to eq(403) # the peer resolved to an ip, so the page comes back as a triple
  end

  it "serves the challenge as a rack triple and tracks by env" do
    engine = described_class.configure(env: Host::ENV_BASE, transport: a)
    Host.loaded(engine)
    drv = Host::RackDriver.new(engine, lambda { |env|
      answer = described_class.serve_challenge(env)
      answer || [200, {}, ["file"]]
    })
    r = drv.call(Host::Call.new(method: "GET", path: "/export", headers: Host::HTML, body: "", peer: Host::PEER))
    expect(r.status).to eq(403)
    expect(r.header("x-camada-challenge")).to eq("1")
    expect(r.header("content-type")).to start_with("text/html")
    cookie = engine.kit.issue(Host::PEER, engine.now_ms)
    r2 = drv.call(Host::Call.new(method: "GET", path: "/export", headers: [*Host::HTML, ["cookie", "_cch=#{cookie}"]], body: "", peer: Host::PEER))
    expect(r2.body).to eq("file")
    described_class.track(drv.seen[-1], "signup", user: "x")
    engine.queue.flush
    expect(a.all_events.map { |e| [e["st"], e["blk"], e["et"]] }).to eq([[403, "challenge", nil], [200, nil, nil], [nil, nil, "signup"]])
  end

  it "stands down silently without a context or an engine" do
    described_class.configure(env: { "CAMADA_DISABLED" => "1", "CAMADA_KEY" => "a.b" }, transport: a)
    expect(described_class.script_tag({})).to eq("")
    expect(described_class.serve_challenge({})).to be_nil
    expect { described_class.track({}, "x", user: nil) }.not_to raise_error
    expect { described_class.track(nil, "x") }.not_to raise_error
  end
end
