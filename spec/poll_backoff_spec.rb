# frozen_string_literal: true

# Snapshot poll pacing (camada-all-pbv9): a failed poll keeps the blocks and gates the next
# self-initiated poll. Driven by camada-core's test/fixtures/poll/backoff.json; fails by name when
# the fixture is missing, never skips.
RSpec.describe "snapshot poll pacing" do
  fx = Fixtures.read_json("poll/backoff.json")
  blocked_ip = fx["blockedIp"]

  def input(ip) = Camada::Snapshot::MatchInput.new(ip: ip)

  describe "next_poll_delay" do
    fx["delay"].each do |c|
      it c["name"] do
        got = Camada::Snapshot.next_poll_delay(c["status"], c["retryAfter"], c["refreshSeconds"])
        if c["expectDelaySeconds"].nil?
          expect(got).to be_nil
        else
          expect(got).to be_within(1e-9).of(c["expectDelaySeconds"])
        end
      end
    end
  end

  describe "timelines" do
    fx["timelines"].each do |tl|
      it tl["name"] do
        a = FakeAnalyst.new
        c = Camada::Snapshot::Client.new("https://analyst.test/snapshot", "snap-test", transport: a, mode: :lazy,
                                                                                       refresh_s: tl["refreshSeconds"])
        now = tl["clockBase"].to_f
        allow(c).to receive(:monotonic) { now }
        tl["steps"].each do |st|
          now = tl["clockBase"] + st["t"]
          label = "#{tl["name"]} @ t=#{st["t"]}"
          expect(c.send(:due?)).to eq(st["poll"]), label
          next unless st["poll"]

          r = st["respond"]
          a.snapshot_down = r["status"].zero?
          a.snapshot_status = [0, 200].include?(r["status"]) ? nil : r["status"]
          a.snapshot_retry_after = r["retryAfter"]
          c.refresh
          v = c.verdict(input(blocked_ip))
          expect(v.reason == "cold").to eq(st["after"]["cold"]), "#{label} cold"
          expect(v.block).to eq(st["after"]["blocked"]), "#{label} blocked"
        end
      end
    end
  end

  describe "background kick" do
    def client(a, **kw)
      Camada::Snapshot::Client.new("https://analyst.test/snapshot", "snap-test", transport: a, mode: :lazy, **kw)
    end

    def join_loads = Thread.list.select { |t| t.name == "camada-snapshot-load" }.each { |t| t.join(5) }

    it "does not poll when it is stale but gated once the slot is taken" do
      a = FakeAnalyst.new
      c = client(a, refresh_s: 60)
      now = 1000.0
      allow(c).to receive(:monotonic) { now }
      c.refresh
      now += 100 # stale
      a.snapshot_status = 503
      a.snapshot_retry_after = "30"
      c.refresh # gates the next poll until now + 30
      n = a.snapshot_requests.size
      expect(c.stale?).to be(true)
      expect(c.send(:due?)).to be(false)
      c.send(:refresh_if_due) # what the kick runs after taking the slot
      expect(a.snapshot_requests.size).to eq(n)
    end

    it "the request path honours a closed gate" do
      a = FakeAnalyst.new
      c = client(a, refresh_s: 60)
      now = 1000.0
      allow(c).to receive(:monotonic) { now }
      c.refresh
      now += 100 # stale
      a.snapshot_status = 503
      a.snapshot_retry_after = "30"
      n = a.snapshot_requests.size
      6.times do
        c.ensure_fresh
        join_loads
      end
      expect(a.snapshot_requests.size).to eq(n + 1)
      now += 30
      c.ensure_fresh
      join_loads
      expect(a.snapshot_requests.size).to eq(n + 2)
    end
  end

  describe "a transport that raises" do
    it "is logged (rate-limited) and still gated as status 0" do
      lines = []
      Camada::Guarded.logger = ->(s) { lines << s }
      Camada::Guarded.instance_variable_set(:@last_log, nil)
      calls = 0
      boom = lambda do |_req|
        calls += 1
        raise IOError, "socket exploded"
      end
      c = Camada::Snapshot::Client.new("https://analyst.test/snapshot", "snap-test", transport: boom, mode: :lazy,
                                                                                     refresh_s: 60)
      now = 1000.0
      allow(c).to receive(:monotonic) { now }
      begin
        c.refresh
        c.send(:refresh_if_due)
        c.refresh # forced polls: a second log line is rate-limited away
      ensure
        Camada::Guarded.logger = nil
      end
      expect(lines.size).to eq(1)
      expect(lines[0]).to include("IOError: socket exploded")
      expect(c.verdict(Camada::Snapshot::MatchInput.new(ip: "1.1.1.1")).reason).to eq("cold")
      expect(c.send(:due?)).to be(false) # gated
      expect(calls).to eq(2) # refresh + refresh (refresh_if_due was gated, did not call)
    end
  end

  describe "an unreadable gzip body" do
    it "is no answer: status 0 and no headers, so retry-after is not honoured" do
      r = Camada::Transport.response(503, { "content-encoding" => "gzip", "retry-after" => "30" }, "not gzip".b)
      expect(r.status).to eq(0)
      expect(r.headers).to eq({})
    end
  end

  describe "an empty body that still carries content-encoding gzip" do
    it "keeps a 304 with its headers (never decoded)" do
      r = Camada::Transport.response(304, { "content-encoding" => "gzip", "etag" => '"x"' }, "".b)
      expect(r.status).to eq(304)
      expect(r.headers["etag"]).to eq('"x"')
    end

    it "does not close the gate on a warm client" do
      a = FakeAnalyst.new
      gz304 = lambda do |req|
        r = a.call(req)
        next r unless r.status == 304

        Camada::Transport.response(304, r.headers.merge("content-encoding" => "gzip"), "".b)
      end
      c = Camada::Snapshot::Client.new("https://analyst.test/snapshot", "snap-test", transport: gz304, mode: :lazy,
                                                                                     refresh_s: 30)
      now = 1000.0
      allow(c).to receive(:monotonic) { now }
      c.refresh
      now = 1028.0
      c.refresh # healthy 304
      expect(c.send(:due?)).to be(false)
      now = 1034.0
      expect(c.send(:due?)).to be(false) # a failed poll (5 s gate, still stale) would be due by now
    end
  end
end
