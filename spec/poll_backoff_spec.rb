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
          expect(c.due?).to eq(st["poll"]), label
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

    it "does not poll when it is no longer due after taking the slot" do
      a = FakeAnalyst.new
      c = client(a, refresh_s: 30)
      c.refresh
      n = a.snapshot_requests.size
      allow(c).to receive(:due?).and_return(true, false) # due when kicked, fresh once the slot is taken
      c.ensure_fresh
      Thread.list.select { |t| t.name == "camada-snapshot-load" }.each { |t| t.join(5) }
      expect(a.snapshot_requests.size).to eq(n)
    end
  end
end
