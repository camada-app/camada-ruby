# frozen_string_literal: true

# EventQueue: fire-and-forget batched shipping to POST /e. Nothing here may ever raise into the
# customer's request path, and a dead ingest must cost nothing but dropped telemetry.
RSpec.describe Camada::Events::Queue do
  def queue(a, **kw) = described_class.new("https://analyst.test", "tok-test", transport: a, sdk: "@camada/ruby/0.0.0", **kw)

  def wait_until(seconds = 2)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    until yield
      raise "condition never met" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.005
    end
  end

  it "posts a JSON array with the tenant and sdk headers" do
    a = FakeAnalyst.new
    seen = []
    spy = lambda do |req|
      seen << req
      a.call(req)
    end
    q = queue(spy)
    q.push({ "p" => "/" })
    q.flush
    expect(a.events).to eq([[{ "p" => "/" }]])
    expect(a.sdk_headers).to eq(["@camada/ruby/0.0.0"])
    expect(seen[0].method).to eq("POST")
    expect(seen[0].url).to eq("https://analyst.test/e")
    expect(seen[0].headers).to include("x-tenant" => "tok-test", "content-type" => "application/json")
    expect(seen[0].timeout_s).to eq(2.0)
  end

  it "flushes when the batch size is reached" do
    a = FakeAnalyst.new
    q = queue(a, max_batch: 3, flush_s: 60)
    3.times { |i| q.push({ "i" => i }) }
    wait_until { !a.events.empty? }
    expect(a.events).to eq([[{ "i" => 0 }, { "i" => 1 }, { "i" => 2 }]])
    q.stop
  end

  it "flushes on the interval" do
    a = FakeAnalyst.new
    q = queue(a, flush_s: 0.02)
    q.push({ "i" => 1 })
    wait_until { !a.events.empty? }
    expect(a.events).to eq([[{ "i" => 1 }]])
    q.stop
  end

  it "drains in slices of 1000" do
    a = FakeAnalyst.new
    q = queue(a, max_batch: 5000, max_queue: 5000)
    1500.times { |i| q.push({ "i" => i }) }
    q.flush
    expect(a.events.map(&:length)).to eq([1000, 500])
    q.stop
  end

  it "drops the oldest beyond the queue cap" do
    a = FakeAnalyst.new
    q = queue(a, max_queue: 3, max_batch: 100, flush_s: 60)
    5.times { |i| q.push({ "i" => i }) }
    expect(q.size).to eq(3)
    expect(q.dropped).to eq(2)
    q.flush
    expect(a.events).to eq([[{ "i" => 2 }, { "i" => 3 }, { "i" => 4 }]])
    q.stop
  end

  it "drops silently on a dead ingest and recovers" do
    a = FakeAnalyst.new
    a.ingest_down = true
    q = queue(a)
    q.push({ "i" => 1 })
    q.flush
    expect(q.dropped).to eq(1)
    expect(q.size).to eq(0)
    a.ingest_down = false
    q.push({ "i" => 2 })
    q.flush
    expect(a.events).to eq([[{ "i" => 2 }]])
    q.stop
  end

  it "never raises from push or flush" do
    a = FakeAnalyst.new
    q = queue(a)
    q.transport = nil
    q.push({ "i" => 1 })
    expect { q.flush }.not_to raise_error # a broken transport is swallowed and logged, never raised
    expect(q.size).to eq(0)
    q.push(Object.new) # not JSON-serialisable: dropped at flush, not raised
    expect { q.flush }.not_to raise_error
    q.stop
  end

  it "ends the flush thread on stop" do
    a = FakeAnalyst.new
    q = queue(a, flush_s: 0.01)
    q.push({ "i" => 1 })
    q.stop
    sleep 0.03
    n = a.events.length
    q.push({ "i" => 2 })
    sleep 0.03
    expect(a.events.length).to eq(n) # nothing flushes on its own after stop
  end

  it "drains a waiting flush behind the one in flight" do
    a = FakeAnalyst.new
    open = false
    slow = lambda do |req|
      sleep 0.005 until open # the periodic flush is mid-POST when the exit drain starts
      a.call(req)
    end
    q = queue(a, max_batch: 1, flush_s: 60)
    q.transport = slow
    q.push({ "i" => 1 })
    wait_until { q.inflight? }
    q.push({ "i" => 2 })
    q.flush # the request-path flush yields to the one in flight
    expect(a.events).to eq([])
    t = Thread.new { q.drain(2) }
    open = true
    t.join(2)
    expect(a.events).to eq([[{ "i" => 1 }], [{ "i" => 2 }]])
    q.stop
  end

  it "starts empty with fresh locks after a fork" do
    a = FakeAnalyst.new
    q = queue(a, flush_s: 60)
    q.push({ "i" => 1 })
    lock = q.lock
    lock.lock # what a child inherits when the parent forked mid-flush
    q.after_fork!
    expect(q.lock).not_to be(lock)
    expect(q.size).to eq(0)
    q.push({ "i" => 2 }) # would deadlock on the inherited lock
    q.flush
    expect(a.events).to eq([[{ "i" => 2 }]])
    q.stop
  end

  it "drains at exit within the budget through install_exit_flush" do
    a = FakeAnalyst.new
    q = queue(a, flush_s: 60)
    q.install_exit_flush(0.5)
    q.install_exit_flush(0.5) # idempotent
    q.push({ "i" => 1 })
    q.drain(0.5)
    expect(a.events).to eq([[{ "i" => 1 }]])
    q.stop
  end
end
