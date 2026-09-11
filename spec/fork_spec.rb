# frozen_string_literal: true

# Ruby has no os.register_at_fork: the client and the queue notice a changed Process.pid on
# their next call and start over (new mutexes, an empty queue, restarted threads). This covers
# Puma cluster mode with preload_app!, Unicorn and Passenger without any hook. The child
# reports through its exit status; exit! skips the parent's at_exit hooks.
RSpec.describe "fork safety" do
  it "gives a forked worker fresh state and its own threads" do
    a = FakeAnalyst.new
    q = Camada::Events::Queue.new("https://analyst.test", "tok", transport: a, flush_s: 60)
    c = Camada::Snapshot::Client.new("https://analyst.test/snapshot", "snap", transport: a, mode: :timer, refresh_s: 60)
    c.start
    3.times { |i| q.push({ "i" => i }) }
    q.lock.lock # the parent is "mid-flush" at the moment of the fork
    parent_pid = Process.pid
    pid = Process.fork do
      ok = Process.pid != parent_pid && q.lock.locked? && q.size == 3
      old = q.lock
      q.push({ "child" => 1 })                  # the pid check: new lock, empty queue, thread restarted
      ok &&= !q.lock.equal?(old) && q.size == 1 && q.flush_thread&.alive?
      c.ensure_fresh                            # same for the client: the timer thread is re-armed in the child
      ok &&= c.poll_thread&.alive?
      Process.exit!(ok ? 0 : 1)
    end
    q.lock.unlock
    _, status = Process.wait2(pid)
    expect(status.exitstatus).to eq(0)
    expect(q.size).to eq(3) # the parent kept its own queue
    q.stop
    c.stop
  end
end
