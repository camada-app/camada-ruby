# frozen_string_literal: true

# Container handling the golden cases do not reach: malformed input, the advisory version byte,
# and the rule-compilation rules (drop, never guess).
RSpec.describe Camada::Snapshot do
  v4 = Fixtures.read_bin("blk3/v4-basic.bin")
  v4_meta = Fixtures.read_json("blk3/v4-basic.meta.json")

  # A tiny BLK container: header then the sections back to back.
  def container(magic, sections)
    k = sections.length
    header = [magic, k]
    off = 2 + (k * 3)
    body = []
    sections.each do |t, words|
      header += [t, off, words.length]
      body += words
      off += words.length
    end
    (header + body).pack("V*")
  end

  def input(**kw) = Camada::Snapshot::MatchInput.new(**kw)

  def rules_snapshot(rules, sections = [])
    Camada::Snapshot::Matcher.new(described_class.parse_snapshot(container(0x424C4B35, sections), { "version" => "v", "rules" => rules }))
  end

  it "raises on a bad magic and on truncation" do
    expect { described_class.parse_snapshot("nope", { "version" => "1" }) }.to raise_error(ArgumentError)
    expect { described_class.parse_snapshot([0x424C4B35, 3].pack("V*"), { "version" => "1" }) }.to raise_error(ArgumentError) # claims 3 sections, has none
    expect { described_class.parse_snapshot([0x424C4B35, 1, 10, 5, 100].pack("V*"), { "version" => "1" }) }.to raise_error(ArgumentError) # section runs past the end
  end

  it "drops an unaligned tail instead of failing" do
    expect(described_class.parse_snapshot("#{v4}\x01".b, v4_meta).format).to eq(4)
  end

  it "reads a container handed in at a byte offset without copying it" do
    framed = "\x00\x00\x00\x00#{v4}".b
    words = Camada::Snapshot::Words.new(framed, 4)
    m = Camada::Snapshot::Matcher.new(described_class.parse_snapshot(words, v4_meta))
    expect(m.match(input(ip: "203.0.113.66")).reason).to eq("ip4")
  end

  it "still reads v4 sections under a v3 magic" do
    # the version byte is advisory: an allow range under a BLK3 magic still allows
    n = (192 << 24) | (0 << 16) | (2 << 8) | 20
    bin3 = container(0x424C4B33, [[10, [n, n]]])
    r = Camada::Snapshot::Matcher.new(described_class.parse_snapshot(bin3, { "version" => "x" })).match(input(ip: "192.0.2.20"))
    expect(r.allowed).to be(true)
    expect(r.reason).to eq("ip4")
    expect(described_class.parse_snapshot(bin3, { "version" => "x" }).format).to eq(3)
  end

  it "drops an unknown action and an empty rule" do
    m = rules_snapshot([
                         { "id" => "a", "action" => "teleport", "conds" => [{ "f" => "path", "op" => "is", "v" => "/x" }] },
                         { "id" => "b", "action" => "block", "conds" => [] },
                         { "id" => "c", "action" => "block", "conds" => [{ "f" => "path", "op" => "is", "v" => "/x" }] }
                       ])
    expect(m.snap.rules.map(&:id)).to eq(["c"])
    expect(m.match(input(path: "/x")).rule).to eq("c")
  end

  it "never matches and never raises on a regex Ruby rejects" do
    m = rules_snapshot([{ "id" => "bad", "action" => "block", "conds" => [{ "f" => "path", "op" => "matches", "v" => "(?<=a" }] }])
    expect(m.match(input(path: "/a")).block).to be(false)
    m2 = Camada::Snapshot::Matcher.new(described_class.parse_snapshot(container(0x424C4B35, []), { "version" => "v", "pathsRegex" => ["(?<=a", "^/dump$"] }))
    expect(m2.match(input(path: "/dump")).reason).to eq("path")
  end

  it "compares asn conditions as strings and never fires an unanswerable field" do
    m = rules_snapshot([
                         { "id" => "asn", "action" => "block", "conds" => [{ "f" => "asn", "op" => "is_in", "v" => [14_061, "7922"] }] },
                         { "id" => "cc", "action" => "block", "conds" => [{ "f" => "country", "op" => "is_not", "v" => "US" }] }
                       ])
    expect(m.match(input(asn: 14_061)).rule).to eq("asn")
    expect(m.match(input(asn: 7922)).rule).to eq("asn")
    expect(m.match(input(asn: 1)).rule).to be_nil # country unanswerable: is_not stays false
    expect(m.match(input(country: "BR")).rule).to eq("cc")
  end

  it "reads a header getter that raises or returns junk as absent" do
    m = rules_snapshot([{ "id" => "h", "action" => "block", "conds" => [{ "f" => "header", "op" => "is", "name" => "X-Api-Key", "v" => "k" }] }])
    boom = ->(_n) { raise "app bug" }
    expect(m.match(input(header: boom)).block).to be(false)
    expect(m.match(input(header: ->(n) { n == "x-api-key" ? 42 : nil })).block).to be(false)
    expect(m.match(input(header: ->(n) { n == "x-api-key" ? "k" : nil })).rule).to eq("h")
  end

  it "reads contains, starts_with and the entity-plane fields" do
    m = rules_snapshot([
                         { "id" => "ua", "action" => "warn", "conds" => [{ "f" => "ua", "op" => "contains", "v" => "Scrapy" }] },
                         { "id" => "pfx", "action" => "challenge", "conds" => [{ "f" => "path", "op" => "starts_with", "v" => "/admin/" }] },
                         { "id" => "tls", "action" => "block", "conds" => [{ "f" => "tlsx", "op" => "is", "v" => "t1" }] },
                         { "id" => "bot", "action" => "block", "conds" => [{ "f" => "bot.verified", "op" => "is", "v" => "true" }] }
                       ])
    expect(m.match(input(ua: "Scrapy/2.11")).warn).to be(true)
    expect(m.match(input(path: "/admin/x?y=1")).challenge).to be(true)
    expect(m.match(input(tlsx: "t1")).rule).to eq("tls")
    expect(m.match(input(path: "/")).rule).to be_nil # bot.verified is never answerable here
  end

  it "consumes two section pairs in order for two ip conditions" do
    a = (10 << 24) | 1
    b = (10 << 24) | 2
    m = rules_snapshot(
      [{ "id" => "r", "action" => "block", "conds" => [{ "f" => "ip", "op" => "is_in", "set" => true }, { "f" => "ip", "op" => "not_in", "set" => true }] }],
      [[14, [0, a, a]], [15, [0]], [14, [0, b, b]], [15, [0]]]
    )
    expect(m.match(input(ip: "10.0.0.1")).rule).to eq("r")  # in the first, not in the second
    expect(m.match(input(ip: "10.0.0.2")).rule).to be_nil   # not in the first
    expect(m.match(input(ip: nil)).rule).to be_nil          # no address: false for every op, negatives included
  end

  it "translates the JS regex spellings" do
    m = rules_snapshot([{ "id" => "ver", "action" => "block", "conds" => [{ "f" => "path", "op" => "matches", "v" => "^/api/(?<ver>v\\d+)/" }] }])
    expect(m.match(input(path: "/api/v2/dump")).rule).to eq("ver")
    expect(m.match(input(path: "/api/v٣/dump")).rule).to be_nil # \d is ASCII, as JS reads it
    m2 = rules_snapshot([{ "id" => "any", "action" => "block", "conds" => [{ "f" => "ua", "op" => "matches", "v" => "^a[^]b\\cJ$" }] }])
    expect(m2.match(input(ua: "a\nb\n")).rule).to eq("any")
    expect(m2.match(input(ua: "ab")).rule).to be_nil
    # JS anchors bind the whole input; Ruby's ^ and $ are line anchors unless translated
    m3 = rules_snapshot([{ "id" => "whole", "action" => "block", "conds" => [{ "f" => "ua", "op" => "matches", "v" => "^bot$" }] }])
    expect(m3.match(input(ua: "bot")).rule).to eq("whole")
    expect(m3.match(input(ua: "x\nbot\ny")).rule).to be_nil
    expect(m3.match(input(ua: "a$b\nbot")).rule).to be_nil
    expect(Camada::Snapshot.compile_regex("[$^]x")).to match("$x")
  end

  it "never raises on a value the pattern cannot read" do
    m = rules_snapshot([{ "id" => "rx", "action" => "block", "conds" => [{ "f" => "ua", "op" => "matches", "v" => "^\\w+$" }] }])
    expect(m.match(input(ua: "\xff".b)).block).to be(false) # a binary string no UTF-8 regex can read
    expect(m.match(input(ua: "ok")).block).to be(true)
  end

  it "never raises on a binary value against a non-ASCII contains or starts_with needle" do
    # Puma's env strings are ASCII-8BIT; a rule value is UTF-8. `include?` across that pair raises
    # once either side carries a high byte — and an exception here would let the later ip rule go unread.
    n = (203 << 24) | (0 << 16) | (113 << 8) | 66
    m = rules_snapshot(
      [{ "id" => "ua", "action" => "block", "conds" => [{ "f" => "ua", "op" => "contains", "v" => "é" }] },
       { "id" => "pfx", "action" => "block", "conds" => [{ "f" => "path", "op" => "starts_with", "v" => "/é" }] },
       { "id" => "ip", "action" => "block", "conds" => [{ "f" => "ip", "op" => "is_in", "set" => true }] }],
      [[14, [2, n, n]], [15, [2]]]
    )
    expect(m.match(input(ua: "x\xff".b, path: "/\xff".b)).rule).to be_nil
    expect(m.match(input(ua: "x\xff".b, path: "/\xff".b, ip: "203.0.113.66")).rule).to eq("ip")
    expect(m.match(input(ua: "café")).rule).to eq("ua")
    expect(m.match(input(path: "/été")).rule).to eq("pfx")
  end

  it "serves concurrent requests from one matcher without crosstalk" do
    a = (10 << 24) | 1
    m = rules_snapshot(
      [{ "id" => "r", "action" => "block", "conds" => [{ "f" => "header", "op" => "is", "name" => "x-a", "v" => "1" }, { "f" => "ip", "op" => "is_in", "set" => true }] }],
      [[14, [0, a, a]], [15, [0]]]
    )
    header = lambda do |_n|
      Thread.pass # hand the GVL to the other request between the header read and the ip check
      "1"
    end
    wrong = [0, 0]
    hammer = lambda do |slot, ip, expect|
      1500.times { wrong[slot] += 1 if m.match(input(ip: ip, header: header)).block != expect }
    end
    ts = [Thread.new { hammer.call(0, "10.0.0.1", true) }, Thread.new { hammer.call(1, "10.0.0.2", false) }]
    ts.each(&:join)
    expect(wrong).to eq([0, 0])
  end
end
