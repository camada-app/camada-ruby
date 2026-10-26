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

  describe "meta pathsRegex" do
    def meta_matcher(rx, rules = [])
      Camada::Snapshot::Matcher.new(described_class.parse_snapshot(container(0x424C4B35, []), { "version" => "v", "pathsRegex" => rx, "rules" => rules }))
    end

    it "is case-insensitive like a path matches condition" do
      m = meta_matcher(["^/DUMP$"])
      expect(m.match(input(path: "/dump")).reason).to eq("path")
      expect(m.match(input(path: "/dumpx")).block).to be(false)
    end

    it "never matches a pattern this SDK refuses" do
      m = meta_matcher(["(?>a)", "(?<=a"])
      expect(%w[/a /aa /b].map { |p| m.match(input(path: p)).block }).to eq([false, false, false])
    end

    it "blocks a path over the cap, not one at it" do
      m = meta_matcher(["^/never$"])
      expect(m.match(input(path: "/#{"a" * Camada::Snapshot::MAX_MATCH_INPUT}")).reason).to eq("path")
      expect(m.match(input(path: "/#{"a" * (Camada::Snapshot::MAX_MATCH_INPUT - 1)}")).block).to be(false)
    end

    it "runs inside the budget shared with the rule walk" do
      rule = { "id" => "h", "action" => "block", "conds" => [{ "f" => "header", "op" => "is", "name" => "x-spend", "v" => "never" }] }
      m = meta_matcher(["^/never$"], [rule])
      spend = lambda { |_n|
        Thread.current[:camada_regex_budget] = 0
        nil
      }
      expect(m.match(input(path: "/x", header: spend)).reason).to eq("path")
      expect(m.match(input(path: "/x", header: ->(_n) {})).block).to be(false)
    end
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
    expect(m2.match(input(ua: "aXb\n")).rule).to eq("any") # v3 (S5): a deny also tests the raw value, which \cJ reads
    expect(Camada::Snapshot.compile_regex("^a[^]b\\cJ$").match?("a\nb\n")).to be(true)
    expect(m2.match(input(ua: "ab")).rule).to be_nil
    # JS anchors bind the whole input; Ruby's ^ and $ are line anchors unless translated
    m3 = rules_snapshot([{ "id" => "whole", "action" => "block", "conds" => [{ "f" => "ua", "op" => "matches", "v" => "^bot$" }] }])
    expect(m3.match(input(ua: "bot")).rule).to eq("whole")
    expect(m3.match(input(ua: "x\nbot\ny")).rule).to be_nil
    expect(m3.match(input(ua: "a$b\nbot")).rule).to be_nil
    expect(Camada::Snapshot.compile_regex("[$^]x")).to match("$x")
    # JS has no nested or POSIX classes and no `&&`: `[[:alpha:]]` is {[ : a l p h} then `]` (checked against node)
    posix = Camada::Snapshot.compile_regex("[[:alpha:]]")
    expect(posix).not_to be_nil
    expect(posix).not_to match("b")
    expect(posix).to match("a]")
    expect(posix).to match(":]")
    nested = Camada::Snapshot.compile_regex("[a[b]]")
    expect(nested).to match("a]")
    expect(nested).to match("[]")
    expect(nested).not_to match("b")
    amp = Camada::Snapshot.compile_regex("[a&&b]")
    %w[& a b].each { |v| expect(amp).to match(v) }
  end

  it "reads a non-JS brace as text" do
    rx = ->(p) { Camada::Snapshot.compile_regex("^(?:#{p})$") }
    expect(Camada::Snapshot.js_to_onigmo("a{,3}")).to eq("a\\{,3}")
    expect(rx.call("a{,3}")).to match("a{,3}")
    expect(rx.call("a{,3}")).not_to match("aa")
    expect(rx.call("a{,}")).to match("a{,}")
    expect(rx.call("a{,}")).not_to match("aaa")
    expect(rx.call("a{1,3}")).to match("aaa")
    expect(Camada::Snapshot.compile_regex("a{1,3}?").match("aaa")[0]).to eq("a")
    expect(rx.call("[{,3}]")).to match(",")
    expect(rx.call("\\{,3}")).to match("{,3}")
    expect(rx.call("a{ 1}")).to match("a{ 1}")
    expect(rx.call("x{")).to match("x{")
    expect(rx.call("[^]{,2}")).to match("z{,2}")
    # real path: Onigmo would read each `.{,2000}` as a bound and backtrack catastrophically
    m = rules_snapshot([{ "id" => "bt", "action" => "block", "conds" => [{ "f" => "ua", "op" => "matches", "v" => ".{,2000}.{,2000}.{,2000}!" }] }])
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    expect(m.match(input(ua: "!#{"a" * 2047}")).rule).to be_nil
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0).to be < 0.1
  end

  it "reads JS identity escapes as the letter and {n}? as exact-n" do
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    {
      "^\\p{L}$" => [["p{L}", true], ["A", false]],
      "^\\x{41}$" => [["A", false]], "^\\x{2}$" => [["xx", true]],
      "^\\u{41}$" => [["A", false]], "^\\u{2}$" => [["uu", true]], "^\\u{1F600}$" => [["u{1F600}", true]],
      "^\\o{101}$" => [["A", false]], "^\\o{2}$" => [["oo", true]],
      "^\\g{1}$" => [["g", true], ["gg", false]],
      "^\\Qa.b$" => [["Qa.b", true], ["Qaxb", true]],
      "^a{2}?$" => [["", false], ["aa", true]], "^a{2,3}?$" => [["aaa", true], ["a", false]],
      "^\\A\\z$" => [["Az", true]], "^\\e$" => [["e", true]], "^\\h$" => [["h", true]],
      "^\\x4$" => [["x4", true]], "^\\x41$" => [["A", true]], "^A$" => [["A", true]],
      "^\\k$" => [["k", true]], "(?<n>a)\\k<n>" => [["aa", true]],
      "^[\\B]$" => [["B", true]], "^[\\p]$" => [["p", true]], "^[\\b]$" => [["\b", true]],
      "^\\d\\w\\b" => [["1a", true]], "^\\u0041$" => [["A", true]], "^admin$" => [["admin\n", false]],
      "^\\c1$" => [["\\c1", true]], "^\\c$" => [["\\c", true]], "^[\\c1]$" => [["\x11", true]],
      "^\\v$" => [["\v", true], ["\n", false]]
    }.each do |pat, cases|
      cases.each { |s, want| expect(rx.call(pat).match?(s)).to(be(want), "#{pat} on #{s.inspect}") }
    end
    expect(Camada::Snapshot.js_to_onigmo("\\x{2}?")).to eq("x{2}")
    # a numbered backreference beside named groups: Onigmo rejects \1 there, so it reads as \k<name>
    bref = Camada::Snapshot.compile_regex("^(?<n>a)\\1$")
    expect(bref.match?("aa")).to be(true)
    expect(bref.match?("ab")).to be(false)
    expect(Camada::Snapshot.compile_regex("(?<x>[(])(?<y>b)\\2\\1").match?("(bb(")).to be(true)
    expect(Camada::Snapshot.compile_regex("a{2,3}?").match("aaa")[0]).to eq("aa")
    %w[\\p{L} \\u{1F600}].each do |pat|
      expect do
        old = $VERBOSE
        $VERBOSE = true
        Camada::Snapshot.compile_regex(pat)
      ensure
        $VERBOSE = old
      end.not_to output.to_stderr
    end
  end

  it "reads \\k as a letter unless a real named group exists, emulates JS for a backreference to an optional group, and fails open where it cannot" do
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    expect(rx.call('[(?<]\k<n>').match?("(k<n>")).to be(true)
    expect(rx.call('\(?<x>\k<n>').match?("(<x>k<n>")).to be(true)
    ['^(?:(?<n>a)|b)+\k<n>$', '(?<=(a)\1)b', '(?<=([ab]){2})\1', '(?<=(a))\1', '(?<=\1(a))b',
     '(?<m>)|\k<n>', '(?:(a)|b)+\1', '(?:(a)|b){2}\1', '(?:(?<n>a)?)*\k<n>', 'a\k<n>(?<m>b)',
     '(a)*\1', '(a)*x\1', '(a){0,2}x\1', # an empty last iteration (node rejects it, Onigmo takes it)
     '(b*)*x\1', '(b|)*x\1', '(a?){0,2}x\1', '(?:(?=(a)))?a\1', '(?=(a))?a\1', '(?=(a)){0,1}a\1',
     '(?<a>x)(?=(?<b>y))?y\k<b>', # a capture in a lookahead a min-0 quantifier covers
     '(?=(?:a??)?(b?))a\1', '(?=(?:|a)?(b?))a\1', '(?=(?:a*?)*(b?))a\1', '(?=x(?=(?:a??)?(b?)))xa\1', '(?=(?:a??)?(?<n>b?))a\k<n>',
     '(?=(a??)?)\1a', '(?=(?:a??)?(b)?)a\1', '(?=(a*?){0,1})[ab]*\1', '(?=x(?<n>a??(x)*|){0,1})x\k<n>', # a conditional reference into a lookahead
     '(?:(?<n>a)|(?<n>b))\k<n>', '(?:(?<n>a)|(?<n>b))\1',
     '(b*)+x\1', '(b|)+x\1', '(a?)+x\1', '\1(b*)+x\1', '(?:(b*))+x\1', '(?<m>b*)+x\k<m>', # a plain reference to a repeat that can match empty
     '(\x41?)+x\1', '(é?)+x\1', '([a]?)+x\1', '(a{0,2})+x\1',
     '((?:a?))+x\1', '((?:b*))+x\1', # a group header is no atom
     '(?:(?:(b*)))+x\1', '(?<m>(?:b*))+x\k<m>',
     '(?:(?<a>b*)\k<a>)+x\k<a>',
     '(b*){2,3}x\1', '(b*){2,}x\1', '(?:(b*){2})+x\1', '(?:((?:b+|(?=x))){2}c?)+x\1',
     '(b*){2}x\1', '(b*){2,2}x\1', '(?:(b*)){3}x\1', '(a*){2}x\1', '(b*){3}x\1',
     '(?:(?:(b?)b*){2}){2}x\1', '(?:(?:((?=^)+\w*)){2}){2}x\1', '(?:(?:(b*)b*){2}c)+x\1'].each do |pat| # Onigmo exits an exact-count loop on an empty iteration below its minimum
      expect(rx.call(pat)).to(be_nil, pat)
    end
    # node's answers (new RegExp("^(?:" + pat + ")$").test(s)): [matching, not matching]
    { '(a)?x\1' => [%w[x axa], %w[ax]], '(?:(a)|b)\1' => [%w[aa b], %w[ba a]],
      '(?<q>["\'])?x\k<q>' => [["x", '"x"', "'x'"], ['"x', %('x")]], '\1(a)' => [%w[a], %w[aa]], '(a\1)' => [%w[a], %w[aa]],
      '(?:\1(a))+' => [%w[a aa], []], '(a)|b\1' => [%w[b a], %w[ab]], '(a){00}x\1' => [%w[x], %w[xa]], '(?!(a))\1b' => [%w[b], %w[ab]],
      '(?:(a)\1|b)' => [%w[aa b], %w[a]], '(?<m>)|\k<n>(?<n>b)' => [["", "b"], []], '\k<n>(?<n>b)' => [%w[b], []],
      'a|\k<n>(?<n>b)' => [%w[a b], []], '(a|b)\1' => [%w[aa bb], %w[ab]], '(a)+\1' => [%w[aaa], []],
      '(?:(a)\1)+' => [%w[aaaa], []], '(?<n>a)\k<n>' => [%w[aa], []], '(?<n>a)\1' => [%w[aa], []],
      '(a){1,2}\1' => [%w[aaa], []], '(a)+x\1' => [%w[axa], %w[ax]], '(\w)+\1' => [%w[aa abb], %w[a ab]],
      '(?:(b)c?)+x\1' => [%w[bxb bcbxb], %w[bx]], '(a{1,2})+x\1' => [%w[axa aaxa], %w[ax]],
      '(?=(?:a)?(b?))a\1' => [%w[ab a], %w[abb]], '(?=(a))a\1' => [%w[aa], %w[a]], '(?:(a)|b)(?=(\1))\2' => [%w[aa b], %w[a aaa]],
      '(\x41)+x\1' => [%w[AxA], %w[Ax]],
      '(?:(a?)\1)+' => [["", "aa", "aaaa"], %w[a aaa]] }.each do |pat, (yes, no)|
      re = rx.call("^(?:#{pat})$")
      yes.each { |s| expect(re&.match?(s)).to(be(true), "#{pat} on #{s.inspect}") }
      no.each { |s| expect(re&.match?(s)).to(be(false), "#{pat} on #{s.inspect}") }
    end
    expect(rx.call('[\1](a)').match?("\x01a")).to be(true)
    expect(Camada::Snapshot.scan_groups('\2(a)')[1]).to be(false) # not a backreference with one group
  end

  it "fails open on a pattern that is not a String" do
    [nil, 42, ["a"]].each { |pat| expect(Camada::Snapshot.compile_regex(pat)).to be_nil, pat.inspect }
  end

  it "pins an Onigmo divergence from node on an empty-bodied capture loop (accepted gap, camada-all-mx0s)" do
    # node: /^(?:((x?[ab]*)+?[ab]){2})$/.test('aa') is true. Onigmo says false. If a Ruby upgrade flips
    # this, update the README `matches` paragraph.
    re = Camada::Snapshot.compile_regex("^(?:((x?[ab]*)+?[ab]){2})$")
    expect(re).not_to be_nil
    expect(re.match?("aa")).to be(false)
  end

  it "fails open on a non-UTF-8 pattern (the binary walk misreads it)" do
    [["ソ(a)?x\\1".encode("Shift_JIS"), "a(b)?\\1".encode("UTF-16LE")]].flatten.each do |pat|
      expect(Camada::Snapshot.compile_regex(pat)).to be_nil, pat.encoding.to_s
    end
    expect(Camada::Snapshot.compile_regex("a(b)?x\\1".encode("US-ASCII"))).not_to be_nil
  end

  it "classifies deeply nested backreferences in linear time" do
    ["(a)?", "(a)"].each do |inner|
      pat = "#{"(?:" * 4000}#{inner}#{")" * 4000}#{"\\1" * 4000}"
      t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      Camada::Snapshot.scan_groups(pat)
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - t).to be < 0.5, inner
    end
  end

  it "fails open on a (? or (* group JS lacks, which JS rejects or V8 mis-evaluates (camada-all-lsl8)" do
    ['(?:(a{0,2}))((\\b\\3)*?)?(?i:\\1|[^a]*)+?', "(?i:googlebot|bingbot)", "(?-i:a)", "(?s:.)", "(?m:a$)",
     "(?i-m:a)", "x(?i:a)", "a(?i)b", "(?i)admin", "(?x:a b)", "(?^i:a)", "(?-i)a", "(?s)a.b", "(?R)",
     "x(?im-s)y", "(?>a+)b", "(?#c)a", "(a)?(?(1)b)", "(?'n'a)", "(?~a)", "(?|a|b)", "(?P<n>a)(?P=n)",
     "(a)(?1)", "(*FAIL)", "(?<n>a)(?&n)", "(?0)", "a(?", "a(*", "(?", "(*"].each { |pat| expect(Camada::Snapshot.compile_regex(pat)).to be_nil, pat }
    expect(Camada::Snapshot.compile_regex("(?i:a)", Regexp::IGNORECASE)).to be_nil
  end

  it "fails open on a group name JS rejects or a duplicate that could both participate (camada-all-7xyl)" do
    ["(?<n-m>a)", "(?<n+1>a)", "(?<\u00b7a>a)", "(?<>a)", "(?<1a>a)", "(?<n>a)(?<n>b)", "(?<n>(?<n>a))",
     "(?:(?<n>a)|b)(?<n>c)", "(?<n>a)|(?<n>b)\\k<n>", "(?:(?<n>a)|(?<n>b))(c)\\2", "(?<n>a)|(?<n>b)\\1",
     "(?<n>a)|(?<n>b)(?<n>c)", "(?:(?<n>a)|(?<n>b))(?<n>c)",
     "(?<n>a)[\\k]", "(?<n>a)[\\k<n>]", "(?<n>a)[\\k<m>]", "(?<n>a)|(?<n>b)[\\k<n>]"].each { |pat| expect(Camada::Snapshot.compile_regex(pat)).to be_nil, pat }
  end

  it "compiles group names JS accepts, copied verbatim (camada-all-7xyl)" do
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    # an escaped backslash or a class `[\1]` is no reference, so the twins compile (camada-all-cwwz)
    { '(?<n>a)|(?<n>b)\\\\1' => ["b\\1", "b"], '(?<n>a)|(?<n>b)[\1]' => ["b\x01", "b1"] }.each do |pat, (hit, miss)|
      expect(rx.call(pat)).to match(hit)
      expect(rx.call(pat)).not_to match(miss)
    end
    expect(rx.call("[\\k]")).to match("k")
    expect(rx.call("(?<\u00e9>a)\\k<\u00e9>")).to match("aa")
    expect(rx.call("(?<$x>a)\\k<$x>")).to match("aa")
    expect(rx.call("(?<$x_\u200c>a)")).to match("a")
    expect(rx.call("(?<\u2118>a)")).to match("a")
    expect(rx.call("(?<n>a)|(?<n>b)").match("b")[:n]).to eq("b")
    expect(rx.call("(?:(?<n>a)|(?<n>b))c")).to match("bc")
    expect(rx.call("((?<n>a)|x)|(?<n>b)")).to match("b")
    expect(rx.call("(?<n>a)|(?:(?<n>b)|(?<n>c))")).to match("c")
  end

  it "does not mistake other constructs for an inline flag group" do
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    expect(rx.call("[(?i:a)]")).to match("i")
    expect(rx.call("\\(?i:a\\)")).to match("(i:a)")
    expect(rx.call("[(?i)]")).to match("i")
    expect(rx.call("\\(?i\\)")).to match("(i)")
    ["(?:a)", "(?<n>a)", "(?=a)", "(?<!a)b"].each { |pat| expect(rx.call(pat)).not_to be_nil, pat }
    expect(rx.call("(?:a)")).to match("a")
    expect(rx.call("(?=a)a")).to match("a")
    expect(rx.call("(?!b)a")).to match("a")
    expect(rx.call("(?<=a)b")).to match("ab")
    expect(rx.call("(?<!b)a")).to match("a")
    expect(rx.call("(?<n>a)\\k<n>")).to match("aa")
    expect(rx.call("[(?>]")).to match(">")
    expect(rx.call("\\(?>")).to match("(>")
    expect(rx.call("[(*]")).to match("*")
    expect(rx.call("\\(*")).to match("((")
  end

  it "fails open on a backreference-bearing alternation that cannot be unmatched safely (camada-all-wlww)" do
    expect(Camada::Snapshot.compile_regex('a|\k<n>((?<m>a)')).to be_nil
  end

  it "translates a large non-ASCII pattern in linear time and keeps its meaning (camada-all-ffbk)" do
    big = "é(a)\\1" * 20_000
    best = Array.new(3) do # best of three: a busy machine adds noise, never a quadratic walk's seconds
      t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      expect(Camada::Snapshot.compile_regex(big)).not_to be_nil
      Process.clock_gettime(Process::CLOCK_MONOTONIC) - t
    end.min
    expect(best).to be < 1.0 # CI runners take ~0.28 s; the quadratic walk this guards against takes seconds
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    expect(rx.call("[é-ü]").match?("ö")).to be(true)
    expect(rx.call("[é-ü]").match?("a")).to be(false)
    expect(rx.call('é\s').match?("é\u00a0")).to be(true)
    expect(rx.call('[a\s-é]').match?("-")).to be(true)
    expect(rx.call('[a\s-é]').match?("b")).to be(false)
    expect(rx.call('[a\s-éb]').match?("b")).to be(true)
    expect(rx.call('(?<ñ>é)\k<ñ>').match?("éé")).to be(true)
    expect(rx.call('(?<n>é)\k<n>').match?("éa")).to be(false)
    expect(rx.call('(é)?x\1').match?("x")).to be(true)
    expect(rx.call("é(a)\\1").source.encoding).to eq(Encoding::UTF_8)
  end

  it "scans a run of \\k< openers in linear time (literal text without a named group)" do
    t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    rx = Camada::Snapshot.compile_regex("#{"\\k<" * 20_000}>")
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - t).to be < 1
    expect(rx).not_to be_nil
    expect(Camada::Snapshot.compile_regex("#{"\\k<" * 3}>").match?("k<k<k<>")).to be(true)
  end

  it "reads \\k as literal text when no group is named, even beside unnamed groups" do
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    { '()\k<m>' => "k<m>", '(a)x\k<n>' => "axk<n>", '(\d+)-\k<id>' => "12-k<id>" }.each { |pat, s| expect(rx.call(pat)&.match?(s)).to be(true), pat }
  end

  it "fails open on a malformed \\k beside named groups (a JS SyntaxError; Onigmo aborts the process)" do
    ['(?<n>a)|\k<', '(?<n>a)|\k<n', '(?<n>a)|\k<a<b>', '|\k<(?<n>a)', '(?<n>a)|\k'].each { |pat| expect(Camada::Snapshot.compile_regex(pat)).to be_nil, pat }
  end

  it "scans a run of group openers in linear time" do
    t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    Camada::Snapshot.compile_regex("#{"(?<" * 20_000}>\\1")
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - t).to be < 1
  end

  it "clamps a JS quantifier bound above Onigmo's 100000 (camada-all-yh2t)" do
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    expect(rx.call("^a{1,99999999999}$")).to match("a")
    expect(rx.call("^a{1,99999999999}$")).not_to match("b")
    expect(rx.call("^a{99999999999}$")).not_to be_nil
    expect(rx.call("^a{99999999999,}$")).not_to be_nil
    expect(rx.call("^(?:ab){1,99999999999}$")).to match("abab")
    expect(rx.call("^a{1,#{"9" * 5000}}$")).to match("a")
    ["a{100001,100000}", "a{99999999999,99999999998}", "a{2,1}"].each { |p| expect(rx.call(p)).to be_nil }
    expect(rx.call("^a{0002,03}$")).to match("aa")
    expect(rx.call("^a{0002,03}$")).not_to match("a")
    expect(Camada::Snapshot.js_to_onigmo("^a{2,3}$")).to eq("\\Aa{2,3}\\z")
  end

  it "reads \\c in a class as a control char only before a letter, digit or _ (camada-all-mqcb)" do
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    {
      "^[\\c*]$" => [["\\", true], ["c", true], ["*", true], ["j", false]],
      "^[\\c1]$" => [["\u0011", true], ["q", false]], "^[\\c_]$" => [["\u001f", true]],
      "^[\\s-\\c-x]$" => [["-", true], ["\\", true], ["d", true], ["y", false]],
      "^\\c1$" => [["\\c1", true]]
    }.each do |pat, cases|
      cases.each { |s, want| expect(rx.call(pat).match?(s)).to(be(want), "#{pat} on #{s.inspect}") }
    end
    ["[\\c]", "[\\c"].each { |p| expect { rx.call(p) }.not_to raise_error }
  end

  it "fails open on an unterminated class after \\s-" do
    ["[a\\s-", "[\\s-"].each { |p| expect { expect(Camada::Snapshot.compile_regex(p)).to be_nil }.not_to raise_error }
  end

  it "reads JS ., [] and \\s/\\S as JS does" do
    rx = ->(p) { Camada::Snapshot.compile_regex(p) }
    {
      "^.$" => [["\r", false], ["\u2028", false], ["\u2029", false], ["\n", false], ["a", true], ["\u{1F600}", true]],
      "^\\.$" => [[".", true], ["a", false]], "^[.]$" => [[".", true], ["a", false]],
      "[]a]" => [["a", false], ["]", false], ["a]", false]],
      "^[^]x]$" => [["qx]", true], ["x", false]], "a[]*b" => [["ab", true]],
      "^\\s$" => [[" ", true], ["\u2028", true], ["\u00a0", true], ["\ufeff", true], ["a", false]],
      "^\\S$" => [[" ", false], ["\u2028", false], ["\u3000", false], ["a", true], ["\u{1F600}", true]],
      "^[a\\s]$" => [["\u00a0", true], ["a", true], ["b", false]],
      "^[^a\\s]$" => [["\u00a0", false], ["a", false], ["b", true]],
      "^[a-\\sz]$" => [["-", true], ["m", false], ["z", true], [" ", true]],
      "^[\\s-a-z]$" => [["b", false], ["-", true], ["z", true], ["a", true]], "^[\\s-\\x41-z]$" => [["b", false], ["-", true]],
      "^[\\s-\\cA-z]$" => [["b", false], ["-", true]], "^[\\s-\\101-z]$" => [["b", false], ["-", true]],
      "^[\\s\\S]$" => [["\n", true]], "^[^\\s\\S]$" => [["a", false]],
      "^[\\s-\\d-z]$" => [["b", false]], "^[\\s-ab-z]$" => [["c", true]], "^[a-\\s-z]$" => [["b", false], ["-", true]],
      "^[\\sa-]$" => [["-", true], ["a", true]], "^[a\\s-z]$" => [["-", true], ["m", false]],
      "^[\\s^]$" => [["^", true], [" ", true], ["a", false]], "^[^\\s^]$" => [["^", false], ["a", true]],
      "^[\\S\\d]$" => [[" ", false], ["a", true]], "^[^\\S]$" => [[" ", true], ["a", false]],
      "(?<=[a\\s])b" => [[" b", true], ["ab", true], ["cb", false]], "(?<![a\\s])b" => [[" b", false], ["cb", true]],
      # an astral char is one char here, two UTF-16 units in JS (accepted gap, camada-all-vuvo)
      "^..$" => [["\u{1F600}", false]], "^[^a]$" => [["\u{1F600}", true]], "^a.*b$" => [["a\u{1F600}b", true]]
    }.each do |pat, cases|
      cases.each { |s, want| expect(rx.call(pat).match?(s)).to(be(want), "#{pat} on #{s.inspect}") }
    end
    expect do
      old = $VERBOSE
      $VERBOSE = true
      Camada::Snapshot.compile_regex("[]a]")
    ensure
      $VERBOSE = old
    end.not_to output.to_stderr
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

# contracts §D3 "Path matching": the golden fixtures pin the canon on ASCII input; these pin the
# byte handling a Rack PATH_INFO can hand over (binary, invalid UTF-8) — it never raises.
RSpec.describe "Camada::Snapshot.canon_path" do
  it "canonicalises on bytes, whatever the string's encoding" do
    expect(Camada::Snapshot.canon_path("/Caf\xC3\xA9/".b)).to eq("/caf%c3%a9")
    expect(Camada::Snapshot.canon_path("/caf%C3%A9")).to eq("/caf%c3%a9")
    expect(Camada::Snapshot.canon_path("/a\xFF%2F..;x/b".dup.force_encoding("UTF-8"))).to eq("/a%ff%2f../b") # %2F is not a separator, so ".." stays inside the segment
    expect(Camada::Snapshot.path_forms("/x/%2e%2E/Y?q=1#f")).to eq(["/x/%2e%2E/Y", "/x/../y", "/y"])
  end
end

# regex-cap-sdk v1: the `matches` input cap, the control-character strip, and fail-closed on errors
RSpec.describe "Camada::Snapshot matches cap" do
  def input(**kw) = Camada::Snapshot::MatchInput.new(**kw)

  def matcher(rules)
    snap = Camada::Snapshot.parse_snapshot([0x424C4B35, 0].pack("V*"), { "version" => "v", "rules" => rules })
    Camada::Snapshot::Matcher.new(snap)
  end

  def rule(action, field, pattern, name: nil)
    cond = { "f" => field, "op" => "matches", "v" => pattern }
    cond["name"] = name if name
    { "id" => "r", "action" => action, "conds" => [cond] }
  end

  %w[block challenge warn].each do |action|
    it "#{action}: over the cap is a hit, at the cap the regex runs" do
      m = matcher([rule(action, "ua", "^x")])
      expect(m.match(input(ua: "a" * 2048)).rule).to be_nil
      expect(m.match(input(ua: "a" * 2049)).rule).to eq("r")
    end
  end

  it "skip: over the cap is a miss" do
    m = matcher([rule("skip", "ua", "^x"), { "id" => "b", "action" => "block", "conds" => [{ "f" => "ua", "op" => "contains", "v" => "x" }] }])
    expect(m.match(input(ua: "x" * 2048)).rule).to eq("r")
    expect(m.match(input(ua: "x" * 2049)).rule).to eq("b")
  end

  it "counts UTF-16 code units, and bytes for invalid UTF-8" do
    m = matcher([rule("block", "ua", "^x")])
    expect(m.match(input(ua: "é" * 2048)).rule).to be_nil
    expect(m.match(input(ua: ("é" * 2048).b)).rule).to be_nil # binary from Rack, valid UTF-8 inside
    expect(m.match(input(ua: "😀" * 1024)).rule).to be_nil
    expect(m.match(input(ua: "😀" * 1025)).rule).to eq("r")
    expect(m.match(input(ua: ("\xFF" * 2048).b)).rule).to be_nil
    expect(m.match(input(ua: ("\xFF" * 2049).b)).rule).to eq("r")
    expect(Camada::Snapshot.utf16_len("é😀")).to eq(3)
    expect(Camada::Snapshot.utf16_len("a\xFF".b)).to eq(2)
  end

  def skip_block(field, skip_pat, name: nil)
    s = rule("skip", field, skip_pat, name: name).merge("id" => "s")
    c = { "f" => field, "op" => "contains", "v" => "a" }
    c["name"] = name if name
    matcher([s, { "id" => "b", "action" => "block", "conds" => [c] }])
  end

  it "S5: a deny regex tests the raw value too, so a control-char pattern fires" do
    expect(matcher([rule("block", "ua", "\\t")]).match(input(ua: "a\tb")).rule).to eq("r")
    expect(matcher([rule("block", "header", "\\t", name: "x-v")]).match(input(header: ->(n) { n == "x-v" ? "a\tb" : nil })).rule).to eq("r")
  end

  it "S5: a deny regex still meets the stripped value" do
    expect(matcher([rule("block", "ua", "sqlmap")]).match(input(ua: "sql\tmap")).rule).to eq("r")
    expect(matcher([rule("block", "header", "sqlmap", name: "x-v")]).match(input(header: ->(n) { n == "x-v" ? "sql\tmap" : nil })).rule).to eq("r")
  end

  it "S5: a skip hits a clean value and misses one with control characters" do
    m = skip_block("ua", "^partner-[a-z]+$")
    expect(m.match(input(ua: "partner-acme")).rule).to eq("s")
    expect(m.match(input(ua: "partner-acme\n")).rule).to eq("b")
    h = skip_block("header", "^partner-[a-z]+$", name: "x-p")
    expect(h.match(input(header: ->(n) { n == "x-p" ? "partner-acme" : nil })).rule).to eq("s")
    expect(h.match(input(header: ->(n) { n == "x-p" ? "partner-acme\n" : nil })).rule).to eq("b")
  end

  it "S5: raw over the cap but stripped under it: deny hits, skip misses" do
    over = "#{"a" * 2048}\t"
    expect(matcher([rule("block", "ua", "^b")]).match(input(ua: over)).rule).to eq("r")
    m = skip_block("ua", "^a+$")
    expect(m.match(input(ua: "a" * 2048)).rule).to eq("s")
    expect(m.match(input(ua: over)).rule).to eq("b")
  end

  it "deletes control characters from ua and header before matches, contains stays raw" do
    m = matcher([rule("warn", "ua", "Scrapy/[0-9]"), rule("block", "header", "^1\\.2$", name: "x-v").merge("id" => "h")])
    expect(m.match(input(ua: "Scrapy\t/2.11")).rule).to eq("r")
    expect(m.match(input(ua: "Scr\x00apy/2\x7f.1")).rule).to eq("r")
    expect(m.match(input(header: ->(n) { n == "x-v" ? "1\x7f.2\n" : nil })).rule).to eq("h")
    expect(matcher([rule("block", "ua", "^b")]).match(input(ua: "#{"a" * 2048}\t")).rule).to eq("r") # v3 (S5): raw 2049 is over the cap
    c = matcher([{ "id" => "c", "action" => "block", "conds" => [{ "f" => "ua", "op" => "contains", "v" => "curl/" }] }])
    expect(c.match(input(ua: "cu\x00rl/8")).rule).to be_nil
    expect(Camada::Snapshot.strip_control("a\xFFb\n".b)).to eq("a\xFFb".b)
  end

  it "answers a value the regex engine cannot read per action (camada-all-cwb4)" do
    bad = "\xFF\xFEevil".dup.force_encoding("UTF-8")
    expect(matcher([rule("block", "ua", "evil")]).match(input(ua: bad)).rule).to eq("r")
    expect(matcher([rule("warn", "ua", "evil")]).match(input(ua: bad)).rule).to eq("r")
    sk = matcher([rule("skip", "ua", "evil"), { "id" => "b", "action" => "block", "conds" => [{ "f" => "ua", "op" => "is", "v" => bad }] }])
    expect(sk.match(input(ua: bad)).rule).to eq("b") # the skip did not fire on an unreadable value
    rx = Camada::Snapshot.compile_regex("evil")
    expect(Camada::Snapshot.regex_hit?(rx, bad, true)).to be(true)
    expect(Camada::Snapshot.regex_hit?(rx, bad)).to be(false)
  end

  it "reads a binary-tagged value that is valid UTF-8 as UTF-8 (camada-all-cwb4)" do
    cafe = "caf\u00e9".b
    expect(matcher([rule("block", "ua", "\u00f1")]).match(input(ua: cafe)).rule).to be_nil # a deny that cannot match stays a miss
    expect(matcher([rule("block", "ua", "\u00e9")]).match(input(ua: cafe)).rule).to eq("r")
    expect(matcher([rule("skip", "ua", "\u00e9")]).match(input(ua: cafe)).rule).to eq("r") # a skip that matches fires
    expect(matcher([rule("skip", "path", "^/caf")]).match(input(path: "/caf\u00e9".b)).rule).to eq("r")
    expect(matcher([rule("block", "path", "\u00f1")]).match(input(path: "/caf\u00e9".b)).rule).to be_nil
    expect(Camada::Snapshot.regex_hit?(Camada::Snapshot.compile_regex("\u00e9"), cafe)).to be(true)
  end

  it "applies the cap to path forms, deny and skip" do
    m = matcher([rule("skip", "path", "^/static-mirror/").merge("id" => "s"), rule("block", "path", "^/api/v[0-9]+/dump$").merge("id" => "b")])
    {
      "/static-mirror/#{"a" * 2033}" => "s",
      "/static-mirror/#{"a" * 2034}" => "b",
      "/x/#{"a" * 2045}" => nil,
      "/x/#{"a" * 2046}" => "b",
      "/x?#{"q" * 3000}" => nil,
      "/#{"%61" * 700}" => "b",
      "/static-mirror/#{"%61" * 700}" => "s",
      "/static-mirror/#{"./" * 1100}x" => "b",
      "/#{"é" * 400}" => "b",
      "/api/v2/dump\n" => nil,
      "/api/v2/dump%0A" => nil
    }.each { |path, want| expect(m.match(input(path: path)).rule).to eq(want), path[0, 40] }
  end

  it "percent-encodes raw control characters in the raw form only" do
    expect(Camada::Snapshot.path_forms("/a\nb\x00\x7f")).to eq(%w[/a%0ab%00%7f] * 3)
    expect(Camada::Snapshot.path_forms("/x/\xFF\n".b)[0]).to eq("/x/\xFF%0a".b)
  end

  it "does not backtrack exponentially on an overlapping class union" do
    rx = Camada::Snapshot.compile_regex("^[ \\s]+x")
    expect(Camada::Snapshot.regex_hit?(rx, " " * 3000)).to be(false)
  end

  it "compiles classes that repeat a \\s member without an Onigmo warning under -w" do
    verbose = $VERBOSE
    begin
      $VERBOSE = true
      ["[a\\S]", "[^a\\S]", "[\\s\\t]", "[\\s ]"].each do |src|
        expect { Camada::Snapshot.compile_regex(src) }.not_to output.to_stderr
      end
    ensure
      $VERBOSE = verbose
    end
    expect(Camada::Snapshot.compile_regex("[\\s\\t]x")).to match("\tx")
  end

  # camada-all-ccjo: Onigmo's multi-char case folds must not make a lookbehind variable-length under /i
  context "lookbehinds under IGNORECASE" do
    let(:ci) { ->(p) { Camada::Snapshot.compile_regex(p, Regexp::IGNORECASE) } }

    it "compiles a lookbehind holding [\\s\\S] or a dot and matches like JS" do
      rx = ci.call("(?<=a[\\s\\S])x")
      expect(rx).not_to be_nil
      expect(rx.match?("a\nx")).to be(true)
      expect(rx.match?("a\u00e9x")).to be(true)
      rx = ci.call("(?<=(?:ss|k.))x")
      expect(rx).not_to be_nil
      %W[ssx k\u00e9x KAx SSx].each { |v| expect(rx.match?(v)).to be(true), v }
      %W[k\nx ßx].each { |v| expect(rx.match?(v)).to be(false), v }
      rx = ci.call("(?<=z(?:[\\s\\S]|e))x")
      expect(rx).not_to be_nil
      ["z x", "zEx"].each { |v| expect(rx.match?(v)).to be(true), v }
    end

    it "compiles a lone multi-char-fold literal and splits only adjacent literals" do
      ["(?<=\ufb00)x", "(?<=\u01f0)x", "(?<!\ufb00)x"].each { |p| expect(ci.call(p)).not_to be_nil, p }
      expect(ci.call("(?<=\ufb00)x").match?("\ufb00x")).to be(true)
      expect(Camada::Snapshot.js_to_onigmo("(?<=ab)x")).to include("a(?:)b")
      expect(Camada::Snapshot.js_to_onigmo("(?<=a)x")).to eq("(?<=a)x")
    end

    # camada-all-ozix: Onigmo reads ß (and, on Ruby 3.3.13+/3.4.12+, ﬀ and İ) in a lookbehind as its fold alone; JS matches it only to itself
    it "matches a multi-char-fold char in a lookbehind only to itself, as JS does" do
      {
        "(?<=\u00df)x" => [%W[\u00dfx a\u00dfx], %w[ssx SSx]],
        "(?<=\\u00df)x" => [%W[\u00dfx], %w[ssx]],
        "(?<=\\\u00df)x" => [%W[\u00dfx], %w[ssx]],
        "(?<=\ufb00)x" => [%W[\ufb00x], %w[ffx FFx]],
        "(?<=\u0130)x" => [%W[\u0130x], %w[ix Ix]],
        "(?<=a\ufb00)x" => [%W[a\ufb00x A\ufb00x], %w[affx]],
        "(?<=\ufb00a)x" => [%W[\ufb00Ax], %w[ffax]],
        "(?<=(?:\ufb00|a))x" => [%W[\ufb00x Ax], %w[ffx]],
        "(?<=a(?:\u00df|b))x" => [%W[a\u00dfx aBx], %w[assx]],
        "(?<=[\u00df])x" => [%W[\u00dfx], %w[ssx]],
        "(?<=[\u00dfa])x" => [%W[\u00dfx Ax], %w[ssx]],
        "(?<=[\u00df\\S]b)x" => [%W[\u00dfbx abx ssbx], [" bx"]],
        "(?<!\ufb00)x" => [%w[ffx x], %W[\ufb00x]]
      }.each do |pat, (hits, misses)|
        rx = ci.call(pat)
        expect(rx).not_to be_nil, pat
        hits.each { |v| expect(rx.match?(v)).to be(true), "#{pat} #{v}" }
        misses.each { |v| expect(rx.match?(v)).to be(false), "#{pat} #{v}" }
      end
      expect(Camada::Snapshot.js_to_onigmo("(?<=[a-\u00df])x")).to eq("(?<=[a-\u00df])x") # a range end stays
    end

    it "does not raise on a non-ASCII value for a literal run" do
      { "(?<=ass)x" => %w[éassx éASSx], "(?<=/class/)x" => ["\u00e9/CLASS/x"] }.each do |pat, vals|
        rx = ci.call(pat)
        vals.each { |v| expect(Camada::Snapshot.regex_hit?(rx, v, :err)).to be(true), v }
      end
      expect(ci.call("(?<=ss)x").match?("\u00dfx")).to be(false)
    end

    it "escapes a caret after a leading \\S and keeps a digit escape whole" do
      [0, Regexp::IGNORECASE].each do |f|
        rx = Camada::Snapshot.compile_regex("(?<=[\\S^a])x", f)
        expect(rx).not_to be_nil
        expect(rx.match?(" x")).to be(false)
        %w[^x bx].each { |v| expect(rx.match?(v)).to be(true), v }
        rx = Camada::Snapshot.compile_regex("(?<=[\\S^])x", f)
        expect(rx).not_to be_nil
        expect(rx.match?("^x")).to be(true)
      end
      expect(Camada::Snapshot.js_to_onigmo("(?<=\\81)y")).to include("\\81")
    end

    it "keeps a positive class with \\S and other members, and a dash, like JS" do
      rx = ci.call("(?<=a[x\\S])y")
      expect(rx).not_to be_nil
      %w[axy aéy aQy].each { |v| expect(rx.match?(v)).to be(true), v }
      expect(rx.match?("a y")).to be(false)
      rx = ci.call("(?<=a[\\S-x])y")
      expect(rx).not_to be_nil
      %w[a-y axy ayy].each { |v| expect(rx.match?(v)).to be(true), v }
      expect(rx.match?("a y")).to be(false)
    end

    it "keeps an escape in a lookbehind whole" do
      { "(?<=\\x41)x" => "Ax", "(?<=\\u0041)x" => "Ax", "(?<=a\\101)x" => "aAx" }.each do |pat, v|
        expect(Camada::Snapshot.compile_regex(pat)&.match?(v)).to be(true), pat
        expect(ci.call(pat)&.match?(v.swapcase)).to be(true), pat
      end
    end

    # camada-all-fe1r
    it "splits a one-char class from adjacent literals and splices \\W/\\D like \\S" do
      { "(?<=s[s]s)x" => { "ssx" => false, "sssx" => true, "\u00e9\u00dfx" => false },
        "(?<=[s]s)x" => { "\u00dfx" => false, "ssx" => true },
        "(?<=a[\\W])x" => { "a\ufb00x" => true, "\u00e9a\ufb00x" => true, "aax" => false },
        "(?<=a[\\D])x" => { "\u00e9a\ufb00x" => true, "a1x" => false },
        "(?<=a[\\d\\D])x" => { "\u00e9a\ufb00x" => true, "a1x" => true } }.each do |pat, cases|
        rx = ci.call(pat)
        expect(rx).not_to be_nil, pat
        cases.each { |v, want| expect(Camada::Snapshot.regex_hit?(rx, v, :err)).to be(want), "#{pat} #{v.inspect}" }
      end
      expect(Camada::Snapshot.js_to_onigmo("[s][\\W]x")).to eq("[s][\\W]x")
    end

    it "still reads [^] as any char" do
      rx = ci.call("^a[^]b$")
      expect(rx.match?("a\nb")).to be(true)
      expect(ci.call("(?<=[^])x").match?("\nx")).to be(true)
    end
  end
end

RSpec.describe "Camada::Snapshot.path_hit?" do
  def count(forms, deny, hit = [])
    calls = 0
    res = Camada::Snapshot.path_hit?(forms, deny) do |p|
      calls += 1
      hit.include?(p)
    end
    [res, calls]
  end

  it "tries a repeated path form once" do
    same = Camada::Snapshot.path_forms("/blocked-path")
    expect(same.uniq.size).to eq(1)
    expect(count(same, true)).to eq([false, 1])
    expect(count(same, false)).to eq([false, 1])
    expect(count(same, true, ["/blocked-path"])).to eq([true, 1])
    expect(count(same, false, ["/blocked-path"])).to eq([true, 1])
    distinct = %w[/a /b /c]
    expect(count(distinct, true)).to eq([false, 3])
    expect(count(distinct, true, ["/c"])).to eq([true, 3])
    expect(count(distinct, false, ["/b"])).to eq([false, 2])
    expect(count(distinct, false, %w[/b /c])).to eq([true, 2])
    expect(count(%w[/a /b /b], true)).to eq([false, 2])
  end

  # V8 repeats only the low unit of an astral char: x😀y hits when the count allows 1; xy and x😀😀y never (camada-all-5lra)
  astral_once = %w[? * + ?? *? +? {1} {01} {0,1} {0,2} {1,} {1}?]
  (astral_once + %w[{0} {2} {2,} {2,3}]).each do |q|
    it "reads x😀#{q}y as V8 does" do
      rx = Camada::Snapshot.compile_regex("x😀#{q}y")
      expect(["xy", "x😀y", "x😀😀y"].map { |u| rx.match?(u) }).to eq([false, astral_once.include?(q), false])
    end
  end

  it "keeps a group whole and a non-quantifier brace literal after an astral char" do
    expect(Camada::Snapshot.compile_regex("x(?:😀)?y").match?("xy")).to be(true)
    expect(Camada::Snapshot.compile_regex("x😀{y").match?("x😀{y")).to be(true)
  end

  # V8 repeats only the low unit; the zero-low reading (high unit alone) is not emulated, so these miss (camada-all-5lra)
  [
    ["x😀{0}", "x😀", false], ["x😀{0}.y", "x😀y", false], ["x😀?", "x😁", false], ["x😀?.", "x😁", false],
    ["x😀{0,1}..", "x😁a", false], ["x\\😀{0}", "x😀", false], ["x😀?😁", "x😁", false], ["x😀?\\b", "x😀", false],
    ["x😀?(?<=x)", "x😀", false]
  ].each do |pattern, text, hit|
    it "does not emulate V8's zero-low reading of #{pattern} on #{text.inspect}" do
      expect(Camada::Snapshot.compile_regex(pattern).match?(text)).to be(hit)
    end
  end

  [
    ["x😀{0}y", "x😀y", false], ["x😀{0}y", "xy", false], ["x😀?y", "xy", false],
    ["x\\😀?y", "xy", false], ["x\\😀?y", "x😀y", true], ["x\\😀y", "x😀y", true]
  ].each do |pattern, text, hit|
    it "reads #{pattern} on #{text.inspect} as V8 does" do
      expect(Camada::Snapshot.compile_regex(pattern).match?(text)).to be(hit)
    end
  end

  it "keeps a one-count astral char in a lookbehind" do
    rx = Camada::Snapshot.compile_regex("(?<=a😀?)b")
    expect([rx.match?("a😀b"), rx.match?("ab")]).to eq([true, false])
  end

  it "leaves an m > n count after an astral char as written (a SyntaxError)" do
    expect(Camada::Snapshot.compile_regex("x😀{3,2}")).to be_nil
  end
end
