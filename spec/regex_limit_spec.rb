# frozen_string_literal: true

require "digest"

# Contract regex-limit v1 (camada-all-2pap): the shared vectors, read from the camada-core sibling
# checkout. Each rule is built into a v5 snapshot (blk5/v5-empty.bin + meta with rules = [rule]) and
# matched through the public matcher: hit = the result names the rule.
RSpec.describe "regex limit" do
  vectors_path = Fixtures.path("regex-limit/regex-limit-vectors.json")
  vectors = JSON.parse(File.read(vectors_path))
  budgeted = Regexp.respond_to?(:timeout)
  no_bound = "Ruby #{RUBY_VERSION} has no regex match timeout (needs >= 3.2)"

  def matcher(rules)
    meta = Fixtures.read_json("blk5/v5-empty.meta.json").merge("rules" => rules)
    Camada::Snapshot::Matcher.new(Camada::Snapshot.parse_snapshot(Fixtures.read_bin("blk5/v5-empty.bin"), meta))
  end

  def hit?(rule, input)
    matcher([rule]).match(Camada::Snapshot::MatchInput.new(**input)).rule == rule["id"]
  end

  # {prefix?, repeat, times, suffix?} -> prefix + repeat x times + suffix
  def expand(v) = v.is_a?(Hash) ? "#{v["prefix"]}#{v["repeat"] * v["times"]}#{v["suffix"]}" : v
  def as_input(i) = i.transform_keys(&:to_sym).transform_values { |v| expand(v) }

  it "reads the pinned vectors" do
    expect(Digest::SHA256.file(vectors_path).hexdigest).to eq("b8628729ffe24963f3bf868842f77f644f57edeb7ec0f179208160e3060fffbb")
  end

  it "has the contract constants" do
    c = vectors["constants"]
    expect(Camada::Snapshot::MATCH_BUDGET_MS).to eq(c["MATCH_BUDGET_MS"])
    expect(Camada::Snapshot::REQUEST_REGEX_BUDGET_MS).to eq(c["REQUEST_REGEX_BUDGET_MS"])
    expect(Camada::Snapshot::MAX_MATCH_INPUT).to eq(c["MAX_MATCH_INPUT"])
  end

  it "compiles on every Ruby, bounded where the engine can, without touching the host's Regexp.timeout" do
    rx = Camada::Snapshot.compile_regex("a+")
    expect(rx).to be_a(Regexp)
    next unless budgeted

    expect(rx.timeout).to eq(0.05)
    expect(Regexp.timeout).to be_nil
  end

  vectors["over_limit"].each do |row|
    it "#{row["id"]}: #{row["why"]}" do
      skip no_bound unless budgeted
      expect(hit?(row["rule"], as_input(row["input"]))).to eq(row["hit"]["budget"])
    end
  end

  { "refused" => "native", "accepted_match" => "native", "astral_split" => "ruby" }.each do |key, engine|
    vectors[key].each do |row|
      it "#{row["id"]}: #{row["kind"]} answers per engine" do
        rule = vectors["refused_rule"].merge("conds" => [{ "f" => vectors["refused_rule"]["field"], "op" => "matches", "v" => row["pattern"] }])
        row["cases"].each do |c|
          expect(hit?(rule, ip: "8.8.8.8", ua: expand(c["ua"]))).to eq(c["hit"][engine]), c["ua"].inspect
        end
      end
    end
  end

  it "has rows to run natively" do
    expect(vectors["astral_split"]).not_to be_empty
    expect(vectors["refused"]).not_to be_empty
    expect(vectors["accepted_match"]).not_to be_empty
  end

  describe "request budget" do
    it "answers on_error without running once the budget is spent, and resets after the walk" do
      rx = instance_double(Regexp)
      Camada::Snapshot.with_regex_budget do
        Thread.current[:camada_regex_budget] = 0
        expect(rx).not_to receive(:match?)
        expect(Camada::Snapshot.regex_hit?(rx, "a", true)).to be(true)
        expect(Camada::Snapshot.regex_hit?(rx, "a", false)).to be(false)
      end
      expect(Thread.current[:camada_regex_budget]).to be_nil
    end

    it "limits the sum of the runs in one walk" do
      skip no_bound unless budgeted
      slow = { "f" => "ua", "op" => "matches", "v" => "(?:(?:a|aa){1,10}){1,10}a\\d" }
      rules = Array.new(3) { |k| { "id" => "cr_0000000003a#{k}", "action" => "skip", "conds" => [slow] } }
      rules << { "id" => "cr_0000000003b0", "action" => "skip", "conds" => [{ "f" => "ua", "op" => "matches", "v" => "^a" }] }
      r = matcher(rules).match(Camada::Snapshot::MatchInput.new(ip: "8.8.8.8", ua: "a" * 2048))
      # two slow skips spend the 100 ms, the third answers over-limit unrun (a skip miss), so does ^a
      expect(r.rule).to be_nil
    end
  end

  # camada-all-zpbv: a stored `matches` value that is "" or not a String never matches, over the cap or not.
  describe "a non-string matches value" do
    str = '123 0 1 true {"x"=>1} {"x" => 1} ["^/a"] [123]' # every coerced spelling (Ruby <3.4 and 3.4 Hash#inspect) of the values appears in the input
    big = "a" * (Camada::Snapshot::MAX_MATCH_INPUT + 1)
    blk = { "id" => "cr_blk", "action" => "block", "conds" => [{ "f" => "ip", "op" => "is_not", "v" => "1.1.1.1" }] }

    [123, 0, true, nil, { "x" => 1 }, ["^/a"], [123], ""].each do |v|
      %w[ua path header].each do |f|
        [false, true].each do |over|
          it "#{v.inspect} on #{f}#{" over the cap" if over}: block never matches, skip does not exempt" do
            input = Camada::Snapshot::MatchInput.new(
              ip: "8.8.8.8",
              path: over && f == "path" ? "/a/#{str}/#{big}" : "/a/#{str}",
              ua: over && f == "ua" ? "#{str} #{big}" : str,
              header: ->(_n) { over && f == "header" ? "#{str} #{big}" : str }
            )
            cond = { "f" => f, "op" => "matches", "v" => v }
            cond["name"] = "x-h" if f == "header"
            expect(matcher([{ "id" => "cr_b", "action" => "block", "conds" => [cond] }]).match(input).block).to be(false)
            r = matcher([{ "id" => "cr_s", "action" => "skip", "conds" => [cond] }, blk]).match(input)
            expect(r.rule).to eq("cr_blk")
          end
        end
      end
    end
  end
end
