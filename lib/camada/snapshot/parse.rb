# frozen_string_literal: true

require "set"
require_relative "../constants"
require_relative "../ipparse"

module Camada
  # BLK snapshot parser (v3, v4, v5), ported from @camada/core src/snapshot/parse.ts, itself a
  # port of edge-analyst src/blocklist.js load() (the reference implementation).
  #
  # Container: sectioned little-endian uint32 —
  #   [0] magic 0x424c4b3<version>   [1] section count K
  #   K x [type, offset(words), length(words)]   then the sections.
  # Types: 1 V4_STARTS  2 V4_ENDS  3 V4_IDX16  4 V4_BM24  5 V6_STARTS  6 V6_ENDS  7 V6_BM24
  #        8 ASN_BM  9 ASN_EXTRA.
  # v4 (contracts §A3) adds two side lists as INTERLEAVED range pairs:
  #        10 ALLOW_V4  11 ALLOW_V6  12 CHALLENGE_V4  13 CHALLENGE_V6
  #   *_V4: [start, end, …] (2 words per range, sorted by start)
  #   *_V6: [s0,s1,s2,s3, e0,e1,e2,e3, …] (8 words per range, big-endian word order, sorted by start)
  # v5 (contracts §D3) adds the tenant's ordered custom rules, which run BEFORE the three sides:
  #        14 RULE_V4  15 RULE_V6   — repeated, word 0 = the rule's index into meta.rules, then range
  #   pairs exactly as 10/11. One 14 + one 15 per `ip` condition, in condition order (an empty half
  #   still ships its index word), so a rule with two ip conditions reads two pairs.
  # Meta travels separately: { version, country[], tls[], pathsExact[], pathsPrefix[], pathsRegex[],
  #                            allow?: side, challenge?: side, rules?: [] } with side = { asn[], country[], pathsExact[], pathsPrefix[] }.
  # The version byte is advisory: sections 10-15 are read whenever they are present.
  #
  # A Uint32Array is a `Words` view: one String of bytes read a word at a time with
  # String#unpack1("V", offset:), so a 5 MB container never becomes 1.3 M Integers, and the
  # bitmaps are indexed, never unpacked wholesale. Ruby integers are unbounded, so every
  # `>>> 0` of the original is simply absent.
  module Snapshot
    FORMATS = { 0x424C4B33 => 3, 0x424C4B34 => 4, 0x424C4B35 => 5 }.freeze
    ACTIONS = %w[skip block challenge warn].freeze

    # A read-only uint32 little-endian view over a byte String, from a byte offset, `length` words long.
    class Words
      attr_reader :length

      def initialize(buf, byte_off = 0, length = nil)
        @buf = buf
        @off = byte_off
        @length = length || [(buf.bytesize - byte_off) / 4, 0].max # a trailing partial word is dropped, as the Uint32Array view does
      end

      def [](i) = @buf.unpack1("V", offset: @off + (4 * i))
      def slice(start, len) = Words.new(@buf, @off + (4 * start), len)
      def empty? = @length == 0
    end

    # A zero-filled section of `length` words: what an absent bitmap/index reads as.
    class Zeros
      attr_reader :length

      def initialize(length)
        @length = length
      end

      def [](_i) = 0
      def empty? = @length == 0
    end

    EMPTY = Words.new("".b, 0, 0)

    # A v4 side list. `empty` short-circuits the matcher on the (common) v3 snapshot.
    RangeSet = Struct.new(:r4, :r6, :n6, :asn, :country, :paths_exact, :paths_prefix, :empty, keyword_init: true)

    # The request a compiled condition reads. `ip6` is the parsed address words, or nil; `header`
    # is called with an already lower-cased name, absent where the tap cannot read headers.
    RuleRequest = Struct.new(:n4, :ip6, :asn, :country, :tlsx, :path, :ua, :header, keyword_init: true)

    CompiledRule = Struct.new(:id, :action, :conds)

    Snap = Struct.new(
      :version, :format, :s4, :e4, :idx4, :bm4, :s6, :e6, :n6, :bm6, :asn_bm, :asn_extra,
      :country, :tls, :paths_exact, :paths_prefix, :paths_regex, :allow, :challenge,
      :rules, # v5 only; empty on v3/v4, and the matcher then skips them
      keyword_init: true
    )

    def self.range_set(r4, r6, m)
      m ||= {}
      asn = (m["asn"] || []).to_set(&:to_i)
      country = (m["country"] || []).to_set
      exact = (m["pathsExact"] || []).to_set
      prefix = (m["pathsPrefix"] || []).to_set
      empty = r4.empty? && r6.empty? && asn.empty? && country.empty? && exact.empty? && prefix.empty?
      RangeSet.new(r4: r4, r6: r6, n6: r6.length >> 3, asn: asn, country: country, paths_exact: exact, paths_prefix: prefix, empty: empty)
    end

    # Binary search over interleaved [start, end] uint32 pairs sorted by start.
    def self.in_range4?(r, n)
      lo = 0
      hi = (r.length >> 1) - 1
      return false if hi < 0

      while lo < hi
        m = (lo + hi + 1) >> 1
        if r[m * 2] <= n
          lo = m
        else
          hi = m - 1
        end
      end
      n.between?(r[lo * 2], r[(lo * 2) + 1])
    end

    # Compares the 4 words at a[o..o+3] against the address words.
    def self.cmp_words(a, o, w)
      4.times do |k|
        x = a[o + k]
        y = w[k]
        return x < y ? -1 : 1 if x != y
      end
      0
    end

    # Binary search over an interleaved [4-word start, 4-word end] side section.
    def self.in_range6?(r, n, w)
      return false if n < 1

      lo = 0
      hi = n - 1
      while lo < hi
        m = (lo + hi + 1) >> 1
        if cmp_words(r, m * 8, w) <= 0
          lo = m
        else
          hi = m - 1
        end
      end
      o = lo * 8
      cmp_words(r, o, w) <= 0 && cmp_words(r, o + 4, w) >= 0 # rubocop:disable Style/ComparableBetween -- two different comparisons
    end

    # A pattern this runtime rejects never matches, and never throws (fail open). Patterns are
    # authored as JS regexes (the analyst validates them with `new RegExp`), so the JS spellings
    # Onigmo reads differently are translated first — see js_to_onigmo; \d \w \b are ASCII in
    # Ruby by default, as JS reads them.
    def self.compile_regex(pattern)
      Regexp.new(js_to_onigmo(pattern))
    rescue RegexpError, TypeError, ArgumentError, EncodingError
      nil
    end

    # The JS-only spellings a tenant is likely to author: `[^]` (any char) -> `[\s\S]`, `\cX` ->
    # the control character, and the anchors: JS `^`/`$` bind the whole input while Ruby's are
    # line anchors, so outside a class they become `\A`/`\z`. `(?<name>` is native to Onigmo.
    # Anything else Ruby rejects still fails open.
    def self.js_to_onigmo(pattern)
      out = +""
      i = 0
      n = pattern.length
      in_class = false
      while i < n
        ch = pattern[i]
        if ch == "\\" && i + 1 < n
          if pattern[i + 1] == "c" && i + 2 < n && pattern[i + 2].match?(/[A-Za-z]/)
            out << Regexp.escape((pattern[i + 2].upcase.ord - 64).chr)
            i += 3
            next
          end
          out << pattern[i, 2]
          i += 2
          next
        end
        if in_class
          in_class = ch != "]"
        elsif ch == "["
          if pattern[i, 3] == "[^]"
            out << "[\\s\\S]"
            i += 3
            next
          end
          in_class = true
        elsif ch == "^"
          out << "\\A"
          i += 1
          next
        elsif ch == "$"
          out << "\\z"
          i += 1
          next
        end
        out << ch
        i += 1
      end
      out
    end

    # A regex test that never raises: a value in an encoding the pattern cannot read (a binary
    # PATH_INFO with high bytes, say) reads as "no match" rather than an exception on the request path.
    def self.regex_hit?(rx, value)
      rx.match?(value)
    rescue StandardError
      false
    end

    # The same envelope for the plain string ops: Puma hands every env value to Rack as
    # ASCII-8BIT while a rule's needle arrives from JSON as UTF-8, and `include?` /
    # `start_with?` across that pair raise Encoding::CompatibilityError once either side carries a
    # high byte. The adapter scrubs its values, but the matcher must not depend on it: an
    # exception here escapes match(), handle() falls back to INERT and a blocked client passes.
    def self.text_hit?
      yield
    rescue StandardError
      false
    end

    # ---------- custom rules (v5) ----------

    # The string one condition reads, or nil when this request cannot answer the field.
    # `header` is not here: it needs the condition's own name, so compile_cond builds its reader.
    def self.field_value(f, r)
      case f
      when "asn" then r.asn&.to_s
      when "country" then Camada.present(r.country)
      when "tlsx" then Camada.present(r.tlsx)
      when "path" then r.path
      when "ua" then Camada.present(r.ua)
      end
      # an entity-plane field (bot.verified, rule) answers nil: never true here
    end

    # One condition -> a predicate. `sets` yields this rule's (v4, v6) section pair per ip
    # condition, in condition order, so an ip condition consumes the next one.
    def self.compile_cond(c, sets)
      f = c["f"].to_s
      op = c["op"].to_s
      negate = op == "is_not" || op == "not_in"
      # A header condition reads the request through the caller's getter. The name is lower-cased
      # once, here; a tap that cannot read headers (no getter) and a header the request does not
      # carry are both nil, and nil is false for every op — the rule simply does not fire (fail
      # open, §A4). The getter is app code: one that raises, or answers something other than a
      # String, is read as "no header" rather than allowed to take the whole match() down.
      read =
        if f == "header"
          hname = c["name"].to_s.downcase
          lambda do |r|
            next nil if hname.empty? || r.header.nil?

            v = begin
              r.header.call(hname)
            rescue StandardError
              nil
            end
            v.is_a?(String) ? v : nil
          end
        else
          ->(r) { field_value(f, r) }
        end

      if f == "ip"
        p4, p6 = sets.empty? ? [EMPTY, EMPTY] : sets.shift
        n6 = p6.length >> 3
        return lambda do |r|
          next false if r.n4 < 0 && r.ip6.nil? # no address: false for every op, negatives included

          hit = (r.n4 >= 0 && in_range4?(p4, r.n4)) || (!r.ip6.nil? && in_range6?(p6, n6, r.ip6))
          negate ? !hit : hit
        end
      end
      raw = c["v"]
      values = raw.is_a?(Array) ? raw.map(&:to_s) : [raw.to_s]
      case op
      when "matches"
        rx = compile_regex(values[0])
        lambda do |r|
          v = read.call(r)
          !v.nil? && !rx.nil? && regex_hit?(rx, v)
        end
      when "contains"
        needle = values[0]
        lambda do |r|
          v = read.call(r)
          !v.nil? && text_hit? { v.include?(needle) }
        end
      when "starts_with"
        prefix = values[0]
        lambda do |r|
          v = read.call(r)
          !v.nil? && text_hit? { v.start_with?(prefix) }
        end
      else # is | is_not | is_in | not_in
        members = values.to_set
        lambda do |r|
          v = read.call(r)
          next false if v.nil?

          negate ? !members.include?(v) : members.include?(v)
        end
      end
    end

    # meta.rules + the repeated 14/15 sections -> predicates, in evaluation order. A rule this SDK
    # cannot compile (unknown action, no conditions) is dropped rather than guessed at.
    def self.compile_rules(meta, v4s, v6s)
      out = []
      (meta["rules"] || []).each_with_index do |r, i|
        action = r["action"].to_s
        next unless ACTIONS.include?(action) # an action this SDK does not know: ignore the rule rather than guess

        v4 = v4s.select { |s| s[0] == i }
        v6 = v6s.select { |s| s[0] == i }
        sets = Array.new([v4.length, v6.length].max) do |k|
          [k < v4.length ? v4[k].slice(1, v4[k].length - 1) : EMPTY, k < v6.length ? v6[k].slice(1, v6[k].length - 1) : EMPTY]
        end
        conds = begin
          (r["conds"] || []).map { |c| compile_cond(c, sets) }
        rescue StandardError
          next # a malformed rule is dropped, never enforced
        end
        out << CompiledRule.new(r["id"].to_s, action, conds) unless conds.empty? # a rule with no conditions would match everything
      end
      out
    end

    # Parses a BLK container (a byte String, or a Words view into one) + meta into a Snap. Raises
    # ArgumentError on a malformed container — callers keep the previous snapshot, exactly like
    # the edge collector does.
    def self.parse_snapshot(binary, meta)
      u = binary.is_a?(Words) ? binary : Words.new(binary)
      fmt = u.length >= 2 ? FORMATS[u[0]] : nil
      raise ArgumentError, "camada: not a BLK3 snapshot" unless fmt

      count = u[1]
      sec = {}
      rule4 = []
      rule6 = []
      raise ArgumentError, "camada: truncated BLK3 header" if u.length < 2 + (count * 3)

      count.times do |i|
        t = u[2 + (i * 3)]
        off = u[3 + (i * 3)]
        ln = u[4 + (i * 3)]
        raise ArgumentError, "camada: truncated BLK3 section" if off + ln > u.length

        s = u.slice(off, ln)
        case t
        when 14 then rule4 << s # repeated, one per ip condition: kept in container order
        when 15 then rule6 << s
        else sec[t] = s
        end
      end
      s6 = sec.fetch(5, EMPTY)
      Snap.new(
        version: meta["version"].to_s,
        format: fmt,
        s4: sec.fetch(1, EMPTY), e4: sec.fetch(2, EMPTY), idx4: sec[3] || Zeros.new(65_537), bm4: sec[4] || Zeros.new(524_288),
        s6: s6, e6: sec.fetch(6, EMPTY), n6: s6.length / 4, bm6: sec[7] || Zeros.new(524_288),
        asn_bm: sec[8] || Zeros.new(131_072), asn_extra: sec.fetch(9, EMPTY),
        country: (meta["country"] || []).to_set,
        tls: (meta["tls"] || []).to_set,
        paths_exact: (meta["pathsExact"] || []).to_set,
        paths_prefix: (meta["pathsPrefix"] || []).to_set,
        paths_regex: (meta["pathsRegex"] || []).filter_map { |p| compile_regex(p) },
        allow: range_set(sec.fetch(10, EMPTY), sec.fetch(11, EMPTY), meta["allow"]),
        challenge: range_set(sec.fetch(12, EMPTY), sec.fetch(13, EMPTY), meta["challenge"]),
        rules: compile_rules(meta, rule4, rule6)
      )
    end
  end
end
