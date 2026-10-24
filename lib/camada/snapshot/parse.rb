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
    # `paths` is the request path's [raw, lit, full] forms (Snapshot.path_forms).
    RuleRequest = Struct.new(:n4, :ip6, :asn, :country, :tlsx, :paths, :ua, :header, keyword_init: true)

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
      exact = (m["pathsExact"] || []).to_set { |p| canon_path(p.to_s) }
      prefix = (m["pathsPrefix"] || []).to_set { |p| dir_key(p.to_s) }
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
    # Ruby by default, as JS reads them. An astral char is one code point here and two UTF-16 units
    # in JS, so `.`, `[^a]` and `\S` count it once (an accepted gap, camada-all-vuvo).
    def self.compile_regex(pattern, options = 0)
      source = js_to_onigmo(pattern)
      verbose = $VERBOSE
      begin
        $VERBOSE = nil # `[a\S]` expands to a class with a duplicated range; Onigmo warns under -w, matching is right
        Regexp.new(source, options)
      ensure
        $VERBOSE = verbose
      end
    rescue RegexpError, TypeError, ArgumentError, EncodingError
      nil
    end

    # The capture groups of a JS pattern in number order: the name, or nil for an unnamed group.
    def self.capture_group_names(pattern)
      names = []
      in_class = false
      i = 0
      while i < pattern.length
        ch = pattern[i]
        if ch == "\\"
          i += 1
        elsif in_class
          in_class = false if ch == "]"
        elsif ch == "["
          in_class = true
        elsif ch == "(" && pattern[i + 1] != "?"
          names << nil
        elsif (m = pattern.match(/\G\(\?<([^=!>][^>]*)>/, i))
          names << m[1]
        end
        i += 1
      end
      names
    end

    JS_BRACE = /\G\{[0-9]+(?:,[0-9]*)?\}/
    JS_WS = "\\t-\\r\\u0020\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff" # JS \s (Ruby's is ASCII)
    JS_SPACE = { "s" => "[#{JS_WS}]", "S" => "[^#{JS_WS}]" }.freeze
    JS_ATOM = /\G(?:\\(?:c[A-Za-z]|x\h{2}|u\h{4}|[0-3][0-7]{0,2}|[4-7][0-7]?|[\s\S])|[\s\S])/ # one class atom
    JS_DOT = "[^\\n\\r\\u2028\\u2029]" # JS . (Onigmo's excludes only \n)
    JS_ESCAPE = /\G(?:[bdDfnrsStvwW]|x\h{2}|u\h{4})/ # the letter escapes JS reads without `u`

    # The JS-only spellings a tenant is likely to author: `[^]` (any char) -> `[\s\S]`, `\cX` ->
    # the control character, and the anchors: JS `^`/`$` bind the whole input while Ruby's are
    # line anchors, so outside a class they become `\A`/`\z`; a `{` that is no JS quantifier
    # (`{,3}`, `{ 1}`) -> `\{` (JS reads it as text, Onigmo as a bound), and `x{n}?` -> `x{n}` (JS
    # reads it as exact-n, Onigmo as optional). `\<letter>` outside JS's escape set is the bare
    # letter, as JS reads it without `u` (`\p{L}` is "p{L}", `\A` is "A"). `.` -> JS_DOT, `[]` ->
    # `(?!)` (never matches; a `]` right after `[`/`[^` closes the class, a stray `]` -> `\]`), and
    # `\s`/`\S` -> the JS whitespace set; inside a class they nest as a class
    # (`[a\s]` -> `[a[WS]]`: one atom, no ReDoS, fine in a lookbehind), a `-` beside one stays a literal dash, as in JS,
    # and so does a `-` right after the atom that follows it.
    # A literal `[` or `&` in a class is escaped (no nesting, POSIX class or `&&`, as in JS).
    # `(?<name>` is native to Onigmo. Anything else Ruby rejects still fails open.
    def self.js_to_onigmo(pattern)
      out = +""
      i = 0
      n = pattern.length
      in_class = false
      pull_end = solo_end = -1 # where the last in-class \\s/\\S ended; where the atom after its dash ended
      named = pattern.match?(/\(\?<(?![=!])/)
      group_names = named ? capture_group_names(pattern) : []
      while i < n
        ch = pattern[i]
        if ch == "\\" && i + 1 < n
          l = pattern[i + 1]
          if l == "s" || l == "S"
            out << JS_SPACE[l] # in a class too: Onigmo nests classes, one atom, safe in a lookbehind
            pull_end = i + 2 if in_class
            i += 2
            next
          end
          if l == "c" && i + 2 < n && pattern[i + 2].match?(/[A-Za-z]/)
            out << Regexp.escape((pattern[i + 2].upcase.ord - 64).chr)
            i += 3
            next
          end
          if named && !in_class && (m = pattern.match(/\G[1-9][0-9]*/, i + 1)) && (m[0].to_i <= group_names.length)
            nm = group_names[m[0].to_i - 1] # Onigmo rejects a numbered backreference beside named groups
            if nm
              out << "\\k<#{nm}>"
              i += 1 + m[0].length
              next
            end
          end
          kept = !l.match?(/[A-Za-z]/) || pattern.match?(JS_ESCAPE, i + 1) || (l == "B" && !in_class) ||
                 (l == "k" && named) || (l == "c" && in_class)
          l = "\\\\c" if l == "c" # JS reads `\c` before a non-letter as text
          out << (kept ? pattern[i, 2] : l)
          i += 2
          next
        end
        if in_class
          if ch == "]"
            in_class = false
            out << "]"
            i += 1
            next
          end
          if ch == "-" && (pull_end == i || solo_end == i || pattern.match?(/\G-\\[sS]/, i))
            if pull_end == i # JS reads the atom after that dash as standalone: a dash right after it is text too
              m = pattern.match(JS_ATOM, i + 1) # nil when the pattern ends on the dash
              solo_end = m ? i + 1 + m[0].length : pattern.length
            end
            ch = "\\-"
          end
          ch = "\\#{ch}" if ch == "[" || ch == "&" # JS: `[[:alpha:]]` is {[ : a l p h} then `]`
        elsif ch == "."
          out << JS_DOT
          i += 1
          next
        elsif ch == "]"
          out << "\\]"
          i += 1
          next
        elsif ch == "["
          neg = pattern[i + 1] == "^"
          j = i + (neg ? 2 : 1)
          if pattern[j] == "]"
            out << (neg ? "[\\s\\S]" : "(?!)")
            i = j + 1
            next
          end
          out << pattern[i...j]
          i = j
          in_class = true
          next
        elsif ch == "^"
          out << "\\A"
          i += 1
          next
        elsif ch == "$"
          out << "\\z"
          i += 1
          next
        elsif ch == "{"
          m = pattern.match(JS_BRACE, i)
          out << (m ? m[0] : "\\{")
          i += m ? m[0].length : 1
          i += 1 if m && !m[0].include?(",") && pattern[i] == "?"
          next
        end
        out << ch
        i += 1
      end
      out
    end

    # A regex test that never raises: a value in an encoding the pattern cannot read (a binary
    # PATH_INFO with high bytes, say) reads as "no match" rather than an exception on the request path.
    #
    # `on_error` is what a value the engine cannot read answers. The legacy block-side path regexes
    # keep false; a custom `matches` rule passes `deny` (regex-cap-sdk v1: an unevaluable value is a
    # hit for block/challenge/warn and a miss for skip, the same as an over-cap one, camada-all-cwb4).
    def self.regex_hit?(rx, value, on_error = false)
      rx.match?(utf8_view(value))
    rescue StandardError
      on_error
    end

    # A value tagged ASCII-8BIT (Rack) whose bytes are valid UTF-8 is read as UTF-8, so a non-ASCII
    # pattern neither raises nor flips a deny/skip outcome. Genuinely invalid bytes stay as they are
    # and take the on_error path.
    def self.utf8_view(v)
      return v if v.encoding == Encoding::UTF_8

      s = v.dup.force_encoding(Encoding::UTF_8)
      s.valid_encoding? ? s : v
    end

    # regex-cap-sdk v1 S1: the longest value a `matches` regex runs on, in UTF-16 code units.
    MAX_MATCH_INPUT = 2048

    # Length in UTF-16 code units (what edge's `v.length` counts: an astral code point is 2). A String
    # that is not valid UTF-8 (Rack hands over ASCII-8BIT) counts its bytes.
    def self.utf16_len(v)
      s = v.dup.force_encoding(Encoding::UTF_8)
      return v.bytesize unless s.valid_encoding?

      s.length + s.each_char.count { |c| c.ord > 0xFFFF }
    end

    def self.over_cap?(v)
      v.bytesize > MAX_MATCH_INPUT && utf16_len(v) > MAX_MATCH_INPUT
    end

    # regex-cap-sdk S2: delete [\x00-\x1f\x7f] from a ua/header value before a `matches` regex runs.
    # Bytewise, so it stays safe on invalid UTF-8.
    def self.strip_control(v)
      v.b.delete("\x00-\x1f\x7f").force_encoding(v.encoding)
    end

    # regex-cap-sdk S3: a raw control character in the raw path form is spelled %xx, as canon_path does.
    def self.encode_control(p)
      b = p.b
      return p unless b.match?(/[\x00-\x1f\x7f]/n)

      b.gsub(/[\x00-\x1f\x7f]/n) { |c| format("%%%02x", c.ord) }.force_encoding(p.encoding)
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

    # ---------- paths (contracts §D3 "Path matching") ----------
    # A port of edge-analyst src/blocklist.js canonPath / pathForms / pathHit / pathPred. Both sides
    # of a comparison are canonicalised so a rule catches every spelling a framework routes to the
    # same handler: query cut at ? or #; per UTF-8 byte, %XX decoded when printable ASCII other
    # than / and % (%2F stays %2f, one pass), every other byte written as lower-case %xx; ASCII
    # lower-cased; each segment cut at its first ;; empty segments dropped; . and .. resolved
    # (`full`; `lit` skips that step). A deny matches on raw, lit or full; an exemption (allow
    # side, skip rule) needs lit AND full. Works on bytes, so a binary PATH_INFO never raises.
    PATH_HEX = "0123456789abcdef"
    CANON_PATH = %r{\A(?:/(?!\.\.?(?:/|\z))[a-z0-9\-._~!$&'()*+,=:@]+)+\z} # already canonical: skips the byte walk

    def self.hexv(c)
      if c.between?(48, 57) then c - 48
      elsif c.between?(97, 102) then c - 87
      elsif c.between?(65, 70) then c - 55
      else -1
      end
    end

    def self.strip_query(raw)
      p = raw.nil? || raw.empty? ? "/" : raw
      q = p.b.index(/[?#]/)
      q.nil? ? p : p.byteslice(0, q)
    end

    def self.canonical?(p) = p == "/" || (p.ascii_only? && CANON_PATH.match?(p))

    def self.canon_path(raw, dots: true)
      p = strip_query(raw)
      return p if canonical?(p)

      b = p.bytes
      s = +""
      i = 0
      while i < b.length
        c = b[i]
        decoded = c == 37 && i + 2 < b.length && hexv(b[i + 1]) >= 0 && hexv(b[i + 2]) >= 0
        if decoded
          c = (hexv(b[i + 1]) * 16) + hexv(b[i + 2])
          i += 2
        end
        if decoded && c == 47 then s << "%2f" # a decoded %2F is never a separator
        elsif c < 0x21 || c > 0x7e || c == 37 then s << "%" << PATH_HEX[c >> 4] << PATH_HEX[c & 15]
        else s << (c.between?(65, 90) ? c + 32 : c).chr
        end
        i += 1
      end
      out = []
      s.split("/").each do |seg|
        k = seg.index(";")
        seg = seg[0, k] unless k.nil?
        next if seg.empty? || (dots && seg == ".")

        if dots && seg == ".."
          out.pop
          next
        end
        out << seg
      end
      "/#{out.join("/")}"
    end

    # [raw (query cut), lit, full] for one request path.
    def self.path_forms(raw)
      p = strip_query(raw)
      return [p, p, p] if canonical?(p)

      [encode_control(p), canon_path(p, dots: false), canon_path(p)]
    end

    def self.path_dir(p) = p.end_with?("/") ? p : "#{p}/"

    # A prefix entry or a starts_with value ending in / -> its canonical directory key ('/' stays '/').
    def self.dir_key(v) = path_dir(canon_path(v))

    # Walks '/' boundaries: /a/b tries /, /a/, /a/b/.
    def self.prefix_hit?(prefixes, path)
      d = path_dir(path).b
      i = 0
      until i.nil?
        return true if prefixes.include?(d.byteslice(0, i + 1))

        i = d.index("/", i + 1)
      end
      false
    end

    # One path form against a side's (or the block side's) exact, prefix and regex entries.
    def self.path_in?(st, path, regexes = [])
      return true if st.paths_exact.include?(path)
      return true if !st.paths_prefix.empty? && prefix_hit?(st.paths_prefix, path)

      regexes.any? { |rx| regex_hit?(rx, path) }
    end

    # Does the block hold for this request's path? deny = any spelling; an exemption = both canonical forms.
    def self.path_hit?(forms, deny, &pred)
      deny ? (pred.call(forms[0]) || pred.call(forms[1]) || pred.call(forms[2])) : (pred.call(forms[1]) && pred.call(forms[2]))
    end

    # One path condition -> a predicate over a single path form. A `matches` form over MAX_MATCH_INPUT
    # never runs the regex: it answers `deny` (a hit for block/challenge/warn, a miss for skip), and so
    # does a form the regex engine cannot read.
    def self.path_pred(op, values, deny = true)
      case op
      when "matches"
        rx = compile_regex(values[0], Regexp::IGNORECASE)
        ->(p) { !rx.nil? && (over_cap?(p) ? deny : regex_hit?(rx, p, deny)) }
      when "starts_with"
        v = values[0]
        key = v.end_with?("/") ? dir_key(v) : canon_path(v)
        ->(p) { text_hit? { path_dir(p).start_with?(key) } }
      else
        set = values.to_set { |v| canon_path(v) }
        ->(p) { set.include?(p) }
      end
    end

    # ---------- custom rules (v5) ----------

    # The string one condition reads, or nil when this request cannot answer the field.
    # `header` is not here: it needs the condition's own name, so compile_cond builds its reader.
    def self.field_value(f, r)
      case f
      when "asn" then r.asn&.to_s
      when "country" then Camada.present(r.country)
      when "tlsx" then Camada.present(r.tlsx)
      when "ua" then Camada.present(r.ua)
      end
      # an entity-plane field (bot.verified, rule) answers nil: never true here
    end

    # One condition -> a predicate. `sets` yields this rule's (v4, v6) section pair per ip
    # condition, in condition order, so an ip condition consumes the next one.
    def self.compile_cond(c, sets, deny = true)
      f = c["f"].to_s
      op = c["op"].to_s
      if f == "path" # every path op reads the canonical forms (see "paths" above)
        raw = c["v"]
        pred = path_pred(op, raw.is_a?(Array) ? raw.map(&:to_s) : [raw.to_s], deny)
        return ->(r) { path_hit?(r.paths, deny, &pred) }
      end
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
        strip = f == "ua" || f == "header"
        lambda do |r|
          v = read.call(r)
          next false if v.nil? || rx.nil?

          # The cap comes before regex_hit?, whose rescue would turn an encoding error into a miss.
          hit = ->(s) { over_cap?(s) ? deny : regex_hit?(rx, s, deny) }
          next hit.call(v) unless strip

          stripped = strip_control(v) # one scan (S5)
          next hit.call(v) if stripped.bytesize == v.bytesize

          # S5: control chars never widen a skip and never neuter a deny regex
          deny && (hit.call(v) || hit.call(stripped))
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
          (r["conds"] || []).map { |c| compile_cond(c, sets, action != "skip") }
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
        paths_exact: (meta["pathsExact"] || []).to_set { |p| canon_path(p.to_s) },
        paths_prefix: (meta["pathsPrefix"] || []).to_set { |p| dir_key(p.to_s) },
        paths_regex: (meta["pathsRegex"] || []).filter_map { |p| compile_regex(p, Regexp::IGNORECASE) },
        allow: range_set(sec.fetch(10, EMPTY), sec.fetch(11, EMPTY), meta["allow"]),
        challenge: range_set(sec.fetch(12, EMPTY), sec.fetch(13, EMPTY), meta["challenge"]),
        rules: compile_rules(meta, rule4, rule6)
      )
    end
  end
end
