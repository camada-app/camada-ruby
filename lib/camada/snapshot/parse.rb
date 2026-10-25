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

    # regex-limit v1: the longest one customer regex may run, and what one request's rule walk may spend on all of them.
    MATCH_BUDGET_MS = 50
    REQUEST_REGEX_BUDGET_MS = 100
    MATCH_TIMEOUT = Regexp.respond_to?(:timeout) ? MATCH_BUDGET_MS / 1000.0 : nil

    # Runs the block with a fresh per-request regex budget (seconds left, in request-scoped state), reset in ensure.
    def self.with_regex_budget
      Thread.current[:camada_regex_budget] = REQUEST_REGEX_BUDGET_MS / 1000.0
      yield
    ensure
      Thread.current[:camada_regex_budget] = nil
    end

    # A pattern this runtime rejects never matches, and never throws (fail open). Patterns are
    # authored as JS regexes (the analyst validates them with `new RegExp`), so the JS spellings
    # Onigmo reads differently are translated first — see js_to_onigmo; \d \w \b are ASCII in
    # Ruby by default, as JS reads them. An astral char is one code point here and two UTF-16 units
    # in JS, so `.`, `[^a]` and `\S` count it once (an accepted gap, camada-all-vuvo). Onigmo also diverges from JS on a
    # repeated capture group whose body can match empty, even with no backreference: `((x?[ab]*)+?[ab]){2}` on 'aa'
    # matches in JS, not here (an accepted gap, camada-all-mx0s).
    # A backreference JS and Onigmo read differently is rewritten or, when it cannot be, fails open (scan_groups).
    # A `(?` or `(*` group JS lacks (`(?i)`, `(?>`, `(*FAIL)`, ...) fails open too: JS rejects it or V8 mis-evaluates it (camada-all-lsl8).
    # Only a UTF-8 or ASCII pattern is walked: snapshot patterns arrive as UTF-8 JSON, and the binary walk
    # misreads other encodings.
    def self.compile_regex(pattern, options = 0)
      return nil unless pattern.is_a?(String) && (pattern.encoding == Encoding::UTF_8 || pattern.ascii_only?)

      bin = pattern.b # the one binary copy both walks read (O(1) indexing; the syntax is ASCII)
      scan = scan_groups(bin)
      return nil if scan[1]

      source = js_to_onigmo(bin, scan).force_encoding(pattern.encoding)
      verbose = $VERBOSE
      begin
        $VERBOSE = nil # `[a\S]` expands to a class with a duplicated range; Onigmo warns under -w, matching is right
        # Ruby >= 3.2: a per-regex match bound (regex-limit v1). Never the global Regexp.timeout, that is the host app's.
        # Ruby 3.1 has no match-time bound and rejects the keyword, so it compiles without it.
        MATCH_TIMEOUT ? Regexp.new(source, options, timeout: MATCH_TIMEOUT) : Regexp.new(source, options)
      ensure
        $VERBOSE = verbose
      end
    rescue RegexpError, TypeError, ArgumentError, EncodingError
      nil
    end

    # One escape/class-aware walk: [the capture groups of a JS pattern in number order (the name, or
    # nil when unnamed), whether the pattern fails open, {reference position => [end position, :empty or :cond]}].
    # JS reads a backreference to a group that has not captured as empty and clears captures each
    # iteration; Onigmo fails it and keeps the last capture. A reference to a group not closed before
    # it (forward or self) is always empty in JS: kind :empty, written `(?:)`. One to a group that may not have
    # captured (it or an enclosing group is followed by a min-0 quantifier or sits in a negative lookaround, or
    # it lies in an alternation branch: a `|` in an enclosing group or at top level) becomes the conditional
    # `(?(N)\N)` (kind :cond; unset reads as empty), unless the group or an ancestor repeats (an empty last iteration
    # makes Onigmo overwrite the capture, JS rejects that iteration and keeps it and the per-iteration reset
    # diverges) or the group sits inside a positive lookahead (a lookahead keeps its first successful path, and JS tries the
    # paths in another order and rejects an empty optional iteration): fail open. So does a plain reference (the group
    # closed before it, always captured) to a group that sits in, or is, a repeated body that can match empty
    # (`(b*)+x\1`): the walk tracks per frame whether its body must consume input (solid) or can match empty (nullable).
    # A reference inside that repeat reads its own iteration's capture and stays compiled. So does a backward reference to a
    # name two groups share (JS allows that in separate
    # branches; Onigmo reads another group). A backreference inside a lookbehind, or to a group with a lookbehind
    # ancestor, fails open too: JS matches a lookbehind right to left ("closed before the reference" is backwards
    # there; a quantified group keeps its leftmost repetition). Beside named groups, a `\k<name>` naming no group
    # is a JS SyntaxError: fail open (Onigmo aborts the process on it).
    # So does a plain reference to a group in a positive lookahead that holds a quantified frame with optional
    # iterations and a body that can match empty (JS rejects the empty iteration, so the lookahead's first success differs).
    # Walks a binary copy (O(1) indexing; the syntax is ASCII), so the names come back binary.
    # After the walk one forward pass over the frames (a parent precedes its children) settles, per
    # frame, what its ancestors imply, so each reference costs O(1) however deeply its group nests.
    def self.scan_groups(pattern)
      pattern = binary(pattern)
      return [[], false, {}] unless pattern.match?(/\\[1-9k]/) # no reference: nothing reads the names or can diverge

      cur = { parent: nil }
      frames = [cur] # every group, capturing or not, in `(` order
      groups = [] # capture groups in number order
      refs = [] # [position, number or name]
      in_class = false
      i = 0
      while i < pattern.length
        ch = pattern[i]
        if ch == "\\"
          if in_class
            refs << [i, :bad, cur, i + 2] if pattern[i + 1] == "k" # `[\k]` is a SyntaxError beside named groups
          elsif (m = pattern.match(/\G(?:k<([^<>]*)>|([1-9][0-9]*)|(k))/, i + 1))
            refs << [i, m[3] ? :bad : m[1] || m[2].to_i, cur, m.end(0)]
            i = m.end(0) - 2 # the reference is no atom: skip its name or digits (the loop's step and the one below)
          elsif (m = ESC_ATOM.match(pattern, i))
            cur[:solid] = true unless min_zero?(pattern, m.end(0))
            i = m.end(0) - 2
          end
          i += 1
        elsif in_class
          if ch == "]"
            in_class = false
            cur[:solid] = true unless min_zero?(pattern, i + 1)
          end
        elsif ch == "["
          in_class = true
        elsif ch == "("
          cur = { parent: cur, neg: pattern.match?(/\G\(\?<?!/, i), lb: pattern.match?(/\G\(\?<[=!]/, i), la: pattern.match?(/\G\(\?=/, i) }
          frames << cur
          if pattern[i + 1] != "?"
            groups << cur
          elsif (m = pattern.match(/\G\(\?<([^=!<>][^<>]*)>/, i))
            groups << cur.merge!(name: m[1])
          end
          if (m = pattern.match(/\G\(\?(?:<[=!]|<[^<>]*>|[A-Za-z-]*:|[=!])/, i))
            i = m.end(0) - 1 # the group's prefix is no atom
          end
        elsif ch == ")" && cur[:parent]
          cur[:end] = i
          b = pattern.match(JS_BRACE, i + 1)
          cur[:zero] = min_zero?(pattern, i + 1)
          cur[:nullable] ||= !cur[:solid] || cur[:lb] || cur[:la] || cur[:neg] # a lookaround consumes nothing
          cur[:rep] = pattern.match?(/\G[+*]/, i + 1) || (b && (b[2] ? b[3].empty? || over_one?(b[3]) : over_one?(b[1]))) # repeats
          cur[:holds] ||= (cur[:zero] || cur[:rep]) && cur[:nullable] # it or a frame inside it: an optional nullable repeat
          cur[:parent][:holds] ||= cur[:holds]
          closed = cur
          cur = cur[:parent]
          cur[:solid] = true unless closed[:nullable] || closed[:zero] # the branch now holds an atom that must consume
        elsif ch == "|"
          cur[:alt] = true
          cur[:nullable] ||= !cur[:solid]
          cur[:solid] = false
        elsif ch == "{" && (b = pattern.match(JS_BRACE, i))
          i = b.end(0) - 1 # a quantifier, not an atom
        elsif ch.ord >= 0xC0 || (ch.ord < 0x80 && !"^$?*+".include?(ch))
          e = i + 1
          e += 1 while e < pattern.length && pattern.getbyte(e).between?(0x80, 0xBF)
          cur[:solid] = true unless min_zero?(pattern, e)
          i = e - 1
        end
        i += 1
      end
      return [[], false, {}] if refs.empty? # an escaped backslash or a class `[\1]` is no reference

      names = groups.map { |g| g[:name] }
      index = names.each_with_index.reverse_each.to_h # name => first group number - 1
      named = names.any?
      frames.drop(1).each do |f|
        p = f[:parent]
        f[:la_div] = (f[:la] && f[:holds]) || p[:la_div]
        f[:in_lb] = f[:lb] || p[:in_lb]
        f[:unset] = f[:zero] || f[:neg] || p[:alt] || p[:unset] # may not have captured when a reference runs
        f[:rep_above] = p[:rep] || p[:rep_above] # a strict ancestor repeats
        f[:in_la] = f[:la] || p[:in_la] # inside a positive lookahead
        f[:rn] = f[:rep] && f[:nullable] ? f : p[:rn] # innermost repeating frame (or ancestor) whose body can match empty
      end
      dups = names.compact.tally.select { |_, c| c > 1 }
      plan = {}
      diverges = refs.any? do |pos, ref, home, stop|
        next named if ref == :bad # a `\k` not followed by `<name>`: a SyntaxError beside named groups

        k = if ref.is_a?(String)
              index[ref]
            else
              ref <= groups.length ? ref - 1 : nil
            end
        next named && ref.is_a?(String) unless k # a name with no group beside named groups: a JS SyntaxError

        g = groups[k]
        next true if home[:in_lb] || g[:in_lb]

        unless g[:end] && g[:end] < pos
          plan[pos] = [stop, :empty] # never captured yet: empty, and a quantifier after it keeps its atom
          next false
        end
        next true if g[:name] && dups[g[:name]] # JS allows a name in two branches; Onigmo reads another group
        # a repeat that can match empty: Onigmo's last empty iteration overwrites the capture, JS keeps it
        next true if (rn = g[:rn]) && rn[:end] < pos

        next true if g[:la_div]
        next false unless g[:unset]
        next true if g[:rep_above] || g[:rep] || g[:in_la]

        plan[pos] = [stop, :cond]
        false
      end
      [names, diverges, plan]
    end

    # Whether the text at j starts a min-0 quantifier (`?`, `*`, `{0}`, `{0,}`, `{0,m}`).
    def self.min_zero?(pattern, j)
      c = pattern.getbyte(j)
      return true if c == 0x3F || c == 0x2A # ? *
      return false unless c == 0x7B # {

      b = pattern.match(JS_BRACE, j)
      !b.nil? && b[1].delete("0").empty?
    end

    JS_BRACE = /\G\{([0-9]+)(?:(,)([0-9]*))?\}/
    ONIGMO_REPEAT_MAX = 100_000 # Onigmo rejects a repeat number above this ("too big number for repeat range")
    JS_WS = "\\t-\\r\\u0020\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff" # JS \s (Ruby's is ASCII)
    JS_SPACE = { "s" => "[#{JS_WS}]", "S" => "[^#{JS_WS}]" }.freeze
    ANY_CHAR = '[\x00-\x7f]|[\xc0-\xff][\x80-\xbf]*|[\s\S]' # one char of a binary UTF-8 string, whole
    JS_ATOM = /\G(?:\\(?:c[A-Za-z0-9_]|x\h{2}|u\h{4}|[0-3][0-7]{0,2}|[4-7][0-7]?|(?!c)(?:#{ANY_CHAR}))|#{ANY_CHAR})/n # one class atom
    # One escape that must consume input (nil where it may match empty: \b \B, \c without a letter, a trailing \).
    # An unsure escape is no match: calling it nullable only fails open, splitting an atom would not.
    ESC_ATOM = /\G\\(?:c[A-Za-z]|x\h{2}|u\h{4}|0[0-7]{0,2}|(?![bBc])(?:#{ANY_CHAR}))/n
    JS_DOT = "[^\\n\\r\\u2028\\u2029]" # JS . (Onigmo's excludes only \n)
    NON_JS_GROUP = /\G\((?:\*|\?(?![:=!<]))/ # a `(?` or `(*` opening none of the JS forms `(?:` `(?=` `(?!` `(?<`
    JS_OPENER = /\G\((?:\?(?:[:=!]|(<)[=!]))?/ # an unnamed group's opener; the capture is set for a lookbehind
    JS_GROUP = /\G\(\?<(?![=!])([^<>]*)>/n # a named group's opener: a JS name holds no `<` or `>`
    JS_NAME = /\A[\p{ID_Start}$_][\p{ID_Continue}$\u200c\u200d]*\z/ # a JS group name
    JS_ESCAPE = /\G(?:[bdDfnrsStvwW]|x\h{2}|u\h{4})/ # the letter escapes JS reads without `u`

    # The JS-only spellings a tenant is likely to author: `[^]` (any char) -> `(?m:.)`, `\cX` ->
    # the control character, and the anchors: JS `^`/`$` bind the whole input while Ruby's are
    # line anchors, so outside a class they become `\A`/`\z`; a `{` that is no JS quantifier
    # (`{,3}`, `{ 1}`) -> `\{` (JS reads it as text, Onigmo as a bound), and `x{n}?` -> `x{n}` (JS
    # reads it as exact-n, Onigmo as optional). `\<letter>` outside JS's escape set is the bare
    # letter, as JS reads it without `u` (`\p{L}` is "p{L}", `\A` is "A"). `.` -> JS_DOT, `[]` ->
    # `(?!)` (never matches; a `]` right after `[`/`[^` closes the class, a stray `]` -> `\]`), and
    # `\s`/`\S` -> the JS whitespace set; inside a class they nest as a class
    # (`[a\s]` -> `[a[WS]]`: one atom, no ReDoS), a `-` beside one stays a literal dash, as in JS,
    # and so does a `-` right after the atom that follows it.
    # Under IGNORECASE Onigmo folds several chars at once (`ss` ~ ß, and a positive class holding
    # `\S` gains such folds), which makes a lookbehind variable-length and uncompilable; JS folds one
    # char at a time. So inside a lookbehind adjacent literal chars are split with `(?:)` (`ab` -> `a(?:)b`; a
    # lone literal stays a plain string node, which Onigmo can still expand for a multi-char fold) and a positive
    # class with `\S` becomes `(?:[^WS]|[rest])` (camada-all-ccjo).
    # In a class `\c` is a control char only before a letter, digit or `_` (ClassControlLetter); before
    # anything else (`[\c*]`) it is a literal `\` then `c` (camada-all-mqcb).
    # A `{m,n}` bound above Onigmo's 100000 is clamped: m to 100000, and an n above it drops (`{m,}`,
    # exact for any input shorter than n), where JS accepts it (camada-all-yh2t).
    # A literal `[` or `&` in a class is escaped (no nesting, POSIX class or `&&`, as in JS).
    # `(?<name>` and `\k<name>` are copied verbatim once the name fits JS's grammar (JS_NAME); a name
    # used twice is kept only when the twins sit in different alternatives of one disjunction (JS
    # throws otherwise), and then no backreference may exist (camada-all-7xyl). Anything else Ruby
    # rejects still fails open.
    # Raises RegexpError on a group JS lacks (see compile_regex).
    # `scan` is the scan_groups result (default: scan the pattern). Walks a binary copy (O(1) indexing
    # on a non-ASCII pattern) and returns the pattern's encoding.
    def self.js_to_onigmo(pattern, scan = nil)
      enc = pattern.encoding
      pattern = binary(pattern)
      out = String.new(encoding: Encoding::BINARY)
      i = 0
      n = pattern.length
      in_class = false
      pull_end = solo_end = -1 # where the last in-class \\s/\\S ended; where the atom after its dash ended
      group_names, _, plan = scan || scan_groups(pattern)
      named = group_names.any?
      opens = [] # the unclosed `(` indices outside a class
      bars = [-1] # per open group, the root first: the index of the last `|` in it or an ancestor
      lbs = [false] # per open group, the root first: inside a lookbehind (camada-all-ccjo)
      lit_end = -1 # the pattern index right after the last literal emitted inside a lookbehind
      class_start = nil # the out index of an open positive class's `[` inside a lookbehind
      class_alts = [] # the `\S`/`\W`/`\D` that class held
      last_named = {} # name -> the index of its last opener
      while i < n
        ch = pattern[i]
        if ch == "\\" && i + 1 < n
          if !in_class && (r = plan[i])
            if r[1] == :empty
              out << "(?:)"
            else
              ref = pattern[(i + 1)...r[0]]
              nm = ref.start_with?("k") ? ref[2..-2] : (named && group_names[ref.to_i - 1])
              out << (nm ? "(?(<#{nm}>)\\k<#{nm}>)" : "(?(#{ref})\\#{ref})")
            end
            i = r[0]
            next
          end
          l = pattern[i + 1]
          if in_class && class_start && (l == "S" || l == "W" || l == "D")
            class_alts << (l == "S" ? JS_SPACE["S"] : "\\#{l}") # spliced in at the `]`: a positive class holding one gains multi-char folds
            pull_end = i + 2 if l == "S"
            i += 2
            next
          end
          if l == "s" || l == "S"
            out << JS_SPACE[l] # in a class too: Onigmo nests classes, one atom
            pull_end = i + 2 if in_class
            i += 2
            next
          end
          if l == "c" && pattern[i + 2]&.match?(in_class ? /[A-Za-z0-9_]/ : /[A-Za-z]/) # JS Annex B: `[\c1]` too
            out << Regexp.escape((pattern[i + 2].ord & 0x1F).chr)
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
          if named && !in_class && l == "k" && (m = pattern.match(/\G\\k<[^<>]*>/n, i))
            out << m[0] # a `$` in the name is no anchor; scan_groups failed open on a name no group has
            i += m[0].length
            next
          end
          kept = !l.match?(/[A-Za-z]/) || pattern.match?(JS_ESCAPE, i + 1) || (l == "B" && !in_class) ||
                 (l == "k" && named)
          l = "\\\\c" if l == "c" # JS reads `\c` before a non-letter as text
          if kept
            e = (pattern.match(/\G\\\d+/n, i) || pattern.match(JS_ATOM, i))[0] # the whole escape: a lookbehind must not split `\x41`
            out << e
            i += e.length
            next
          end
          if !in_class && lbs.last # a bare letter is a literal (2 long): split it from a literal just before
            out << "(?:)" if lit_end == i
            lit_end = i + 2
          end
          out << l
          i += 2
          next
        end
        if in_class
          if ch == "]"
            in_class = false
            if class_alts.any?
              rest = out.slice!(class_start..)[1..]
              rest = "\\#{rest}" if rest.start_with?("^") # `[^..]` would negate the spliced class
              alts = class_alts.join("|")
              alts = "(?:#{alts}" + (rest.empty? ? ")" : "|[#{rest}])") if class_alts.length > 1 || !rest.empty?
              out << alts
              class_alts = []
            else
              out << "]"
            end
            lit_end = i + 1 if class_start # Onigmo merges a one-char class into the literals beside it
            class_start = nil
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
        elsif ch == "(" && pattern.match?(NON_JS_GROUP, i)
          raise RegexpError, "non-JS group" # compile_regex fails open
        elsif ch == "(" && (m = pattern.match(JS_GROUP, i))
          nm = m[1].dup.force_encoding(Encoding::UTF_8)
          raise RegexpError, "invalid group name" unless nm.valid_encoding? && nm.match?(JS_NAME)

          # the twin is exclusive when a group open since before it has seen a `|` since (transitive:
          # checking the last twin is enough)
          if (prev = last_named[nm]) && (named || bars[opens.bsearch_index { |o| o >= prev } || opens.length] < prev)
            raise RegexpError, "duplicate group name"
          end

          last_named[nm] = i
          opens << i
          bars << bars.last
          lbs << lbs.last
          out << m[0]
          i += m[0].length
          next
        elsif ch == "("
          m = pattern.match(JS_OPENER, i)
          opens << i
          bars << bars.last
          lbs << (lbs.last || !m[1].nil?)
          out << m[0]
          i += m[0].length
          next
        elsif ch == "|"
          bars[-1] = i
        elsif ch == ")" && opens.any?
          opens.pop
          bars.pop
          lbs.pop
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
            out << (neg ? "(?m:.)" : "(?!)")
            i = j + 1
            next
          end
          if !neg && lbs.last
            out << "(?:)" if lit_end == i
            class_start = out.length
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
          out << (m ? brace_quantifier(m) : "\\{")
          i += m ? m[0].length : 1
          i += 1 if m && !m[0].include?(",") && pattern[i] == "?"
          next
        end
        # a literal in a lookbehind directly after another gets `(?:)` (never inside a UTF-8 char): Onigmo folds `ss` to ß under /i
        if !in_class && lbs.last && !"()|*+?".include?(ch)
          if ch.ord.between?(0x80, 0xBF)
            lit_end = i + 1 if lit_end == i
          else
            out << "(?:)" if lit_end == i
            lit_end = i + 1
          end
        end
        out << ch
        i += 1
      end
      out.force_encoding(enc)
    end

    def self.over_one?(digits)
      digits = digits.sub(/\A0+/, "") # a digit-string test: to_i on a huge one is slow
      digits.length > 1 || digits > "1"
    end

    def self.binary(str)
      str.encoding == Encoding::BINARY ? str : str.b
    end

    def self.brace_quantifier(match)
      lo, comma, hi = match.captures.map { |d| d&.sub(/\A0+(?=.)/, "") } # canonical: no leading zeros
      # m > n is a JS SyntaxError: leave it as written for Onigmo to reject
      return match[0] if hi.to_s != "" && ([lo.length, lo] <=> [hi.length, hi]).positive?

      lo = ONIGMO_REPEAT_MAX.to_s if over_repeat_max?(lo)
      hi = "" if over_repeat_max?(hi) # an upper bound past it never binds a real input
      "{#{lo}#{comma}#{hi}}"
    end

    def self.over_repeat_max?(digits)
      digits = digits.to_s # nil: `{m}` has no upper bound
      digits.length > 6 || digits.to_i > ONIGMO_REPEAT_MAX # length first: to_i on a huge digit string is slow
    end

    # A regex test that never raises: a value in an encoding the pattern cannot read (a binary
    # PATH_INFO with high bytes, say) reads as "no match" rather than an exception on the request path.
    #
    # `on_error` is what a value the engine cannot read answers. The legacy block-side path regexes
    # keep false; a custom `matches` rule passes `deny` (regex-cap-sdk v1: an unevaluable value is a
    # hit for block/challenge/warn and a miss for skip, the same as an over-cap one, camada-all-cwb4).
    #
    # Inside a rule walk the request's regex budget is spent first: once it is gone the regex does not
    # run and answers `on_error`, like an over-limit run (Regexp::TimeoutError is a StandardError).
    def self.regex_hit?(rx, value, on_error = false)
      left = Thread.current[:camada_regex_budget]
      return on_error if left && left <= 0

      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC) if left
      begin
        rx.match?(utf8_view(value))
      rescue StandardError
        on_error
      ensure
        Thread.current[:camada_regex_budget] = left - (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) if left
      end
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
