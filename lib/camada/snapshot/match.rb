# frozen_string_literal: true

require_relative "parse"

module Camada
  module Snapshot
    # Matcher: sub-millisecond checks over a parsed Snap, ported from @camada/core
    # src/snapshot/match.ts (itself from edge-analyst src/blocklist.js). Matching is fully
    # synchronous and allocation-light. The original's per-instance scratch request is not ported:
    # a JS isolate runs one match() at a time, but here one Matcher serves every request thread,
    # so the rule loop reads a RuleRequest built per call.
    #
    # Outcome order is contract (contracts §D3, fixtures pin it): the tenant's ordered custom rules
    # first (first match wins, the order IS the precedence), then allow -> block -> challenge.
    # Within each side the axis order is ip4 -> ip6 -> asn -> country -> tls -> path.
    # At the SDK position only ip, path, ua and the request headers are usually known;
    # asn/country/tlsx entries and conditions then simply never match — that is the documented,
    # honest enforcement scope (fail open, never guess).
    MatchInput = Struct.new(
      :ip, :asn, :country, :tlsx, :path,
      :ua,     # v5 rules read it; the three sides never do
      :header, # v5 header conditions read it, always with a lower-cased name
      keyword_init: true
    )

    class MatchResult
      attr_reader :block, :challenge, :allowed, :warn, :action, :rule, :reason, :version

      # allowed: true for skip (which absorbed the old allow) and for the allow side;
      # action:  the action of the rule that decided, nil when a side did;
      # rule:    the rule id, present only when reason is 'rule';
      # reason:  ip4 | ip6 | asn | country | tls | path | rule | cold.
      def initialize(block: false, challenge: false, allowed: false, warn: false, action: nil, rule: nil, reason: nil, version: nil)
        @block = block
        @challenge = challenge
        @allowed = allowed
        @warn = warn
        @action = action
        @rule = rule
        @reason = reason
        @version = version
        freeze
      end
    end

    # A rule decided this request (§D3): at most one of allowed / block / challenge / warn is
    # true, `reason` is 'rule', and `rule` names the id the adapters stamp on the event.
    def self.rule_result(rule, version)
      a = rule.action
      MatchResult.new(
        block: a == "block", challenge: a == "challenge", allowed: a == "skip", warn: a == "warn",
        action: a, rule: rule.id, reason: "rule", version: version
      )
    end

    class Matcher
      attr_reader :snap

      def initialize(snap)
        @snap = snap
      end

      def match(i)
        s = @snap
        ip = i.ip || ""
        n4 = -1
        w = nil
        unless ip.empty?
          if ip.include?(":")
            w = IpParse.parse_ip6(ip)
          else
            n4 = IpParse.parse_ip4(ip)
          end
        end
        forms = Snapshot.path_forms(i.path) # [raw, lit, full]: contracts §D3 "Path matching"
        unless s.rules.empty?
          r = RuleRequest.new(n4: n4, ip6: w, asn: i.asn, country: i.country, tlsx: i.tlsx,
                              paths: forms, ua: i.ua, header: i.header)
          s.rules.each do |rule| # the order IS the precedence (§A4): first match wins
            return Snapshot.rule_result(rule, s.version) if rule.conds.all? { |cond| cond.call(r) }
          end
        end
        reason = side(s.allow, i, n4, w, forms, false) # an exemption: every canonical spelling must agree
        return MatchResult.new(allowed: true, reason: reason, version: s.version) if reason

        reason = block_side(i, n4, w, forms)
        return MatchResult.new(block: true, reason: reason, version: s.version) if reason

        reason = side(s.challenge, i, n4, w, forms, true)
        return MatchResult.new(challenge: true, reason: reason, version: s.version) if reason

        MatchResult.new(version: s.version)
      end

      private

      def blocked4?(n)
        s = @snap
        b = n >> 8
        return false if (s.bm4[b >> 5] >> (b & 31)) & 1 == 0

        hi = n >> 16
        left = s.idx4[hi]
        right = s.idx4[hi + 1] - 1
        left -= 1 if left > 0
        return false if right < left

        s4 = s.s4
        while left < right
          m = (left + right + 1) >> 1
          if s4[m] <= n
            left = m
          else
            right = m - 1
          end
        end
        n.between?(s4[left], s.e4[left])
      end

      def words_at(a, o) = [a[o], a[o + 1], a[o + 2], a[o + 3]]

      def blocked6?(w)
        s = @snap
        b = w[0] >> 8
        return false if (s.bm6[b >> 5] >> (b & 31)) & 1 == 0

        left = 0
        right = s.n6 - 1
        return false if right < 0

        s6 = s.s6
        while left < right
          m = (left + right + 1) >> 1
          if (words_at(s6, m * 4) <=> w) <= 0
            left = m
          else
            right = m - 1
          end
        end
        o = left * 4
        (words_at(s6, o) <=> w) <= 0 && (w <=> words_at(s.e6, o)) <= 0
      end

      def blocked_asn?(asn)
        s = @snap
        return (s.asn_bm[asn >> 5] >> (asn & 31)) & 1 != 0 if asn < 4_194_304

        extra = s.asn_extra
        left = 0
        right = extra.length - 1
        while left <= right
          m = (left + right) >> 1
          v = extra[m]
          return true if v == asn

          if v < asn
            left = m + 1
          else
            right = m - 1
          end
        end
        false
      end

      # The block side: v3 sections plus the top-level meta.
      def block_side(i, n4, w, forms)
        s = @snap
        return "ip4" if n4 >= 0 && blocked4?(n4)
        return "ip6" if !w.nil? && blocked6?(w)
        return "asn" if !i.asn.nil? && blocked_asn?(i.asn)
        return "country" if Camada.present(i.country) && !s.country.empty? && s.country.include?(i.country)
        return "tls" if Camada.present(i.tlsx) && s.tls.include?(i.tlsx)
        if (!s.paths_exact.empty? || !s.paths_prefix.empty? || !s.paths_regex.empty?) &&
           Snapshot.path_hit?(forms, true) { |p| Snapshot.path_in?(s, p, s.paths_regex) }
          return "path"
        end

        nil
      end

      # A v4 side list (allow or challenge). No tls axis: §A3's side meta has no tls key.
      def side(st, i, n4, w, forms, deny)
        return nil if st.empty # the common v3 snapshot
        return "ip4" if n4 >= 0 && Snapshot.in_range4?(st.r4, n4)
        return "ip6" if !w.nil? && Snapshot.in_range6?(st.r6, st.n6, w)
        return "asn" if !i.asn.nil? && st.asn.include?(i.asn)
        return "country" if Camada.present(i.country) && st.country.include?(i.country)

        if (!st.paths_exact.empty? || !st.paths_prefix.empty?) && Snapshot.path_hit?(forms, deny) { |p| Snapshot.path_in?(st, p) }
          return "path"
        end

        nil
      end
    end
  end
end
