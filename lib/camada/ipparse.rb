# frozen_string_literal: true

module Camada
  # Allocation-free IP parsers, ported 1:1 from edge-analyst src/blocklist.js through
  # @camada/core src/snapshot/ipparse.ts (the reference the conformance fixtures are generated
  # from). Behaviour must not drift: ip4 returns -1 on anything unusual; ip6 rejects zone ids and
  # v4-mapped forms. Ruby integers are unbounded, so the words come back as a 4-element Array
  # instead of being written into a caller's scratch array.
  module IpParse
    DOT = 46
    COLON = 58
    ZERO = 48
    NINE = 57

    # Dotted-quad IPv4 to a uint32, or -1 when the string is not a plain IPv4 address.
    def self.parse_ip4(s)
      n = part = digits = dots = 0
      s.each_byte do |ch|
        if ch == DOT
          return -1 if digits == 0 || part > 255

          dots += 1
          return -1 if dots > 3

          n = (n * 256) + part
          part = digits = 0
        elsif ch.between?(ZERO, NINE)
          part = (part * 10) + (ch - ZERO)
          digits += 1
          return -1 if digits > 3
        else
          return -1
        end
      end
      return -1 if dots != 3 || digits == 0 || part > 255

      (n * 256) + part
    end

    # IPv6 text to four big-endian uint32 words, or nil when it is not a plain IPv6 address.
    def self.parse_ip6(s)
      length = s.bytesize
      groups = Array.new(8, 0)
      n = val = digits = 0
      dbl = -1
      i = 0
      if length > 1 && s.getbyte(0) == COLON && s.getbyte(1) == COLON
        dbl = 0
        i = 2
      end
      while i <= length
        c = i < length ? s.getbyte(i) : COLON # a sentinel colon closes the last group
        if c == COLON
          if digits > 0
            return nil if n >= 8

            groups[n] = val
            n += 1
            val = digits = 0
          elsif i < length
            return nil if dbl != -1

            dbl = n
          end
        else
          d = hex_digit(c)
          return nil if d.nil?

          val = (val << 4) | d
          digits += 1
          return nil if digits > 4
        end
        i += 1
      end
      if dbl == -1
        return nil if n != 8
      else
        return nil if n >= 8

        shift = 8 - n
        7.downto(dbl + shift) { |k| groups[k] = groups[k - shift] }
        (dbl...(dbl + shift)).each { |k| groups[k] = 0 }
      end
      [
        (groups[0] << 16) | groups[1],
        (groups[2] << 16) | groups[3],
        (groups[4] << 16) | groups[5],
        (groups[6] << 16) | groups[7]
      ]
    end

    def self.hex_digit(c)
      if c.between?(ZERO, NINE) then c - ZERO
      elsif c.between?(97, 102) then c - 87  # a-f
      elsif c.between?(65, 70) then c - 55   # A-F
      end
    end
    private_class_method :hex_digit
  end
end
