# frozen_string_literal: true

require_relative "ipparse"

module Camada
  # Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
  # raw X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration;
  # a spoofed XFF must not reach the analysis or the blocklist. Ported from @camada/core src/ip.ts.
  module Ip
    Cidr = Struct.new(:base4, :base6, :bits) # base4: v4 base or -1; base6: words or nil

    def self.valid_ip?(s)
      s.include?(":") ? !IpParse.parse_ip6(s).nil? : IpParse.parse_ip4(s) >= 0
    end

    def self.parse_cidr(c)
      slash = c.index("/")
      return nil if slash.nil?

      addr = c[0, slash]
      bits = Integer(c[(slash + 1)..], 10, exception: false)
      return nil if bits.nil?

      unless addr.include?(":")
        base = IpParse.parse_ip4(addr)
        return base >= 0 && bits.between?(0, 32) ? Cidr.new(base, nil, bits) : nil
      end
      words = IpParse.parse_ip6(addr)
      words && bits.between?(0, 128) ? Cidr.new(-1, words, bits) : nil
    end

    def self.in_cidr?(ip, cidr)
      if cidr.base6.nil?
        n = IpParse.parse_ip4(ip)
        return false if n < 0

        bits = cidr.bits
        mask = bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        return (n & mask) == (cidr.base4 & mask)
      end
      words = IpParse.parse_ip6(ip)
      return false if words.nil?

      remaining = cidr.bits
      4.times do |k|
        break if remaining <= 0

        take = [32, remaining].min
        mask = take == 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - take)) & 0xFFFFFFFF
        return false if (words[k] & mask) != (cidr.base6[k] & mask)

        remaining -= take
      end
      true
    end

    # The client IP from the socket peer and X-Forwarded-For per the trusted-proxy config.
    # Anything unresolvable falls back to the peer (fail safe).
    def self.resolve_client_ip(peer, xff, cfg)
      sock = peer&.start_with?("::ffff:") ? peer[7..] : peer # dual-stack v4-mapped form
      return sock if cfg.nil? || cfg["mode"] == "none" || xff.nil? || xff.empty?

      entries = xff.split(",").map(&:strip).reject(&:empty?)
      return sock if entries.empty?

      candidate = nil
      case cfg["mode"]
      when "hops"
        hops = cfg["hops"].to_i
        candidate = entries[entries.length - hops] if hops.between?(1, entries.length)
      when "vercel"
        candidate = entries.last # Vercel overwrites XFF, so its rightmost entry is trustworthy
      when "cidrs"
        trusted = (cfg["cidrs"] || []).filter_map { |x| parse_cidr(x.to_s) }
        candidate = entries.reverse_each.find { |entry| trusted.none? { |t| in_cidr?(entry, t) } }
      end
      candidate && valid_ip?(candidate) ? candidate : sock
    end
  end
end
