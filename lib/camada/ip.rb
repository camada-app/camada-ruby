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

    PORT_RE = /\A:[0-9]{1,5}\z/

    # One X-Forwarded-For entry without its port (camada-all-0vho): `[v6]:port` and `[v6]` -> `v6`,
    # `a.b.c.d:port` -> `a.b.c.d`. A bare IPv6 literal comes back whole (its last group is never a port); anything
    # else malformed comes back unchanged, so validation still rejects it and the peer wins.
    def self.strip_port(e)
      if e.start_with?("[")
        close = e.index("]")
        return e if close.nil?

        inner = e[1...close]
        rest = e[(close + 1)..]
        return inner.include?(":") && (rest.empty? || PORT_RE.match?(rest)) ? inner : e
      end
      return e if e.count(":") != 1 # no colon, or a bare IPv6 literal

      host, port = e.split(":", 2)
      IpParse.parse_ip4(host) >= 0 && PORT_RE.match?(":#{port}") ? host : e
    end

    # 127.0.0.0/8 or ::1 (camada-all-yfc6, decision D1). The peer's `::ffff:127.x.x.x` form is already reduced to the
    # dotted quad by resolve_client_ip.
    def self.loopback?(ip)
      return IpParse.parse_ip4(ip) >> 24 == 127 unless ip.include?(":")

      IpParse.parse_ip6(ip) == [0, 0, 0, 1]
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
    #
    # XFF entries are read without a port (`ip:port`, `[v6]:port`, as Azure writes them) in every mode.
    #
    # `cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]` from the right: if
    # the peer is not a trusted proxy, the request did not come through one and the peer IS the client; XFF is
    # ignored, since anyone hitting the origin directly can write it. A loopback peer (127.0.0.0/8, ::1,
    # ::ffff:127.x.x.x) counts as a trusted hop: it is a local front end or sidecar (App Engine's is always
    # 127.0.0.1), and no remote client can be one. Loopback is trusted only as the peer, never as an XFF entry. With
    # no peer at all (nil, or not an ip, as on a unix socket) the walk runs over XFF alone: such a host trusts its
    # network edge to have written XFF, and the app must not be reachable around that edge. `hops` and `vercel`
    # trust XFF by definition and ignore the peer.
    def self.resolve_client_ip(peer, xff, cfg)
      sock = peer && peer[0, 7].casecmp?("::ffff:") ? peer[7..] : peer # dual-stack v4-mapped form
      return sock if cfg.nil? || cfg["mode"] == "none" || xff.nil? || xff.empty?

      entries = xff.split(",").map { |e| strip_port(e.strip) }.reject(&:empty?)
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
        # the peer is the first hop: if it is not a trusted proxy, it is the client
        return sock if sock && valid_ip?(sock) && !loopback?(sock) && trusted.none? { |t| in_cidr?(sock, t) }

        candidate = entries.reverse_each.find { |entry| trusted.none? { |t| in_cidr?(entry, t) } }
      end
      candidate && valid_ip?(candidate) ? candidate : sock
    end
  end
end
