# frozen_string_literal: true

require_relative "ipparse"

module Camada
  # Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
  # raw X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration;
  # a spoofed XFF must not reach the analysis or the blocklist. Ported from @camada/core src/ip.ts.
  module Ip
    Cidr = Struct.new(:base4, :base6, :bits) # base4: v4 base or -1; base6: words or nil

    # A plain IPv4 or IPv6 address (C6 v3), by our own grammar, never IPAddr (which accepts zone ids, brackets and
    # embedded dotted quads). Stricter than IpParse.parse_ip6, which mirrors edge-analyst and must not drift: a single
    # leading or trailing `:` (`:8:8:8`, `2001:db8::1:`) is rejected here only.
    def self.valid_ip?(s)
      return IpParse.parse_ip4(s) >= 0 unless s.include?(":")

      n = s.bytesize
      return false if n < 2 || (s.getbyte(0) == 58 && s.getbyte(1) != 58) || (s.getbyte(n - 1) == 58 && s.getbyte(n - 2) != 58)

      !IpParse.parse_ip6(s).nil?
    end

    # `::ffff:a.b.c.d` (any case) -> `a.b.c.d`, only when a valid dotted quad follows; anything else comes back
    # unchanged (`::ffff:7f00:1` stays an ordinary IPv6 address). C6 v2.
    def self.unmap(s)
      return s if s.bytesize < 14 || !s.byteslice(0, 7).casecmp?("::ffff:")

      v4 = s.byteslice(7..)
      IpParse.parse_ip4(v4) >= 0 ? v4 : s
    end

    # HTTP optional whitespace only (SP, HTAB), never String#strip (which also removes CR, LF, VT, FF and NUL). C6 v3.
    def self.trim_ows(s)
      a = 0
      b = s.bytesize
      a += 1 while a < b && (s.getbyte(a) == 32 || s.getbyte(a) == 9)
      b -= 1 while b > a && (s.getbyte(b - 1) == 32 || s.getbyte(b - 1) == 9)
      s.byteslice(a, b - a)
    end

    # Split on `,`, each entry OWS-trimmed, port-stripped and unmapped; empty entries dropped before `hops` counts.
    def self.entries(xff)
      xff.split(",", -1).map { |e| unmap(strip_port(trim_ows(e))) }.reject(&:empty?)
    end

    # A trusted hop: a valid ip inside a configured range. An entry that is not an ip never is (C6 v3).
    def self.trusted?(ip, cidrs)
      valid_ip?(ip) && cidrs.any? { |t| in_cidr?(ip, t) }
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

    # 127.0.0.0/8 or ::1 (camada-all-yfc6, decision D1), compared by value, never IPAddr#loopback?. The peer's
    # `::ffff:127.x.x.x` form is already reduced to the dotted quad by unmap; `::ffff:7f00:1` is not loopback.
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

    # The client IP from the socket peer and X-Forwarded-For per the trusted-proxy config. The result is always a
    # valid ip or nil, in every mode (C6 v3). Anything unresolvable falls back to the peer (fail safe).
    #
    # XFF entries are trimmed of SP/HTAB only, read without a port (`ip:port`, `[v6]:port`, as Azure writes them)
    # and with `::ffff:a.b.c.d` reduced to `a.b.c.d`, in every mode. The peer is unmap(peer) when that is a valid ip,
    # else nil: a non-empty peer that is not an ip (a socket path, `@`, `ip:port`, a zone id) could not be read, and
    # the result falls back to nil, never to the XFF walk. The peer is never trimmed or port-stripped.
    #
    # `cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]` from the right: if
    # the peer is not a trusted proxy, the request did not come through one and the peer IS the client; XFF is
    # ignored, since anyone hitting the origin directly can write it. A loopback peer (127.0.0.0/8, ::1,
    # ::ffff:127.x.x.x) counts as a trusted hop: it is a local front end or sidecar (App Engine's is always
    # 127.0.0.1), and no remote client can be one. Loopback is trusted only as the peer, never as an XFF entry; an
    # XFF entry that is not an ip is never a trusted hop. With no peer at all (nil or "": a host that exposes no
    # socket, or a unix-socket listener whose REMOTE_ADDR is empty) the walk runs over XFF alone: such a host trusts
    # its network edge to have written XFF, and the app must not be reachable around that edge. `hops` and `vercel`
    # trust XFF by definition and ignore the peer.
    def self.resolve_client_ip(peer, xff, cfg)
      ip = resolve(peer.nil? || peer.empty? ? nil : peer.b, xff&.b, cfg) # bytewise: valid ips are ASCII
      ip&.force_encoding(Encoding::UTF_8)
    end

    def self.resolve(raw_peer, xff, cfg)
      mapped = raw_peer && unmap(raw_peer) # dual-stack v4-mapped form
      sock = mapped && valid_ip?(mapped) ? mapped : nil
      return sock if cfg.nil? || cfg["mode"] == "none" || xff.nil? || xff.empty?

      list = entries(xff)
      return sock if list.empty?

      candidate = nil
      case cfg["mode"]
      when "hops"
        hops = cfg["hops"].to_i
        candidate = list[list.length - hops] if hops.between?(1, list.length)
      when "vercel"
        candidate = list.last # Vercel overwrites XFF, so its rightmost entry is trustworthy
      when "cidrs"
        trusted = (cfg["cidrs"] || []).filter_map { |x| parse_cidr(x.to_s) }
        # the peer is the first hop: if it is not a trusted proxy, it is the client. An unreadable peer gives nil,
        # never the walk; only no peer at all walks.
        return sock if mapped && (sock.nil? || (!loopback?(sock) && !trusted?(sock, trusted)))

        candidate = list.reverse_each.find { |entry| !trusted?(entry, trusted) }
      end
      candidate && valid_ip?(candidate) ? candidate : sock
    end
    private_class_method :resolve
  end
end
