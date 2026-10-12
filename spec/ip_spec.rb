# frozen_string_literal: true

# Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
# raw X-Forwarded-For is attacker-writable and never trusted without explicit configuration.
RSpec.describe Camada::Ip do
  def resolve(...) = described_class.resolve_client_ip(...)

  it "uses the socket peer without config even when xff is present" do
    expect(resolve("10.0.0.1", "203.0.113.66", nil)).to eq("10.0.0.1")
    expect(resolve("10.0.0.1", "203.0.113.66", { "mode" => "none" })).to eq("10.0.0.1")
  end

  it "unwraps a v4-mapped peer" do
    expect(resolve("::ffff:10.0.0.1", nil, nil)).to eq("10.0.0.1")
    expect(resolve(nil, "1.2.3.4", nil)).to be_nil
  end

  it "counts hops from the right" do
    expect(resolve("10.0.0.1", "203.0.113.66, 198.51.100.7", { "mode" => "hops", "hops" => 1 })).to eq("198.51.100.7")
    expect(resolve("10.0.0.1", "203.0.113.66, 198.51.100.7", { "mode" => "hops", "hops" => 2 })).to eq("203.0.113.66")
    expect(resolve("10.0.0.1", "203.0.113.66", { "mode" => "hops", "hops" => 2 })).to eq("10.0.0.1") # out of range: the peer
  end

  it "takes the rightmost entry on vercel" do
    expect(resolve("10.0.0.1", "spoof, 203.0.113.66", { "mode" => "vercel" })).to eq("203.0.113.66")
  end

  it "skips trusted cidrs from the right" do
    cfg = { "mode" => "cidrs", "cidrs" => ["10.0.0.0/8", "2001:db8::/32"] }
    expect(resolve("10.0.0.1", "203.0.113.66, 10.1.2.3, 10.9.9.9", cfg)).to eq("203.0.113.66")
    expect(resolve("10.0.0.1", "203.0.113.66, 2001:db8::5", cfg)).to eq("203.0.113.66")
    expect(resolve("10.0.0.1", "10.1.2.3", cfg)).to eq("10.0.0.1")            # everything trusted: the peer
    expect(resolve("10.0.0.1", "not-an-ip, 10.1.2.3", cfg)).to eq("10.0.0.1") # candidate must parse
  end

  it "ignores a malformed cidr and a bare address" do
    cfg = { "mode" => "cidrs", "cidrs" => ["10.0.0.0/8", "10.0.0.0", "10.0.0.0/33", "x/8", "2001:db8::/129"] }
    expect(resolve("10.0.0.1", "203.0.113.66, 10.1.2.3", cfg)).to eq("203.0.113.66")
  end

  it "reads the env string forms" do
    expect(Camada::Config.parse_trusted_proxy_env(nil)).to be_nil
    expect(Camada::Config.parse_trusted_proxy_env("none")).to eq({ "mode" => "none" })
    expect(Camada::Config.parse_trusted_proxy_env("vercel")).to eq({ "mode" => "vercel" })
    expect(Camada::Config.parse_trusted_proxy_env("hops:2")).to eq({ "mode" => "hops", "hops" => 2 })
    expect(Camada::Config.parse_trusted_proxy_env("hops:0")).to be_nil
    expect(Camada::Config.parse_trusted_proxy_env("hops:x")).to be_nil
    expect(Camada::Config.parse_trusted_proxy_env("cidrs:10.0.0.0/8, 192.0.2.0/24")).to eq({ "mode" => "cidrs", "cidrs" => ["10.0.0.0/8", "192.0.2.0/24"] })
    expect(Camada::Config.parse_trusted_proxy_env("cidrs:")).to be_nil
    expect(Camada::Config.parse_trusted_proxy_env("bogus")).to be_nil
  end

  # camada-all-0vho: an X-Forwarded-For entry may carry a port (Azure Application Gateway writes `ip:port`).
  it "resolves xff entries with a port to the address" do
    hops1 = { "mode" => "hops", "hops" => 1 }
    azure = { "mode" => "cidrs", "cidrs" => ["169.254.0.0/16"] }
    expect(resolve("169.254.130.1", "203.0.113.66:51234", hops1)).to eq("203.0.113.66")
    expect(resolve("169.254.130.1", "[2001:db8::66]:51234", hops1)).to eq("2001:db8::66")
    expect(resolve("169.254.130.1", "[2001:db8::66]", hops1)).to eq("2001:db8::66")
    expect(resolve("169.254.130.1", "2001:db8::66:8080", hops1)).to eq("2001:db8::66:8080") # a bare v6 is never split
    expect(resolve("169.254.130.1", "203.0.113.66:51234", { "mode" => "vercel" })).to eq("203.0.113.66")
    expect(resolve("169.254.130.1", "203.0.113.66:51234", azure)).to eq("203.0.113.66")
    expect(resolve("169.254.130.1", "203.0.113.66, 169.254.1.1:5000", azure)).to eq("203.0.113.66") # the trust test sees the address
  end

  it "falls back to the peer on a malformed port entry" do
    ["203.0.113.66:", "203.0.113.66:abc", "203.0.113.66:123456", "203.0.113.66:80:90", "[2001:db8::66:51234",
     "[2001:db8::66]:", "[2001:db8::66]x", "[203.0.113.66]:80", "[]:80", "not-an-ip:80", "203.0.113.256:80"].each do |bad|
      expect(resolve("169.254.130.1", bad, { "mode" => "hops", "hops" => 1 })).to eq("169.254.130.1"), bad
    end
  end

  # camada-all-yfc6 (D1): in cidrs mode the chain is [...xff, peer]. A peer outside every trusted range is the client
  # and its XFF is ignored; a loopback peer is a local front end (App Engine's is 127.0.0.1) and counts as a trusted hop.
  describe "cidrs walk from the peer" do
    cf = %w[173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18
            190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
            104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32
            2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32].freeze
    let(:cloudflare) { { "mode" => "cidrs", "cidrs" => cf, "cloudflare" => cf } }

    it "still resolves the client for Trialsights (App Engine behind Cloudflare)" do
      # the peer is App Engine's local front end, Google appends 169.254.1.1, Cloudflare's edge sits in front of that
      cfg = { "mode" => "cidrs", "cidrs" => [*cf, "169.254.0.0/16"], "cloudflare" => cf }
      expect(resolve("127.0.0.1", "6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1", cfg)).to eq("198.51.100.9")
      expect(resolve("127.0.0.1", "6.6.6.6, 198.51.100.9, 169.254.1.1", cfg)).to eq("198.51.100.9") # direct appspot hit
    end

    it "ignores xff from an untrusted peer (a direct hit on the origin)" do
      ["203.0.113.66", "8.8.8.8", "8.8.8.8, 172.64.1.1"].each do |xff|
        ["203.0.113.200", "::ffff:203.0.113.200", "::FFFF:203.0.113.200"].each do |peer|
          expect(resolve(peer, xff, cloudflare)).to eq("203.0.113.200"), "#{peer} #{xff}"
        end
      end
      expect(resolve("2001:db8::99", "198.51.100.9", cloudflare)).to eq("2001:db8::99")
      expect(resolve("172.64.1.1", "1.2.3.4, 198.51.100.9", cloudflare)).to eq("198.51.100.9") # a trusted peer still walks
    end

    it "trusts a loopback peer as a hop, but never a loopback xff entry" do
      ["127.0.0.1", "127.5.6.7", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"].each do |peer|
        expect(resolve(peer, "198.51.100.9, 172.64.1.1", cloudflare)).to eq("198.51.100.9"), peer
      end
      expect(resolve("127.0.0.1", "8.8.8.8", cloudflare)).to eq("8.8.8.8") # D1's accepted trade-off
      expect(resolve("172.64.1.1", "127.0.0.1", cloudflare)).to eq("127.0.0.1")
    end

    it "keeps the plain walk with no peer (or a non-ip one, a unix socket)" do
      expect(resolve(nil, "1.2.3.4, 198.51.100.9, 172.64.1.1", cloudflare)).to eq("198.51.100.9")
      expect(resolve(nil, "172.64.1.1", cloudflare)).to be_nil
      expect(resolve("unix:/run/app.sock", "198.51.100.9, 172.64.1.1", cloudflare)).to eq("198.51.100.9")
    end
  end
end
