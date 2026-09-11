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
end
