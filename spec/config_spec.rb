# frozen_string_literal: true

RSpec.describe Camada::Config do
  describe ".parse_key" do
    it "splits on the first dot" do
      expect(described_class.parse_key("tok-acme.snap-acme")).to eq(%w[tok-acme snap-acme])
      expect(described_class.parse_key("a.b.c")).to eq(["a", "b.c"])
    end

    it "rejects missing halves" do
      [nil, "", "nodot", ".snap", "tok."].each { |bad| expect(described_class.parse_key(bad)).to be_nil, bad.inspect }
    end
  end

  describe ".token_hash_enabled?" do
    it "gives the option precedence and accepts only 1 from the environment" do
      expect(described_class.token_hash_enabled?(false, "1")).to be(false)
      expect(described_class.token_hash_enabled?(true, nil)).to be(true)
      expect(described_class.token_hash_enabled?(nil, "1")).to be(true)
      [nil, "true", " 1"].each do |value|
        expect(described_class.token_hash_enabled?(nil, value)).to be(false)
      end
    end
  end

  describe ".resolve_token_header" do
    it "uses the first non-empty setting and lowercases ASCII" do
      expect(described_class.resolve_token_header("X-Extra", "X-Env")).to eq(["x-extra", false])
      expect(described_class.resolve_token_header("", "X-Env")).to eq(["x-env", false])
      expect(described_class.resolve_token_header(nil, nil)).to eq([nil, false])
    end

    it "reports invalid or forbidden settings without falling back to the environment" do
      ["X Extra", "Authorization", "Cookie", "Set-Cookie", "X-\u212Aey", "X-Key\n", "x" * 65].each do |value|
        expect(described_class.resolve_token_header(value, "X-Env")).to eq([nil, true]), value.inspect
      end
      expect(described_class.resolve_token_header(nil, "X-\u212Aey")).to eq([nil, true])
    end
  end
end

RSpec.describe Camada::Env do
  it "resolves CAMADA_KEY into the tokens, the secret and the default urls" do
    env = described_class.resolve({ "CAMADA_KEY" => "tok.snap" })
    expect([env.ingest_token, env.snap_token, env.secret]).to eq(%w[tok snap tok.snap])
    expect(env.ingest_url).to eq(Camada::Env::DEFAULT_INGEST_URL)
    expect(env.snapshot_url).to eq("#{Camada::Env::DEFAULT_INGEST_URL}/snapshot")
    expect(env.serverless).to be(false)
    expect(env.trusted_proxy).to be_nil
  end

  it "accepts the split tokens, strips a trailing slash and reads the flags" do
    env = described_class.resolve({
                                    "CAMADA_TOKEN" => "t", "CAMADA_SNAPSHOT_TOKEN" => "s", "CAMADA_INGEST_URL" => "http://localhost:8787/",
                                    "CAMADA_SNAPSHOT_URL" => "http://x/snap", "CAMADA_SERVERLESS" => "1", "CAMADA_TRUSTED_PROXY" => "hops:1"
                                  })
    expect([env.ingest_token, env.snap_token, env.secret]).to eq(%w[t s t.s])
    expect(env.ingest_url).to eq("http://localhost:8787")
    expect(env.snapshot_url).to eq("http://x/snap")
    expect(env.serverless).to be(true)
    expect(env.trusted_proxy).to eq({ "mode" => "hops", "hops" => 1 })
  end

  it "is nil without credentials" do
    expect(described_class.resolve({})).to be_nil
    expect(described_class.resolve({ "CAMADA_KEY" => "" })).to be_nil
    expect(described_class.resolve({ "CAMADA_TOKEN" => "t" })).to be_nil
  end

  it "reads the process environment through ENV" do
    expect(described_class.resolve(ENV)).to be_nil.or be_a(described_class)
  end
end
