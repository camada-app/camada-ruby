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
