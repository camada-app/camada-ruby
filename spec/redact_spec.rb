# frozen_string_literal: true

require "openssl"

# Redaction is not configurable off: credential-looking query values become ~r, body values
# never ship, user identifiers are HMAC-hashed inside the SDK.
RSpec.describe Camada::Redact do
  it "scrubs the query by name and by value shape" do
    expect(described_class.scrub_query("?q=hello&token=abc&x=1")).to eq("?q=hello&token=~r&x=1")
    expect(described_class.scrub_query("?api_key=k&PASSWORD=p")).to eq("?api_key=~r&PASSWORD=~r")
    expect(described_class.scrub_query("?t=eyJhbGciOi.eyJzdWIiOi.sig")).to eq("?t=~r")
    expect(described_class.scrub_query("?h=#{"a" * 32}")).to eq("?h=~r")
    expect(described_class.scrub_query("?b=#{"A" * 40}==")).to eq("?b=~r")
    expect(described_class.scrub_query("?flag&x=1")).to eq("?flag&x=1") # a bare name is kept as is
  end

  it "keeps the shape and the empties" do
    expect(described_class.scrub_query("")).to eq("")
    expect(described_class.scrub_query(nil)).to eq("")
    expect(described_class.scrub_query("?")).to eq("?")
    expect(described_class.scrub_query("a=1&code=2")).to eq("a=1&code=~r") # no leading ? is fine too
  end

  it "reduces a body to names and sizes only" do
    expect(described_class.body_shape({ "email" => "a@b.c", "n" => 12, "none" => nil, "arr" => [1, 2] })).to eq({ "email" => 5, "n" => 2, "none" => 0, "arr" => 5 })
    expect(described_class.body_shape([1])).to be_nil
    expect(described_class.body_shape("str")).to be_nil
  end

  it "hashes a user id as a labelled truncated hmac" do
    expected = OpenSSL::HMAC.hexdigest("SHA256", "tok", "uid:alice@example.com")[0, 32]
    expect(described_class.hash_user_id("alice@example.com", "tok")).to eq(expected)
    expect(described_class.hash_user_id("x", "tok").length).to eq(32)
  end
end
