# frozen_string_literal: true

# The wire event's ref field (camada-all-ijsa): the request's own query was scrubbed, the Referer shipped verbatim.
RSpec.describe Camada::Events do
  def build(headers, **opts)
    info = Camada::Events::RequestInfo.new(method: "GET", host: "x.test", path: "/p", query: "", headers: headers, ip: "1.2.3.4",
                                           http_version: "1.1")
    described_class.build_wire_event(info, tap: "sdk-ruby", rid: "r", **opts)
  end

  it "ships the Referer with its query scrubbed" do
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTQyIn0.sig-sig-sig"
    ev = build([["Referer", "https://x.test/reset-password?token=#{jwt}&code=4/0AbC"]])
    expect(ev["ref"]).to eq("https://x.test/reset-password?token=~r&code=~r")
    expect(JSON.generate(ev)).not_to include(jwt, "4/0AbC")
    expect(build([%w[Origin https://x.test]])["ref"]).to be_nil
  end

  it "uses first header values even when a later value would yield a credential" do
    headers = [["X-Extra", "short"], %w[x-extra fake-extra-token],
               ["Authorization", "Bearer first-token"], ["authorization", "Bearer second-token"]]
    ev = build(headers, token_header: "x-extra", token_hasher: ->(value) { Camada::Redact.hash_token(value, "key") })
    expect(ev["tk"]).to eq(Camada::Redact.hash_token("first-token", "key"))
  end

  it "keeps a request row when the token hasher raises" do
    headers = [["Authorization", "Bearer fake-token"], %w[User-Agent fake-api-key-0007]]
    failing_hasher = ->(_value) { raise "hashing unavailable" }
    ev = build(headers, token_header: "user-agent", token_hasher: failing_hasher)
    expect(ev).to include("rid" => "r", "auth" => "Bearer")
    expect(ev).not_to have_key("tk")
    expect(JSON.generate(ev)).not_to include("fake-api-key-0007")
  end
end
