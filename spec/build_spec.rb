# frozen_string_literal: true

# The wire event's ref field (camada-all-ijsa): the request's own query was scrubbed, the Referer shipped verbatim.
RSpec.describe Camada::Events do
  def build(headers)
    info = Camada::Events::RequestInfo.new(method: "GET", host: "x.test", path: "/p", query: "", headers: headers, ip: "1.2.3.4",
                                           http_version: "1.1")
    described_class.build_wire_event(info, tap: "sdk-ruby", rid: "r")
  end

  it "ships the Referer with its query scrubbed" do
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTQyIn0.sig-sig-sig"
    ev = build([["Referer", "https://x.test/reset-password?token=#{jwt}&code=4/0AbC"]])
    expect(ev["ref"]).to eq("https://x.test/reset-password?token=~r&code=~r")
    expect(JSON.generate(ev)).not_to include(jwt, "4/0AbC")
    expect(build([%w[Origin https://x.test]])["ref"]).to be_nil
  end
end
