# frozen_string_literal: true

# C6 sdk-conformance v3: the language-neutral cases every server SDK runs (camada-core test/fixtures/ip/resolve.json,
# redact/referer.json and redact/query.json), so the XFF-port (0vho), peer-first cidrs (yfc6) and Referer/query-scrub
# (ijsa) semantics cannot drift from core. A missing fixture fails by name at load; no case is skipped.
RSpec.describe "sdk conformance (C6)" do
  ip = Fixtures.read_json("ip/resolve.json")
  referer = Fixtures.read_json("redact/referer.json")
  query = Fixtures.read_json("redact/query.json")

  it "reads v3 fixtures with cases" do
    expect([ip["version"], referer["version"], query["version"]]).to eq([3, 3, 3])
    expect(ip["cases"]).not_to be_empty
    expect(referer["cases"]).not_to be_empty
    expect(query["cases"]).not_to be_empty
  end

  describe "resolve_client_ip" do
    ip["cases"].each do |c|
      it c["id"] do
        expect(ip["configs"]).to have_key(c["config"])
        expect(Camada::Ip.resolve_client_ip(c["peer"], c["xff"], ip["configs"][c["config"]])).to eq(c["expect"])
      end
    end
  end

  describe "Referer redaction" do
    referer["cases"].each do |c|
      it c["id"] do
        headers = [%w[User-Agent ua]]
        headers << ["Referer", c["referer"]] unless c["referer"].nil?
        info = Camada::Events::RequestInfo.new(method: "GET", host: "x.test", path: "/api/me", query: "", headers: headers,
                                               ip: "1.2.3.4", http_version: "1.1")
        ev = Camada::Events.build_wire_event(info, tap: "sdk-ruby", rid: "r")
        expect(ev["ref"]).to eq(c["ref"])
        wire = JSON.generate(ev)
        (c["absent"] || []).each { |secret| expect(wire).not_to include(secret) }
      end
    end
  end

  describe "request query redaction" do
    query["cases"].each do |c|
      it c["id"] do
        info = Camada::Events::RequestInfo.new(method: "GET", host: "x.test", path: "/api/me", query: c["query"],
                                               headers: [%w[User-Agent ua]], ip: "1.2.3.4", http_version: "1.1")
        ev = Camada::Events.build_wire_event(info, tap: "sdk-ruby", rid: "r")
        expect(ev["q"]).to eq(c["q"])
        wire = JSON.generate(ev)
        (c["absent"] || []).each { |secret| expect(wire).not_to include(secret) }
      end
    end
  end
end
