# frozen_string_literal: true

# C6 sdk-conformance v3: the language-neutral cases every server SDK runs (camada-core test/fixtures/ip/resolve.json,
# redact/referer.json and redact/query.json), so the XFF-port (0vho), peer-first cidrs (yfc6) and Referer/query-scrub
# (ijsa) semantics cannot drift from core. A missing fixture fails by name at load; no case is skipped.
RSpec.describe "sdk conformance (C6)" do
  ip = Fixtures.read_json("ip/resolve.json")
  referer = Fixtures.read_json("redact/referer.json")
  query = Fixtures.read_json("redact/query.json")
  token = Fixtures.read_json("redact/token.json")

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

  describe "token hash" do
    it "reads all 22 cases in the v1 fixture" do
      expect(token["version"]).to eq(1)
      expect(token["cases"].length).to eq(22)
    end

    token["cases"].each do |c|
      it c["id"] do
        headers = c["headers"]
        token_header, = Camada::Config.resolve_token_header(c["tokenHeader"], nil)
        expect(Camada::Redact.select_credential(headers, token_header)).to eq(c["credential"])

        info = Camada::Events::RequestInfo.new(method: "GET", host: "x.test", path: "/api/me", headers: headers.to_a)
        hasher = ->(credential) { Camada::Redact.hash_token(credential, c["key"]) }
        config = Camada::Events::TokenConfig.new(header: token_header, hasher: hasher)
        ev = Camada::Events.build_wire_event(info, tap: "sdk-ruby", rid: "r", token_config: config)
        if c["tk"].nil?
          expect(ev).not_to have_key("tk")
        else
          expect(ev["tk"]).to eq(c["tk"])
          expect(JSON.generate(ev)).not_to include(c["credential"])
        end
      end
    end
  end
end
