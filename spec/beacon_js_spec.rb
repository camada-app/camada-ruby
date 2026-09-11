# frozen_string_literal: true

require "digest"

# The first-party beacon is @camada/browser's auto build, vendored as a string so the gem has
# no runtime file reads. It must be byte-for-byte the sibling's dist/auto.global.js; the spec
# fails by name (never skips) when that checkout or its build is missing.
RSpec.describe "Camada::BEACON_JS" do
  dist = ENV["CAMADA_BROWSER_DIST"] || File.expand_path("../../camada-browser/dist/auto.global.js", __dir__)

  it "matches the sibling build byte for byte" do
    expect(File.exist?(dist)).to be(true), "beacon build missing: #{dist} (run npm run build in camada-browser, or set CAMADA_BROWSER_DIST)"
    src = File.read(dist)
    expect(Camada::BEACON_JS).to eq(src), "run scripts/sync_beacon.rb to re-vendor @camada/browser"
    expect(Camada::BEACON_SHA256).to eq(Digest::SHA256.hexdigest(src))
  end

  it "names its own version and posts to fp" do
    expect(Camada::BEACON_JS).to include("\"#{Camada::BEACON_VERSION}\"", "@camada/browser", '"fp"')
    expect(Camada::BEACON_JS.encoding).to eq(Encoding::UTF_8)
    expect(Camada::BEACON_JS).to be_frozen
  end
end
