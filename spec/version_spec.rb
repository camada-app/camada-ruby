# frozen_string_literal: true

# The SDK's wire identity: x-camada-sdk: @camada/ruby/<version>. One literal in version.rb is the
# single source the gemspec reads and every sibling drift guard parses.
RSpec.describe "Camada::VERSION" do
  # edge-analyst src/freshness.js SDK_RE: anything else is silently dropped from sdk_versions.
  analyst_sdk_re = %r{\A@?[a-z0-9._-]+(/[a-z0-9._-]+)?/\d+\.\d+\.\d+[a-z0-9.-]*\z}i
  root = File.expand_path("..", __dir__)

  it "is the literal the drift guards parse and the gemspec builds" do
    source = File.read(File.join(root, "lib/camada/version.rb"))
    expect(source[/^\s*VERSION = "([^"]+)"/m, 1]).to eq(Camada::VERSION)
    expect(Gem::Specification.load(File.join(root, "camada.gemspec")).version.to_s).to eq(Camada::VERSION)
  end

  it "is the family wire identity" do
    expect(Camada::SDK_ID).to eq("@camada/ruby/#{Camada::VERSION}")
    expect(Camada::SDK_ID).to match(analyst_sdk_re)
    expect(Camada::SDK_ID.length).to be <= 64
  end
end
