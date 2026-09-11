# frozen_string_literal: true

require "json"

# The golden snapshot containers live in the camada-core sibling checkout (copied verbatim from
# edge-analyst, the format owner); the suite fails by name when they are missing rather than
# skipping, the same stance the web/mkt drift guards take.
module Fixtures
  DIR = ENV["CAMADA_FIXTURES_DIR"] || File.expand_path("../../../camada-core/test/fixtures", __dir__)
  REQUIRED = %w[blk3/cases.json blk3/hdrs.json blk3/v3-basic.bin blk3/v4-basic.bin blk5/cases.json blk5/v5-rules.bin].freeze

  def self.path(rel)
    p = File.join(DIR, rel)
    raise "golden fixture missing: #{p} (no camada-core checkout? set CAMADA_FIXTURES_DIR)" unless File.exist?(p)

    p
  end

  def self.check!
    REQUIRED.each { |rel| path(rel) }
  end

  def self.read_bin(rel) = File.binread(path(rel))
  def self.read_json(rel) = JSON.parse(File.read(path(rel)))
end
