# frozen_string_literal: true

require "json"
require "zlib"
require "stringio"

# An in-process transport standing in for the analyst Worker (GET /snapshot, POST /e): the
# Ruby twin of camada-python's tests/fake_analyst.py. Anything responding to #call(req) is a
# transport, so a FakeAnalyst instance is passed as `transport:` directly.
class FakeAnalyst
  BLOCKED_IP = "203.0.113.66"     # an ip4 entry in v3-basic and v4-basic
  CHALLENGED_IP = "192.0.2.20"    # a challenge-only ip4 entry in v4-basic
  ALLOWED_IP = "10.0.0.7"         # allow-listed inside the blocked 10.0.0.0/8
  # v5-rules only (§D3): the ordered custom rules the golden container carries.
  RULE_BLOCKED_IP = "198.51.100.7"       # builtin:block, a manual-block entry
  SKIP_PATH = "/healthz"                 # cr_00000000000a, skip — beats every side
  RULE_BLOCKED_PATH = "/api/v2/dump"     # cr_00000000000c, block by path regex
  WARN_UA = "Scrapy/2.11 (+https://scrapy.org)" # cr_00000000000e, warn
  BLOCKED_UA = "curl/8.4.0"              # cr_00000000000f, block
  BLOCKED_HEADER = "x-api-key"           # cr_000000000019, `header is` -> block
  BLOCKED_HEADER_VALUE = "leaked-key-1"

  META_FILES = { "v3" => "blk3/v3-basic.meta.json", "v4" => "blk3/v4-basic.meta.json", "v5" => "blk5/v5-rules.meta.json" }.freeze
  BIN_FILES = { "v3" => "blk3/v3-basic.bin", "v4" => "blk3/v4-basic.bin", "v5" => "blk5/v5-rules.bin" }.freeze

  def self.frame(meta, body)
    m = JSON.generate(meta)
    [m.bytesize].pack("V") + m + body
  end

  def self.gzip_bytes(s)
    io = StringIO.new("".b)
    gz = Zlib::GzipWriter.new(io)
    gz.write(s)
    gz.close
    io.string
  end

  attr_accessor :config, :snapshot_down, :ingest_down, :snapshot_status, :container, :gzip, :ingest_status
  attr_reader :events, :sdk_headers, :snapshot_versions, :snapshot_requests

  def initialize
    @events = []             # batches POSTed to /e
    @sdk_headers = []        # x-camada-sdk seen on /snapshot and /e
    @snapshot_versions = []  # x-camada-snapshot seen on /snapshot
    @snapshot_requests = []
    @config = { "tenant" => "acme", "beacon" => true, "sample" => 1, "exclude" => [], "trusted_proxy" => { "mode" => "none" }, "poll_seconds" => 30 }
    @snapshot_down = false
    @ingest_down = false
    @snapshot_status = nil   # force a status (204, 304, 401, 500)
    @container = "v3"        # v3 | v4 | v5
    @gzip = false            # gzip the frame when the client asks for it, decoded the way Transport.response does
    @ingest_status = 202
    @lock = Mutex.new
  end

  def meta = Fixtures.read_json(META_FILES[@container])
  def binary = Fixtures.read_bin(BIN_FILES[@container])
  def etag = "\"#{meta["version"]}#{{ "v3" => "", "v4" => "-v4", "v5" => "-v5" }[@container]}\""

  def call(req)
    @lock.synchronize { serve(req) }
  end

  def all_events = @events.flatten(1)

  private

  def serve(req)
    @sdk_headers << req.headers.fetch("x-camada-sdk", "") if req.url.end_with?("/snapshot", "/e")
    if req.url.end_with?("/snapshot")
      @snapshot_requests << req
      @snapshot_versions << req.headers.fetch("x-camada-snapshot", "")
      return Camada::HttpResponse.new(status: 0, headers: {}, body: "".b) if @snapshot_down

      headers = { "x-camada-config" => JSON.generate(@config), "cache-control" => "private, no-store" }
      return Camada::HttpResponse.new(status: @snapshot_status, headers: headers, body: "".b) if @snapshot_status
      return Camada::HttpResponse.new(status: 304, headers: headers, body: "".b) if req.headers["if-none-match"] == etag

      body = FakeAnalyst.frame(meta, binary)
      headers["etag"] = etag
      if @gzip && req.headers.fetch("accept-encoding", "").include?("gzip")
        headers["content-encoding"] = "gzip"
        return Camada::Transport.response(200, headers, FakeAnalyst.gzip_bytes(body))
      end
      return Camada::HttpResponse.new(status: 200, headers: headers, body: body)
    end
    return Camada::HttpResponse.new(status: 0, headers: {}, body: "".b) if @ingest_down

    if req.url.end_with?("/e")
      @events << JSON.parse(req.body || "[]")
      return Camada::HttpResponse.new(status: @ingest_status, headers: {}, body: "".b)
    end
    raise "unmocked request: #{req.url}"
  end
end
