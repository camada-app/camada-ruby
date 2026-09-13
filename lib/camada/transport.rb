# frozen_string_literal: true

require "net/http"
require "uri"
require "zlib"
require "stringio"

module Camada
  # The one HTTP seam. The engine, the snapshot client and the event queue speak to the analyst
  # through a transport (anything responding to #call(HttpRequest) -> HttpResponse), so tests
  # inject an in-process fake and production uses Net::HTTP. A transport never raises: a network
  # failure is a status-0 response, which every caller treats as "keep what we have".
  HttpRequest = Struct.new(:method, :url, :headers, :body, :timeout_s, keyword_init: true)
  HttpResponse = Struct.new(
    :status,  # 0 when the request never got an answer
    :headers, # lower-cased names
    :body,    # a binary String
    keyword_init: true
  )

  module Transport
    # Net::HTTP over the stdlib, gzip-aware (GET /snapshot ships ~5 MB that gzips to a few KB).
    # Net::HTTP negotiates and decodes gzip on its own as long as the caller does not set
    # accept-encoding by hand (that switches decode_content off), so that header is dropped here
    # and the response is inflated below should a server still label it.
    def self.net_http(req)
      uri = URI.parse(req.url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = req.timeout_s
      http.read_timeout = req.timeout_s
      http.write_timeout = req.timeout_s
      r = Net::HTTPGenericRequest.new(req.method, !req.body.nil?, true, uri.request_uri)
      (req.headers || {}).each { |k, v| r[k] = v unless k.downcase == "accept-encoding" }
      r.body = req.body if req.body
      res = http.start { |h| h.request(r) }
      headers = {}
      res.each_header { |k, v| headers[k.downcase] = v }
      response(res.code.to_i, headers, (res.body || "").b)
    rescue StandardError
      HttpResponse.new(status: 0, headers: {}, body: "".b)
    end

    def self.response(status, headers, body)
      if headers["content-encoding"].to_s.downcase == "gzip"
        begin
          body = Zlib::GzipReader.new(StringIO.new(body)).read.b
        rescue StandardError
          return HttpResponse.new(status: 0, headers: headers, body: "".b) # a body we cannot read is no answer at all
        end
        headers.delete("content-encoding")
      end
      HttpResponse.new(status: status, headers: headers, body: body)
    end

    DEFAULT = method(:net_http)
  end
end
