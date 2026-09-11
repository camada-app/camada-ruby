# frozen_string_literal: true

module Camada
  # The SDK's wire identity: x-camada-sdk: @camada/ruby/<version>. This literal is the single
  # source: camada.gemspec reads it at build, and the sibling drift guards (camada-backend,
  # camada-web, camada-mkt) parse this file with /^\s*VERSION = "([^"]+)"/m the way they parse
  # a package.json. Plain X.Y.Z only: the analyst's SDK_RE drops anything else.
  VERSION = "0.1.0"
  SDK_ID = "@camada/ruby/#{VERSION}".freeze
end
