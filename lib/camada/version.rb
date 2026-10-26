# frozen_string_literal: true

module Camada
  # The SDK's wire identity: x-camada-sdk: @camada/ruby/<version>. This literal is the single
  # source: camada.gemspec reads it at build, and the sibling drift guards (camada-backend,
  # camada-web, camada-mkt) parse this file with /^\s*VERSION = "([^"]+)"/m the way they parse
  # a package.json. Plain X.Y.Z only, and @camada/ruby must stay in the analyst's SDK_NAMES:
  # its sdkId drops anything else.
  VERSION = "0.2.0"
  SDK_ID = "@camada/ruby/#{VERSION}".freeze
end
