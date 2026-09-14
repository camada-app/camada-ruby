# frozen_string_literal: true

require_relative "lib/camada/version"

# The build reads the version literal from lib/camada/version.rb (the way hatch reads
# camada-python's version.py), so the gem, the wire id and the sibling drift guards agree.
Gem::Specification.new do |spec|
  spec.name = "camada"
  spec.version = Camada::VERSION
  spec.authors = ["camada"]
  spec.summary = "camada SDK for Ruby: inline enforcement of your snapshot, first-party beacon and challenge, batched events"
  spec.description = "camada SDK for Ruby: inline enforcement of your snapshot (ordered custom rules, then allow, block, " \
                     "challenge), first-party beacon and proof-of-work challenge, batched event shipping. A Rack " \
                     "middleware for any Rack app (Sinatra, Rails via the Railtie, Hanami, plain Rack)."
  spec.homepage = "https://github.com/camada-app/camada-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir["lib/**/*.rb"] + ["README.md", "LICENSE"]
  spec.require_paths = ["lib"]
  # No runtime dependencies: stdlib only (net/http, openssl, digest, json, securerandom, zlib, stringio).
end
