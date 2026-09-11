# frozen_string_literal: true

require "digest"

# The proof-of-work solver the challenge and engine specs share.
module ChallengeHelpers
  DAY_MS = 86_400_000
  NOW = 1_800_000_000_000
  IP = "203.0.113.9"

  def solve(nonce, bits = 16)
    n = 0
    n += 1 until Camada::Challenge.pow_ok?(Digest::SHA256.hexdigest("#{nonce}.#{n}"), bits)
    n.to_s
  end
end
