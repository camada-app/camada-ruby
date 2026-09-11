# frozen_string_literal: true

require "camada"
require_relative "support/fixtures"

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :defined
  config.before(:suite) { Fixtures.check! }
end
require_relative "support/fake_analyst"
