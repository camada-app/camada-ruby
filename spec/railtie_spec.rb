# frozen_string_literal: true

# The Railtie inserts the middleware first, and exists only when Rails is loaded.
RSpec.describe "Camada::Railtie" do
  it "is not defined without Rails" do
    expect(defined?(Camada::Railtie)).to be_nil
  end

  it "inserts Camada::Rack at position 0 of the Rails middleware stack" do
    inits = []
    rails = Module.new
    railtie = Class.new do
      define_singleton_method(:initializer) { |name, &blk| inits << [name, blk] }
    end
    rails.const_set(:Railtie, railtie)
    Object.const_set(:Rails, rails)
    begin
      load File.expand_path("../lib/camada/railtie.rb", __dir__)
      expect(defined?(Camada::Railtie)).to eq("constant")
      expect(inits.map(&:first)).to eq(["camada.middleware"])
      inserted = []
      stack = Object.new
      stack.define_singleton_method(:insert_before) { |*args| inserted << args }
      app = Struct.new(:middleware).new(stack)
      inits[0][1].call(app)
      expect(inserted).to eq([[0, Camada::Rack]])
    ensure
      Camada.send(:remove_const, :Railtie)
      Object.send(:remove_const, :Rails)
    end
  end
end
