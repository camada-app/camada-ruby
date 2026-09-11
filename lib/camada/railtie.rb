# frozen_string_literal: true

require_relative "rack"

# Rails: the gem inserts Camada::Rack first in the middleware stack, so camada answers before
# anything else runs. Defined only when Rails is loaded (Bundler.require after rails); the
# helpers are the module-level ones: Camada.script_tag(request.env), Camada.track(request.env,
# "login_failed", user: email), Camada.serve_challenge(request.env).
if defined?(Rails::Railtie)
  module Camada
    class Railtie < Rails::Railtie
      initializer "camada.middleware" do |app|
        app.middleware.insert_before 0, Camada::Rack
      end
    end
  end
end
