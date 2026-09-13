# frozen_string_literal: true

require "json"
require "securerandom"
require_relative "beacon_js"
require_relative "challenge/format"
require_relative "challenge/page"
require_relative "challenge/verify"
require_relative "constants"
require_relative "env"
require_relative "events/build"
require_relative "events/queue"
require_relative "guarded"
require_relative "ip"
require_relative "redact"
require_relative "snapshot/client"
require_relative "snapshot/match"
require_relative "version"

module Camada
  # What an adapter hands the engine. Header names are lower-cased; the list keeps the order the
  # host gave (the Rack env's order). `route` is the matched route pattern, set by the adapter at
  # finish time when the host knows it.
  class Req
    attr_reader :method, :path, :query, :host, :http_version, :peer, :https, :headers
    attr_accessor :route

    def initialize(method:, path:, query: "", host: "", http_version: nil, peer: nil, https: false, headers: [], route: nil)
      @method = method
      @path = path        # no query
      @query = query      # with the leading '?', or ''
      @host = host
      @http_version = http_version
      @peer = peer        # the socket peer the host vouches for
      @https = https
      @headers = headers  # [[lowercased name, value], ...]
      @route = route
    end

    # A header the client repeated is joined the way node:http does it: cookies with '; ' (HTTP/2
    # clients split them into several fields; cookie_value looks for '; name='), the rest with ', '.
    def header(name)
      vals = @headers.filter_map { |k, v| v if k == name }
      return nil if vals.empty?

      vals.join(name == "cookie" ? "; " : ", ")
    end
  end

  # camada answered the request; the adapter writes exactly this. `headers` is a Hash of
  # lower-cased names (Rack 3 style), `body` a String.
  Answer = Struct.new(:status, :headers, :body, keyword_init: true) do
    # The Rack triple. content-length is stamped except where a body is forbidden (1xx, 204,
    # 304): Rack::Lint — in every `rackup` development stack — rejects it there, and the beacon's
    # 204 would 500 on every page in dev.
    def to_rack
      h = status < 200 || status == 204 || status == 304 ? headers : headers.merge("content-length" => body.bytesize.to_s)
      [status, h, [body]]
    end
  end

  # Run the app. rid/set_cookie ride the response; ctx is stored on the host request
  # (env["camada"]); on_finish.call(status) is called once at the end. A nil on_finish means inert.
  Passed = Struct.new(:rid, :set_cookie, :ctx, :on_finish, keyword_init: true)

  INERT = Passed.new(rid: nil, set_cookie: nil, ctx: nil, on_finish: nil).freeze

  def self.cookie_value(cookie, name)
    src = "; #{cookie}"
    i = src.index("; #{name}=")
    return nil if i.nil?

    start = i + name.length + 3
    j = src.index(";", start)
    j.nil? ? src[start..] : src[start...j]
  end

  # The engine: the host-neutral request handling every adapter delegates to (the Ruby twin of
  # camada-python's Camada class). An adapter turns its request into a Req, asks wants_body and
  # reads at most that many bytes, then calls handle: an Answer means camada fully answered the
  # request (block, challenge, verify, beacon endpoints); a Passed means run the app, stamp the
  # rid header and session cookie on its response, and call on_finish(status) once when it is
  # done. Everything runs inside the fail-open envelope: a camada bug must never 5xx the customer,
  # and CAMADA_DISABLED=1 bypasses the SDK entirely.
  class Engine
    CHALLENGE_HEADERS = { "cache-control" => "no-store", "x-camada-challenge" => "1" }.freeze

    attr_reader :env, :snap, :queue, :kit, :script_path, :fp_path, :challenge_path, :challenge_on

    def initialize(env: ENV, transport: nil, refresh_s: nil, script_path: SCRIPT_PATH, fp_path: FP_PATH,
                   challenge: true, challenge_path: CHALLENGE_PATH, snapshot_version: DEFAULT_SNAPSHOT_VERSION)
      # env: where CAMADA_* are read from (ENV, or a Hash); transport: threaded into the snapshot
      # client and event queue (tests); refresh_s: pinned poll cadence; challenge: enforce
      # `challenge` verdicts with the first-party page (CAMADA_CHALLENGE=0 also off).
      @env_source = env
      @script_path = script_path
      @fp_path = fp_path
      @challenge_path = challenge_path
      @challenge_on = challenge && env["CAMADA_CHALLENGE"] != "0"
      @env = Env.resolve(env)
      @snap = nil
      @queue = nil
      @kit = nil
      return if @env.nil? || env[KILL_SWITCH_ENV] == "1" # unconfigured or killed at boot: no threads, no exit hooks, truly silent

      @snap = Snapshot::Client.new(
        @env.snapshot_url, @env.snap_token, refresh_s: refresh_s, mode: @env.serverless ? :lazy : :timer,
                                            transport: transport, sdk: SDK_ID, snapshot_version: snapshot_version
      )
      @queue = Events::Queue.new(@env.ingest_url, @env.ingest_token, transport: transport, sdk: SDK_ID)
      @kit = Challenge.create_challenge(@env.secret)
      @snap.start
      @queue.install_exit_flush
    end

    def disabled?
      @env.nil? || @env_source[KILL_SWITCH_ENV] == "1"
    end

    def now_ms = Events.now_ms

    # ---- the adapter contract ----

    # The byte cap to read the body under, when camada itself may answer this request.
    def wants_body(method, path)
      return nil if disabled? || method != "POST"
      return FP_MAX if path == @fp_path && beacon_enabled?
      return BODY_MAX if path == @challenge_path && @challenge_on

      nil
    end

    # Never raises. `body` is the request body when wants_body asked for one, or nil when the
    # adapter refused to read it (declared or actual size over the cap).
    def handle(req, body = nil)
      decide(req, body)
    rescue StandardError => e # a camada bug costs the join, never the request
      Guarded.log_rate_limited(e)
      INERT
    end

    # For HTML templates: the first-party beacon tag with the request's rid.
    def script_tag(ctx)
      return "" if disabled? || !beacon_enabled?

      rid = ctx && ctx["rid"]
      %(<script src="#{@script_path}#{"?r=#{rid}" if rid}" async></script>)
    end

    # Serve the challenge for this request on demand — for a route the app wants to gate itself.
    # nil when the client already holds a valid _cch (render your own page), or when the client
    # cannot be identified (fail open).
    def serve_challenge(ctx)
      return nil if disabled? || @kit.nil? || ctx.nil?

      req = ctx["_req"]
      ip = ctx["ip"]
      return nil if req.nil? || ip.nil? || ip.empty? || challenge_passed?(req, ip)

      ctx["challenged"] = true
      serve_challenge_answer(req, ip, ctx["sid"])
    rescue StandardError => e
      Guarded.log_rate_limited(e)
      nil
    end

    # App-context outcome events (login failed, signup, ...). The identifier is HMAC-hashed
    # in-process; the raw value never reaches the queue.
    def track(ctx, event, user: nil)
      return if disabled? || @queue.nil?

      uid = user.nil? || user.to_s.empty? ? nil : Redact.hash_user_id(user.to_s, @env.ingest_token)
      c = ctx || {}
      row = { "tap" => TAP, "et" => event, "uid" => uid, "rid" => c["rid"], "sid" => c["sid"], "ip" => c["ip"], "ts" => now_ms }
      @queue.push(row)
    rescue StandardError => e
      Guarded.log_rate_limited(e)
    end

    def stop
      @snap&.stop
      @queue&.stop
    end

    private

    def trusted_proxy
      return @env.trusted_proxy if @env && !@env.trusted_proxy.nil? # explicit local override wins

      @snap && (@snap.config || {})["trusted_proxy"]
    end

    def beacon_enabled?
      !@snap.nil? && (@snap.config || {})["beacon"] != false
    end

    def client_ip(req)
      Ip.resolve_client_ip(req.peer, req.header("x-forwarded-for"), trusted_proxy)
    end

    def secure?(req) = req.https || req.header("x-forwarded-proto") == "https"

    def decide(req, body)
      return INERT if disabled? || @snap.nil?

      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      @snap.ensure_fresh
      ip = client_ip(req)

      # Enforce before anything else, beacon endpoints included — fail open while cold. The
      # custom rules read the user agent and the request headers (§D3).
      v = @snap.verdict(Snapshot::MatchInput.new(ip: ip, path: req.path, ua: req.header("user-agent"), header: ->(n) { req.header(n) }))
      if v.block
        headers = { "content-type" => "text/plain", "x-block-reason" => v.reason || "", "x-block-version" => v.version || "" }
        headers["x-block-rule"] = v.rule if v.rule # a custom rule blocked: name it, so the customer knows which row to edit
        ev = event(req, SecureRandom.uuid, nil, false, ip)
        ev["st"] = 403       # blocked requests always ship: silent expiry makes blocks oscillate
        ev["blk"] = v.reason # the reason rides the event so the analyst counts SDK blocks, not the app's own 403s
        ev["rl"] = v.rule if v.rule
        @queue.push(ev)
        return Answer.new(status: 403, headers: headers, body: "Forbidden")
      end
      # `warn` passes the request and only marks its event (below, on finish); a skip passes
      # with nothing stamped at all — it is the absence of enforcement.

      # A challenge needs a resolved client IP: the nonce and the _cch cookie are bound to it,
      # so without one a single solve would mint a cookie every unidentified client could
      # present. No ip -> no challenge (fail open), the same stance ip rules take.
      if @challenge_on && ip && !ip.empty?
        # The verify endpoint answers first: a challenged client must be able to reach it.
        return verify(req, body, ip) if req.method == "POST" && req.path == @challenge_path
        if v.challenge && !challenge_passed?(req, ip)
          return serve_challenge_answer(req, ip, Camada.cookie_value(req.header("cookie"), SESSION_COOKIE))
        end
      end

      if beacon_enabled?
        if req.method == "GET" && req.path == @script_path
          return Answer.new(status: 200, headers: { "content-type" => "application/javascript", "cache-control" => "public, max-age=3600" },
                            body: BEACON_JS)
        end
        return relay_beacon(body, ip) if req.method == "POST" && req.path == @fp_path
      end

      rid = SecureRandom.uuid
      sid = Camada.cookie_value(req.header("cookie"), SESSION_COOKIE)
      new_session = sid.nil? || sid.empty?
      set_cookie = nil
      if new_session
        sid = SecureRandom.uuid
        set_cookie = "#{SESSION_COOKIE}=#{sid}; Path=/; Max-Age=#{SESSION_MAX_AGE}; HttpOnly; SameSite=Lax"
        set_cookie += "; Secure" if secure?(req)
      end
      ctx = { "rid" => rid, "sid" => sid, "ip" => ip, "_req" => req, "_engine" => self }

      cfg = @snap.config || {}
      excluded = (cfg["exclude"] || []).any? { |x| req.path.start_with?(x.to_s) }
      sample = cfg["sample"]
      sampled = rand < (sample.nil? ? 1.0 : sample.to_f) # sampling, not crypto
      warn_rule = v.warn ? v.rule : nil

      on_finish = lambda do |status|
        # serve_challenge may have answered from inside the app, and it already shipped the
        # `blk: "challenge"` row — one request, one event.
        next if ctx["challenged"] || excluded || !sampled

        ev = event(req, rid, sid, new_session, ip)
        ev["st"] = status
        ev["dur"] = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).to_i
        ev["rt"] = req.route if req.route
        ev["wrn"] = warn_rule if warn_rule # §D3: the warn rule that let this request through
        @queue.push(ev)
      rescue StandardError => e
        Guarded.log_rate_limited(e)
      end

      Passed.new(rid: rid, set_cookie: set_cookie, ctx: ctx, on_finish: on_finish)
    end

    def event(req, rid, sid, new_session, ip)
      info = Events::RequestInfo.new(method: req.method, host: req.host, path: req.path, query: req.query, headers: req.headers,
                                     ip: ip, http_version: req.http_version)
      Events.build_wire_event(info, tap: TAP, rid: rid, sid: sid, new_session: new_session)
    end

    # ---- beacon ----

    # Answers 204, and queues the beacon as a `sig: 1` row with the trusted-proxy-resolved
    # client IP: it rides the next event batch. Junk bodies are dropped, never shipped.
    def relay_beacon(body, ip)
      return Answer.new(status: 413, headers: {}, body: "") if body.nil?

      answer = Answer.new(status: 204, headers: { "cache-control" => "no-store" }, body: "")
      parsed = Camada.parse_json(body)
      return answer unless parsed.is_a?(Hash)

      @queue.push(parsed.merge("sig" => 1, "ip" => ip, "tap" => TAP)) # spread first: ip and tap are the server's word
      answer
    end

    # ---- challenge ----

    def challenge_passed?(req, ip)
      !@kit.nil? && @kit.token_valid?(ip, now_ms, Camada.cookie_value(req.header("cookie"), Challenge::CHALLENGE_COOKIE))
    end

    def page(ip, to)
      html = Challenge.challenge_page(nonce: @kit.nonce(ip, now_ms), action: @challenge_path, to: to)
      Answer.new(status: 403, headers: CHALLENGE_HEADERS.merge("content-type" => "text/html; charset=utf-8"), body: html)
    end

    # 403 + the proof-of-work page (HTML navigations) or 403 JSON (everything else), plus the
    # `blk: "challenge"` event — a served challenge is reported like a block (contract §D2).
    def serve_challenge_answer(req, ip, sid)
      to = Challenge.safe_return_to(req.path + req.query)
      answer =
        if Challenge.wants_html?(req.header("accept"), req.header("sec-fetch-dest"))
          page(ip, to)
        else
          Answer.new(status: 403, headers: CHALLENGE_HEADERS.merge("content-type" => "application/json"),
                     body: '{"error":"challenge_required"}')
        end
      begin
        ev = event(req, SecureRandom.uuid, sid, false, ip)
        ev["st"] = 403
        ev["blk"] = "challenge"
        @queue.push(ev)
      rescue StandardError => e # the response is decided; telemetry must never undo that
        Guarded.log_rate_limited(e)
      end
      answer
    end

    # POST from the challenge page: validate the nonce and the proof of work, set _cch, 302
    # back to the (sanitised, same-site) original URL, and ship `{ st: 200, ch: 1 }`.
    def verify(req, body, ip)
      return Answer.new(status: 413, headers: {}, body: "") if body.nil?

      form = Challenge.parse_form_body(body)
      to = Challenge.safe_return_to(form["to"])
      now = now_ms
      return page(ip, to) unless @kit.verify?(ip, now, form["nonce"], form["solution"])

      cookie = Challenge.challenge_cookie(@kit.issue(ip, now), secure?(req))
      ev = event(req, SecureRandom.uuid, Camada.cookie_value(req.header("cookie"), SESSION_COOKIE), false, ip)
      ev["st"] = 200
      ev["ch"] = 1 # challenge passed (contract §A3 ingest field)
      @queue.push(ev)
      Answer.new(status: 302, headers: { "location" => to, "set-cookie" => cookie, "cache-control" => "no-store" }, body: "")
    end
  end

  # The engine that produced a request context (the helpers resolve script_tag/track through it).
  def self.engine_of(ctx)
    eng = ctx && ctx["_engine"]
    eng.is_a?(Engine) ? eng : nil
  end

  def self.create_engine(**opts)
    e = Engine.new(**opts)
    Guarded.log_rate_limited("CAMADA_KEY (or CAMADA_TOKEN + CAMADA_SNAPSHOT_TOKEN) not set — camada is inactive") if e.env.nil?
    e
  end
end
