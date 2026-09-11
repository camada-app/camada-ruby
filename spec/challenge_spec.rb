# frozen_string_literal: true

# The SDK-served challenge (contracts §D2): a stateless per-(ip, UTC day) HMAC nonce, a 16-bit
# SHA-256 proof of work, and an HMAC cookie bound to the ip for one hour. Ported case for case
# from camada-core/test/challenge.test.ts via camada-python's test_challenge.py.
RSpec.describe Camada::Challenge do
  include ChallengeHelpers

  let(:kit) { Camada::Challenge.create_challenge("secret") }
  let(:ip) { ChallengeHelpers::IP }
  let(:now) { ChallengeHelpers::NOW }
  let(:day) { ChallengeHelpers::DAY_MS }

  describe "nonce" do
    it "is deterministic per ip and UTC day" do
      a = kit.nonce(ip, now)
      expect(kit.nonce(ip, now + 1000)).to eq(a)
      expect(a.length).to eq(Camada::Challenge::NONCE_HEX)
      expect(a).to match(/\A[0-9a-f]+\z/)
      expect(kit.nonce("203.0.113.10", now)).not_to eq(a)
      expect(kit.nonce(ip, now + day)).not_to eq(a)
      expect(Camada::Challenge.create_challenge("other").nonce(ip, now)).not_to eq(a)
    end

    it "accepts today and yesterday, rejects older and forgeries" do
      yesterday = kit.nonce(ip, now - day)
      expect(kit.nonce_valid?(ip, now, kit.nonce(ip, now))).to be(true)
      expect(kit.nonce_valid?(ip, now, yesterday)).to be(true)
      expect(kit.nonce_valid?(ip, now, kit.nonce(ip, now - (2 * day)))).to be(false)
      expect(kit.nonce_valid?(ip, now, "0" * 32)).to be(false)
      expect(kit.nonce_valid?(ip, now, kit.nonce(ip, now)[0..-2])).to be(false)
      expect(kit.nonce_valid?(nil, now, kit.nonce(ip, now))).to be(false)
      expect(kit.nonce_valid?(ip, now, nil)).to be(false)
    end
  end

  describe "token" do
    it "round-trips within the hour and expires after" do
      t = kit.issue(ip, now)
      expect(kit.token_valid?(ip, now + 3_599_000, t)).to be(true)
      expect(kit.token_valid?(ip, now + 3_600_000, t)).to be(false)
    end

    it "is bound to the ip and unforgeable" do
      t = kit.issue(ip, now)
      expect(kit.token_valid?("203.0.113.10", now, t)).to be(false)
      exp, mac = t.split(".")
      expect(kit.token_valid?(ip, now, "#{exp}.#{"0" * mac.length}")).to be(false)
      expect(kit.token_valid?(ip, now, "#{exp.to_i + 1}.#{mac}")).to be(false)
      expect(kit.token_valid?(nil, now, t)).to be(false) # no ip: never
      [nil, "", "x", ".mac", "notanumber.mac", "12."].each { |junk| expect(kit.token_valid?(ip, now, junk)).to be(false), junk.inspect }
    end

    it "refuses an expiry further out than the ttl" do
      far = kit.issue(ip, now + 10_000_000) # minted "in the future": exp > now + TTL
      expect(kit.token_valid?(ip, now, far)).to be(false)
    end
  end

  describe "proof of work" do
    it "accepts a 16-bit solution and rejects anything else" do
      nonce = kit.nonce(ip, now)
      sol = solve(nonce)
      expect(kit.solution_ok?(nonce, sol)).to be(true)
      expect(kit.verify?(ip, now, nonce, sol)).to be(true)
      expect(kit.solution_ok?(nonce, "#{sol}1")).to be(false)
      expect(kit.solution_ok?(nonce, "x" * 33)).to be(false)
      expect(kit.solution_ok?(nonce, nil)).to be(false)
      expect(kit.verify?(ip, now, "f" * 32, solve("f" * 32))).to be(false) # a forged nonce, even with real work
    end

    it "counts leading zero bits" do
      expect(Camada::Challenge.pow_ok?("0000ffff", 16)).to be(true)
      expect(Camada::Challenge.pow_ok?("0001ffff", 16)).to be(false)
      expect(Camada::Challenge.pow_ok?("00007fff", 17)).to be(true)
      expect(Camada::Challenge.pow_ok?("0000ffff", 17)).to be(false)
      expect(Camada::Challenge.pow_ok?("0", 4)).to be(true)
      expect(Camada::Challenge.pow_ok?("", 4)).to be(false)
      expect(Camada::Challenge.pow_ok?("0g", 5)).to be(false)
    end
  end

  describe "helpers" do
    it "formats the cookie" do
      expect(Camada::Challenge.challenge_cookie("1.abc", false)).to eq("_cch=1.abc; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax")
      expect(Camada::Challenge.challenge_cookie("1.abc", true)).to end_with("; Secure")
    end

    it "keeps only a same-site path in safe_return_to" do
      expect(Camada::Challenge.safe_return_to("/a/b?c=1")).to eq("/a/b?c=1")
      [nil, "", "https://evil", "//evil", "/\\evil", "/a b", "/é", "/#{"a" * 2048}", "relative"].each do |bad|
        expect(Camada::Challenge.safe_return_to(bad)).to eq("/"), bad.inspect
      end
    end

    it "decides wants_html" do
      expect(Camada::Challenge.wants_html?("text/html,*/*", nil)).to be(true)
      expect(Camada::Challenge.wants_html?("text/html", "document")).to be(true)
      expect(Camada::Challenge.wants_html?("application/json", nil)).to be(false)
      expect(Camada::Challenge.wants_html?("text/html", "empty")).to be(false)
      expect(Camada::Challenge.wants_html?(nil, nil)).to be(false)
    end

    it "parses a form body, last value wins, never raises" do
      expect(Camada::Challenge.parse_form_body("a=1&b=x+y&a=2&c&%zz=%zz")).to eq({ "a" => "2", "b" => "x y", "c" => "", "%zz" => "%zz" })
      f = Camada::Challenge.parse_form_body("nonce=abc&solution=7&to=%2Fx%3Fy%3D1")
      expect(f).to eq({ "nonce" => "abc", "solution" => "7", "to" => "/x?y=1" })
      expect(Camada::Challenge.parse_form_body("")).to eq({})
      expect(Camada::Challenge.parse_form_body("u=%ff%fe")["u"]).to eq("\uFFFD\uFFFD") # invalid UTF-8 is replaced, not raised
      expect(Camada::Challenge.parse_form_body("u=%c3%a9")["u"]).to eq("é")
    end

    it "escapes attributes and script values" do
      expect(Camada::Challenge.escape_attr("a<b>&\"c'")).to eq("a&lt;b&gt;&amp;&quot;c&#39;")
      expect(Camada::Challenge.escape_script("</script>")).to eq('"\\u003c/script>"')
    end

    it "splits a token" do
      expect(Camada::Challenge.split_token("12.abc")).to eq([12, "abc"])
      expect(Camada::Challenge.split_token("x.abc")).to be_nil
      expect(Camada::Challenge.split_token(".abc")).to be_nil
      expect(Camada::Challenge.split_token("12.")).to be_nil
      expect(Camada::Challenge.split_token(nil)).to be_nil
    end
  end

  describe "page" do
    it "is self-contained and escaped" do
      html = Camada::Challenge.challenge_page(nonce: "ab" * 16, action: "/__camada/challenge", to: '/x"><script>')
      expect(html).to start_with("<!doctype html>")
      expect(html.split("<script>")[0].gsub("http-equiv", "")).not_to include("http") # no external assets before the solver
      expect(html).to include('action="/__camada/challenge"')
      expect(html).to include('value="/x&quot;&gt;&lt;script&gt;"')
      expect(html).not_to include("crypto.subtle")
      expect(html).to include("__camadaSha256Words")
      expect(html).to include("shift=16")
      expect(html).to include('var nonce="abababababababababababababababab"')
    end

    it "clamps the difficulty" do
      expect(Camada::Challenge.challenge_page(nonce: "a" * 32, action: "/v", to: "/", bits: 99)).to include("shift=0")
      expect(Camada::Challenge.challenge_page(nonce: "a" * 32, action: "/v", to: "/", bits: 0)).to include("shift=31")
    end
  end
end
