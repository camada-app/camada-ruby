# frozen_string_literal: true

# Ported from the reference edge-analyst src/blocklist.js parsers: ip4 returns -1 on anything
# unusual; ip6 rejects zone ids and v4-mapped forms. The golden fixtures pin the rest.
RSpec.describe Camada::IpParse do
  describe ".parse_ip4" do
    it "turns a dotted quad into an integer" do
      expect(described_class.parse_ip4("203.0.113.66")).to eq((203 << 24) | (0 << 16) | (113 << 8) | 66)
      expect(described_class.parse_ip4("255.255.255.255")).to eq(0xFFFFFFFF)
      expect(described_class.parse_ip4("0.0.0.0")).to eq(0)
    end

    it "rejects anything unusual" do
      ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1..2.3", "01.2.3.4444", "a.b.c.d", " 1.2.3.4", "1.2.3.4\n"].each do |bad|
        expect(described_class.parse_ip4(bad)).to eq(-1), bad
      end
    end
  end

  describe ".parse_ip6" do
    it "reads full and compressed forms" do
      expect(described_class.parse_ip6("2001:db8::1")).to eq([0x20010DB8, 0, 0, 1])
      expect(described_class.parse_ip6("::1")).to eq([0, 0, 0, 1])
      expect(described_class.parse_ip6("::")).to eq([0, 0, 0, 0])
      expect(described_class.parse_ip6("fe80:0:0:0:0:0:0:1")).to eq([0xFE800000, 0, 0, 1])
      expect(described_class.parse_ip6("2001:DB8:CAFE::")).to eq([0x20010DB8, 0xCAFE0000, 0, 0])
    end

    it "rejects zone ids, mapped v4 and malformed input" do
      ["fe80::1%eth0", "::ffff:1.2.3.4", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "g::1", "1:2:3:4:5:6:7", ":1::"].each do |bad|
        expect(described_class.parse_ip6(bad)).to be_nil, bad
      end
    end
  end
end
