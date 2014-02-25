require './lib/h_type'

module Fuzzer
  module Handshake
    class KeyExchange < Handshake::Type
      ECCURVETYPE = { explicit_prime: "\x01",
                      explicit_char2: "\x02",
                      named_curve:    "\x03"
                      # reserved(248..255)
                      # max = 255
      }
      NAMEDCURVE = { sect163k1: "\x00\x01",
                     sect163r1: "\x00\x02",
                     sect163r2: "\x00\x03",
                     sect193r1: "\x00\x04",
                     sect193r2: "\x00\x05",
                     sect233k1: "\x00\x06",
                     sect233r1: "\x00\x07",
                     sect239k1: "\x00\x08",
                     sect283k1: "\x00\x09",
                     sect283r1: "\x00\x10",
                     sect409k1: "\x00\x11",
                     sect409r1: "\x00\x12",
                     sect571k1: "\x00\x13",
                     sect571r1: "\x00\x14",
                     secp160k1: "\x00\x15",
                     secp160r1: "\x00\x16",
                     secp160r2: "\x00\x17",
                     secp192k1: "\x00\x18",
                     secp192r1: "\x00\x19",
                     secp224k1: "\x00\x20",
                     secp224r1: "\x00\x21",
                     secp256k1: "\x00\x22",
                     secp256r1: "\x00\x23",
                     secp384r1: "\x00\x24",
                     secp521r1: "\x00\x25",
                     # reserved: \xfe\x00..\xfe\xff
                     arbitrary_explicit_prime_curves: "\xff\x01",
                     arbitrary_explicit_char2_curves: "\xff\x02"
                     # max: \xffff
      }
      POINTTYPE = { compressed: "\x02",
                    uncompressed: "\x04",
                    hybrid: "\x06"
      }

      attr_reader :psk_hint, :curve, :point
      attr_accessor :psk_hint_length

      def self.parse_ex(type, data)
        # pskHint_len (2) + pskHint (16) + ECTyp (1) + NamedCurve (2) +
        # ECPoint_len (1) + Point_type (1) + p_X (32) + p_Y (32) = (87)
        data.force_encoding('ASCII-8BIT')
        @psk_hint_len = data.slice!(0...2).unpack('n')[0]
        psk_hint = data.slice!(0...@psk_hint_len)
        curve = nil
        point = nil
        if data.length > 0
          curve = data.slice!(0...3)
          point_len = data.slice!(0...1).ord
          point = data.slice!(0...point_len)
        end
        type.new(psk_hint, curve, point)
      end

      public

      def initialize(type, psk_hint, curve, point)
        super(type)
        self.psk_hint = psk_hint
        self.curve = curve
        self.point = point
      end

      def psk_hint=(psk_hint)
        if psk_hint.nil? || psk_hint.b.length == 0
          fail HandshakeError, 'PSK-Hint needed'
        else
          @psk_hint = psk_hint.force_encoding('ASCII-8BIT')
          @psk_hint_length = psk_hint.length
        end
      end

      def curve=(curve)
        @curve = curve.force_encoding('ASCII-8BIT') unless curve.nil?
      end

      def point=(point)
        @point = point.force_encoding('ASCII-8BIT') unless curve.nil?
      end

      def to_wire
        # pskHint_len (2) + pskHint (16) + ECTyp (1) + NamedCurve (2) +
        # ECPoint_len (1) + Point_type (1) + p_X (32) + p_Y (32) = (87)
        s = ''.force_encoding('ASCII-8BIT')
        s.concat([@psk_hint_length].pack('n'))
        s.concat(@psk_hint)
        unless (@curve.nil? && @point.nil?)
          s.concat(@curve)
          s.concat([@point.length].pack('c'))
          s.concat(@point)
        end
        s
      end
    end

    # laber
    class ServerKeyExchange < KeyExchange
      def self.parse(data)
        parse_ex(ServerKeyExchange, data)
      end

      def initialize(psk_hint, curve = nil, point = nil)
        super(12, psk_hint, curve, point)
      end
    end

    # laber
    class ClientKeyExchange < KeyExchange
      def self.parse(data)
        parse_ex(ClientKeyExchange, data)
      end

      def initialize(psk_hint, curve = nil, point = nil)
        super(16, psk_hint, curve, point)
      end
    end
  end
end
