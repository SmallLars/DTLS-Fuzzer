require './lib/r_type'

module Fuzzer
  module Record
    class Alert < Record::Type
      LEVEL = { warning: 1, fatal: 2 }
      DESCRIPTION = { close_notify: 0,
                      unexpected_message: 10,
                      bad_record_mac: 20,
                      decryption_failed_reserved: 21,
                      record_overflow: 22,
                      decompression_failure: 30,
                      handshake_failure: 40,
                      no_certificate_reserved: 41,
                      bad_certificate: 42,
                      unsupported_certificate: 43,
                      certificate_revoked: 44,
                      certificate_expired: 45,
                      certificate_unknown: 46,
                      illegal_parameter: 47,
                      unknown_ca: 48,
                      access_denied: 49,
                      decode_error: 50,
                      decrypt_error: 51,
                      export_restriction_reserved: 60,
                      protocol_version: 70,
                      insufficient_security: 71,
                      internal_error: 80,
                      user_canceled: 90,
                      no_renegotiation: 100,
                      unsupported_extension: 110 }

      attr_reader :level, :description

      def self.parse(data)
        data.force_encoding('ASCII-8BIT')
        Alert.new(LEVEL.key(data[0].ord), DESCRIPTION.key(data[1].ord))
      end

      public

      def initialize(level, description)
        super(21)
        self.level = level
        self.description = description
      end

      def level=(level)
        fail RecordError, 'Unknown Level' if LEVEL[level].nil?
        @level = level
      end

      def description=(description)
        fail RecordError, 'Unknown Level' if DESCRIPTION[description].nil?
        @description = description
      end

      def to_wire
        w = ''.force_encoding('ASCII-8BIT')
        w.concat(LEVEL[@level].chr)
        w.concat(DESCRIPTION[@description].chr)
      end
    end
  end
end
