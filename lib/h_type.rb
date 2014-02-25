module Fuzzer
  module Handshake
    class HandshakeError < StandardError
    end

    class Type
      attr_reader :id

      def self.parse(type, data)
        case type
          when 1;  ClientHello
          when 2;  ServerHello
          when 3;  HelloVerifyRequest
          when 11; Certificate
          when 12; ServerKeyExchange
          when 13; CertificateRequest
          when 14; ServerHelloDone
          when 15; CertificateVerify
          when 16; ClientKeyExchange
          when 20; Finished
          else
            fail HandshakeError, "parse: Unknown handshake packet: #{type}"
        end.parse(data)
      end

      public

      def initialize(id)
        @id = id
      end

      def to_wire
        fail HandshakeError, "to_wire: Not implemented: #{self.class}"
      end
    end
  end
end
