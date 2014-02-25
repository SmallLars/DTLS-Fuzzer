module Fuzzer
  module Record
    class RecordError < StandardError
    end

    class Type
      attr_reader :id

      def self.parse(type, data)
        case type
          when 20; ChangeCipherSpec
          when 21; Alert
          when 22; HandshakeHead
          when 23; AppData
          else
            fail RecordError, "parse: Unknown handshake packet: #{type}"
        end.parse(data)
      end

      public

      def initialize(id)
        @id = id
      end

      def to_wire
        fail HandshakeError, 'Not implemented'
      end
    end
  end
end
