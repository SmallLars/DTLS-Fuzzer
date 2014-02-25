require './lib/r_type'

module Fuzzer
  module Record
    class ChangeCipherSpec < Record::Type
      def self.parse(data)
        data.force_encoding('ASCII-8BIT')
        fail HandshakeError, 'Missing data' if data.length < 1
        fail HandshakeError, 'Wrong value' unless data[0] == "\x01"
        ChangeCipherSpec.new
      end

      public

      def initialize
        super(20)
      end

      def to_wire
        "\x01".force_encoding('ASCII-8BIT')
      end
    end
  end
end
