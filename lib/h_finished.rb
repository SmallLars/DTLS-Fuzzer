require './lib/h_type'

module Fuzzer
  module Handshake
    class Finished < Handshake::Type
      attr_reader :value

      def self.parse(data)
        fail HandshakeError, 'Missing data' if
          data.force_encoding('ASCII-8BIT').length < 2
        Finished.new(data)
      end

      public

      def initialize(value)
        super(20)
        self.value = value
      end

      def value=(value)
        @value = value
        @value = '' if value.nil?
        @value.force_encoding('ASCII-8BIT')
      end

      def to_wire
        @value
      end
    end
  end
end
