require './lib/h_type'

module Fuzzer
  module Handshake
    class ServerHelloDone < Handshake::Type
      def self.parse(data)
        ServerHelloDone.new
      end

      public

      def initialize
        super(32)
      end

      def to_wire
        ''.force_encoding('ASCII-8BIT')
      end
    end
  end
end
