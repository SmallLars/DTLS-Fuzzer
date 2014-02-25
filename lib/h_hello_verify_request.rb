require './lib/h_type'

module Fuzzer
  module Handshake
    class HelloVerifyRequest < Handshake::Type
      attr_reader :cookie

      def self.parse(data)
        HelloVerifyRequest.new(data.force_encoding('ASCII-8BIT')[3..-1])
      end

      public

      def initialize(cookie)
        super(3)
        @cookie = cookie
        @cookie = '' if cookie.nil?
        @cookie.force_encoding('ASCII-8BIT')
      end

      def to_wire
        "\xFE\xFD".force_encoding('ASCII-8BIT') + @cookie.length.chr + @cookie
      end
    end
  end
end
